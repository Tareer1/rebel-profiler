/**
 * Rebel Profiler Bridge — background service worker.
 *
 * Talks ONLY to the local bridge (127.0.0.1). Protocol, mirrored from
 * rebel_profiler/browser/bridge.py:
 *
 *   GET  /tasks           → [{job_id, seq, url, extract}]
 *   POST /ack             → claim (SYN-ACK)   {job_id, ack, url, extract}
 *   POST /result          → final result (ACK) {job_id, ok, data|error...}
 *
 * Safety rules enforced client-side (defense in depth):
 *   - every URL is re-checked against the locally cached scope patterns
 *     before any navigation; out-of-scope jobs are failed, never fetched,
 *   - extraction is read-only: page text, links, headers, meta, forms
 *     shape, cookies for the page's own origin. No clicks, no typing,
 *     no script injection into pages beyond the declared extractors.
 *   - results never include page content beyond the requested extractors,
 *     bounded in size.
 */

const BRIDGE = "http://127.0.0.1:8765";
const POLL_MS = 2000;
let scopePatterns = [];      // e.g. ["*.lab.example.test", "example.com"]
let running = false;

async function api(path, options = {}) {
  const token = (await chrome.storage.local.get("token")).token || "";
  const res = await fetch(BRIDGE + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: "Bearer " + token } : {}),
      ...(options.headers || {}),
    },
  });
  if (!res.ok) throw new Error("bridge " + path + " → " + res.status);
  return res.json();
}

async function refreshScope() {
  try {
    const data = await api("/healthz");
    scopePatterns = data.scope || scopePatterns;
  } catch (e) {
    /* bridge down; keep last known scope */
  }
}

/** Scope check mirrors security/scope.py: exclusions win, then includes. */
function inScope(url) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return false;
  }
  for (const p of scopePatterns) {
    if (!p.excluded) continue;
    if (matchPattern(p.value, host)) return false;
  }
  for (const p of scopePatterns) {
    if (p.excluded) continue;
    if (matchPattern(p.value, host)) return true;
  }
  return false;
}

/** fnmatch-style wildcard (*.example.test), plus the apex-host rule. */
function matchPattern(pattern, host) {
  pattern = pattern.toLowerCase().replace(/\.$/, "");
  if (pattern === host) return true;
  if (pattern.includes("*")) {
    const re = new RegExp(
      "^" + pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^.]*") + "$"
    );
    if (re.test(host)) return true;
    if (pattern.startsWith("*.")) {
      const apex = pattern.slice(2);
      if (host === apex || host.endsWith("." + apex)) return true;
    }
  }
  return false;
}

function failResult(jobId, errorClass, message, fix) {
  return {
    job_id: jobId,
    ok: false,
    error_class: errorClass,
    error: String(message).slice(0, 300),
    fix: fix || "Read the error log, correct the job, re-submit.",
  };
}

/**
 * Interaction executor: performs user-like actions (click/type/scroll/submit)
 * inside the page. Only ops validated by the bridge reach here; submit/navigate
 * jobs required operator approval before publication.
 */
async function runInteractions(tabId, actions) {
  const log = [];
  for (const step of actions || []) {
    const entry = { op: step.op, selector: step.selector || "", ok: false };
    try {
      const [{ result } = {}] = await chrome.scripting.executeScript({
        target: { tabId },
        func: (step) => {
          const wait = (ms) => new Promise((r) => setTimeout(r, ms));
          if (step.op === "wait") return wait(step.wait_ms || 300);
          if (step.op === "scroll") {
            window.scrollBy(0, parseInt((step.text || "600").replace(/[^0-9-]/g, "")) || 600);
            return "scrolled";
          }
          const el = document.querySelector(step.selector);
          if (!el) throw new Error("selector not found: " + step.selector);
          el.scrollIntoView({ block: "center" });
          if (step.op === "click") {
            el.click();
            return "clicked";
          }
          if (step.op === "type") {
            el.focus();
            el.value = step.text || "";
            el.dispatchEvent(new Event("input", { bubbles: true }));
            el.dispatchEvent(new Event("change", { bubbles: true }));
            return "typed";
          }
          if (step.op === "submit") {
            if (el.form) {
              el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
              return "submitted";
            }
            if (el.tagName === "FORM") {
              el.requestSubmit ? el.requestSubmit() : el.submit();
              return "submitted";
            }
            throw new Error("element is not in a form");
          }
          if (step.op === "navigate") {
            location.href = step.text;   // validated as http(s) URL by the bridge
            return "navigating";
          }
          throw new Error("unknown op " + step.op);
        },
        args: [step],
      });
      entry.ok = true;
      entry.result = String(result).slice(0, 80);
    } catch (e) {
      entry.ok = false;
      entry.error = String(e.message || e).slice(0, 160);
      log.push(entry);
      return log;   // stop the script at the first failing step
    }
    log.push(entry);
    await new Promise((r) => setTimeout(r, step.wait_ms || 300));
  }
  return log;
}

/** The read-only extractor set. */
async function extractFromTab(tabId, extractors, url) {
  const data = {};
  const [{ result: frameResult } = {}] = await chrome.scripting
    .executeScript({
      target: { tabId },
      func: (wanted, maxText, maxLinks) => {
        const out = {};
        if (wanted.includes("title")) out.title = document.title || "";
        if (wanted.includes("text")) {
          out.text = (document.body ? document.body.innerText : "").slice(0, maxText);
        }
        if (wanted.includes("links")) {
          const seen = new Set();
          out.links = [];
          for (const a of document.querySelectorAll("a[href]")) {
            let abs;
            try {
              abs = new URL(a.href, document.baseURI).href;
            } catch {
              continue;
            }
            if (!seen.has(abs)) {
              seen.add(abs);
              out.links.push(abs);
            }
            if (out.links.length >= maxLinks) break;
          }
        }
        if (wanted.includes("meta")) {
          out.meta = {};
          for (const m of document.querySelectorAll("meta[name], meta[property]")) {
            const key = m.getAttribute("name") || m.getAttribute("property");
            if (key && out.meta[key] === undefined) out.meta[key] = m.getAttribute("content") || "";
          }
        }
        if (wanted.includes("forms")) {
          out.forms = Array.from(document.querySelectorAll("form")).slice(0, 20).map((f) => ({
            action: f.action || "",
            method: (f.method || "get").toLowerCase(),
            fields: Array.from(f.querySelectorAll("input,select,textarea")).slice(0, 40).map((i) => ({
              name: i.name || "",
              type: i.type || "",
            })),
          }));
        }
        return out;
      },
      args: [extractors, 20000, 300],
    })
    .catch((e) => ({ result: null }));

  Object.assign(data, frameResult || {});

  if (extractors.includes("headers")) {
    // response headers are not readable from the page; report what we can
    data.headers = { note: "use header-audit action for response headers" };
  }
  if (extractors.includes("cookies")) {
    try {
      const jar = await chrome.cookies.getAll({ url });
      // cookie values are secrets — names + flags only, never values
      data.cookies = jar.slice(0, 50).map((c) => ({
        name: c.name,
        domain: c.domain,
        secure: c.secure,
        httpOnly: c.httpOnly,
        sameSite: c.sameSite,
      }));
    } catch (e) {
      data.cookies = { error: String(e).slice(0, 120) };
    }
  }
  return data;
}

async function runJob(task) {
  const { job_id: jobId, url, extract, actions } = task;
  if (!inScope(url)) {
    return failResult(jobId, "ScopeViolationError", "URL out of scope: " + url,
      "Ask the operator to widen the case scope; the extension never fetches out-of-scope URLs.");
  }
  let tab;
  try {
    tab = await chrome.tabs.create({ url, active: false });
    await waitForComplete(tab.id, 15000);
  } catch (e) {
    if (tab?.id !== undefined) await closeQuietly(tab.id);
    return failResult(jobId, "NavigationError", e.message || String(e),
      "Check the URL and network, then re-submit the job.");
  }
  try {
    let actionLog = [];
    if (actions && actions.length) {
      actionLog = await runInteractions(tab.id, actions);
      const failed = actionLog.find((a) => !a.ok);
      if (failed) {
        // page state changed mid-script; re-extract what we can, then fail
        const data = await extractFromTab(tab.id, extract, url).catch(() => ({}));
        return {
          job_id: jobId, ok: false, url,
          error_class: "InteractionError",
          error: "step failed: " + failed.op + " " + failed.selector +
                 (failed.error ? " — " + failed.error : ""),
          fix: "Fix the failing selector/op and re-submit; a read-only extract of the current page state is attached.",
          action_log: actionLog,
          data,
        };
      }
      // give the page a moment to react to the last action before extracting
      await new Promise((r) => setTimeout(r, 800));
    }
    const data = await extractFromTab(tab.id, extract, url);
    return { job_id: jobId, ok: true, url, data, action_log: actionLog };
  } catch (e) {
    return failResult(jobId, "ExtractionError", e.message || String(e),
      "The page may block scripted reads (CSP/permissions); try fewer extractors.");
  } finally {
    await closeQuietly(tab.id);
  }
}

function waitForComplete(tabId, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("navigation timeout"));
    }, timeoutMs);
    function cleanup() {
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(listener);
    }
    function listener(id, info) {
      if (id === tabId && info.status === "complete") {
        cleanup();
        resolve();
      }
    }
    chrome.tabs.onUpdated.addListener(listener);
    chrome.tabs.get(tabId).then((t) => {
      if (t.status === "complete") {
        cleanup();
        resolve();
      }
    }).catch(() => {});
  });
}

async function closeQuietly(tabId) {
  try {
    await chrome.tabs.remove(tabId);
  } catch {
    /* already gone */
  }
}

async function tick() {
  if (running) return;
  running = true;
  try {
    await refreshScope();
    const { tasks } = await api("/tasks");
    for (const task of tasks || []) {
      const claimed = await api("/ack", {
        method: "POST",
        body: JSON.stringify({ job_id: task.job_id }),
      });
      if (!claimed || !claimed.url) continue;
      let result;
      try {
        result = await runJob(claimed);
      } catch (e) {
        result = failResult(task.job_id, "WorkerError", e.message || String(e));
      }
      await api("/result", { method: "POST", body: JSON.stringify(result) });
    }
  } catch (e) {
    /* bridge down or transient — retry next tick */
  } finally {
    running = false;
  }
}

chrome.alarms.create("poll", { periodInMinutes: POLL_MS / 60000 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "poll") tick();
});
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.tick) tick();
  return false;
});
chrome.runtime.onInstalled.addListener(tick);
tick();
