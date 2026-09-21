"""Autonomous JS surface hunter: crawl → collect JS → mine → rank.

The missing piece between "audited headers" and a real bug-hunt workflow:
the crawler saves pages but never follows ``<script src>``, so everything
interesting a web app leaks through its JavaScript (API routes, S3 buckets,
Firebase projects, keys) stayed invisible. This module closes that loop —
the hunter *is* the analyst:

1. take the pages the scope-enforced auditor already fetched (or fetch the
   seed itself), harvest every ``<script src>`` and inline script;
2. mine each JS document through :mod:`jsintel` (bounded, offline);
3. optionally fold in Wayback CDX history for the host;
4. rank everything into a triaged queue — secret candidates first, then
   in-scope API endpoints, then cloud assets, then historical URLs — with
   a ready-to-run ``probe`` suggestion per high-priority item.

Every fetch is scope-validated on the exact URL (same law as the auditor):
an out-of-scope script src is recorded as skipped, never fetched. All
evidence is hash-chained; all output is a triage queue a human reads.
"""

from __future__ import annotations

import html.parser
import time
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.errors import ScopeViolationError, UsageError
from .jsintel import extract

MAX_JS_BYTES = 512 * 1024          # per-file fetch cap (jsintel re-caps text)
MAX_SCRIPTS = 25                   # scripts mined per hunt
MAX_BODY_BYTES = 2 * 1024 * 1024   # per-page fetch cap
_FETCH_TIMEOUT = 20

_SCRIPT_SRC = "script-src"         # evidence meta key


class _ScriptParser(html.parser.HTMLParser):
    """Collect <script src> URLs and inline script bodies from a page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._buffer: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            src = a.get("src", "")
            if src:
                self.script_srcs.append(src)
                self._in_script = False   # external: no body to collect
            else:
                self._in_script = True
                self._buffer = []

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._buffer))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._buffer.append(data)


@dataclass
class HuntItem:
    """One ranked triage item."""
    priority: int          # 1 = drop everything, 3 = background noise
    category: str          # secret | endpoint | cloud | historical
    kind: str              # jsintel claim kind
    value: str
    origin: str            # which script/page it came from
    confidence: str        # high | candidate
    suggestion: str        # what the operator (or probe) should do next

    def as_dict(self) -> dict:
        return {
            "priority": self.priority, "category": self.category,
            "kind": self.kind, "value": self.value, "origin": self.origin,
            "confidence": self.confidence, "suggestion": self.suggestion,
        }


def _suggestion(category: str, kind: str, value: str) -> str:
    """The ready-to-run next step per item — the hunter hands over work."""
    if category == "secret":
        return ("verify out-of-band; if it is a live key, revoke+rotate is "
                "the responsible-disclosure action — do not paste it anywhere")
    if category == "cloud":
        return (f"check listing/auth on {value} manually (one request, e.g. "
                f"'rebel-profiler intel collect <case> probe https://{value}/ "
                "-p method GET') after adding it to scope if authorized")
    if category == "endpoint":
        return (f"candidate API route — try IDOR/authz variation manually, "
                f"or probe: intel collect <case> probe {value} -p method GET")
    return "review the historical URL; check whether the path still exists"


class JsHunter:
    """Scope-enforced autonomous JS miner for one case."""

    source_key = "js.static"

    def __init__(self, case_id: str, *, scope_engine, evidence,
                 fetch=None, max_scripts: int = MAX_SCRIPTS) -> None:
        self.case_id = case_id
        self.scope_engine = scope_engine
        self.evidence = evidence
        self.fetch = fetch or _hunt_fetch
        self.max_scripts = max_scripts

    # -- scope ------------------------------------------------------------
    def _check_scope(self, url: str) -> bool:
        """True when this exact URL may be fetched; False otherwise."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        try:
            return self.scope_engine.evaluate(self.case_id, host) == "in_scope"
        except Exception:
            return False

    # -- the hunt ----------------------------------------------------------
    def hunt(self, page_url: str, *, page_body: bytes | None = None,
             include_wayback: bool = True) -> dict:
        """Mine one in-scope page: scripts harvested, JS fetched, ranked."""
        started = time.time()
        if not self._check_scope(page_url):
            raise ScopeViolationError(
                f"Seed {page_url} is not authorized in case {self.case_id}",
                action="Add the host to the case scope first.")

        if page_body is None:
            status, _, page_body = self.fetch(page_url)
            if status != 200:
                return self._empty(page_url, f"seed status {status}")
        else:
            status = 200

        parser = _ScriptParser()
        try:
            parser.feed(page_body.decode("utf-8", errors="replace"))
        except Exception:
            return self._empty(page_url, "unparseable seed page")

        items: list[HuntItem] = []
        skipped: list[dict] = []
        scripts: list[dict] = []

        # inline scripts: mine directly, no fetch needed
        for i, body in enumerate(parser.inline_scripts[:self.max_scripts]):
            items.extend(self._mine(body, origin=f"{page_url}#inline[{i}]"))

        # external scripts: scope-check the RESOLVED url, then fetch
        base = page_url
        for src in parser.script_srcs:
            if len(scripts) >= self.max_scripts:
                break
            absolute = urljoin(base, src)
            if not self._check_scope(absolute):
                skipped.append({"src": absolute, "reason": "out_of_scope"})
                continue
            try:
                s, _headers, js_body = self.fetch(absolute)
            except UsageError as exc:
                skipped.append({"src": absolute, "reason": exc.message[:120]})
                continue
            if s != 200 or not js_body:
                skipped.append({"src": absolute, "reason": f"status {s}"})
                continue
            scripts.append({"url": absolute, "bytes": len(js_body),
                            _SCRIPT_SRC: True})
            # Some 'script' URLs are images/fonts/html served as bytes —
            # decode defensively and skip what is not text.
            try:
                js_text = js_body.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                skipped.append({"src": absolute, "reason": "binary body"})
                continue
            items.extend(self._mine(js_text, origin=absolute))

        # optional history
        if include_wayback:
            items.extend(self._wayback_items(page_url))

        # nothing found beyond history is a legitimate result, but the seed
        # still ships *something*; keep the report from looking like a no-op
        ranked = self._rank(items)
        blob = _evidence_blob(page_url, scripts, ranked, skipped)
        rec = self.evidence.register(
            self.case_id, kind="js_hunt", data=blob, source=self.source_key,
            note=f"js hunt on {page_url}",
            meta={"scripts_mined": len(scripts),
                  "items": len(ranked),
                  "skipped": len(skipped)},
        )
        return {
            "schema_version": 1,
            "case_id": self.case_id,
            "seed": page_url,
            "scripts_mined": scripts,
            "skipped": skipped,
            "items": [i.as_dict() for i in ranked],
            "evidence_id": rec.id,
            "stats": {
                "scripts_mined": len(scripts),
                "skipped": len(skipped),
                "p1": sum(1 for i in ranked if i.priority == 1),
                "p2": sum(1 for i in ranked if i.priority == 2),
                "p3": sum(1 for i in ranked if i.priority == 3),
                "wall_seconds": round(time.time() - started, 2),
            },
        }

    # -- pieces --------------------------------------------------------------
    def _mine(self, js_text: str, *, origin: str) -> list[HuntItem]:
        items: list[HuntItem] = []
        report = extract(js_text)
        for e in report["endpoints"]:
            cat = "endpoint" if e["kind"] == "api_path" else "url"
            items.append(HuntItem(
                priority=2, category=cat, kind=e["kind"], value=e["value"],
                origin=origin, confidence=e["confidence"],
                suggestion=_suggestion(cat, e["kind"], e["value"])))
        for s in report["secrets"]:
            items.append(HuntItem(
                priority=1, category="secret", kind=s["kind"],
                value=s["value"], origin=origin,
                confidence=s["confidence"],
                suggestion=_suggestion("secret", s["kind"], s["value"])))
        for h in report["hosts"]:
            items.append(HuntItem(
                priority=2, category="cloud", kind=h["kind"],
                value=h["value"], origin=origin,
                confidence=h["confidence"],
                suggestion=_suggestion("cloud", h["kind"], h["value"])))
        return items

    def _wayback_items(self, page_url: str) -> list[HuntItem]:
        host = (urlparse(page_url).hostname or "").lower()
        if not host:
            return []
        import json as _json
        try:
            request = urllib.request.Request(
                "https://web.archive.org/cdx/search/cdx"
                f"?url={host}%2F*&output=text&fl=original&collapse=urlkey"
                "&limit=300",
                headers={"User-Agent": "rebel-profiler-hunter/0.1"})
            with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as r:
                lines = r.read(200_000).decode("utf-8", errors="replace")
        except Exception:
            return []   # archive down/rate-limited: history is optional
        items: list[HuntItem] = []
        base = (urlparse(page_url).scheme or "https") + "://" + host
        for line in lines.splitlines():
            url = line.strip()
            if not url.startswith("http"):
                continue
            path = url.split(host, 1)[-1] if host in url else ""
            items.append(HuntItem(
                priority=3, category="historical", kind="wayback_url",
                value=url[:300], origin=f"wayback:{host}",
                confidence="candidate",
                suggestion=_suggestion("historical", "wayback_url", url)))
        return items[:150]

    @staticmethod
    def _rank(items: list[HuntItem]) -> list[HuntItem]:
        # dedupe on (category, value) keeping the first (highest) occurrence
        seen: set = set()
        unique: list[HuntItem] = []
        for item in items:
            key = (item.category, item.value.lower())
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        # XML namespace boilerplate (w3.org et al.) is noise in every SPA:
        # demote it behind every real finding instead of ranking by URL.
        for item in unique:
            if "w3.org" in item.value or "xml.namespace" in item.value:
                item.priority = max(item.priority, 3)
        unique.sort(key=lambda i: (i.priority,
                                   0 if i.confidence == "high" else 1,
                                   i.value))
        return unique[:200]

    def _empty(self, page_url: str, note: str) -> dict:
        return {"schema_version": 1, "case_id": self.case_id,
                "seed": page_url, "scripts_mined": [], "skipped": [],
                "items": [], "evidence_id": None,
                "stats": {"scripts_mined": 0, "skipped": 0, "p1": 0,
                          "p2": 0, "p3": 0, "note": note}}


def _hunt_fetch(url: str) -> tuple[int, dict, bytes]:
    """Bounded fetch with a browser-ish UA (defaults look like a bot)."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; "
                                    "rv:128.0) Gecko/20100101 Firefox/128.0"})
    try:
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT) as resp:
            return resp.status, dict(resp.headers.items()), \
                resp.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, b""
    except (urllib.error.URLError, OSError) as exc:
        raise UsageError(
            f"Fetch failed for {url}", reason=str(exc),
            action="Check network reachability or skip this URL.") from exc


def _evidence_blob(page_url: str, scripts: list, items: list,
                   skipped: list) -> bytes:
    import json as _json
    return _json.dumps({
        "seed": page_url,
        "scripts": scripts,
        "skipped": skipped,
        "items": [i.as_dict() for i in items],
    }, indent=1, default=str).encode("utf-8", errors="replace")
