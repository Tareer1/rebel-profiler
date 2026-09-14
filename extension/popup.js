const $ = (id) => document.getElementById(id);

$("save").addEventListener("click", async () => {
  await chrome.storage.local.set({ token: $("token").value.trim() });
  $("status").textContent = "token saved";
});

$("check").addEventListener("click", async () => {
  const token = (await chrome.storage.local.get("token")).token || "";
  try {
    const res = await fetch("http://127.0.0.1:8765/healthz", {
      headers: token ? { Authorization: "Bearer " + token } : {},
    });
    const data = await res.json();
    $("status").className = "ok";
    $("status").textContent =
      "bridge ok — case " + (data.case_id || "?") +
      "\nscope entries: " + ((data.scope || []).length);
  } catch (e) {
    $("status").className = "bad";
    $("status").textContent = "bridge unreachable: " + e.message;
  }
});

$("poll").addEventListener("click", async () => {
  $("status").textContent = "polling…";
  try {
    await chrome.runtime.sendMessage({ tick: true });
    $("status").className = "ok";
    $("status").textContent = "tick complete — see bridge result files";
  } catch (e) {
    $("status").className = "bad";
    $("status").textContent = "tick failed: " + e.message;
  }
});
