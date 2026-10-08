/* Gate scanner: reads QR codes from the phone camera (or a photo) and sends
   them to the verifier, then shows each of the ten checks. */
(function () {
  "use strict";
  SPUI.topbar("/gate");
  const $ = (id) => document.getElementById(id);
  let meta, stream = null, busy = false, lastText = "", lastAt = 0;

  async function init() {
    meta = await SPUI.api("/api/meta");
    $("event").innerHTML = Object.entries(meta.events).map(([id, e]) => `<option value="${id}">${e.name}</option>`).join("");
    const savedEvent = SPUI.store.get("sp-gate-event"), savedName = SPUI.store.get("sp-gate-name");
    if (savedEvent && meta.events[savedEvent]) $("event").value = savedEvent;
    if (savedName) $("gateName").value = savedName;
    $("event").addEventListener("change", () => SPUI.store.set("sp-gate-event", $("event").value));
    $("gateName").addEventListener("change", () => SPUI.store.set("sp-gate-name", $("gateName").value));
    const secure = window.isSecureContext && navigator.mediaDevices && navigator.mediaDevices.getUserMedia;
    $("secure").className = `chip ${location.protocol === "https:" ? "teal" : "saffron"}`;
    $("secure").textContent = location.protocol === "https:" ? "TLS connection" : "Plain HTTP";
    if (!secure) {
      $("camHint").textContent = "Live camera needs HTTPS. Open this page on the https:// address, or use \"Take a photo instead\", which works anywhere.";
      $("camBtn").disabled = true;
    }
    SPUI.renderPipeline($("pipe"), meta.steps, null);
  }

  $("camBtn").addEventListener("click", async () => {
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false });
      const v = $("video");
      v.srcObject = stream;
      await v.play();
      $("vfIdle").classList.add("hidden");
      $("viewfinder").classList.add("live");
      requestAnimationFrame(scanLoop);
    } catch (e) {
      $("camHint").textContent = "Camera unavailable: " + e.message + ". Use \"Take a photo instead\".";
    }
  });

  function scanLoop() {
    if (!stream) return;
    const v = $("video");
    if (v.readyState >= 2 && !busy) {
      const cv = $("frame");
      const w = 640, h = Math.round((v.videoHeight / v.videoWidth) * 640) || 480;
      cv.width = w; cv.height = h;
      const ctx = cv.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(v, 0, 0, w, h);
      const img = ctx.getImageData(0, 0, w, h);
      const code = jsQR(img.data, w, h, { inversionAttempts: "dontInvert" });
      if (code && code.data) handle(code.data);
    }
    setTimeout(() => requestAnimationFrame(scanLoop), 120);
  }

  $("photo").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    try { await handle(await SPUI.decodeImageFile(f), true); }
    catch (err) { $("camHint").textContent = err.message; }
    e.target.value = "";
  });

  $("pasteBtn").addEventListener("click", () => {
    const t = prompt("Paste the code text (starts with SP1.)");
    if (t) handle(t.trim(), true);
  });

  async function handle(text, force = false) {
    const now = Date.now();
    if (!force && text === lastText && now - lastAt < 4000) return; // same code still in view
    lastText = text; lastAt = now; busy = true;
    try {
      const res = await SPUI.api("/api/verify", { event: $("event").value, gate: $("gateName").value, qr: text });
      show(res);
    } catch (e) {
      show({ admitted: false, reason: e.message, steps: [], student: null });
    }
    setTimeout(() => { busy = false; }, 1200);
  }

  function show(res) {
    $("resultBox").classList.remove("hidden");
    SPUI.verdict($("verdict"), res);
    if (res.steps && res.steps.length) SPUI.renderPipeline($("pipe"), meta.steps, res);
    const fl = $("flash");
    fl.className = `flash on ${res.admitted ? "ok" : "no"}`;
    if (navigator.vibrate) navigator.vibrate(res.admitted ? 60 : [80, 60, 80]);
    setTimeout(() => { fl.className = "flash"; }, 650);
    if (!stream) $("resultBox").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  init().catch((e) => { $("camHint").textContent = "Could not reach the server: " + e.message; });
})();
