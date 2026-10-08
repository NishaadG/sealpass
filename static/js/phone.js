/* Student phone: holds the signed pass and K_se, and redraws the QR every slot.
   The tag is computed here, in the browser, with the same HMAC as the server. */
(function () {
  "use strict";
  SPUI.topbar("/phone");
  const $ = (id) => document.getElementById(id);
  const KEY = "sp-phone-pass";
  let pass = null, offset = 0, lastSlot = null, meta = null;

  function loadSaved() {
    try { return JSON.parse(SPUI.store.get(KEY) || "null"); } catch (e) { return null; }
  }

  async function init() {
    meta = await SPUI.api("/api/meta");
    $("student").innerHTML = Object.entries(meta.students).map(([id, n]) => `<option value="${id}">${n} (${id})</option>`).join("");
    $("event").innerHTML = Object.entries(meta.events).map(([id, e]) => `<option value="${id}">${e.name}</option>`).join("");
    const saved = loadSaved();
    if (saved && saved.not_after > Date.now() / 1000) { pass = saved; await syncClock(); show(); }
  }

  async function syncClock() {
    // The gate checks the slot against its own clock, so line the phone up with the server.
    try {
      const t0 = Date.now() / 1000;
      const m = await SPUI.api("/api/meta");
      const t1 = Date.now() / 1000;
      offset = m.server_time - (t0 + t1) / 2;
    } catch (e) { /* offline: keep the last known offset */ }
  }

  $("enrolBtn").addEventListener("click", async () => {
    $("enrolBtn").disabled = true; $("enrolErr").textContent = "";
    try {
      const t0 = Date.now() / 1000;
      const res = await SPUI.api("/api/enrol", { student: $("student").value, event: $("event").value });
      const t1 = Date.now() / 1000;
      offset = res.server_time - (t0 + t1) / 2;
      pass = res;
      SPUI.store.set(KEY, JSON.stringify(res));
      show();
    } catch (e) { $("enrolErr").textContent = e.message; }
    $("enrolBtn").disabled = false;
  });

  $("switchBtn").addEventListener("click", () => {
    $("pass").classList.add("hidden"); $("enrol").classList.remove("hidden"); pass = null;
  });

  function show() {
    $("enrol").classList.add("hidden");
    $("pass").classList.remove("hidden");
    const ev = meta.events[pass.event] || {};
    $("pEventKind").textContent = `${ev.kind || "Pass"} · ${ev.venue || ""}`;
    $("pEvent").textContent = pass.event_name;
    $("pName").textContent = pass.student_name;
    $("pRoll").textContent = pass.student;
    $("pSeal").innerHTML = SPUI.sealMark(44);
    SPUI.microtext($("micro"), `${pass.student} ${pass.event} SEALPASS `);
    const p = SP.parsePass(pass.static);
    $("pKv").innerHTML = [
      ["pass_id", SP.hex(p.passId)], ["key_id", SP.hex(p.keyId)],
      ["valid until", new Date(p.notAfter * 1000).toLocaleString()],
      ["signature e", SPUI.short(SP.hex(p.sig.slice(0, 32)), 12)], ["signature s", SPUI.short(SP.hex(p.sig.slice(32)), 12)],
      ["K_se (secret)", "stored on this phone only"],
    ].map(([k, v]) => `<dt>${k}</dt><dd class="mono">${v}</dd>`).join("");
    SPUI.guilloche(document.querySelector(".pass-guilloche"), { size: 400, rings: [[180, 29, 56], [140, 23, 40], [100, 17, 26]], opacity: 0.35 });
    lastSlot = null;
    tick();
  }

  function tick() {
    if (!pass) return;
    const now = Date.now() / 1000 + offset;
    const slot = SP.timeSlot(now);
    if (slot !== lastSlot) {
      lastSlot = slot;
      const p = SP.parsePass(pass.static);
      const tag = SP.liveTag(SP.fromHex(pass.k_se), p.passId, slot);
      const text = `${pass.static}.${slot}.${SP.b64url(tag)}`;
      const size = Math.min(window.innerWidth - 90, 320);
      SPUI.qrCanvas(text, size, { canvas: $("qr"), cssSize: size });
      $("slot").textContent = slot;
    }
    const into = (now % SP.SLOT_SECONDS) / SP.SLOT_SECONDS;
    SPUI.ring($("ring"), 1 - into);
    $("secs").textContent = Math.ceil(SP.SLOT_SECONDS * (1 - into));
    $("liveClock").textContent = new Date(now * 1000).toLocaleTimeString([], { hour12: false });
    document.querySelector(".pass-guilloche").style.transform = `rotate(${(now * 6) % 360}deg)`;
  }

  setInterval(tick, 200);
  init().catch((e) => { $("enrolErr").textContent = "Could not reach the server: " + e.message; });
})();
