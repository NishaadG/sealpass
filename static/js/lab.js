/* Lab: authority, phone and gate on one screen, plus the threat lab. */
(function () {
  "use strict";
  SPUI.topbar("/lab");
  const $ = (id) => document.getElementById(id);
  const esc = SPUI.esc;
  let META, pass = null, offset = 0, lastSlot = null;
  const shots = [];

  const THREATS = [
    ["screenshot", "Screenshot replay", "A friend uses a 30-second-old screenshot, then edits the slot number."],
    ["relay", "Live relay", "A code is streamed live to a friend at the gate, then the real student arrives."],
    ["tamper", "Edit the roll number", "One character inside the signed body is changed."],
    ["forge", "Forge a pass", "The attacker signs a pass with their own key."],
    ["wrong_event", "Wrong event", "A valid Tech Fest pass is shown at the lab gate."],
    ["expired", "Expired pass", "Yesterday's pass, with a correctly rotating tag."],
    ["stolen_gate", "Stolen gate", "K_event from a stolen scanner is used to mint a pass."],
    ["revoked", "Lost phone", "A revoked pass is presented by whoever found the phone."],
    ["ledger_edit", "Edit the ledger", "An admin changes who attended after the fact."],
    ["brute_force", "Guess the tag", "Random 128-bit tags are tried against the gate."],
    ["nonce_reuse", "Nonce reuse", "What if the Authority signed two passes with the same k?"],
  ];

  async function init() {
    META = await SPUI.api("/api/meta");
    const studs = Object.entries(META.students).map(([id, n]) => `<option value="${id}">${n} (${id})</option>`).join("");
    const evs = Object.entries(META.events).map(([id, e]) => `<option value="${id}">${e.name}</option>`).join("");
    $("aStudent").innerHTML = studs; $("aEvent").innerHTML = evs; $("gEvent").innerHTML = evs;
    SPUI.renderPipeline($("gPipe"), META.steps, null, { compact: true });
    $("tGrid").innerHTML = THREATS.map(([id, t, d]) => `<button class="threat" type="button" data-id="${id}"><b>${t}</b><span>${d}</span></button>`).join("");
    $("tGrid").querySelectorAll(".threat").forEach((b) => b.addEventListener("click", () => runThreat(b.dataset.id, b)));
    listPasses();
  }

  // ---------- authority ----------
  $("aIssue").addEventListener("click", async () => {
    $("aIssue").disabled = true;
    try {
      const t0 = Date.now() / 1000;
      const res = await SPUI.api("/api/enrol", { student: $("aStudent").value, event: $("aEvent").value });
      offset = res.server_time - (t0 + Date.now() / 1000) / 2;
      pass = res; lastSlot = null;
      $("gEvent").value = res.event;
      const p = SP.parsePass(res.static);
      $("aOut").innerHTML = `<p style="margin:0 0 6px">${res.reused ? "This student already holds a valid pass for this event. It has been re-sent." : "New pass signed."}</p>
        <dl class="kv"><dt>pass_id</dt><dd class="mono">${SP.hex(p.passId)}</dd>
        <dt>body</dt><dd class="mono">${p.body.length} bytes</dd>
        <dt>e</dt><dd class="mono">${SPUI.short(SP.hex(p.sig.slice(0, 32)), 8)}</dd>
        <dt>s</dt><dd class="mono">${SPUI.short(SP.hex(p.sig.slice(32)), 8)}</dd>
        <dt>K_se</dt><dd class="mono val-saffron">${SPUI.short(res.k_se, 8)} <span class="muted">(to phone, over TLS)</span></dd></dl>`;
      listPasses();
    } catch (e) { $("aOut").innerHTML = `<span class="val-red">${esc(e.message)}</span>`; }
    $("aIssue").disabled = false;
  });

  async function listPasses() {
    const list = await SPUI.api("/api/passes");
    $("aList").innerHTML = list.length ? list.slice(0, 8).map((p) => `<div class="pl-row ${p.revoked ? "rev" : ""}">
        <div><b>${esc(p.name)}</b> <span class="mono small muted">${esc(p.event)}</span><div class="mono small muted">${p.pass_id}</div></div>
        ${p.revoked ? '<span class="chip red">revoked</span>' : `<button class="btn ghost sm" data-pid="${p.pass_id}" type="button">Revoke</button>`}</div>`).join("")
      : '<p class="small muted">No passes yet.</p>';
    $("aList").querySelectorAll("button[data-pid]").forEach((b) => b.addEventListener("click", async () => {
      await SPUI.api("/api/revoke", { pass_id: b.dataset.pid });
      listPasses();
    }));
  }

  // ---------- phone ----------
  function currentText() {
    const now = Date.now() / 1000 + offset, slot = SP.timeSlot(now);
    const p = SP.parsePass(pass.static);
    return { slot, now, text: `${pass.static}.${slot}.${SP.b64url(SP.liveTag(SP.fromHex(pass.k_se), p.passId, slot))}` };
  }
  function phoneTick() {
    if (!pass) return;
    const { slot, now, text } = currentText();
    if (slot !== lastSlot) {
      lastSlot = slot;
      SPUI.qrCanvas(text, 220, { canvas: $("lpQr"), cssSize: 220 });
      $("lpEvent").textContent = pass.event_name;
      $("lpName").textContent = pass.student;
    }
    SPUI.ring($("lpRing"), 1 - (now % 10) / 10);
    $("lpSlot").textContent = `slot ${slot}`;
    shots.forEach((s) => {
      const age = Math.round(now - s.at);
      s.el.querySelector(".age").textContent = `${age} s old`;
      s.el.classList.toggle("stale", age > 20);
    });
  }
  setInterval(phoneTick, 250);

  $("lpShot").addEventListener("click", () => {
    if (!pass) return;
    const src = $("lpQr");
    const cv = document.createElement("canvas");
    cv.width = src.width; cv.height = src.height;
    cv.getContext("2d").drawImage(src, 0, 0);
    cv.style.width = "92px"; cv.style.height = "92px";
    cv.draggable = true;
    const el = document.createElement("div");
    el.className = "shot";
    el.appendChild(cv);
    el.insertAdjacentHTML("beforeend", `<span class="age small mono">0 s old</span><button class="btn ghost sm" type="button">Scan</button>`);
    const id = "shot" + Date.now();
    cv.id = id;
    shots.unshift({ el, at: Date.now() / 1000 + offset });
    if (shots.length > 4) shots.pop().el.remove();
    const box = $("shots");
    if (box.querySelector("p")) box.innerHTML = "";
    box.prepend(el);
    cv.addEventListener("dragstart", (e) => e.dataTransfer.setData("text/plain", id));
    el.querySelector("button").addEventListener("click", () => scanCanvas(cv));
  });
  $("lpCopy").addEventListener("click", async () => {
    if (!pass) return;
    try { await navigator.clipboard.writeText(currentText().text); $("lpCopy").textContent = "Copied"; } catch (e) { $("lpCopy").textContent = "Copy blocked"; }
    setTimeout(() => { $("lpCopy").textContent = "Copy text"; }, 1400);
  });
  $("lpQr").addEventListener("dragstart", (e) => e.dataTransfer.setData("text/plain", "lpQr"));

  // ---------- gate ----------
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault(); drop.classList.remove("over");
    const id = e.dataTransfer.getData("text/plain");
    const cv = document.getElementById(id);
    if (cv && cv.tagName === "CANVAS") scanCanvas(cv);
    else if (e.dataTransfer.files[0]) SPUI.decodeImageFile(e.dataTransfer.files[0]).then(verify).catch((err) => showErr(err.message));
  });
  $("gScan").addEventListener("click", () => { if (pass) scanCanvas($("lpQr")); else showErr("Issue a pass first."); });

  function scanCanvas(cv) {
    const text = SPUI.decodeCanvas(cv);
    if (!text) return showErr("No QR found in that image.");
    drop.classList.add("hit"); setTimeout(() => drop.classList.remove("hit"), 500);
    verify(text);
  }
  async function verify(text) {
    try {
      const res = await SPUI.api("/api/verify", { event: $("gEvent").value, gate: "Lab gate", qr: text });
      SPUI.verdict($("gVerdict"), res);
      SPUI.renderPipeline($("gPipe"), META.steps, res, { compact: true });
    } catch (e) { showErr(e.message); }
  }
  function showErr(m) { $("gVerdict").innerHTML = `<p class="small val-red">${esc(m)}</p>`; }

  // ---------- threat lab ----------
  async function runThreat(id, btn) {
    $("tGrid").querySelectorAll(".threat").forEach((b) => b.classList.toggle("on", b === btn));
    $("tOut").innerHTML = '<p class="muted">Running on the server...</p>';
    const [, title, desc] = THREATS.find((t) => t[0] === id);
    let out;
    try { out = await SPUI.api(`/api/attack/${id}`, {}); } catch (e) { $("tOut").innerHTML = `<p class="val-red">${esc(e.message)}</p>`; return; }
    let html = `<h3>${esc(title)}</h3><p class="muted">${esc(desc)}</p>`;
    if (out.attempts) {
      html += `<div class="attempts">${out.attempts.map((a, i) => `<div class="attempt">
          <div class="att-head"><span class="chip ${a.result.admitted ? "teal" : "red"}">${a.result.admitted ? "Admitted" : "Blocked at " + esc(stepName(a.result.failed_step))}</span>
          <b>Attempt ${i + 1}.</b> ${esc(a.label)}</div>
          <div class="att-body"><div class="qr-frame att-qr" data-i="${i}"></div><div class="att-pipe" data-i="${i}"></div></div>
          <p class="small" style="margin:8px 0 0">${esc(a.result.reason)}</p></div>`).join("")}</div>`;
    }
    if (out.note) html += `<div class="note teal" style="margin-top:14px">${esc(out.note)}</div>`;
    if (out.avalanche) {
      const av = out.avalanche;
      html += `<div class="grid g2" style="margin-top:16px"><div><p class="panel-title">Signed body vs edited body</p>
        <div class="hex">${diffHex(av.original, av.tampered)}</div><p class="small muted">${av.input_bits_changed} input bits changed</p></div>
        <div><p class="panel-title">Their SHA-256 hashes</p><div class="hex">${diffHex(av.h1, av.h2)}</div>
        <p class="small"><b class="val-red">${av.bits_changed} of 256</b> hash bits differ, so the signature on the old hash says nothing about the new body.</p></div></div>`;
    }
    if (out.ledger_after) {
      html += `<p class="panel-title" style="margin-top:12px">Ledger after the edit</p><div class="chain-mini">${out.ledger_after.map((b, i) => `
        <div class="cm ${i === out.first_bad ? "bad" : i > out.first_bad ? "after" : ""}"><b>#${b.index} ${esc(b.student)}</b>
        <span class="mono small">stored ${b.hash.slice(0, 10)}</span>${i === out.first_bad ? `<span class="mono small val-red">recomputed ${out.recomputed.slice(0, 10)}</span>` : ""}</div>`).join("")}</div>
        <div class="note red" style="margin-top:12px">Entry #1 was changed from ${esc(out.ledger_before[1].student)} to ${esc(out.ledger_after[1].student)}. Its recomputed hash no longer matches the stored one, and entry #2's prev_hash points to the old value. The chain reports the break at entry ${out.first_bad}.</div>`;
    }
    if (out.tries !== undefined) {
      html += `<div class="note" style="margin-top:14px">${out.tries} random guesses in ${out.seconds} s: <b>${out.hits} hits</b>. With a ${out.tag_bits}-bit tag each guess succeeds with probability 2<sup>-${out.tag_bits}</sup> &asymp; 3 &times; 10<sup>-39</sup>, and the guess has to land inside a single 10-second slot. ${esc(out.note)}</div>`;
    }
    if (out.recovered) {
      html += `<div class="grid g2" style="margin-top:12px"><div class="hex">sig 1: e=${SPUI.short(out.sig1[0])}, s=${SPUI.short(out.sig1[1])}<br>sig 2: e=${SPUI.short(out.sig2[0])}, s=${SPUI.short(out.sig2[1])}<br><br>
        x = (s1 - s2) / (e1 - e2) mod n<br>recovered <span class="val-red">${SPUI.short(out.recovered, 14)}</span><br>real key&nbsp;&nbsp;<span class="val-saffron">${SPUI.short(out.private, 14)}</span></div>
        <div><div class="note red">${out.match ? "The private signing key is recovered from two public signatures. Every pass could then be forged." : "No match."}</div>
        <p class="small" style="margin-top:10px">SealPass's HMAC-derived nonces for these two messages differ:<br><span class="mono">${SPUI.short(out.hmac_nonces[0])}</span><br><span class="mono">${SPUI.short(out.hmac_nonces[1])}</span></p></div></div>`;
    }
    $("tOut").innerHTML = html;
    (out.attempts || []).forEach((a, i) => {
      const q = $("tOut").querySelector(`.att-qr[data-i="${i}"]`);
      q.appendChild(SPUI.qrCanvas(a.qr, 120, { cssSize: 120 }));
      SPUI.renderPipeline($("tOut").querySelector(`.att-pipe[data-i="${i}"]`), META.steps, a.result, { compact: true });
    });
  }
  const stepName = (id) => (META.steps.find((s) => s.id === id) || { name: id }).name;
  function diffHex(a, b) {
    let out = "";
    for (let i = 0; i < Math.max(a.length, b.length); i += 2) {
      const x = a.substr(i, 2), y = b.substr(i, 2);
      out += x === y ? `<span class="muted">${y}</span>` : `<span class="val-red">${y}</span>`;
    }
    return out;
  }

  init();
})();
