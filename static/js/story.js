/* Story page: hero, design chapters, architecture, the gate demo, analysis and self-test. */
(function () {
  "use strict";
  SPUI.topbar("/");
  const $ = (id) => document.getElementById(id);
  const esc = SPUI.esc;
  const C = window.SPC;
  let META = null;

  // ---------- hero ----------
  SPUI.guilloche($("heroG"), { size: 900, rings: [[400, 63, 120], [330, 52, 96], [260, 41, 70], [190, 30, 46]], opacity: 0.22, width: 0.7 });
  SPUI.guilloche($("sampleG"), { size: 400, rings: [[180, 29, 56], [140, 23, 40], [100, 17, 26]], opacity: 0.32 });
  SPUI.microtext($("heroMicro"), "SEALPASS SIGNED ROTATING SINGLE USE ");
  $("heroSeal").innerHTML = SPUI.sealMark(38);
  let heroPass = null, heroSlot = null, heroOffset = 0;

  async function heroInit() {
    META = await SPUI.api("/api/meta");
    const t0 = Date.now() / 1000;
    heroPass = await SPUI.api("/api/enrol", { student: "IT-4106", event: "TECHFEST-D1" });
    heroOffset = heroPass.server_time - (t0 + Date.now() / 1000) / 2;
    setTimeout(() => $("stamp").classList.add("on"), 500);
  }
  function heroTick() {
    if (!heroPass) return;
    const now = Date.now() / 1000 + heroOffset;
    const slot = SP.timeSlot(now);
    if (slot !== heroSlot) {
      heroSlot = slot;
      const p = SP.parsePass(heroPass.static);
      const tag = SP.liveTag(SP.fromHex(heroPass.k_se), p.passId, slot);
      SPUI.qrCanvas(`${heroPass.static}.${slot}.${SP.b64url(tag)}`, 230, { canvas: $("heroQr"), cssSize: 230 });
      $("heroTag").textContent = SP.hex(tag).slice(0, 12) + "...";
    }
    SPUI.ring($("heroRing"), 1 - (now % 10) / 10);
    $("heroClock").textContent = new Date(now * 1000).toLocaleTimeString([], { hour12: false });
    $("sampleG").style.transform = `rotate(${(now * 6) % 360}deg)`;
  }
  setInterval(heroTick, 200);

  // ---------- chapter index ----------
  const chapters = [...document.querySelectorAll(".chapter")];
  $("toc").innerHTML = chapters.map((c, i) => `<a href="#${c.id}" data-id="${c.id}"><span>${String(i + 1).padStart(2, "0")}</span><em>${esc(c.dataset.title)}</em></a>`).join("");
  const tocLinks = [...$("toc").querySelectorAll("a")];
  const tocIO = new IntersectionObserver((ents) => ents.forEach((en) => {
    if (en.isIntersecting) tocLinks.forEach((a) => a.classList.toggle("on", a.dataset.id === en.target.id));
  }), { rootMargin: "-40% 0px -55% 0px" });
  chapters.forEach((c) => tocIO.observe(c));
  window.addEventListener("scroll", () => $("toc").classList.toggle("show", window.scrollY > window.innerHeight * 0.7), { passive: true });

  // ---------- 01 problem board ----------
  const people = ["Owner", "Friend 1", "Friend 2", "Friend 3", "Friend 4", "Friend 5"];
  function board(mode) {
    $("probStatic").className = mode === "static" ? "btn sm" : "btn ghost sm";
    $("probSeal").className = mode === "seal" ? "btn sm" : "btn ghost sm";
    const sealOut = [["Admitted", "ok", "live code, first use"], ["Rejected", "no", "screenshot 34 s old (freshness)"],
      ["Rejected", "no", "edited slot, tag wrong"], ["Rejected", "no", "relayed live, already used"],
      ["Rejected", "no", "home-made code, bad signature"], ["Rejected", "no", "screenshot 2 min old (freshness)"]];
    $("cloneBoard").innerHTML = `<div class="clones">${people.map((p, i) => {
      const [v, cls, why] = mode === "static" ? ["Admitted", "ok", i ? "copy of the owner's code" : "original"] : sealOut[i];
      return `<div class="clone ${cls}" style="animation-delay:${i * 90}ms">
        <div class="mini-qr">${miniQr(i, mode)}</div>
        <div class="who">${p}</div><div class="v">${v}</div><div class="why">${why}</div></div>`;
    }).join("")}</div>
    <p class="small ${mode === "static" ? "val-red" : "val-teal"}" style="margin:14px 0 0">${mode === "static"
      ? "Six entries from one student. The scanner cannot tell copies apart, because they are the same bits."
      : "One entry. Copies expire, edits break the tag or signature, and the pass works only once."}</p>`;
  }
  function miniQr(seed, mode) {
    // A decorative 9x9 pattern; identical for every copy in static mode.
    let s = mode === "static" ? 7 : seed * 13 + 5, out = "";
    for (let r = 0; r < 9; r++) for (let c = 0; c < 9; c++) {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      const finder = (r < 3 && c < 3) || (r < 3 && c > 5) || (r > 5 && c < 3);
      if (finder || (s >> 16) % 2) out += `<rect x="${c}" y="${r}" width="1" height="1"/>`;
    }
    return `<svg viewBox="-1 -1 11 11">${out}</svg>`;
  }
  $("probStatic").addEventListener("click", () => board("static"));
  $("probSeal").addEventListener("click", () => board("seal"));
  board("static");

  // ---------- 02 requirements ----------
  $("reqGrid").innerHTML = C.requirements.map((r) => `<article class="card flat req req-${r.color}">
      <div class="req-letter">${r.letter}</div><h3>${r.name}</h3>
      <p class="small">${esc(r.need)}</p>
      <p class="kicker" style="margin:10px 0 4px">X.800 service</p><p class="small"><b>${esc(r.service)}</b></p>
      <p class="kicker" style="margin:10px 0 4px">Provided by</p>
      <ul class="small req-how">${r.how.map((h) => `<li>${esc(h)}</li>`).join("")}</ul></article>`).join("");

  // ---------- 03 threats ----------
  $("vulnList").innerHTML = C.vulns.map(([a, b]) => `<li><b>${esc(a)}</b>: ${esc(b)}</li>`).join("");
  $("threatTable").innerHTML = `<tr><th>Attack (X.800)</th><th>Type</th><th>On a QR pass</th><th>Stopped by</th></tr>` +
    C.threats.map(([a, t, s, d]) => `<tr><td><b>${esc(a)}</b></td><td><span class="chip ${t === "Passive" ? "azure" : "red"}">${t}</span></td><td>${esc(s)}</td><td class="val-teal">${esc(d)}</td></tr>`).join("");

  // ---------- 04 ladder + QR density ----------
  $("ladder").innerHTML = C.ladder.map((r, i) => `<li class="rung ${r.verdict}">
      <div class="rung-n">${i + 1}</div>
      <div class="rung-body"><div class="row spread"><h4>${esc(r.name)}</h4>
        <span class="chip ${r.verdict === "chosen" ? "teal" : r.verdict === "partial" ? "saffron" : "red"}">${r.verdict === "chosen" ? "Chosen" : r.verdict === "partial" ? (r.note ? esc(r.note) : "Partial") : "Rejected"}</span></div>
      <p class="small"><span class="muted">Gives:</span> ${esc(r.gives)}</p>
      <p class="small"><span class="muted">${r.verdict === "chosen" ? "Why it works:" : "Breaks because:"}</span> ${esc(r.fails)}</p></div></li>`).join("");

  function qrCompare() {
    const body = 40, schemes = [["RSA-3072", 384, "red"], ["ElGamal-3072", 768, "red"], ["EC-Schnorr P-256", 64, "teal"]];
    const fill = (n) => { let s = ""; for (let i = 0; i < n; i++) s += String.fromCharCode(65 + ((i * 7) % 26)); return s; };
    $("qrCompare").innerHTML = "";
    for (const [name, sig, col] of schemes) {
      const chars = Math.ceil(((body + sig) * 4) / 3) + 30;
      const fig = document.createElement("figure");
      const frame = document.createElement("div");
      frame.className = "qr-frame";
      const cv = SPUI.qrCanvas("SP1." + fill(chars), 150, { cssSize: 150 });
      frame.appendChild(cv);
      fig.appendChild(frame);
      fig.insertAdjacentHTML("beforeend", `<figcaption><b class="val-${col === "teal" ? "teal" : "red"}">${name}</b><br>${sig}-byte signature<br>QR version ${cv.dataset.version}, ${cv.dataset.modules}&times;${cv.dataset.modules} modules</figcaption>`);
      $("qrCompare").appendChild(fig);
    }
  }
  qrCompare();

  // ---------- 05 architecture ----------
  function arch() {
    const svg = $("archSvg"), A = C.arch;
    const node = (n) => `<g class="arch-node c-${n.color}" data-id="${n.id}" tabindex="0">
        <rect x="${n.x}" y="${n.y}" width="${n.w}" height="${n.h}" rx="14"/>
        <rect class="inner" x="${n.x + 5}" y="${n.y + 5}" width="${n.w - 10}" height="${n.h - 10}" rx="10"/>
        <text x="${n.x + n.w / 2}" y="${n.y + n.h / 2 - 4}" class="t">${n.title}</text>
        <text x="${n.x + n.w / 2}" y="${n.y + n.h / 2 + 20}" class="s">${n.sub}</text></g>`;
    const edge = (e, i) => {
      return `<g class="arch-edge ${e.dashed ? "atk" : ""}" data-i="${i}" tabindex="0">
        <path class="hit" d="${e.d}"/><path class="ln" d="${e.d}" marker-end="url(#arrow${e.dashed ? "R" : ""})"/>
        <path class="flow" d="${e.d}"/>
        <text class="el"><textPath href="#ep${i}" startOffset="${e.off || 50}%">${e.label}</textPath></text>
        <path id="ep${i}" d="${e.d}" fill="none" stroke="none"/></g>`;
    };
    svg.innerHTML = `<defs>
      <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10z" fill="var(--muted)"/></marker>
      <marker id="arrowR" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10z" fill="var(--vermilion)"/></marker></defs>
      <rect x="40" y="290" width="620" height="190" rx="18" class="zone"/><text x="56" y="312" class="zone-t">AT THE EVENT</text>
      <rect x="40" y="16" width="620" height="160" rx="18" class="zone"/><text x="56" y="34" class="zone-t">COLLEGE BACK OFFICE</text>
      ${A.edges.map(edge).join("")}${A.nodes.map(node).join("")}`;
    const info = $("archInfo");
    const def = `<p class="panel-title">How to read this</p><p class="small">Teal components are trusted at the event, saffron holds the secrets that create passes, blue provides trust and records, and vermilion is the attacker. Animated arrows show data moving. Select any item for details.</p>`;
    info.innerHTML = def;
    const focus = (html, el) => {
      svg.querySelectorAll(".on").forEach((x) => x.classList.remove("on"));
      if (el) el.classList.add("on");
      info.innerHTML = html;
    };
    svg.querySelectorAll(".arch-node").forEach((g) => {
      const n = A.nodes.find((x) => x.id === g.dataset.id);
      const h = () => focus(`<p class="panel-title">${n.title}</p><p class="small">${n.info}</p>`, g);
      g.addEventListener("mouseenter", h); g.addEventListener("focus", h); g.addEventListener("click", h);
    });
    svg.querySelectorAll(".arch-edge").forEach((g) => {
      const e = A.edges[g.dataset.i];
      const h = () => focus(`<p class="panel-title">${e.label}</p><p class="small">${e.info}</p>`, g);
      g.addEventListener("mouseenter", h); g.addEventListener("focus", h); g.addEventListener("click", h);
    });
  }
  arch();

  // ---------- 05 workflow sequence diagrams ----------
  let flowName = Object.keys(C.flows)[0], flowStep = 0;
  $("flowTabs").innerHTML = `<div class="seg">${Object.keys(C.flows).map((k) => `<button type="button" data-k="${k}">${k}</button>`).join("")}</div>`;
  $("flowTabs").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => { flowName = b.dataset.k; flowStep = 0; drawFlow(); }));
  $("flowNext").addEventListener("click", () => { const n = C.flows[flowName].steps.length; flowStep = Math.min(n, flowStep + 1); drawFlow(); });
  $("flowPrev").addEventListener("click", () => { flowStep = Math.max(0, flowStep - 1); drawFlow(); });

  function drawFlow() {
    $("flowTabs").querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.k === flowName));
    const f = C.flows[flowName];
    const actors = [...new Set(f.actors)];
    const W = 1000, top = 50, rowH = 50;
    const x = (i) => 120 + (i * (W - 240)) / Math.max(1, actors.length - 1 || 1);
    const H = top + 40 + f.steps.length * rowH;
    $("flowSvg").setAttribute("viewBox", `0 0 ${W} ${H}`);
    let s = actors.map((a, i) => {
      const cx = actors.length === 1 ? W / 2 : x(i);
      return `<line x1="${cx}" y1="${top}" x2="${cx}" y2="${H - 10}" class="life"/>
        <rect x="${cx - 80}" y="${top - 36}" width="160" height="34" rx="9" class="actor"/><text x="${cx}" y="${top - 14}" class="actor-t">${a}</text>`;
    }).join("");
    f.steps.forEach(([from, to], i) => {
      const fa = actors.indexOf(f.actors[from]), ta = actors.indexOf(f.actors[to]);
      const x1 = actors.length === 1 ? W / 2 : x(fa), x2 = actors.length === 1 ? W / 2 : x(ta);
      const y = top + 34 + i * rowH;
      const cls = i < flowStep ? (i === flowStep - 1 ? "msg cur" : "msg done") : "msg";
      if (x1 === x2) s += `<path class="${cls}" d="M${x1} ${y - 10} h46 v20 h-40" marker-end="url(#flowArrow)"/><text x="${x1 + 58}" y="${y + 5}" class="msg-t ${cls}">${i + 1}</text>`;
      else s += `<line class="${cls}" x1="${x1}" y1="${y}" x2="${x2 + (x2 > x1 ? -6 : 6)}" y2="${y}" marker-end="url(#flowArrow)"/><text x="${(x1 + x2) / 2}" y="${y - 8}" class="msg-t ${cls}">${i + 1}</text>`;
    });
    $("flowSvg").innerHTML = `<defs><marker id="flowArrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10z" fill="currentColor"/></marker></defs>${s}`;
    $("flowText").innerHTML = flowStep === 0 ? `<span class="muted">${f.steps.length} steps. Press "Next step".</span>`
      : `<b>Step ${flowStep}.</b> ${esc(f.steps[flowStep - 1][2])}`;
    $("flowNext").disabled = flowStep >= f.steps.length;
  }
  drawFlow();

  // ---------- 12 pipeline demo ----------
  let demoPass = null, demoOffset = 0;
  async function demoCode(ageSeconds = 0) {
    if (!demoPass) {
      const t0 = Date.now() / 1000;
      demoPass = await SPUI.api("/api/enrol", { student: "IT-4104", event: "TECHFEST-D1" });
      demoOffset = demoPass.server_time - (t0 + Date.now() / 1000) / 2;
    }
    const slot = SP.timeSlot(Date.now() / 1000 + demoOffset - ageSeconds);
    const p = SP.parsePass(demoPass.static);
    return `${demoPass.static}.${slot}.${SP.b64url(SP.liveTag(SP.fromHex(demoPass.k_se), p.passId, slot))}`;
  }
  $("pGen").addEventListener("click", async () => { $("pText").value = await demoCode(0); });
  $("pOld").addEventListener("click", async () => { $("pText").value = await demoCode(30); });
  $("pVerify").addEventListener("click", async () => {
    if (!$("pText").value.trim()) $("pText").value = await demoCode(0);
    $("pVerify").disabled = true;
    try {
      const res = await SPUI.api("/api/verify", { event: "TECHFEST-D1", gate: "Story page", qr: $("pText").value.trim() });
      SPUI.verdict($("pVerdict"), res);
      await SPUI.renderPipeline($("pPipe"), META.steps, res);
    } catch (e) { $("pVerdict").innerHTML = `<p class="val-red small">${esc(e.message)}</p>`; }
    $("pVerify").disabled = false;
  });

  // ---------- boot ----------
  SPUI.reveal();
  heroInit().then(() => { SPUI.renderPipeline($("pPipe"), META.steps, null); })
    .catch((e) => console.error(e));
})();
