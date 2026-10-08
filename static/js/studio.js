/* Algorithm studio: interactive SHA-256, HMAC, elliptic curve, Schnorr and number theory. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = SPUI.esc;
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const h8 = (x) => (x >>> 0).toString(16).padStart(8, "0");
  const randBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
  const randBelow = (n) => { let r; do { r = SP.mod(SP.bytesToInt(randBytes(40)), n); } while (r === 0n); return r; };
  const bigShort = (v, n = 10) => { const s = v.toString(16); return s.length > 2 * n ? `${s.slice(0, n)}...${s.slice(-6)}` : s; };

  // =============== SHA-256 ===============
  let shaTrace = null;
  function shaRender() {
    const msg = SP.utf8($("shaIn").value);
    shaTrace = SP.sha256Trace(msg);
    const block = shaTrace.padded.slice(0, 64);
    const multi = shaTrace.padded.length > 64;
    $("shaBytes").innerHTML = [...block].map((b, i) => {
      let cls = "dim";
      if (i < msg.length) cls = "azure";
      else if (i === msg.length) cls = "saffron";
      else if (!multi && i >= 56) cls = "teal";
      return `<span class="${cls}" title="byte ${i}">${b.toString(16).padStart(2, "0")}</span>`;
    }).join("") + (multi ? `<p class="small muted" style="grid-column:1/-1;margin:6px 0 0">Input is ${msg.length} bytes, so padding continues into block ${shaTrace.blocks.length}. The length field sits at the end of the last block.</p>` : "");
    const w = shaTrace.blocks[0].w;
    $("shaW").innerHTML = w.map((x, t) => `<span style="--v:${((x >>> 24) / 255).toFixed(2)}" class="${t < 16 ? "in" : "ex"}" title="W${t} = ${h8(x)}${t < 16 ? " (from the block)" : " (expanded)"}"></span>`).join("");
    $("shaOut").innerHTML = `<span class="val-teal">${SP.hex(shaTrace.digest)}</span>`;
    shaRound();
    avalanche(msg);
  }
  function shaRound() {
    const r = Number($("shaRound").value);
    const b = shaTrace.blocks[0];
    const cur = r === 0 ? b.stateIn : b.rounds[r - 1];
    const prev = r <= 1 ? b.stateIn : b.rounds[r - 2];
    $("shaRoundLbl").textContent = r === 0 ? "initial values H0" : `after round ${r} of 64`;
    $("shaRegs").innerHTML = "abcdefgh".split("").map((name, i) => {
      let bits = "";
      for (let k = 31; k >= 0; k--) {
        const on = (cur[i] >>> k) & 1, changed = r > 0 && ((cur[i] ^ prev[i]) >>> k) & 1;
        bits += `<i class="${on ? "on" : ""} ${changed ? "chg" : ""}"></i>`;
      }
      return `<div class="reg"><span class="mono">${name}</span><div class="bits">${bits}</div><span class="mono small">${h8(cur[i])}</span></div>`;
    }).join("");
  }
  function avalanche(msg) {
    const flipped = msg.length ? msg.slice() : new Uint8Array([0]);
    flipped[flipped.length - 1] ^= 1;
    const a = shaTrace.digest, b = SP.sha256(flipped);
    let diff = 0, cells = "";
    for (let i = 0; i < 256; i++) {
      const x = (a[i >> 3] >> (7 - (i & 7))) & 1, y = (b[i >> 3] >> (7 - (i & 7))) & 1;
      if (x !== y) diff++;
      cells += `<i class="${x !== y ? "d" : ""}"></i>`;
    }
    $("avaGrid").innerHTML = cells;
    const ch = new TextDecoder().decode(flipped.slice(-1));
    $("avaCount").textContent = `${diff} of 256 bits changed (last character becomes "${ch}")`;
  }
  $("shaIn").addEventListener("input", shaRender);
  $("shaRound").addEventListener("input", shaRound);
  shaRender();

  // =============== HMAC ===============
  const hKey = randBytes(32), hPid = randBytes(8);
  let hLast = null;
  const hist = [];
  $("hKey").textContent = SP.hex(hKey);
  $("hPid").textContent = SP.hex(hPid);
  function hmacTick() {
    const now = Date.now() / 1000, slot = SP.timeSlot(now);
    SPUI.ring($("hmacRing"), 1 - (now % 10) / 10);
    if (slot === hLast) return;
    hLast = slot;
    const msg = SP.concat(hPid, SP.u64(slot));
    const t = SP.hmacTrace(hKey, msg);
    $("hSlot").textContent = `${slot}  (0x${SP.hex(SP.u64(slot))})`;
    const box = (label, bytes, cls, note) => `<div class="hf-box ${cls}"><div class="hf-l">${label}</div><div class="hex">${SP.hex(bytes).slice(0, 32)}...</div>${note ? `<div class="hf-n">${note}</div>` : ""}</div>`;
    $("hmacFlow").innerHTML =
      box("K′ = key padded to 64 bytes", t.k0, "saffron") +
      `<div class="hf-row">${box("K′ ⊕ ipad (0x36)", t.ik, "saffron")}${box("K′ ⊕ opad (0x5C)", t.ok, "saffron")}</div>` +
      box("inner = H(K′⊕ipad ‖ pass_id ‖ slot)", t.inner, "azure", "first pass") +
      box("HMAC = H(K′⊕opad ‖ inner)", t.mac, "teal", "second pass");
    const tag = SP.hex(t.mac.slice(0, 16));
    $("hTag").textContent = tag.match(/.{8}/g).join(" ");
    hist.unshift([slot, tag]);
    hist.length = Math.min(hist.length, 4);
    $("hHist").innerHTML = hist.map(([s, tg], i) => `<div style="opacity:${1 - i * 0.22}"><span class="mono small muted">slot ${s}</span> <span class="mono small ${i ? "" : "val-teal"}">${tg.slice(0, 16)}...</span>${i >= 2 ? ' <span class="chip red">rejected at gate</span>' : i === 1 ? ' <span class="chip saffron">still accepted</span>' : ' <span class="chip teal">current</span>'}</div>`).join("");
  }
  setInterval(hmacTick, 250);
  hmacTick();

  // =============== Elliptic curve canvas ===============
  const TOY = SP.TOY;
  const toyPoints = [];
  for (let x = 0n; x < TOY.p; x++) for (let y = 0n; y < TOY.p; y++) if (TOY.contains([x, y])) toyPoints.push([x, y]);

  function plot(cv, highlights = {}, extra = () => {}) {
    const ctx = cv.getContext("2d");
    const W = cv.width, H = cv.height, side = Math.min(W, H) - 40;
    const ox = (W - side) / 2 + 10, oy = (H - side) / 2 + 10;
    const P = Number(TOY.p);
    const px = (x) => ox + (Number(x) / (P - 1)) * (side - 20);
    const py = (y) => oy + side - 20 - (Number(y) / (P - 1)) * (side - 20);
    ctx.clearRect(0, 0, W, H);
    ctx.strokeStyle = css("--line");
    ctx.lineWidth = 1;
    ctx.strokeRect(ox - 8, oy - 8, side - 4, side - 4);
    ctx.fillStyle = css("--muted");
    ctx.font = "11px Plex Mono, monospace";
    ctx.fillText("0", ox - 4, oy + side);
    ctx.fillText("96", ox + side - 32, oy + side);
    ctx.fillText("96", ox - 30, oy + 4);
    // symmetry axis y = p/2 (P and -P mirror across it)
    ctx.setLineDash([3, 5]);
    ctx.beginPath(); ctx.moveTo(ox - 8, py(48.5)); ctx.lineTo(ox + side - 12, py(48.5)); ctx.stroke();
    ctx.setLineDash([]);
    extra(ctx, px, py);
    for (const [x, y] of toyPoints) {
      ctx.fillStyle = css("--ink-soft");
      ctx.globalAlpha = 0.55;
      ctx.beginPath(); ctx.arc(px(x), py(y), 2.6, 0, Math.PI * 2); ctx.fill();
    }
    ctx.globalAlpha = 1;
    for (const [label, pt, color] of Object.values(highlights)) {
      if (!pt) continue;
      ctx.fillStyle = css(color);
      ctx.beginPath(); ctx.arc(px(pt[0]), py(pt[1]), 6.5, 0, Math.PI * 2); ctx.fill();
      ctx.font = "600 13px Plex Sans, sans-serif";
      ctx.fillText(label, px(pt[0]) + 9, py(pt[1]) - 8);
    }
    return { px, py, ox, oy, side };
  }

  let ecSel = [], ecHop = null;
  const ecCv = $("ecCanvas");
  function ecDraw() {
    const hl = {};
    if (ecSel[0]) hl.P = ["P", ecSel[0], "--teal"];
    if (ecSel[1]) hl.Q = ["Q", ecSel[1], "--azure"];
    let R = null, info = {};
    if (ecSel.length === 2) {
      R = TOY.add(ecSel[0], ecSel[1], info);
      if (R) { hl.R = ["P+Q", R, "--saffron"]; hl.nR = ["-(P+Q)", TOY.neg(R), "--vermilion"]; }
    }
    const geo = plot(ecCv, hl, (ctx, px, py) => {
      if (ecHop) {
        ctx.strokeStyle = css("--saffron"); ctx.globalAlpha = 0.65; ctx.lineWidth = 1.4;
        ctx.beginPath();
        ecHop.forEach((p, i) => { if (p) (i ? ctx.lineTo(px(p[0]), py(p[1])) : ctx.moveTo(px(p[0]), py(p[1]))); });
        ctx.stroke(); ctx.globalAlpha = 1;
      }
      if (R && info.lambda !== undefined) {
        // the "line" y = lambda (x - x1) + y1 over F_97 wraps around: draw its points
        const [x1, y1] = ecSel[0];
        ctx.fillStyle = css("--saffron"); ctx.globalAlpha = 0.35;
        for (let x = 0n; x < TOY.p; x++) {
          const y = SP.mod(info.lambda * (x - x1) + y1, TOY.p);
          ctx.fillRect(px(x) - 1.5, py(y) - 1.5, 3, 3);
        }
        ctx.globalAlpha = 1;
        ctx.strokeStyle = css("--vermilion"); ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(px(R[0]), py(R[1])); ctx.lineTo(px(R[0]), py(TOY.neg(R)[1])); ctx.stroke(); ctx.setLineDash([]);
      }
    });
    ecCv._geo = geo;
    if (ecSel.length === 0) $("ecInfo").innerHTML = "Click a point to choose P.";
    else if (ecSel.length === 1) $("ecInfo").innerHTML = `P = (${ecSel[0]}). Now click Q, or click P again to double it.`;
    else if (!R) $("ecInfo").innerHTML = `P and Q are mirror images, so P + Q = O, the point at infinity.`;
    else {
      const [x1, y1] = ecSel[0], [x2, y2] = ecSel[1];
      const lamTxt = info.kind === "double"
        ? `&lambda; = (3&middot;${x1}&sup2; + 3) &middot; (2&middot;${y1})<sup>&minus;1</sup> mod 97 = <b>${info.lambda}</b>`
        : `&lambda; = (${y2} &minus; ${y1}) &middot; (${x2} &minus; ${x1})<sup>&minus;1</sup> mod 97 = <b>${info.lambda}</b>`;
      $("ecInfo").innerHTML = `${info.kind === "double" ? "Tangent at P (doubling)." : "Chord through P and Q."} ${lamTxt}<br>
        The faint dots are that line over F<sub>97</sub>. It meets the curve at -(P+Q) = (${TOY.neg(R)}). Reflecting gives <b class="val-saffron">P + Q = (${R})</b>.`;
    }
  }
  ecCv.addEventListener("click", (ev) => {
    const r = ecCv.getBoundingClientRect(), g = ecCv._geo;
    const mx = ((ev.clientX - r.left) / r.width) * ecCv.width, my = ((ev.clientY - r.top) / r.height) * ecCv.height;
    let best = null, bd = 1e9;
    for (const p of toyPoints) {
      const d = (g.px(p[0]) - mx) ** 2 + (g.py(p[1]) - my) ** 2;
      if (d < bd) { bd = d; best = p; }
    }
    if (bd > 200) return;
    ecHop = null;
    if (ecSel.length >= 2) ecSel = [];
    ecSel.push(best);
    ecDraw();
  });
  $("ecMul").addEventListener("click", () => {
    const k = BigInt(Math.max(1, Math.min(102, Number($("ecK").value) || 1)));
    const steps = [];
    const R = TOY.mul(k, TOY.g, steps);
    ecSel = [];
    ecHop = [TOY.g, ...steps.map((s) => s.point)];
    ecDraw();
    plot(ecCv, { G: ["G", TOY.g, "--teal"], R: [`${k}G`, R, "--saffron"] }, (ctx, px, py) => {
      ctx.strokeStyle = css("--saffron"); ctx.globalAlpha = 0.7; ctx.lineWidth = 1.4; ctx.beginPath();
      ecHop.filter(Boolean).forEach((p, i) => (i ? ctx.lineTo(px(p[0]), py(p[1])) : ctx.moveTo(px(p[0]), py(p[1]))));
      ctx.stroke(); ctx.globalAlpha = 1;
    });
    const bits = k.toString(2);
    $("ecSteps").innerHTML = `k = ${k} = ${bits}<sub>2</sub>. For each bit: double, then add G if the bit is 1.<br>` +
      steps.map((s) => `<span class="${s.op === "add" ? "val-teal" : "val-saffron"}">${s.op === "add" ? "+G" : "x2"}</span>&rarr;${s.point ? `(${s.point})` : "O"}`).join(" ") +
      `<br>${steps.length} group operations, instead of ${k - 1n} additions one at a time. For a 256-bit k that is about 384 operations instead of 2<sup>256</sup>.`;
    $("ecInfo").innerHTML = `${k}G = (${R}). The saffron path is the sequence of points double-and-add visits.`;
  });
  ecDraw();

  // =============== Schnorr ===============
  let sc = { curve: "toy", x: null, P: null, sig: null, signed: null };
  const curveOf = () => (sc.curve === "toy" ? SP.TOY : SP.P256);
  const fmt = (v) => (sc.curve === "toy" ? v.toString() : bigShort(v));
  const fmtP = (p) => (p ? (sc.curve === "toy" ? `(${p[0]}, ${p[1]})` : `(${bigShort(p[0], 6)}, ${bigShort(p[1], 6)})`) : "O");

  function scKey() {
    const c = curveOf();
    sc.x = randBelow(c.n);
    sc.P = c.mul(sc.x);
    sc.sig = null;
    scRender();
  }
  function scSign() {
    if (!sc.x) scKey();
    sc.signed = $("sigMsg").value;
    sc.sig = SP.schnorrSign(sc.x, SP.utf8(sc.signed), curveOf());
    scRender();
  }
  function scRender() {
    const c = curveOf();
    const msg = $("sigMsg").value;
    let html = `<dl class="kv small"><dt>private x</dt><dd class="mono val-saffron">${sc.x !== null ? fmt(sc.x) : "-"}</dd>
      <dt>public P = xG</dt><dd class="mono">${sc.P ? fmtP(sc.P) : "-"}</dd>`;
    let v = null;
    if (sc.sig) {
      const s = sc.sig;
      html += `<dt>nonce k</dt><dd class="mono val-saffron">${fmt(s.k)} <span class="muted">= HMAC(x, H(m))</span></dd>
        <dt>R = kG</dt><dd class="mono">${fmtP(s.R)}</dd>
        <dt>e = H(R&#8214;P&#8214;m)</dt><dd class="mono">${fmt(s.e)}</dd>
        <dt>s = k + e&middot;x</dt><dd class="mono">${fmt(s.s)}</dd>`;
      v = SP.schnorrVerify(sc.P, SP.utf8(msg), s, c);
      html += `</dl><div class="divider" style="margin:10px 0"></div><dl class="kv small">
        <dt>verifying</dt><dd>"${esc(msg)}"${msg !== sc.signed ? ' <span class="chip red">changed</span>' : ""}</dd>
        <dt>sG</dt><dd class="mono">${fmtP(v.sG)}</dd><dt>eP</dt><dd class="mono">${fmtP(v.eP)}</dd>
        <dt>R&prime; = sG &minus; eP</dt><dd class="mono">${fmtP(v.R)}</dd>
        <dt>H(R&prime;&#8214;P&#8214;m)</dt><dd class="mono">${v.e2 !== undefined ? fmt(v.e2) : "-"}</dd></dl>`;
      const collide = v.ok && msg !== sc.signed;
      html += `<div class="verdict ${v.ok && !collide ? "ok" : "no"}" style="margin-top:10px"><div class="mark">${v.ok && !collide ? SPUI.ICON.check : SPUI.ICON.cross}</div>
        <div><div class="title">${collide ? "Toy-curve collision" : v.ok ? "Signature valid" : "Signature invalid"}</div>
        <div class="why">${collide ? "With only 103 possible values of e, a changed message matches by chance about 1 time in 103. On P-256 the chance is about 2<sup>-256</sup>, which is why real curves are large." : v.ok ? "R′ equals R, so the recomputed challenge matches e." : msg !== sc.signed ? "The message changed, so H(R′‖P‖m) no longer equals e." : "Check failed."}</div></div></div>`;
    } else html += "</dl>";
    $("sigOut").innerHTML = html;
    const cv = $("sigCanvas");
    if (sc.curve === "toy") {
      cv.classList.remove("hidden");
      const hl = { G: ["G", SP.TOY.g, "--muted"] };
      if (sc.P) hl.P = ["P", sc.P, "--saffron"];
      if (sc.sig) { hl.R = ["R", sc.sig.R, "--teal"]; if (v) { hl.sG = ["sG", v.sG, "--azure"]; hl.eP = ["eP", v.eP, "--vermilion"]; } }
      plot(cv, hl);
    } else cv.classList.add("hidden");
  }
  $("sigCurve").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    $("sigCurve").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    sc = { curve: b.dataset.c, x: null, P: null, sig: null, signed: null };
    scKey();
  }));
  $("sigKey").addEventListener("click", scKey);
  $("sigSign").addEventListener("click", scSign);
  $("sigTamper").addEventListener("click", () => {
    if (!sc.sig) scSign();
    const m = $("sigMsg").value;
    $("sigMsg").value = m.replace(/\d/, (d) => String((Number(d) + 1) % 10)) === m ? m + "!" : m.replace(/\d/, (d) => String((Number(d) + 1) % 10));
    scRender();
  });
  $("sigMsg").addEventListener("input", scRender);
  scKey();

  $("nonceBtn").addEventListener("click", () => {
    const c = SP.P256, x = randBelow(c.n), k = randBelow(c.n);
    const m1 = "pass for IT-4101", m2 = "pass for IT-4102";
    const s1 = SP.schnorrSign(x, SP.utf8(m1), c, k), s2 = SP.schnorrSign(x, SP.utf8(m2), c, k);
    const rec = SP.mod((s1.s - s2.s) * SP.powmod(SP.mod(s1.e - s2.e, c.n), c.n - 2n, c.n), c.n);
    $("nonceOut").innerHTML = `signature 1 on "${m1}": e=${bigShort(s1.e)}, s=${bigShort(s1.s)}<br>
      signature 2 on "${m2}": e=${bigShort(s2.e)}, s=${bigShort(s2.s)}<br>
      both reused k = ${bigShort(k)}<br><br>
      x = (s1 &minus; s2) / (e1 &minus; e2) mod n<br>
      recovered&nbsp; <span class="val-red">${bigShort(rec, 16)}</span><br>
      real key&nbsp;&nbsp;&nbsp;&nbsp; <span class="val-saffron">${bigShort(x, 16)}</span><br>
      <b class="${rec === x ? "val-red" : ""}">${rec === x ? "Match. The private key is exposed from two public signatures." : "no match"}</b>`;
  });

  // =============== Number theory ===============
  function fermat() {
    const a = BigInt(Math.trunc(Number($("fa").value) || 0)), p = BigInt(Math.trunc(Number($("fp").value) || 0));
    if (p < 3n) { $("fOut").textContent = "Choose p of at least 3."; return; }
    const prime = millerRabin(p, 12).prime;
    if (!prime) { $("fOut").innerHTML = `<span class="val-red">${p} is not prime</span>, so Fermat's theorem does not apply and a<sup>p&minus;2</sup> is not guaranteed to be the inverse.`; return; }
    if (SP.mod(a, p) === 0n) { $("fOut").innerHTML = "0 has no inverse."; return; }
    const e = p - 2n;
    let r = 1n, b = SP.mod(a, p), trace = [];
    for (const bit of e.toString(2)) {
      r = (r * r) % p; if (bit === "1") r = (r * b) % p;
      trace.push(r);
    }
    $("fOut").innerHTML = `${a}<sup>${e}</sup> mod ${p}, exponent in binary ${e.toString(2)}<br>square-and-multiply: ${trace.join(" &rarr; ")}<br>
      inverse = <b class="val-teal">${r}</b> &nbsp; check: ${a}&middot;${r} mod ${p} = ${SP.mod(a * r, p)}`;
  }
  ["fa", "fp"].forEach((id) => $(id).addEventListener("input", fermat));
  fermat();

  function millerRabin(n, rounds) {
    const out = [];
    if (n < 4n) return { prime: n === 2n || n === 3n, out };
    if (n % 2n === 0n) return { prime: false, out: [{ base: 2n, pass: false }] };
    let s = 0n, d = n - 1n;
    while (d % 2n === 0n) { d /= 2n; s++; }
    for (let i = 0; i < rounds; i++) {
      const a = 2n + SP.mod(SP.bytesToInt(randBytes(40)), n - 3n);
      let x = SP.powmod(a, d, n), pass = x === 1n || x === n - 1n;
      for (let r = 1n; !pass && r < s; r++) { x = (x * x) % n; pass = x === n - 1n; }
      out.push({ base: a, pass });
      if (!pass) return { prime: false, out, s, d };
    }
    return { prime: true, out, s, d };
  }
  $("mrBtn").addEventListener("click", () => {
    const v = $("mrN").value;
    const n = v === "p" ? SP.P256.p : v === "n" ? SP.P256.n : v === "3p" ? SP.P256.p * 3n : 561n;
    const res = millerRabin(n, 10);
    $("mrOut").innerHTML = `<p class="small mono">n = ${bigShort(n, 12)}</p>` +
      res.out.map((r, i) => `<div class="mr-r ${r.pass ? "ok" : "no"}"><span class="mono small">round ${i + 1}</span><span class="mono small muted">a = ${bigShort(r.base, 6)}</span><span class="chip ${r.pass ? "teal" : "red"}">${r.pass ? "passes" : "witness: composite"}</span></div>`).join("") +
      `<p class="small" style="margin-top:8px"><b class="${res.prime ? "val-teal" : "val-red"}">${res.prime ? `Probably prime (error below 4<sup>-${res.out.length}</sup>)` : "Definitely composite"}</b></p>`;
  });

  $("dlBtn").addEventListener("click", () => {
    const x = randBelow(SP.TOY.n), P = SP.TOY.mul(x);
    let R = SP.TOY.g, k = 1n;
    while (!(R && R[0] === P[0] && R[1] === P[1])) { R = SP.TOY.add(R, SP.TOY.g); k++; }
    $("dlOut").innerHTML = `public P = (${P})<br>trying G, 2G, 3G, ...<br>found x = <b class="val-red">${k}</b> after ${k} additions (secret was ${x})`;
    $("dlBig").innerHTML = "The same search on P-256: about 2<sup>128</sup> &asymp; 3.4 &times; 10<sup>38</sup> operations. At a trillion per second that is roughly 10<sup>19</sup> years.";
  });

  document.addEventListener("themechange", () => { ecDraw(); scRender(); });
})();
