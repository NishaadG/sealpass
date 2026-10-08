/* Shared page helpers: top bar, theme, QR drawing and decoding, the
   verification pipeline view, guilloche patterns. */
(function () {
  "use strict";

  // ---------- theme (per-viewer convenience only) ----------
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } },
  };
  const savedTheme = store.get("sp-theme");
  if (savedTheme) document.documentElement.dataset.theme = savedTheme;

  const ICON = {
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.2M12 19.3v2.2M2.5 12h2.2M19.3 12h2.2M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M5.3 18.7l1.6-1.6M17.1 6.9l1.6-1.6"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M20 14.6A8.2 8.2 0 0 1 9.4 4a8.2 8.2 0 1 0 10.6 10.6Z"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    cross: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round"><path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/></svg>',
  };

  function sealMark(size = 30) {
    // Wax-seal outline: a scalloped disc with a small QR finder inside.
    const pts = [];
    for (let i = 0; i < 48; i++) {
      const a = (i / 48) * Math.PI * 2, r = i % 2 ? 13.2 : 14.6;
      pts.push(`${(16 + r * Math.cos(a)).toFixed(2)},${(16 + r * Math.sin(a)).toFixed(2)}`);
    }
    return `<svg viewBox="0 0 32 32" width="${size}" height="${size}" aria-hidden="true">
      <polygon points="${pts.join(" ")}" fill="var(--saffron)"/>
      <circle cx="16" cy="16" r="10.2" fill="none" stroke="var(--bg)" stroke-width="1" opacity=".55"/>
      <rect x="10.5" y="10.5" width="5" height="5" fill="var(--bg)"/><rect x="16.5" y="10.5" width="5" height="5" fill="none" stroke="var(--bg)" stroke-width="1.4"/>
      <rect x="10.5" y="16.5" width="5" height="5" fill="none" stroke="var(--bg)" stroke-width="1.4"/><rect x="17.6" y="17.6" width="2.8" height="2.8" fill="var(--bg)"/>
    </svg>`;
  }

  function topbar(active) {
    const links = [["/", "Story"], ["/lab", "Lab"], ["/phone", "Phone"], ["/gate", "Gate"], ["/dashboard", "Dashboard"]];
    const el = document.createElement("header");
    el.className = "topbar";
    el.innerHTML = `<div class="wrap">
      <a class="brand" href="/">${sealMark()}<span>SealPass</span></a>
      <nav class="nav">${links.map(([h, t]) => `<a href="${h}" class="${h === active ? "on" : ""}">${t}</a>`).join("")}</nav>
      <button class="theme-btn" type="button" aria-label="Switch colour theme"></button></div>`;
    document.body.prepend(el);
    const btn = el.querySelector(".theme-btn");
    const paint = () => { btn.innerHTML = document.documentElement.dataset.theme === "light" ? ICON.moon : ICON.sun; };
    paint();
    btn.addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      store.set("sp-theme", next);
      paint();
      document.dispatchEvent(new CustomEvent("themechange"));
    });
  }

  function microtext(el, word = "SEALPASS VERIFIED ORIGINAL ") {
    el.textContent = word.repeat(60);
  }

  // ---------- network ----------
  async function api(path, body) {
    const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  // ---------- QR ----------
  function qrMatrix(text, ecc = "M") {
    const q = qrcode(0, ecc);
    q.addData(text, "Byte");
    q.make();
    const n = q.getModuleCount();
    return { n, dark: (r, c) => q.isDark(r, c), version: (n - 17) / 4 };
  }

  function qrCanvas(text, px = 260, opts = {}) {
    const m = qrMatrix(text, opts.ecc || "M");
    const quiet = 3;
    const cell = Math.max(2, Math.floor(px / (m.n + quiet * 2)));
    const size = cell * (m.n + quiet * 2);
    const cv = opts.canvas || document.createElement("canvas");
    cv.width = size; cv.height = size;
    cv.style.width = (opts.cssSize || px) + "px";
    cv.style.height = (opts.cssSize || px) + "px";
    const ctx = cv.getContext("2d");
    ctx.fillStyle = opts.paper || "#f6f1e7";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = opts.ink || "#131b31";
    for (let r = 0; r < m.n; r++) for (let c = 0; c < m.n; c++) {
      if (m.dark(r, c)) ctx.fillRect((c + quiet) * cell, (r + quiet) * cell, cell, cell);
    }
    cv.dataset.qr = text;
    cv.dataset.version = m.version;
    cv.dataset.modules = m.n;
    return cv;
  }

  function decodeCanvas(cv) {
    const ctx = cv.getContext("2d", { willReadFrequently: true });
    const img = ctx.getImageData(0, 0, cv.width, cv.height);
    const res = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
    return res ? res.data : null;
  }

  function decodeImageFile(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, 1400 / Math.max(img.width, img.height));
        const cv = document.createElement("canvas");
        cv.width = Math.round(img.width * scale); cv.height = Math.round(img.height * scale);
        cv.getContext("2d").drawImage(img, 0, 0, cv.width, cv.height);
        const ctx = cv.getContext("2d");
        const data = ctx.getImageData(0, 0, cv.width, cv.height);
        const res = jsQR(data.data, cv.width, cv.height, { inversionAttempts: "attemptBoth" });
        URL.revokeObjectURL(img.src);
        res ? resolve(res.data) : reject(new Error("No QR code found in the photo"));
      };
      img.onerror = () => reject(new Error("Could not read the image"));
      img.src = URL.createObjectURL(file);
    });
  }

  // ---------- pipeline view ----------
  let STEPS = null;
  async function steps() {
    if (!STEPS) STEPS = (await api("/api/meta")).steps;
    return STEPS;
  }

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function renderPipeline(el, meta, result, { animate = true, compact = false } = {}) {
    el.classList.add("pipeline");
    el.innerHTML = meta.map((s, i) => `<div class="pipe-step wait" data-id="${s.id}">
        <div class="dot">${i + 1}</div>
        <div><div class="name">${esc(s.name)}</div><div class="det">${compact ? "" : esc(s.rule)}</div></div></div>`).join("");
    if (!result) return Promise.resolve();
    const byId = Object.fromEntries(result.steps.map((s) => [s.id, s]));
    const nodes = [...el.children];
    return new Promise((resolve) => {
      nodes.forEach((node, i) => {
        const apply = () => {
          const s = byId[node.dataset.id];
          if (!s) return;
          node.className = `pipe-step ${s.status}`;
          const dot = node.querySelector(".dot");
          if (s.status === "pass") dot.innerHTML = ICON.check.replace('width="', 'width="').replace("<svg", '<svg width="15" height="15"');
          if (s.status === "fail") dot.innerHTML = ICON.cross.replace("<svg", '<svg width="15" height="15"');
          if (s.detail) node.querySelector(".det").textContent = s.detail;
          if (i === nodes.length - 1) resolve();
        };
        animate ? setTimeout(apply, 90 * i) : apply();
      });
    });
  }

  function verdict(el, result) {
    const ok = result.admitted;
    el.className = `verdict ${ok ? "ok" : "no"}`;
    const who = result.student ? `${esc(result.student_name || "")} <span class="mono small">${esc(result.student)}</span>` : "";
    el.innerHTML = `<div class="mark">${ok ? ICON.check : ICON.cross}</div>
      <div><div class="title">${ok ? "Admitted" : "Rejected"}</div>
      <div class="why">${who ? who + "<br>" : ""}${esc(result.reason)}</div></div>`;
  }

  function strip(result) {
    return `<div class="pipe-strip">${result.steps.map((s) => `<span class="${s.status}" title="${esc(s.id)}"></span>`).join("")}</div>`;
  }

  // ---------- countdown ring ----------
  function ring(svg, fraction, color = "var(--saffron)") {
    const r = 46, c = 2 * Math.PI * r;
    if (!svg.firstChild) {
      svg.setAttribute("viewBox", "0 0 100 100");
      svg.innerHTML = `<circle cx="50" cy="50" r="${r}" fill="none" stroke="var(--line-strong)" stroke-width="4"/>
        <circle class="arc" cx="50" cy="50" r="${r}" fill="none" stroke="${color}" stroke-width="4" stroke-linecap="round"
        stroke-dasharray="${c}" transform="rotate(-90 50 50)"/>`;
    }
    svg.querySelector(".arc").setAttribute("stroke-dashoffset", String(c * (1 - fraction)));
  }

  // ---------- guilloche (hypotrochoid rosettes) ----------
  function guillochePath(R, r, d, cx, cy, phase = 0, steps = 1400) {
    const k = (R - r) / r;
    // Close the curve: run t over enough turns for the ratio to repeat.
    const g = gcd(Math.round(R * 10), Math.round(r * 10));
    const turns = Math.round(r * 10) / g;
    const T = Math.PI * 2 * Math.min(turns, 40);
    let dstr = "";
    for (let i = 0; i <= steps; i++) {
      const t = (i / steps) * T;
      const x = cx + (R - r) * Math.cos(t + phase) + d * Math.cos(k * t + phase);
      const y = cy + (R - r) * Math.sin(t + phase) - d * Math.sin(k * t + phase);
      dstr += (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
    }
    return dstr;
  }
  function gcd(a, b) { return b ? gcd(b, a % b) : a; }

  function guilloche(svg, { size = 600, rings = [[220, 34, 60], [170, 27, 48], [120, 21, 30]], colors, width = 0.6, opacity = 0.5 } = {}) {
    const c = size / 2;
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    const cols = colors || ["var(--saffron)", "var(--teal)", "var(--azure)"];
    svg.innerHTML = rings.map(([R, r, d], i) =>
      `<path d="${guillochePath(R, r, d, c, c, i * 0.3)}" fill="none" stroke="${cols[i % cols.length]}" stroke-width="${width}" opacity="${opacity}"/>`).join("");
  }

  // ---------- scroll reveal ----------
  function reveal() {
    const els = document.querySelectorAll(".reveal");
    if (!("IntersectionObserver" in window) || location.search.includes("static")) { els.forEach((e) => e.classList.add("in")); return; }
    const io = new IntersectionObserver((entries) => entries.forEach((en) => {
      if (en.isIntersecting) { en.target.classList.add("in"); io.unobserve(en.target); }
    }), { rootMargin: "0px 0px -8% 0px" });
    els.forEach((e) => io.observe(e));
  }

  const short = (h, n = 10) => (h && h.length > 2 * n ? `${h.slice(0, n)}...${h.slice(-6)}` : h);
  const clock = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  window.SPUI = { store, ICON, sealMark, topbar, microtext, api, qrMatrix, qrCanvas, decodeCanvas, decodeImageFile,
    steps, renderPipeline, verdict, strip, ring, guilloche, guillochePath, reveal, esc, short, clock };
})();
