/* Projector view: polls the server for new scans and the ledger. */
(function () {
  "use strict";
  SPUI.topbar("/dashboard");
  const $ = (id) => document.getElementById(id);
  const esc = SPUI.esc;
  let meta, since = 0, scans = [], selected = null;

  async function init() {
    meta = await SPUI.api("/api/meta");
    const pair = [
      ["Student phone", meta.urls.https + "/phone"],
      ["Gate phone", meta.urls.https + "/gate"],
      ["Root certificate (optional)", meta.urls.http + "/root.cer"],
    ];
    $("pair").innerHTML = "";
    for (const [label, url] of pair) {
      const fig = document.createElement("figure");
      const frame = document.createElement("div");
      frame.className = "qr-frame";
      frame.appendChild(SPUI.qrCanvas(url, 170, { ecc: "L" }));
      fig.appendChild(frame);
      fig.insertAdjacentHTML("beforeend", `<figcaption><b>${label}</b><br>${esc(url)}</figcaption>`);
      $("pair").appendChild(fig);
    }
    poll();
    setInterval(poll, 1500);
  }

  $("pairBtn").addEventListener("click", () => $("pairCard").classList.toggle("hidden"));
  $("resetBtn").addEventListener("click", async () => {
    if (!confirm("Clear all admissions, the ledger and revocations?")) return;
    await SPUI.api("/api/reset", {});
    scans = []; since = 0; selected = null;
    $("feed").innerHTML = ""; $("selVerdict").innerHTML = ""; $("selPipe").innerHTML = "";
    poll();
  });

  async function poll() {
    let data;
    try { data = await SPUI.api(`/api/feed?since=${since}`); } catch (e) { return; }
    if (data.scans.length) {
      if (data.scans[0].seq < since) scans = []; // server restarted
      since = data.scans[data.scans.length - 1].seq;
      scans = scans.concat(data.scans).slice(-60);
      renderFeed(data.scans.map((s) => s.seq));
      select(data.scans[data.scans.length - 1]);
    }
    renderStats(data);
    renderChain(data);
  }

  function renderStats(data) {
    const total = scans.length, rejected = scans.filter((s) => !s.admitted).length;
    const ev = Object.entries(meta.events).map(([id, e]) =>
      `<div class="card flat"><p class="panel-title">${esc(e.kind)}</p><div class="stat">${data.counts[id] || 0}</div><div class="small muted">${esc(e.name)}</div></div>`);
    ev.push(`<div class="card flat"><p class="panel-title">Blocked attempts</p><div class="stat val-red">${rejected}</div><div class="small muted">of ${total} scans this session</div></div>`);
    $("stats").innerHTML = ev.join("");
  }

  function renderFeed(newSeqs = []) {
    $("feed").innerHTML = scans.slice().reverse().map((s) => `
      <div class="feed-item ${s.admitted ? "ok" : "no"} ${newSeqs.includes(s.seq) ? "new" : ""} ${selected && selected.seq === s.seq ? "sel" : ""}" data-seq="${s.seq}">
        <div class="bar"></div>
        <div><div class="t">${s.admitted ? "Admitted" : "Rejected"} &middot; ${esc(s.student_name || s.student || "unknown code")}</div>
        <div class="r">${esc(s.reason)}</div></div>
        <div class="r mono">${SPUI.clock(s.time)}<br>${esc(s.gate)}</div>
      </div>`).join("");
    $("feed").querySelectorAll(".feed-item").forEach((el) =>
      el.addEventListener("click", () => select(scans.find((s) => s.seq === Number(el.dataset.seq)))));
  }

  function select(s) {
    selected = s;
    SPUI.verdict($("selVerdict"), s);
    SPUI.renderPipeline($("selPipe"), meta.steps, s);
    $("feed").querySelectorAll(".feed-item").forEach((el) => el.classList.toggle("sel", Number(el.dataset.seq) === s.seq));
  }

  function renderChain(data) {
    const st = data.ledger_status;
    $("chainStatus").className = `chip ${st.ok ? "teal" : "red"}`;
    $("chainStatus").textContent = st.ok ? `${st.length} entries, chain intact` : `broken at entry ${st.first_bad}`;
    if (!data.ledger.length) { $("chain").innerHTML = '<p class="small muted">No admissions yet.</p>'; return; }
    $("chain").innerHTML = data.ledger.map((b, i) => `${i ? '<div class="link"></div>' : ""}
      <div class="block"><div><b>#${b.index}</b> ${esc(b.student)}</div>
      <div class="muted">${SPUI.clock(b.time)} &middot; ${esc(b.event)}</div>
      <div class="p">prev ${b.prev_hash.slice(0, 12)}</div><div class="h">hash ${b.hash.slice(0, 12)}</div></div>`).join("");
    $("chain").scrollLeft = $("chain").scrollWidth;
  }

  init();
})();
