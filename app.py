"""SealPass server.

    python app.py            HTTPS on :5443 (needed for phone cameras) and HTTP on :5080
"""

import ssl
import threading
import time
from collections import defaultdict

from flask import Flask, abort, jsonify, render_template, request, send_file
from werkzeug.serving import make_server

from core import selftest
from core.pki import HOSTED, PKI_DIR, check_chain
from core.system import EVENTS, STUDENTS, System
from core.threats import ThreatLab
from core.verifier import STEPS
from sealcrypto import keys
from sealcrypto.ec import P256, TOY

HTTPS_PORT, HTTP_PORT = 5443, 5080

app = Flask(__name__)
system = System()
lab = ThreatLab(system)


# ---- availability: token bucket per client on the verify endpoint ----------
class RateLimiter:
    def __init__(self, rate=4.0, burst=8):
        self.rate, self.burst = rate, burst
        self.buckets = defaultdict(lambda: [burst, time.monotonic()])
        self.lock = threading.Lock()

    def allow(self, key) -> bool:
        with self.lock:
            tokens, last = self.buckets[key]
            now = time.monotonic()
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            ok = tokens >= 1
            self.buckets[key] = [tokens - 1 if ok else tokens, now]
            return ok


limiter = RateLimiter()


def lan_ip():
    f = PKI_DIR / "lan_ip.txt"
    return f.read_text().strip() if f.exists() else "127.0.0.1"


# ---- pages ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/lab")
def lab_page():
    return render_template("lab.html")


@app.route("/phone")
def phone():
    return render_template("phone.html")


@app.route("/gate")
def gate():
    return render_template("gate.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/root.cer")
def root_cer():
    return send_file(PKI_DIR / "root.cer", mimetype="application/x-x509-ca-cert",
                     as_attachment=True, download_name="campus-root-ca.cer")


# ---- API --------------------------------------------------------------------
@app.get("/api/meta")
def meta():
    ip = lan_ip()
    if HOSTED:
        base = request.host_url.rstrip("/").replace("http://", "https://")
        urls = {"https": base, "http": base}
    else:
        urls = {"https": f"https://{ip}:{HTTPS_PORT}", "http": f"http://{ip}:{HTTP_PORT}"}
    return jsonify(
        events=EVENTS, students=STUDENTS, slot_seconds=keys.SLOT_SECONDS, tag_bytes=keys.TAG_BYTES,
        steps=[{"id": i, "name": n, "rule": r} for i, n, r in STEPS],
        urls=urls, hosted=HOSTED,
        server_time=time.time(),
        authority={"key_id": system.authority.key_id.hex(),
                   "public": P256.encode(system.authority.public_key).hex()},
        curve={"p": hex(P256.p), "n": hex(P256.n), "gx": hex(P256.g[0]), "gy": hex(P256.g[1]), "b": hex(P256.b)},
        toy={"p": TOY.p, "a": TOY.a, "b": TOY.b, "g": TOY.g, "n": TOY.n},
    )


@app.post("/api/enrol")
def enrol():
    d = request.get_json(force=True)
    try:
        return jsonify(system.enrol(d.get("student", ""), d.get("event", "")))
    except KeyError as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/verify")
def verify():
    if not limiter.allow(request.remote_addr):
        return jsonify(error="Too many scans from this device; slow down (rate limit protects availability)"), 429
    d = request.get_json(force=True)
    try:
        res = system.verify(d.get("event", ""), (d.get("gate") or "Gate")[:40], d.get("qr", "")[:1000])
    except KeyError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(res)


@app.get("/api/feed")
def feed():
    since = request.args.get("since", 0, type=int)
    with system.lock:
        scans = [s for s in system.scans if s["seq"] > since]
        ledger_tail = system.state["ledger"][-8:]
        counts = {e: len(v) for e, v in system.state["admitted"].items()}
    return jsonify(scans=scans, ledger=ledger_tail, ledger_status=system.ledger_status(), counts=counts,
                   revoked=system.state["revoked"], server_time=time.time())


@app.get("/api/passes")
def passes():
    with system.lock:
        out = [{k: p[k] for k in ("pass_id", "student", "event", "issued", "not_after")}
               | {"revoked": p["pass_id"] in system.state["revoked"], "name": STUDENTS.get(p["student"])}
               for p in system.state["passes"].values()]
    return jsonify(sorted(out, key=lambda p: -p["issued"])[:30])


@app.post("/api/revoke")
def revoke():
    system.revoke(request.get_json(force=True).get("pass_id", ""))
    return jsonify(ok=True)


@app.post("/api/reset")
def reset():
    system.reset()
    return jsonify(ok=True)


@app.get("/api/pki")
def pki_info():
    res = check_chain(system.authority_cert, system.root_cert)
    def pem(name):
        return (PKI_DIR / f"{name}.crt").read_text()
    return jsonify(ok=res.ok, detail=res.detail, subject=res.subject, issuer=res.issuer,
                   not_after=res.not_after, authority_pem=pem("authority"), root_pem=pem("root"))


@app.get("/api/selftest")
def run_selftest():
    return jsonify(selftest.run_all(system))


@app.post("/api/attack/<name>")
def attack(name):
    if name not in ThreatLab.ATTACKS:
        abort(404)
    return jsonify(lab.run(name))


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def serve():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(PKI_DIR / "server.crt", PKI_DIR / "server.key")
    https = make_server("0.0.0.0", HTTPS_PORT, app, threaded=True, ssl_context=ctx)
    http = make_server("0.0.0.0", HTTP_PORT, app, threaded=True)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    ip = lan_ip()
    print(f"\n  SealPass is running\n"
          f"    Laptop      https://localhost:{HTTPS_PORT}\n"
          f"    Phones      https://{ip}:{HTTPS_PORT}/phone   and   /gate\n"
          f"    Plain HTTP  http://{ip}:{HTTP_PORT}  (photo-scan fallback)\n")
    https.serve_forever()


if __name__ == "__main__":
    serve()
