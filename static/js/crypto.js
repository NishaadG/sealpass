/* Browser mirror of sealcrypto/: SHA-256, HMAC-SHA256, elliptic curves and
   Schnorr. Same algorithms, same encodings, so results are byte-identical to
   the Python server (checked by tests/test_mirror.py). The trace functions
   expose intermediate values for the visualisers. */
(function (root) {
  "use strict";

  // ---------- bytes ----------
  const enc = new TextEncoder();
  const utf8 = (s) => enc.encode(s);
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const fromHex = (h) => {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  };
  const concat = (...arrs) => {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  };
  const b64url = (b) => {
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const fromB64url = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  };

  // ---------- SHA-256 (FIPS 180-4) ----------
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  function pad(msg) {
    const bitLen = msg.length * 8;
    const total = Math.ceil((msg.length + 9) / 64) * 64;
    const out = new Uint8Array(total);
    out.set(msg);
    out[msg.length] = 0x80;
    const dv = new DataView(out.buffer);
    dv.setUint32(total - 8, Math.floor(bitLen / 2 ** 32));
    dv.setUint32(total - 4, bitLen >>> 0);
    return out;
  }

  function schedule(block) {
    const dv = new DataView(block.buffer, block.byteOffset, 64);
    const w = new Array(64);
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    return w;
  }

  function compress(state, block, rounds) {
    const w = schedule(block);
    let [a, b, c, d, e, f, g, h] = state;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      if (rounds) rounds.push([a, b, c, d, e, f, g, h]);
    }
    return { w, out: state.map((x, i) => (x + [a, b, c, d, e, f, g, h][i]) >>> 0) };
  }

  function sha256(msg) {
    const p = pad(msg);
    let state = H0.slice();
    for (let i = 0; i < p.length; i += 64) state = compress(state, p.subarray(i, i + 64)).out;
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    state.forEach((x, i) => dv.setUint32(i * 4, x));
    return out;
  }

  function sha256Trace(msg) {
    const p = pad(msg);
    let state = H0.slice();
    const blocks = [];
    for (let i = 0; i < p.length; i += 64) {
      const rounds = [];
      const stateIn = state.slice();
      const r = compress(state, p.subarray(i, i + 64), rounds);
      blocks.push({ w: r.w, rounds, stateIn, stateOut: r.out });
      state = r.out;
    }
    return { padded: p, blocks, digest: sha256(msg), msgBits: msg.length * 8 };
  }

  // ---------- HMAC (RFC 2104) ----------
  function blockKey(key) {
    if (key.length > 64) key = sha256(key);
    const k = new Uint8Array(64);
    k.set(key);
    return k;
  }
  function hmacTrace(key, msg) {
    const k0 = blockKey(key);
    const ik = k0.map((b) => b ^ 0x36);
    const ok = k0.map((b) => b ^ 0x5c);
    const inner = sha256(concat(ik, msg));
    const outer = sha256(concat(ok, inner));
    return { k0, ik, ok, inner, mac: outer };
  }
  const hmacSha256 = (key, msg) => hmacTrace(key, msg).mac;

  // ---------- key hierarchy and live tag ----------
  const SLOT_SECONDS = 10, TAG_BYTES = 16;
  function u64(n) {
    const out = new Uint8Array(8);
    let v = BigInt(n);
    for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }
  const timeSlot = (unix) => Math.floor(unix / SLOT_SECONDS);
  const liveTag = (kse, passId, slot) => hmacSha256(kse, concat(passId, u64(slot))).slice(0, TAG_BYTES);

  // ---------- elliptic curves over F_p ----------
  const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r; };
  function powmod(b, e, m) {
    let r = 1n; b = mod(b, m);
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  const invFermat = (a, p) => powmod(a, p - 2n, p); // a^(p-2) = a^-1 mod p

  function makeCurve(o) {
    const c = { name: o.name, p: BigInt(o.p), a: BigInt(o.a), b: BigInt(o.b),
      g: [BigInt(o.g[0]), BigInt(o.g[1])], n: BigInt(o.n), size: o.size };
    c.contains = (P) => P === null || mod(P[1] * P[1] - (P[0] ** 3n + c.a * P[0] + c.b), c.p) === 0n;
    c.neg = (P) => (P === null ? null : [P[0], mod(-P[1], c.p)]);
    c.add = (P, Q, info) => {
      if (P === null) return Q;
      if (Q === null) return P;
      const [x1, y1] = P, [x2, y2] = Q;
      if (x1 === x2 && mod(y1 + y2, c.p) === 0n) return null;
      let lam;
      if (x1 === x2 && y1 === y2) {
        lam = mod((3n * x1 * x1 + c.a) * invFermat(2n * y1, c.p), c.p);
        if (info) info.kind = "double";
      } else {
        lam = mod((y2 - y1) * invFermat(mod(x2 - x1, c.p), c.p), c.p);
        if (info) info.kind = "add";
      }
      if (info) info.lambda = lam;
      const x3 = mod(lam * lam - x1 - x2, c.p);
      return [x3, mod(lam * (x1 - x3) - y1, c.p)];
    };
    c.mul = (k, P, steps) => {
      P = P || c.g;
      k = mod(BigInt(k), c.n);
      if (k === 0n) return null;
      let R = null;
      for (const bit of k.toString(2)) {
        R = c.add(R, R);
        if (steps) steps.push({ op: "double", bit, point: R });
        if (bit === "1") { R = c.add(R, P); if (steps) steps.push({ op: "add", bit, point: R }); }
      }
      return R;
    };
    c.toBytes = (x) => fromHex(x.toString(16).padStart(c.size * 2, "0"));
    c.encode = (P) => concat(new Uint8Array([2 + Number(P[1] & 1n)]), c.toBytes(P[0]));
    return c;
  }

  const P256 = makeCurve({
    name: "P-256",
    p: "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    a: "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    b: "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    g: ["0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"],
    n: "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    size: 32,
  });
  const TOY = makeCurve({ name: "toy-97", p: 97, a: 3, b: 2, g: [2, 4], n: 103, size: 1 });

  // ---------- Schnorr ----------
  const bytesToInt = (b) => (b.length ? BigInt("0x" + hex(b)) : 0n);
  const hashToScalar = (c, ...parts) => mod(bytesToInt(sha256(concat(...parts))), c.n);

  function deriveNonce(x, msg, c) {
    const key = c.toBytes(x);
    for (let counter = 0; ; counter++) {
      const ctr = new Uint8Array([counter >>> 24, (counter >>> 16) & 255, (counter >>> 8) & 255, counter & 255]);
      const k = mod(bytesToInt(hmacSha256(key, concat(sha256(msg), ctr))), c.n);
      if (k !== 0n) return k;
    }
  }

  function schnorrSign(x, msg, c = P256, nonce) {
    x = BigInt(x);
    const P = c.mul(x);
    const k = nonce !== undefined ? BigInt(nonce) : deriveNonce(x, msg, c);
    const R = c.mul(k);
    const e = hashToScalar(c, c.encode(R), c.encode(P), msg);
    const s = mod(k + e * x, c.n);
    return { e, s, k, R, P };
  }

  function schnorrVerify(P, msg, sig, c = P256) {
    const { e, s } = sig;
    if (!(s > 0n && s < c.n && e >= 0n && e < c.n) || P === null || !c.contains(P)) return { ok: false };
    const sG = c.mul(s), eP = c.mul(e, P);
    const R = c.add(sG, c.neg(eP));
    if (R === null) return { ok: false, sG, eP };
    const e2 = hashToScalar(c, c.encode(R), c.encode(P), msg);
    return { ok: e2 === e, sG, eP, R, e2 };
  }

  // ---------- pass parsing (for display on the phone and gate) ----------
  function parsePass(text) {
    const parts = text.trim().split(".");
    if (parts.length < 2 || parts[0] !== "SP1") throw new Error("not a SealPass code");
    const blob = fromB64url(parts[1]);
    const body = blob.slice(0, blob.length - 64), sig = blob.slice(blob.length - 64);
    const dv = new DataView(body.buffer);
    let i = 21;
    const sl = body[i]; const sid = new TextDecoder().decode(body.slice(i + 1, i + 1 + sl)); i += 1 + sl;
    const el = body[i]; const eid = new TextDecoder().decode(body.slice(i + 1, i + 1 + el));
    return { body, sig, version: body[0], keyId: body.slice(1, 5), passId: body.slice(5, 13),
      notBefore: dv.getUint32(13), notAfter: dv.getUint32(17), student: sid, event: eid,
      slot: parts[2] ? Number(parts[2]) : null, tag: parts[3] ? fromB64url(parts[3]) : null };
  }

  const api = { utf8, hex, fromHex, concat, b64url, fromB64url, pad, sha256, sha256Trace, K, H0,
    hmacSha256, hmacTrace, blockKey, SLOT_SECONDS, TAG_BYTES, timeSlot, liveTag, u64,
    mod, powmod, invFermat, makeCurve, P256, TOY, bytesToInt, deriveNonce, schnorrSign, schnorrVerify,
    parsePass };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.SP = api;
})(typeof self !== "undefined" ? self : this);
