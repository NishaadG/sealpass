/* Written content for the story page, kept as data so the layout code stays small. */
window.SPC = {
  requirements: [
    { letter: "C", name: "Confidentiality", color: "azure",
      need: "A QR can be read by anyone standing nearby, so it must not reveal private data. Keys must never be visible on the network.",
      service: "Data confidentiality",
      how: ["Only a roll number and event code in the QR; no name, phone or photo", "Keys delivered only inside TLS (ECDHE + AES-GCM)", "The QR carries no secret, so there is nothing in it to encrypt"] },
    { letter: "I", name: "Integrity", color: "teal",
      need: "A changed roll number, event, expiry date or time slot must be detected.",
      service: "Connectionless integrity",
      how: ["Schnorr signature covers every byte of the pass", "HMAC tag covers pass_id and the time slot", "SHA-256 hash chain protects the attendance log"] },
    { letter: "A", name: "Availability", color: "saffron",
      need: "Gates must keep working at a crowded entrance, even if Wi-Fi is poor or someone floods the scanner.",
      service: "Availability service",
      how: ["The gate derives student keys locally from K_event, with no per-student database", "Small 64-byte signature keeps the QR quick to scan", "Rate limiting on the verify endpoint"] },
    { letter: "Au", name: "Authentication", color: "teal",
      need: "Prove the pass came from the college (data origin) and that it is being shown live by the device it was issued to (entity).",
      service: "Data-origin and peer-entity authentication",
      how: ["Signature verified with the certified Authority key", "Live HMAC tag proves possession of K_se right now", "Event binding and validity window"] },
    { letter: "NR", name: "Non-repudiation", color: "saffron",
      need: "The college cannot deny issuing a pass, and an admission record cannot be quietly rewritten later.",
      service: "Non-repudiation with proof of origin",
      how: ["Only the Authority holds the signing key; HMAC alone could never give this", "X.509 certificate links the key to the Authority", "Hash-chained ledger of admissions"] },
  ],

  vulns: [
    ["Static content", "the same picture works forever, so any copy is as good as the original"],
    ["No proof of origin", "any free QR generator can produce a code the scanner accepts"],
    ["No integrity check", "fields such as roll number or event can be edited without detection"],
    ["No binding to time or event", "a pass for one event or day works at another"],
    ["No single-use rule", "the same code can be scanned many times at different doors"],
    ["Guessable identifiers", "sequential roll numbers make codes easy to fabricate"],
    ["Editable attendance records", "whoever controls the spreadsheet can change who was present"],
  ],

  threats: [
    ["Release of message contents", "Passive", "Shoulder-surfing or photographing a QR to learn personal data", "Data minimisation; TLS for keys"],
    ["Traffic analysis", "Passive", "Watching enrolment traffic to learn who registered for what", "TLS hides content and keys"],
    ["Masquerade", "Active", "A friend presents your pass, or a made-up pass for a roll number", "Signature, live tag, one-time use"],
    ["Replay", "Active", "Reusing a screenshot or an old scan", "Freshness window, HMAC tag, one-time use"],
    ["Modification of messages", "Active", "Editing roll number, event or expiry inside the code", "Schnorr signature"],
    ["Forgery of the issuer", "Active", "Signing passes with an attacker's own key", "Pinned root CA and key id"],
    ["Denial of service", "Active", "Flooding the gate with junk scans", "Rate limit, cheap checks first, offline derivation"],
    ["Repudiation", "Active", "An official denies issuing a pass, or edits the record", "Signature and hash-chained ledger"],
    ["Key compromise", "Active", "Stealing a scanner to mint passes", "Key hierarchy: the gate holds no signing key"],
  ],

  ladder: [
    { name: "Plain QR with a roll number", gives: "Nothing", fails: "Anyone can generate one with a free app. A copy is identical to the original.", verdict: "rejected" },
    { name: "Add a SHA-256 hash of the data", gives: "Detects accidental damage", fails: "The hash has no key, so a forger simply recomputes it for their edited data.", verdict: "rejected" },
    { name: "Encrypt the QR with AES", gives: "Confidentiality", fails: "A copied ciphertext still decrypts. Every scanner needs the decryption key, and a stolen key decrypts and forges everything. It also gives no proof of origin.", verdict: "rejected" },
    { name: "HMAC only", gives: "Integrity, authentication", fails: "The verifier holds the same key as the issuer, so a stolen gate could mint passes. No non-repudiation. A static HMAC can still be copied.", verdict: "partial", note: "kept, but only for the rotating live tag" },
    { name: "RSA signature", gives: "Integrity, origin, non-repudiation", fails: "A 3072-bit key for 128-bit security means a 384-byte signature. The QR becomes dense and slow to scan, and it is still copyable.", verdict: "rejected" },
    { name: "ElGamal signature", gives: "Integrity, origin, non-repudiation", fails: "The signature (r, s) is twice the modulus size, so it is even bigger than RSA. A fresh random k is needed for every signature.", verdict: "rejected" },
    { name: "DSA / ECDSA (DSS)", gives: "Compact signature on curves", fails: "Works, but needs a modular inverse of k in every signature and has a weaker security proof. A fine runner-up.", verdict: "partial", note: "runner-up" },
    { name: "EC-Schnorr signature + rotating HMAC tag + one-time use", gives: "C, I, A, Au, NR, and resistance to copying", fails: "The signature makes the pass unforgeable. The 10-second HMAC tag makes copies expire. One-time use stops live relays.", verdict: "chosen" },
  ],

  // Attack x step matrix: first = step that stops it, also = other steps that would.
  matrix: [
    { attack: "Screenshot replayed later", first: "fresh", also: ["tag", "once"] },
    { attack: "Screenshot with slot number edited", first: "tag", also: ["once"] },
    { attack: "Live relay to a friend", first: "once", also: [] },
    { attack: "Roll number edited in the QR", first: "signature", also: ["tag"] },
    { attack: "Pass made with the attacker's own key", first: "signature", also: ["chain"] },
    { attack: "Valid pass, wrong event", first: "event", also: ["tag"] },
    { attack: "Expired pass", first: "window", also: [] },
    { attack: "Stolen gate used to mint passes", first: "signature", also: [] },
    { attack: "Lost phone, pass revoked", first: "revoked", also: [] },
    { attack: "Random tag guessing", first: "tag", also: [] },
    { attack: "Garbage or malformed code", first: "parse", also: [] },
  ],

  arch: {
    nodes: [
      { id: "ca", x: 70, y: 40, w: 220, h: 96, title: "Campus Root CA", sub: "offline; signs certificates", color: "azure",
        info: "<b>Holds:</b> root private key (kept offline).<br><b>Does:</b> issues the X.509 certificates for the Pass Authority and the TLS server. Its own certificate is pinned in every gate, so trust starts here." },
      { id: "auth", x: 390, y: 40, w: 240, h: 110, title: "Pass Authority", sub: "signing key x, K_master", color: "saffron",
        info: "<b>Holds:</b> the Schnorr private key x and the 256-bit K_master. These are the only two secrets that can create passes.<br><b>Does:</b> signs passes, derives K_event for gates and K_se for phones, publishes the revocation list." },
      { id: "phone", x: 70, y: 330, w: 230, h: 120, title: "Student phone", sub: "signed pass + K_se", color: "teal",
        info: "<b>Holds:</b> its signed pass and K_se, a key for this student and this event only.<br><b>Does:</b> every 10 s computes HMAC(K_se, pass_id || slot) and redraws the QR. Works offline once enrolled." },
      { id: "gate", x: 410, y: 330, w: 220, h: 120, title: "Gate scanner", sub: "root cert, K_event, CRL", color: "teal",
        info: "<b>Holds:</b> pinned root certificate, Authority certificate, K_event for one event, the revocation list and the set of passes already admitted.<br><b>Does:</b> runs the 10 checks. It cannot sign, so a stolen gate cannot create passes." },
      { id: "ledger", x: 730, y: 330, w: 220, h: 120, title: "Attendance ledger", sub: "SHA-256 hash chain", color: "azure",
        info: "<b>Holds:</b> one entry per admission, each storing the hash of the previous entry.<br><b>Does:</b> makes edits, deletions and reordering visible. The dashboard re-checks the chain live." },
      { id: "atk", x: 740, y: 60, w: 210, h: 90, title: "Attacker", sub: "copies, edits, forges", color: "vermilion",
        info: "<b>Can:</b> photograph or screenshot codes, edit bytes, sign with their own key, relay codes live, steal a gate, flood the scanner.<br><b>Cannot:</b> get x or K_master, or produce a valid tag without K_se. Chapter 13 shows where each attempt is stopped." },
    ],
    edges: [
      { from: "ca", to: "auth", label: "X.509 cert", d: "M290 88 L390 92", info: "The root CA signs the Pass Authority's certificate. It binds the P-256 public key to the name 'Pass Authority' with keyUsage digitalSignature and nonRepudiation." },
      { from: "ca", to: "gate", label: "pinned root", off: 24, d: "M200 136 C 260 230, 420 250, 470 330", info: "The root certificate is installed on every gate in advance. The gate trusts only keys that chain back to it." },
      { from: "auth", to: "phone", label: "pass + K_se over TLS", off: 26, d: "M430 150 C 380 240, 260 260, 220 330", info: "At enrolment the Authority signs the pass and sends it, with the student's K_se, over HTTPS. The key never appears outside TLS." },
      { from: "auth", to: "gate", label: "K_event + CRL over TLS", d: "M540 150 L540 330", info: "Before the event, each gate receives K_event for that event only, plus the current revocation list." },
      { from: "phone", to: "gate", label: "QR: pass || slot || tag", d: "M300 395 L410 395", info: "The only channel the attacker can easily see. It is optical, public and copyable, which is why everything sent over it is signed, time-bound and single-use." },
      { from: "gate", to: "ledger", label: "admission entry", d: "M630 395 L730 395", info: "Each admitted scan becomes a ledger entry chained to the previous one by SHA-256." },
      { from: "atk", to: "phone", label: "copies", off: 22, d: "M760 150 C 620 250, 420 300, 300 360", info: "The attacker's main tool: copying what the phone shows. The rotating tag and one-time use make copies worthless.", dashed: true },
    ],
  },

  flows: {
    "PKI setup": { actors: ["Root CA", "Authority", "Gate"], steps: [
      [0, 0, "Root CA generates its P-256 key pair and a self-signed certificate (openssl req -x509)."],
      [1, 0, "The Authority generates its signing key x and sends a certificate signing request containing P = xG."],
      [0, 1, "Root CA signs the Authority's certificate: subject, public key, validity, keyUsage."],
      [0, 2, "The root certificate is installed (pinned) on every gate device."],
      [1, 2, "The gate receives the Authority certificate and checks its chain to the pinned root."],
    ] },
    Enrolment: { actors: ["Phone", "Authority"], steps: [
      [0, 1, "The phone opens a TLS session: ECDHE key agreement, then the server certificate is checked against the root."],
      [0, 1, "The student picks the event. Their identity comes from the college login (outside this demo)."],
      [1, 1, "The Authority builds the 40-byte body: key_id, random pass_id, validity, roll number, event."],
      [1, 1, "It signs the body with Schnorr: k = HMAC(x, H(m)), R = kG, e = H(R||P||m), s = k + ex."],
      [1, 0, "It returns the signed pass and K_se = HMAC(HMAC(K_master, event), student) over TLS."],
    ] },
    "Live code": { actors: ["Phone", "Phone"], steps: [
      [0, 0, "Every 200 ms the phone computes slot = floor(time / 10), using the clock offset learned at enrolment."],
      [0, 0, "When the slot changes it computes tag = HMAC(K_se, pass_id || slot), truncated to 16 bytes."],
      [0, 0, "It draws the QR SP1.<body+signature>.<slot>.<tag>, about 180 characters (QR version 9)."],
      [0, 0, "The moving pattern and ticking clock show a person at the gate that the screen is live."],
    ] },
    Verification: { actors: ["Phone", "Gate", "Ledger"], steps: [
      [0, 1, "The gate camera reads the QR."],
      [1, 1, "It parses the format and checks the Authority certificate chain and key id."],
      [1, 1, "It verifies the Schnorr signature: sG - eP must rebuild R."],
      [1, 1, "It checks the event, the validity window and freshness (slot within plus or minus 1)."],
      [1, 1, "It derives K_se from K_event, recomputes the tag and compares in constant time."],
      [1, 1, "It checks the revocation list and that this pass_id has not been admitted already."],
      [1, 2, "It admits the student and appends a hash-chained ledger entry."],
    ] },
  },

  code: {
    "Schnorr": `def sign(x, message, curve=P256):
    pub = curve.mul(x)                                   # P = xG
    k = derive_nonce(x, message, curve)                  # k = HMAC(x, H(m))
    r = curve.mul(k)                                     # R = kG
    e = _hash_to_scalar(curve, curve.encode(r), curve.encode(pub), message)
    s = (k + e * x) % curve.n                            # s = k + e*x mod n
    return e, s

def verify(pub, message, sig, curve=P256):
    e, s = sig
    r = curve.add(curve.mul(s), curve.neg(curve.mul(e, pub)))   # R' = sG - eP
    e2 = _hash_to_scalar(curve, curve.encode(r), curve.encode(pub), message)
    return e2 == e`,
    "Live tag": `SLOT_SECONDS = 10
TAG_BYTES = 16

def event_key(k_master, event_id):
    return hmac_sha256(k_master, b"event:" + event_id.encode())

def student_key(k_event, student_id):
    return hmac_sha256(k_event, b"student:" + student_id.encode())

def live_tag(k_se, pass_id, slot):
    return hmac_sha256(k_se, pass_id + slot.to_bytes(8, "big"))[:TAG_BYTES]`,
    "HMAC": `def hmac_sha256(key, message):
    k = block_key(key)                         # pad (or hash) the key to 64 bytes
    inner = sha256(bytes(b ^ 0x36 for b in k) + message)
    return sha256(bytes(b ^ 0x5C for b in k) + inner)`,
    "Point addition": `def add(self, p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1; x2, y2 = p2
    if x1 == x2 and (y1 + y2) % self.p == 0:
        return None                                        # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + self.a) * inverse_fermat(2 * y1, self.p) % self.p
    else:
        lam = (y2 - y1) * inverse_fermat(x2 - x1, self.p) % self.p
    x3 = (lam * lam - x1 - x2) % self.p
    return (x3, (lam * (x1 - x3) - y1) % self.p)`,
    "Gate checks": `# 6. Freshness
current = keys.time_slot(now)
if abs(slot - current) > FRESHNESS_SLOTS:
    return fail("fresh", "Code is older than the 20 s window")

# 7. HMAC live tag
k_se = keys.student_key(self.k_event, body.student_id)
expected = keys.live_tag(k_se, body.pass_id, slot)
if not constant_time_equal(expected, tag):
    return fail("tag", "Live tag is wrong")

# 9. One-time use
if pid in self.admitted:
    return fail("once", "Already admitted")`,
    "OpenSSL PKI": `openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -x509 -new -key root.key -sha256 -days 3650 \\
  -subj "/O=Campus Security Office/CN=Campus Root CA" -out root.crt

openssl ecparam -name prime256v1 -genkey -noout -out authority.key
openssl req -new -key authority.key -subj "/CN=Pass Authority" -out authority.csr
openssl x509 -req -in authority.csr -CA root.crt -CAkey root.key \\
  -days 825 -sha256 -extfile authority.ext -out authority.crt

openssl verify -CAfile root.crt authority.crt     # authority.crt: OK`,
  },
};
