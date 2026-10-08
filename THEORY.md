# SealPass: the theory behind each file

Read this next to the code. Each section names the file that implements it.

---

## 1. The problem with a plain QR code

A QR code is just text drawn as a picture. It has no security of its own. If the text says `IT-4101 present`, anyone can:

| Attack (X.800 name) | What it looks like here |
|---|---|
| Replay | Screenshot the QR and send it to a friend who is absent |
| Modification | Decode it, change `IT-4101` to `IT-4105`, print a new QR |
| Masquerade | Make a QR for a roll number that was never issued |
| Release of message contents | Sniff the key while it is sent to the phone |
| Denial of service | Flood the gate with scans |

So we need three properties:
- **Authentication**: the code came from the college.
- **Integrity**: nobody changed it.
- **Freshness**: it is not an old copy.

---

## 2. The design: two locks on every QR

| Lock | Algorithm | Stops | Cannot stop alone |
|---|---|---|---|
| Signature (fixed for the pass's life) | EC-Schnorr on P-256 with SHA-256 | Editing, forgery. Gives non-repudiation | Screenshots, since the signature stays valid forever |
| Live tag (changes every 10 s) | HMAC-SHA256 | Screenshots and old copies | Forgery by anyone holding the key. No non-repudiation |

Each lock covers the other's weakness. This is the main justification for the choice of techniques.

The QR text (`core/passfmt.py`):

```
SP1 . base64url(body || signature) . slot . base64url(tag)
```

The signed body:

| Field | Size |
|---|---|
| version | 1 byte |
| key_id | 4 bytes, first 4 bytes of SHA-256 of the Authority public key |
| pass_id | 8 random bytes |
| not_before | 4 bytes, unix time |
| not_after | 4 bytes, unix time |
| student_id | 1-byte length + text |
| event_id | 1-byte length + text |

The signature is 64 more bytes. The whole QR is about 170 characters, around QR version 9, which scans easily.

---

## 3. SHA-256: the hash function
File: `sealcrypto/sha256.py` (browser mirror: `static/js/crypto.js`)

A hash maps any input to a fixed 256-bit fingerprint. Three properties matter:
- **One-way**: you cannot get the input back from the hash.
- **Collision resistant**: you cannot find two inputs with the same hash.
- **Avalanche**: flipping one input bit flips about half (about 128) of the output bits.

How the code computes it:

1. **`pad()`**: append a `1` bit, then zeros, then the message length as a 64-bit number. The total length becomes a multiple of 512 bits (64 bytes).
2. **`schedule()`**: each 64-byte block becomes 64 words, W0 to W63.
   - W0 to W15 are the block itself.
   - For t ≥ 16: `W[t] = W[t-16] + σ0(W[t-15]) + W[t-7] + σ1(W[t-2])`.
   - σ0 and σ1 are mixes of right-rotations and shifts.
3. **`compress()`**: eight working variables `a` to `h` start from the current state. The first state `H0` is the first 32 bits of the fractional parts of the square roots of the first 8 primes. Each of the 64 rounds computes:
   ```
   T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
   T2 = Σ0(a) + Maj(a,b,c)
   h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
   ```
   - `Ch(e,f,g)` picks f or g bit by bit, depending on e.
   - `Maj(a,b,c)` is the majority bit.
   - `K[t]` is the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
4. The round output is added back into the state. After the last block, the state is the hash.

**Why a hash alone is not enough:** it uses no secret. An attacker who edits the data simply recomputes the hash. That is why we need HMAC or a signature.

---

## 4. HMAC: a keyed hash
File: `sealcrypto/hmac_.py`

```
HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )

K'   = K padded with zeros to 64 bytes (hashed first if longer than 64)
ipad = 0x36 repeated 64 times
opad = 0x5C repeated 64 times
```

- Only someone holding K can produce the right tag. This gives authentication and integrity.
- The two passes (inner, then outer) block the length-extension attack that the naive `H(K || m)` has.
- `constant_time_equal()` compares every byte without stopping early, so the gate's response time does not reveal how many bytes of a guess were right (a timing attack).

---

## 5. The live tag and the key hierarchy
File: `sealcrypto/keys.py`

### Live tag
```
slot = floor(unix_time / 10)
tag  = first 16 bytes of HMAC(K_se, pass_id || slot as 8 bytes)
```

- The phone recomputes the tag every 10 seconds, so the QR keeps changing.
- The gate accepts the current slot and one on either side, about 20 seconds in total. A screenshot is dead after that.
- A random guess of a 128-bit tag succeeds with probability 2^-128.

### Key hierarchy (symmetric key distribution)
```
K_master                                       held only by the server
 └─ K_event = HMAC(K_master, "event:" + id)    given to that event's gate
     └─ K_se = HMAC(K_event, "student:" + id)  given to the student's phone over TLS
```

- The gate re-derives any student's key for its own event, so it needs no database of student keys.
- A stolen gate leaks one event's key only. The master key and the signing key stay safe.
- So the thief can make correct tags but **cannot make a new pass**, because new passes need a signature. This is shown in `ThreatLab.stolen_gate` in `core/threats.py`.

---

## 6. Number theory
File: `sealcrypto/numtheory.py`

**Fermat's little theorem.** If p is prime and a is not a multiple of p, then a^(p−1) ≡ 1 (mod p). So a^(p−2) is the inverse of a.
- `inverse_fermat()` uses this. Every division in elliptic-curve arithmetic is done this way.
- This is why the field size p **must be prime**.

**Extended Euclid** (`egcd`, `inverse_euclid`). Another way to find an inverse. It solves `a·x + m·y = gcd(a, m)`.

**Miller-Rabin** (`miller_rabin`). A probabilistic primality test.
- Write n − 1 = 2^s · d with d odd.
- Pick a random base a. The number n passes the round if a^d ≡ 1, or a^(2^r · d) ≡ −1 for some r < s.
- A composite passes one round with probability at most 1/4. After 40 rounds that is at most 2^-80.
- The self-test runs it on P-256's p and n.

**Chinese Remainder Theorem** (`crt`). Rebuilds x from its remainders modulo coprime numbers. It is included for the syllabus. RSA uses it to speed up decryption.

---

## 7. Elliptic curve cryptography
File: `sealcrypto/ec.py`

The curve is `y² = x³ + ax + b (mod p)`. Its points, together with a "point at infinity" O, form a group.

**Point addition, P ≠ Q (chord):**
```
λ  = (y2 − y1) / (x2 − x1)
x3 = λ² − x1 − x2
y3 = λ(x1 − x3) − y1
```

**Point doubling, P = Q (tangent):**
```
λ = (3·x1² + a) / (2·y1)
```
then the same formulas for x3 and y3.

**Other rules:**
- P + (−P) = O, where −(x, y) = (x, −y).
- **Scalar multiplication** kP is repeated addition, done fast by **double-and-add** (`Curve.mul`). Scan the bits of k from high to low: always double, and add P when the bit is 1. That is about 256 steps for a 256-bit k.

**Hard problem (EC discrete logarithm).** Given G and P = xG, finding x is infeasible. That is the security of the private key.

**Curves in the code:**

| Curve | Field | Order | Use |
|---|---|---|---|
| P-256 (NIST, `prime256v1` in OpenSSL) | 256-bit prime | n, prime | Real passes. About 128-bit security, similar to RSA-3072 |
| Toy curve `y² = x³ + 3x + 2` | F₉₇ | 103 points, prime | Drawing on the website |

On the toy curve, 103 is prime, so every point except O generates the whole group. P-256 has the same property with its order n.

**Compressed point encoding (`encode`/`decode`).** Store a prefix byte 02 or 03 (the parity of y) followed by x, 33 bytes in total. To recover y, take a square root: for P-256, p ≡ 3 (mod 4), so y = rhs^((p+1)/4).

---

## 8. Schnorr digital signature
File: `sealcrypto/schnorr.py`

**Keys:** a private x in [1, n−1] and a public P = xG.

**Sign message m:**
```
k = HMAC(x, SHA-256(m))  mod n      deterministic nonce
R = kG
e = SHA-256(R || P || m) mod n
s = (k + e·x) mod n
signature = (e, s)                  32 + 32 = 64 bytes
```

**Verify:**
```
R' = sG − eP
accept if SHA-256(R' || P || m) mod n == e
```

**Why it works:** sG − eP = (k + e·x)G − e(xG) = kG = R.

**Why the nonce comes from HMAC.** If the same k signs two messages:
```
s1 − s2 = (e1 − e2)·x   ⇒   x = (s1 − s2) / (e1 − e2) mod n
```
The private key falls out. This is the real flaw behind the PS3 key leak. `recover_key_from_nonce_reuse()` demonstrates it. Deriving k from HMAC(x, H(m)) makes k secret, and different for every message, without relying on a random number generator.

**What each verification failure means:**
- Change any byte of the body: its hash changes, so e no longer matches.
- Sign with another key: the check runs with the Authority's P and fails.

**Why Schnorr over the alternatives:**

| Scheme | Signature size | Comment |
|---|---|---|
| RSA-2048 | 256 bytes | QR becomes dense and hard to scan |
| ElGamal (2048-bit) | about 512 bytes | Even larger |
| DSA / ECDSA (DSS) | 64 bytes (EC) | Standard, but signing needs a modular inverse of k |
| **EC-Schnorr** | **64 bytes** | Simplest equation, linear, provably secure |

**Non-repudiation.** Only the Pass Authority holds x. It cannot deny having issued a pass that verifies under P, and anyone can check that.

---

## 9. PKI and X.509 certificates
Files: `pki/make_pki.sh` (OpenSSL), `pki/make_pki.py` (fallback), `core/pki.py` (checks)

How does the gate know P really belongs to the college? Through a certificate chain:

```
Campus Root CA         self-signed, pinned on the gate
 ├─ Pass Authority     holds P; key usage: digitalSignature, nonRepudiation
 └─ SealPass Server    TLS certificate; subjectAltName covers the laptop's LAN IP
```

**An X.509 certificate contains:** subject, issuer, validity dates, public key and extensions (basicConstraints, keyUsage, subjectAltName). The issuer signs it.

**What `check_chain()` checks:**
1. The issuer is the pinned root.
2. The root's signature over the certificate verifies.
3. The current time is inside the validity dates.
4. Key usage allows signing.
5. The key is on P-256.

The verifier then also checks that the pass's `key_id` matches the certified key.

**Revocation (the CRL idea).** A list of revoked `pass_id`s. When a phone is reported lost, its pass is blocked at step 8.

---

## 10. TLS / HTTPS
File: `app.py` (`serve()`)

The server runs HTTPS with the OpenSSL-made certificate, and requires TLS 1.2 or later.

**What a TLS handshake does:**
1. **ECDHE key exchange** (Diffie-Hellman on an elliptic curve): both sides agree a fresh shared secret. It gives forward secrecy.
2. **Server authentication**: the server proves it holds the key in its certificate. The phone checks the chain up to the root CA.
3. **Record protection**: traffic is encrypted and authenticated with symmetric keys (AES-GCM).

**Why it matters here:**
- It keeps K_se confidential while it travels to the phone.
- Browsers only allow the camera on HTTPS pages, so the gate phone needs it to scan.
- Installing `root.cer` on the phone makes it trust our root CA. Otherwise you accept the warning once.

---

## 11. The gate's 10-step pipeline
File: `core/verifier.py`

The checks run in order, and the first failure rejects the scan.

| # | Step | Rule | Attack it stops |
|---|---|---|---|
| 1 | Parse | Format, version and lengths valid | Garbage or random QRs |
| 2 | Certificate chain | Authority certificate signed by the pinned root; key_id matches | Fake authority key |
| 3 | Schnorr signature | sG − eP rebuilds R | Editing, forgery |
| 4 | Event binding | Pass event = gate event | Using a pass at the wrong event |
| 5 | Validity window | not_before ≤ now ≤ not_after | Expired passes |
| 6 | Freshness | \|slot − gate slot\| ≤ 1 | Old screenshots |
| 7 | HMAC tag | Matches, compared in constant time | Edited slot; tag made without the key |
| 8 | Revocation | pass_id not revoked | Lost or stolen phone |
| 9 | One-time use | pass_id not already admitted | Live relay, second entry |
| 10 | Admit and log | Append to the ledger | (records the entry) |

**What a gate holds:** the root certificate, the Authority certificate, K_event for its own event, the revocation list and its admitted set. It never holds the signing key or K_master.

---

## 12. Hash-chained ledger
File: `core/ledger.py`

```
hash_0 = SHA-256(000...0 || entry_0)
hash_i = SHA-256(hash_{i-1} || entry_i)
```

- Each entry stores the previous hash (`prev_hash`).
- If someone edits, deletes or reorders an entry, its hash changes, and the next entry's `prev_hash` no longer matches.
- `verify_chain()` returns the index of the first broken entry. This makes the log **tamper-evident**.

---

## 13. Threat lab: each attack and the step that stops it
File: `core/threats.py`

| Attack | Stopped at |
|---|---|
| Screenshot taken 30 s ago | 6, freshness |
| Same screenshot with the slot edited to "now" | 7, HMAC tag |
| Live relay over a video call (second entry) | 9, one-time use |
| Roll number edited inside the QR | 3, signature (about 128 hash bits change) |
| Pass signed with the attacker's own key | 3, signature (or 2, if they use their own key_id) |
| Valid pass used at a different event | 4, event binding |
| Yesterday's pass | 5, validity window |
| Stolen gate used to mint a pass | 3, signature (the gate has no signing key) |
| Lost phone | 8, revocation |
| Ledger entry edited | Hash chain breaks at that index |
| Brute-forcing the tag | 7, HMAC tag (2^-128 per guess, plus rate limiting) |
| Nonce reuse | Shows the private-key recovery, which is why k comes from HMAC |

---

## 14. Rubric mapping

**1. Security requirements**

| Requirement | How it is met |
|---|---|
| Confidentiality | TLS for key delivery; only the roll number, no name, in the QR |
| Integrity | Schnorr signature, HMAC tag, hash-chained ledger |
| Authentication | Certificate chain, signature, HMAC with the per-student key |
| Non-repudiation | Authority signature on every pass; ledger entries |
| Availability | Gate checks need no per-scan server lookup of student keys; rate limiting (`RateLimiter` in `app.py`) |

**2. Threats:** the table in section 1 and the threat lab in section 13.

**3. Techniques:** section 2, plus the comparison table in section 8.

**4. Architecture:** Root CA, Pass Authority, key server, phone, gate and ledger, as described in sections 5 and 9 to 12.

**5. Implementation:** Python, from-scratch primitives, OpenSSL PKI. `core/selftest.py` checks them against:
- FIPS 180-4 test vectors for SHA-256,
- RFC 4231 test vectors for HMAC,
- `hashlib` and `hmac`,
- OpenSSL for P-256 keys.

**6. Demo:** one phone shows the rotating QR, a second phone scans it, and the laptop dashboard shows the result.

### Limitations, stated honestly
- **Phone handover.** A student can give their whole phone to someone else. Mitigation: the gate shows the holder's name, or a photo, to the person checking.
- **Real-time relay.** Only one entry succeeds and the conflict is flagged. It is caught, not prevented.
- **Teaching code.** The primitives are written from scratch to show how they work. A production build would use vetted libraries. The tests show our output matches theirs.
