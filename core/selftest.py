"""Known-answer tests and cross-checks, shared by pytest and the website's live panel."""

import hashlib
import hmac
import secrets
import time

from cryptography.hazmat.primitives.asymmetric import ec as cec

from sealcrypto import schnorr
from sealcrypto.ec import P256, TOY
from sealcrypto.hmac_ import hmac_sha256
from sealcrypto.numtheory import miller_rabin
from sealcrypto.sha256 import sha256

# FIPS 180-4 / NIST CSRC example values
SHA_VECTORS = [
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]
SHA_MILLION_A = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

# RFC 4231 test cases 1, 2 and 6
HMAC_VECTORS = [
    (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
]


def _check(name, group, fn):
    start = time.perf_counter()
    try:
        ok, detail = fn()
    except Exception as exc:  # a crash is a failed check, shown on the page
        ok, detail = False, f"{type(exc).__name__}: {exc}"
    return {"name": name, "group": group, "ok": bool(ok), "detail": detail,
            "ms": round((time.perf_counter() - start) * 1000, 1)}


def _sha_vectors():
    for msg, want in SHA_VECTORS:
        if sha256(msg).hex() != want:
            return False, f"mismatch on {msg[:20]!r}"
    return True, f"{len(SHA_VECTORS)} FIPS 180-4 vectors match"


def _sha_random():
    for n in (1, 55, 56, 63, 64, 65, 119, 120, 500):
        m = secrets.token_bytes(n)
        if sha256(m) != hashlib.sha256(m).digest():
            return False, f"differs from hashlib at length {n}"
    return True, "matches hashlib on lengths around every padding boundary"


def _hmac_vectors():
    for key, msg, want in HMAC_VECTORS:
        if hmac_sha256(key, msg).hex() != want:
            return False, f"mismatch for key length {len(key)}"
    return True, "RFC 4231 cases 1, 2 and 6 match (short, ASCII and over-long keys)"


def _hmac_random():
    for n in (0, 16, 64, 65, 200):
        k, m = secrets.token_bytes(n), secrets.token_bytes(77)
        if hmac_sha256(k, m) != hmac.new(k, m, "sha256").digest():
            return False, f"differs from hmac module at key length {n}"
    return True, "matches Python's hmac module"


def _p256_cross():
    for _ in range(3):
        x = secrets.randbelow(P256.n - 1) + 1
        nums = cec.derive_private_key(x, cec.SECP256R1()).public_key().public_numbers()
        if P256.mul(x) != (nums.x, nums.y):
            return False, "public key differs from OpenSSL"
    return True, "xG equals OpenSSL's public key for 3 random private keys"


def _curve_laws():
    if P256.mul(P256.n) is not None:
        return False, "nG is not the identity"
    if not P256.contains(P256.g):
        return False, "G is not on the curve"
    if TOY.mul(TOY.n) is not None:
        return False, "toy curve order wrong"
    a, b = secrets.randbelow(1000) + 1, secrets.randbelow(1000) + 1
    if P256.add(P256.mul(a), P256.mul(b)) != P256.mul(a + b):
        return False, "aG + bG != (a+b)G"
    return True, "G on curve, nG = O, aG + bG = (a+b)G"


def _primes():
    p_ok, _ = miller_rabin(P256.p, 20)
    n_ok, _ = miller_rabin(P256.n, 20)
    c_ok, _ = miller_rabin(P256.p * 3, 20)
    return p_ok and n_ok and not c_ok, "field prime p and group order n pass 20 Miller-Rabin rounds; 3p fails"


def _schnorr():
    x, pub = schnorr.generate_keypair()
    m = b"SealPass self-test message"
    sig = schnorr.sign(x, m)
    if not schnorr.verify(pub, m, sig):
        return False, "valid signature rejected"
    if schnorr.verify(pub, m + b"!", sig):
        return False, "accepted a changed message"
    if schnorr.verify(schnorr.generate_keypair()[1], m, sig):
        return False, "accepted the wrong public key"
    if schnorr.verify(pub, m, (sig[0], (sig[1] + 1) % P256.n)):
        return False, "accepted a changed s"
    if schnorr.sign(x, m) != sig:
        return False, "HMAC nonce is not deterministic"
    return True, "valid accepted; changed message, wrong key and changed s rejected"


def _nonce_attack():
    x, _ = schnorr.generate_keypair()
    s1, s2 = schnorr.sign(x, b"a", nonce=99), schnorr.sign(x, b"b", nonce=99)
    return schnorr.recover_key_from_nonce_reuse(s1, s2) == x, "reused nonce reveals the private key (why k comes from HMAC)"


def run_all(system=None, include_slow=False):
    checks = [
        ("SHA-256 known answers", "SHA-256", _sha_vectors),
        ("SHA-256 vs hashlib", "SHA-256", _sha_random),
        ("HMAC known answers", "HMAC", _hmac_vectors),
        ("HMAC vs hmac module", "HMAC", _hmac_random),
        ("P-256 vs OpenSSL", "Elliptic curve", _p256_cross),
        ("Group laws", "Elliptic curve", _curve_laws),
        ("Primality of p and n", "Number theory", _primes),
        ("Schnorr sign and verify", "Signature", _schnorr),
        ("Nonce reuse attack", "Signature", _nonce_attack),
    ]
    if include_slow:
        checks.append(("SHA-256 one million 'a'", "SHA-256",
                       lambda: (sha256(b"a" * 1_000_000).hex() == SHA_MILLION_A, "FIPS long-message vector")))
    if system is not None:
        from .pki import check_chain

        def _chain():
            r = check_chain(system.authority_cert, system.root_cert)
            return r.ok and r.public_key == system.authority.public_key, r.detail

        def _pipeline():
            from .threats import ThreatLab
            lab = ThreatLab(system)
            body, raw, sig, k = lab._pass()
            res = lab._gate().verify(system.authority.live_qr(raw, sig, k, body.pass_id))
            return res["admitted"], "a fresh honest pass clears all 10 steps"

        checks += [("X.509 chain to pinned root", "PKI", _chain), ("Honest pass end to end", "System", _pipeline)]
    return [_check(n, g, f) for n, g, f in checks]
