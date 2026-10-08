"""Schnorr digital signatures on an elliptic curve.

    Key pair:   private x in [1, n-1],  public P = xG
    Sign m:     k = nonce,  R = kG,  e = H(R || P || m) mod n,  s = (k + e*x) mod n
                signature = (e, s)
    Verify:     R' = sG - eP,  accept if H(R' || P || m) mod n == e

Why it works: sG - eP = (k + ex)G - e(xG) = kG = R.

The nonce k must be secret and never repeat. Two signatures with the same k
give s1 - s2 = (e1 - e2) x, which reveals x. So k is derived from the private
key and the message with HMAC instead of a random number generator.
"""

import secrets

from .ec import P256, Curve
from .hmac_ import hmac_sha256
from .sha256 import sha256


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _hash_to_scalar(curve: Curve, *parts: bytes) -> int:
    return _int(sha256(b"".join(parts))) % curve.n


def generate_keypair(curve: Curve = P256):
    x = secrets.randbelow(curve.n - 1) + 1
    return x, curve.mul(x)


def public_from_private(x: int, curve: Curve = P256):
    return curve.mul(x)


def derive_nonce(x: int, message: bytes, curve: Curve = P256, counter: int = 0) -> int:
    """Deterministic nonce: HMAC keyed with the private key over H(m)."""
    key = x.to_bytes(max(curve.size, 1), "big")
    while True:
        k = _int(hmac_sha256(key, sha256(message) + counter.to_bytes(4, "big"))) % curve.n
        if k != 0:
            return k
        counter += 1


def sign(x: int, message: bytes, curve: Curve = P256, nonce: int = None, trace: dict = None):
    """Return (e, s). Pass `trace` to collect intermediate values for the UI."""
    pub = curve.mul(x)
    k = nonce if nonce is not None else derive_nonce(x, message, curve)
    r = curve.mul(k)
    e = _hash_to_scalar(curve, curve.encode(r), curve.encode(pub), message)
    s = (k + e * x) % curve.n
    if trace is not None:
        trace.update(k=k, R=r, e=e, s=s, P=pub)
    return e, s


def verify(pub, message: bytes, sig, curve: Curve = P256, trace: dict = None) -> bool:
    e, s = sig
    if not (0 < s < curve.n and 0 <= e < curve.n) or not curve.contains(pub) or pub is None:
        return False
    r = curve.add(curve.mul(s), curve.neg(curve.mul(e, pub)))
    if r is None:
        return False
    e2 = _hash_to_scalar(curve, curve.encode(r), curve.encode(pub), message)
    if trace is not None:
        trace.update(R=r, e_check=e2)
    return e2 == e


def sig_to_bytes(sig, curve: Curve = P256) -> bytes:
    e, s = sig
    return e.to_bytes(curve.size, "big") + s.to_bytes(curve.size, "big")


def sig_from_bytes(data: bytes, curve: Curve = P256):
    if len(data) != 2 * curve.size:
        raise ValueError("bad signature length")
    return _int(data[:curve.size]), _int(data[curve.size:])


def recover_key_from_nonce_reuse(sig1, sig2, curve: Curve = P256) -> int:
    """The attack the HMAC nonce prevents: same k, different messages.
    s1 - s2 = (e1 - e2) * x  =>  x = (s1 - s2) / (e1 - e2) mod n."""
    (e1, s1), (e2, s2) = sig1, sig2
    return (s1 - s2) * pow(e1 - e2, -1, curve.n) % curve.n
