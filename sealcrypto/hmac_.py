"""HMAC-SHA256 following RFC 2104.

    HMAC(K, m) = H( (K' xor opad) || H( (K' xor ipad) || m ) )

K' is the key padded with zeros to the hash block size (64 bytes), or first
hashed down if it is longer than a block.
"""

from .sha256 import BLOCK_SIZE, sha256

IPAD = 0x36
OPAD = 0x5C


def block_key(key: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    return key.ljust(BLOCK_SIZE, b"\x00")


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    k = block_key(key)
    inner = sha256(bytes(b ^ IPAD for b in k) + message)
    return sha256(bytes(b ^ OPAD for b in k) + inner)


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare two tags without leaking where they first differ (no early exit)."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
