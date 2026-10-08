"""Binary layout of a pass and the text that goes into the QR code.

Signed body (all integers big-endian):
    version     1 byte   (0x01)
    key_id      4 bytes  first 4 bytes of SHA-256(authority public key)
    pass_id     8 bytes  random, unique per pass
    not_before  4 bytes  unix seconds
    not_after   4 bytes  unix seconds
    student_id  1 byte length + UTF-8
    event_id    1 byte length + UTF-8

QR text:  SP1.<base64url(body || signature)>.<slot>.<base64url(tag)>

The first part never changes for a pass. The slot and tag change every
10 seconds on the phone.
"""

import base64
from dataclasses import dataclass

from sealcrypto.ec import P256
from sealcrypto.sha256 import sha256

VERSION = 1
PREFIX = "SP1"
SIG_BYTES = 2 * P256.size


@dataclass
class PassBody:
    key_id: bytes
    pass_id: bytes
    not_before: int
    not_after: int
    student_id: str
    event_id: str
    version: int = VERSION

    def to_bytes(self) -> bytes:
        sid, eid = self.student_id.encode(), self.event_id.encode()
        return (bytes([self.version]) + self.key_id + self.pass_id
                + self.not_before.to_bytes(4, "big") + self.not_after.to_bytes(4, "big")
                + bytes([len(sid)]) + sid + bytes([len(eid)]) + eid)

    @classmethod
    def from_bytes(cls, data: bytes) -> "PassBody":
        if len(data) < 23 or data[0] != VERSION:
            raise ValueError("unknown version or truncated body")
        key_id, pass_id = data[1:5], data[5:13]
        nb, na = int.from_bytes(data[13:17], "big"), int.from_bytes(data[17:21], "big")
        i = 21
        sl = data[i]
        sid = data[i + 1:i + 1 + sl].decode()
        i += 1 + sl
        el = data[i]
        eid = data[i + 1:i + 1 + el].decode()
        if i + 1 + el != len(data) or len(sid) == 0 or len(eid) == 0:
            raise ValueError("length fields do not match the body")
        return cls(key_id, pass_id, nb, na, sid, eid)


def key_id_for(pub) -> bytes:
    return sha256(P256.encode(pub))[:4]


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def static_part(body: bytes, sig: bytes) -> str:
    return f"{PREFIX}.{b64e(body + sig)}"


def qr_text(body: bytes, sig: bytes, slot: int, tag: bytes) -> str:
    return f"{static_part(body, sig)}.{slot}.{b64e(tag)}"


def parse_qr(text: str):
    """Return (body_bytes, PassBody, signature_bytes, slot, tag). Raises ValueError."""
    parts = text.strip().split(".")
    if len(parts) != 4 or parts[0] != PREFIX:
        raise ValueError("not a SealPass code")
    blob = b64d(parts[1])
    if len(blob) <= SIG_BYTES:
        raise ValueError("too short to hold a signature")
    body, sig = blob[:-SIG_BYTES], blob[-SIG_BYTES:]
    if not parts[2].isdigit():
        raise ValueError("slot is not a number")
    return body, PassBody.from_bytes(body), sig, int(parts[2]), b64d(parts[3])
