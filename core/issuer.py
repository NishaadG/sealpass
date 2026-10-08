"""The Pass Authority: signs passes and hands out HMAC keys.

This is the only component that holds the signing key and K_master.
"""

import secrets
import time

from sealcrypto import keys, schnorr
from sealcrypto.ec import P256

from . import passfmt


class PassAuthority:
    def __init__(self, signing_key: int, k_master: bytes):
        self._x = signing_key
        self._k_master = k_master
        self.public_key = P256.mul(signing_key)
        self.key_id = passfmt.key_id_for(self.public_key)

    def event_key(self, event_id: str) -> bytes:
        """Provisioned to a gate scanner for one event, over TLS."""
        return keys.event_key(self._k_master, event_id)

    def student_key(self, event_id: str, student_id: str) -> bytes:
        """Provisioned to the student's phone at enrolment, over TLS."""
        return keys.student_key(self.event_key(event_id), student_id)

    def issue(self, student_id: str, event_id: str, not_before: int, not_after: int, trace: dict = None):
        body = passfmt.PassBody(self.key_id, secrets.token_bytes(8), not_before, not_after,
                                student_id, event_id)
        raw = body.to_bytes()
        sig = schnorr.sign(self._x, raw, trace=trace)
        return body, raw, schnorr.sig_to_bytes(sig)

    def live_qr(self, raw: bytes, sig: bytes, k_se: bytes, pass_id: bytes, now: float = None) -> str:
        """What the phone shows. Computed here only for tests and the threat lab;
        the real phone computes it in the browser."""
        slot = keys.time_slot(time.time() if now is None else now)
        return passfmt.qr_text(raw, sig, slot, keys.live_tag(k_se, pass_id, slot))
