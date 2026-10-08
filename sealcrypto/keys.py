"""Symmetric key hierarchy for the rotating HMAC tag.

    K_master                           held only by the key server
      K_event   = HMAC(K_master, "event:"   + event_id)     given to that event's gate
        K_se    = HMAC(K_event,  "student:" + student_id)   given to the student's phone

A gate can re-derive every student key for its own event, so it needs no
per-student database. A stolen gate exposes one event, never the master key,
and never the signing key, so it still cannot mint new passes.
"""

from .hmac_ import hmac_sha256

SLOT_SECONDS = 10
TAG_BYTES = 16  # 128-bit tag: a blind guess succeeds with probability 2^-128


def event_key(k_master: bytes, event_id: str) -> bytes:
    return hmac_sha256(k_master, b"event:" + event_id.encode())


def student_key(k_event: bytes, student_id: str) -> bytes:
    return hmac_sha256(k_event, b"student:" + student_id.encode())


def time_slot(unix_time: float) -> int:
    return int(unix_time // SLOT_SECONDS)


def live_tag(k_se: bytes, pass_id: bytes, slot: int) -> bytes:
    return hmac_sha256(k_se, pass_id + slot.to_bytes(8, "big"))[:TAG_BYTES]
