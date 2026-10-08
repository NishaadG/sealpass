"""Tamper-evident attendance log built as a SHA-256 hash chain.

    hash_i = SHA-256(hash_{i-1} || canonical(entry_i))

Changing, deleting or reordering any entry changes its hash, which no longer
matches the prev_hash stored in the next entry, so the break is visible.
"""

import json

from sealcrypto.sha256 import sha256

GENESIS = "0" * 64


def _canonical(entry: dict) -> bytes:
    fields = {k: entry[k] for k in ("index", "time", "event", "student", "pass_id", "gate")}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def entry_hash(prev_hash: str, entry: dict) -> str:
    return sha256(bytes.fromhex(prev_hash) + _canonical(entry)).hex()


def append(chain: list, time: int, event: str, student: str, pass_id: str, gate: str) -> dict:
    prev = chain[-1]["hash"] if chain else GENESIS
    entry = {"index": len(chain), "time": time, "event": event, "student": student,
             "pass_id": pass_id, "gate": gate, "prev_hash": prev}
    entry["hash"] = entry_hash(prev, entry)
    chain.append(entry)
    return entry


def verify_chain(chain: list):
    """Return (ok, index_of_first_bad_entry_or_None)."""
    prev = GENESIS
    for i, entry in enumerate(chain):
        if entry["prev_hash"] != prev or entry["index"] != i or entry_hash(prev, entry) != entry["hash"]:
            return False, i
        prev = entry["hash"]
    return True, None
