"""The gate scanner's verification pipeline.

A gate holds only: the pinned root certificate, the Pass Authority
certificate, K_event for its own event, the revocation list and its admitted
set. It never holds the signing key or K_master.

Every scan runs the checks in order and stops at the first failure. Each step
is recorded so the UI can show exactly where an attack was stopped.
"""

import time

from sealcrypto import keys, schnorr
from sealcrypto.hmac_ import constant_time_equal
from sealcrypto.ec import P256

from . import ledger, passfmt
from .pki import check_chain

FRESHNESS_SLOTS = 1  # accept the current slot and one either side (about 20 s)

STEPS = [
    ("parse", "Decode QR", "Format, version and field lengths"),
    ("chain", "Certificate chain", "Pass Authority certificate signed by the pinned root"),
    ("signature", "Schnorr signature", "sG - eP rebuilds R, and H(R || P || body) equals e"),
    ("event", "Event binding", "Pass was issued for this gate's event"),
    ("window", "Validity window", "not_before <= now <= not_after"),
    ("fresh", "Freshness", "Time slot within one step of the gate clock"),
    ("tag", "HMAC live tag", "HMAC(K_se, pass_id || slot) matches, compared in constant time"),
    ("revoked", "Revocation list", "pass_id is not on the revocation list"),
    ("once", "One-time use", "pass_id has not already been admitted"),
    ("admit", "Admit and log", "Appended to the hash-chained attendance ledger"),
]


def _hex(b: bytes, n=None) -> str:
    h = b.hex()
    return h if n is None else h[:n]


class GateVerifier:
    def __init__(self, gate_name, event_id, k_event, authority_cert, root_cert,
                 revoked: set, admitted: dict, chain: list):
        self.gate_name = gate_name
        self.event_id = event_id
        self.k_event = k_event
        self.authority_cert = authority_cert
        self.root_cert = root_cert
        self.revoked = revoked
        self.admitted = admitted
        self.chain = chain

    def verify(self, text: str, now: float = None, commit: bool = True) -> dict:
        now = time.time() if now is None else now
        steps = []
        result = {"admitted": False, "reason": "", "failed_step": None, "steps": steps,
                  "student": None, "pass_id": None, "event": None, "gate": self.gate_name}

        def ok(step_id, detail, **values):
            steps.append({"id": step_id, "status": "pass", "detail": detail, "values": values})

        def fail(step_id, detail, **values):
            steps.append({"id": step_id, "status": "fail", "detail": detail, "values": values})
            result.update(reason=detail, failed_step=step_id)
            done = {s["id"] for s in steps}
            for sid, _, _ in STEPS:
                if sid not in done:
                    steps.append({"id": sid, "status": "skip", "detail": "", "values": {}})
            return result

        # 1. Parse
        try:
            raw, body, sig_bytes, slot, tag = passfmt.parse_qr(text)
        except (ValueError, UnicodeDecodeError, IndexError) as exc:
            return fail("parse", f"Unreadable code: {exc}")
        result.update(student=body.student_id, pass_id=_hex(body.pass_id), event=body.event_id)
        ok("parse", f"{len(text)} characters, body {len(raw)} B, signature {len(sig_bytes)} B",
           student=body.student_id, event=body.event_id, pass_id=_hex(body.pass_id),
           key_id=_hex(body.key_id), slot=slot)

        # 2. Certificate chain and key id
        chain_res = check_chain(self.authority_cert, self.root_cert)
        if not chain_res.ok:
            return fail("chain", chain_res.detail)
        pub = chain_res.public_key
        if passfmt.key_id_for(pub) != body.key_id:
            return fail("chain", "Pass names a signing key the root never certified",
                        claimed=_hex(body.key_id), certified=_hex(passfmt.key_id_for(pub)))
        ok("chain", chain_res.detail, subject=chain_res.subject, issuer=chain_res.issuer,
           key_id=_hex(body.key_id), not_after=chain_res.not_after)

        # 3. Signature
        sig = schnorr.sig_from_bytes(sig_bytes)
        t = {}
        if not schnorr.verify(pub, raw, sig, trace=t):
            values = {"e": f"{sig[0]:064x}", "s": f"{sig[1]:064x}"}
            if "e_check" in t:
                values["e_recomputed"] = f"{t['e_check']:064x}"
            return fail("signature", "Signature does not match the pass contents", **values)
        ok("signature", "Valid Schnorr signature by the Pass Authority",
           e=f"{sig[0]:064x}", s=f"{sig[1]:064x}", R=_hex(P256.encode(t["R"])))

        # 4. Event binding
        if body.event_id != self.event_id:
            return fail("event", f"Pass is for {body.event_id}, this gate is {self.event_id}")
        ok("event", f"Issued for {self.event_id}")

        # 5. Validity window
        if not (body.not_before <= now <= body.not_after):
            when = "not valid yet" if now < body.not_before else "expired"
            return fail("window", f"Pass {when}", not_before=body.not_before, not_after=body.not_after)
        ok("window", "Inside the pass validity period", not_before=body.not_before, not_after=body.not_after)

        # 6. Freshness
        current = keys.time_slot(now)
        delta = slot - current
        if abs(delta) > FRESHNESS_SLOTS:
            age = int(now - slot * keys.SLOT_SECONDS)
            return fail("fresh", f"Code is from {age} s ago, older than the 20 s window: a copied or old screenshot",
                        slot=slot, gate_slot=current, delta=delta)
        ok("fresh", f"Slot {slot} vs gate slot {current} (difference {delta})", slot=slot, gate_slot=current)

        # 7. HMAC live tag
        k_se = keys.student_key(self.k_event, body.student_id)
        expected = keys.live_tag(k_se, body.pass_id, slot)
        if not constant_time_equal(expected, tag):
            return fail("tag", "Live tag is wrong: the code was edited or made without the student's key",
                        received=_hex(tag), expected_prefix=_hex(expected, 8) + "...")
        ok("tag", "Tag matches the student's key for this slot", tag=_hex(tag))

        # 8. Revocation
        if _hex(body.pass_id) in self.revoked:
            return fail("revoked", "Pass has been revoked (reported lost or withdrawn)")
        ok("revoked", "Not revoked")

        # 9. One-time use
        pid = _hex(body.pass_id)
        if pid in self.admitted:
            first = self.admitted[pid]
            return fail("once", f"Already admitted at {time.strftime('%H:%M:%S', time.localtime(first['time']))} "
                                f"by {first['gate']}: second use of the same pass (relay or copy)",
                        first_time=first["time"], first_gate=first["gate"])
        ok("once", "First use of this pass")

        # 10. Admit
        if commit:
            self.admitted[pid] = {"time": int(now), "gate": self.gate_name}
            entry = ledger.append(self.chain, int(now), self.event_id, body.student_id, pid, self.gate_name)
            ok("admit", f"Ledger entry #{entry['index']}", hash=entry["hash"], prev=entry["prev_hash"])
        else:
            ok("admit", "Would admit (dry run)")
        result.update(admitted=True, reason="Admitted")
        return result
