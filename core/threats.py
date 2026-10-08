"""Threat lab: each attack runs against a fresh, isolated gate using the real
keys and the real verifier, so results never touch the live demo state."""

import copy
import secrets
import time

from sealcrypto import keys, schnorr
from sealcrypto.sha256 import sha256

from . import ledger, passfmt
from .verifier import GateVerifier

EVENT = "CNS-LAB-A2"
OTHER_EVENT = "TECHFEST-D1"
VICTIM = "IT-4102"


def _bits_differ(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


class ThreatLab:
    def __init__(self, system):
        self.sys = system
        self.auth = system.authority

    def _gate(self, event=EVENT, revoked=None, name="Threat-lab gate"):
        return GateVerifier(name, event, self.auth.event_key(event), self.sys.authority_cert,
                            self.sys.root_cert, set(revoked or ()), {}, [])

    def _pass(self, student=VICTIM, event=EVENT, nb=None, na=None):
        now = int(time.time())
        body, raw, sig = self.auth.issue(student, event, nb or now - 300, na or now + 3600)
        return body, raw, sig, self.auth.student_key(event, student)

    @staticmethod
    def _attempt(label, qr, result):
        return {"label": label, "qr": qr, "result": result}

    # ---- attacks -------------------------------------------------------
    def screenshot(self):
        body, raw, sig, k = self._pass()
        old = time.time() - 30
        shot = self.auth.live_qr(raw, sig, k, body.pass_id, now=old)
        g = self._gate()
        a1 = self._attempt("Friend presents a screenshot taken 30 s ago", shot, g.verify(shot))
        # The friend edits the slot number to the current one, keeping the old tag.
        parts = shot.split(".")
        parts[2] = str(keys.time_slot(time.time()))
        edited = ".".join(parts)
        a2 = self._attempt("Friend edits the slot number to 'now' but cannot recompute the tag",
                           edited, g.verify(edited))
        return {"attempts": [a1, a2]}

    def relay(self):
        body, raw, sig, k = self._pass()
        live = self.auth.live_qr(raw, sig, k, body.pass_id)
        g = self._gate()
        a1 = self._attempt("Friend at the gate scans a live code relayed over a video call", live, g.verify(live))
        a2 = self._attempt("The real student arrives a few seconds later with the same pass", live, g.verify(live))
        return {"attempts": [a1, a2],
                "note": "One-time use stops the second entry and records who got in first, so the "
                        "relay is caught. The gate also shows the pass holder's name and roll number to "
                        "the person checking entry."}

    def tamper(self):
        body, raw, sig, k = self._pass(student="IT-4105")
        live = self.auth.live_qr(raw, sig, k, body.pass_id)
        forged_body = copy.copy(body)
        forged_body.student_id = "IT-4109"  # change one character of the roll number
        new_raw = forged_body.to_bytes()
        slot = keys.time_slot(time.time())
        tampered = passfmt.qr_text(new_raw, sig, slot, keys.live_tag(
            self.auth.student_key(EVENT, "IT-4109"), body.pass_id, slot))
        h1, h2 = sha256(raw), sha256(new_raw)
        g = self._gate()
        return {
            "attempts": [self._attempt("Roll number IT-4105 changed to IT-4109 inside the QR", tampered,
                                       g.verify(tampered))],
            "avalanche": {"original": raw.hex(), "tampered": new_raw.hex(), "h1": h1.hex(), "h2": h2.hex(),
                          "bits_changed": _bits_differ(h1, h2), "input_bits_changed": _bits_differ(raw, new_raw)},
            "original_qr": live,
        }

    def forge(self):
        x, pub = schnorr.generate_keypair()
        now = int(time.time())
        body = passfmt.PassBody(self.auth.key_id, secrets.token_bytes(8), now - 60, now + 3600, "IT-4199", EVENT)
        raw = body.to_bytes()
        sig = schnorr.sig_to_bytes(schnorr.sign(x, raw))
        slot = keys.time_slot(now)
        # Best case for the attacker: assume they even stole a correct live tag key.
        qr = passfmt.qr_text(raw, sig, slot, keys.live_tag(self.auth.student_key(EVENT, "IT-4199"), body.pass_id, slot))
        body2 = passfmt.PassBody(passfmt.key_id_for(pub), body.pass_id, now - 60, now + 3600, "IT-4199", EVENT)
        raw2 = body2.to_bytes()
        sig2 = schnorr.sig_to_bytes(schnorr.sign(x, raw2))
        qr2 = passfmt.qr_text(raw2, sig2, slot, keys.live_tag(self.auth.student_key(EVENT, "IT-4199"), body.pass_id, slot))
        g = self._gate()
        return {"attempts": [
            self._attempt("Attacker signs a pass with their own key and copies the Authority's key id", qr, g.verify(qr)),
            self._attempt("Attacker uses their own key id instead", qr2, g.verify(qr2)),
        ]}

    def wrong_event(self):
        body, raw, sig, k = self._pass(event=OTHER_EVENT)
        live = self.auth.live_qr(raw, sig, k, body.pass_id)
        return {"attempts": [self._attempt("A valid Tech Fest pass is shown at the Cryptography Lab gate", live,
                                           self._gate().verify(live))]}

    def expired(self):
        now = int(time.time())
        body, raw, sig, k = self._pass(nb=now - 90000, na=now - 3600)
        live = self.auth.live_qr(raw, sig, k, body.pass_id)
        return {"attempts": [self._attempt("Yesterday's pass, still with a correctly rotating tag", live,
                                           self._gate().verify(live))]}

    def stolen_gate(self):
        k_event = self.auth.event_key(EVENT)  # what the thief extracts from the device
        now = int(time.time())
        body = passfmt.PassBody(self.auth.key_id, secrets.token_bytes(8), now - 60, now + 3600, "IT-4777", EVENT)
        raw = body.to_bytes()
        sig = secrets.token_bytes(64)  # no signing key on the gate, so the best they have is a guess
        slot = keys.time_slot(now)
        tag = keys.live_tag(keys.student_key(k_event, "IT-4777"), body.pass_id, slot)
        qr = passfmt.qr_text(raw, sig, slot, tag)
        return {"attempts": [self._attempt("Thief uses K_event from a stolen scanner to mint a pass for a made-up roll number",
                                           qr, self._gate().verify(qr))],
                "note": "The thief can make correct HMAC tags, but the gate holds no signing key, so a new "
                        "pass cannot carry a valid signature. Losing a gate exposes only that one event's "
                        "tag key. The fix is to re-key the event from the master key."}

    def revoked(self):
        body, raw, sig, k = self._pass()
        live = self.auth.live_qr(raw, sig, k, body.pass_id)
        g = self._gate(revoked={body.pass_id.hex()})
        return {"attempts": [self._attempt("Phone reported lost; whoever found it tries to use the pass", live, g.verify(live))]}

    def ledger_edit(self):
        chain = []
        t = int(time.time()) - 600
        for i, sid in enumerate(["IT-4101", "IT-4103", "IT-4104", "IT-4106"]):
            ledger.append(chain, t + i * 40, EVENT, sid, secrets.token_hex(8), "Lab 412 gate")
        before = copy.deepcopy(chain)
        chain[1]["student"] = "IT-4105"  # someone edits the record to mark a friend present
        ok, bad = ledger.verify_chain(chain)
        return {"ledger_before": before, "ledger_after": chain, "ok": ok, "first_bad": bad,
                "recomputed": ledger.entry_hash(chain[1]["prev_hash"], chain[1])}

    def brute_force(self, tries=1500):
        body, raw, sig, k = self._pass()
        slot = keys.time_slot(time.time())
        real = keys.live_tag(k, body.pass_id, slot)
        start = time.time()
        hits = 0
        for _ in range(tries):
            if secrets.token_bytes(keys.TAG_BYTES) == real:
                hits += 1
        elapsed = time.time() - start
        g = self._gate()
        guess = passfmt.qr_text(raw, sig, slot, secrets.token_bytes(keys.TAG_BYTES))
        return {"attempts": [self._attempt("One of the random guesses, sent to the gate", guess, g.verify(guess))],
                "tries": tries, "hits": hits, "seconds": round(elapsed, 3),
                "tag_bits": keys.TAG_BYTES * 8,
                "note": "A guess must land within one 10 s slot, and each wrong guess is rate limited at the gate."}

    def nonce_reuse(self):
        x, pub = schnorr.generate_keypair()
        k = secrets.randbelow(10 ** 12)
        m1, m2 = b"pass for IT-4101", b"pass for IT-4102"
        s1, s2 = schnorr.sign(x, m1, nonce=k), schnorr.sign(x, m2, nonce=k)
        recovered = schnorr.recover_key_from_nonce_reuse(s1, s2)
        d1 = schnorr.derive_nonce(x, m1)
        d2 = schnorr.derive_nonce(x, m2)
        return {"sig1": [f"{s1[0]:064x}", f"{s1[1]:064x}"], "sig2": [f"{s2[0]:064x}", f"{s2[1]:064x}"],
                "private": f"{x:064x}", "recovered": f"{recovered:064x}", "match": recovered == x,
                "hmac_nonces": [f"{d1:064x}", f"{d2:064x}"]}

    ATTACKS = ["screenshot", "relay", "tamper", "forge", "wrong_event", "expired", "stolen_gate",
               "revoked", "ledger_edit", "brute_force", "nonce_reuse"]

    def run(self, name):
        if name not in self.ATTACKS:
            raise KeyError(name)
        return getattr(self, name)()
