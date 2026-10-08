"""Wires the components together and keeps demo state in data/state.json."""

import json
import os
import secrets
import threading
import time
from pathlib import Path

from . import ledger, passfmt, pki
from .issuer import PassAuthority
from .verifier import GateVerifier

DATA = Path("/tmp/sealpass-data") if os.environ.get("VERCEL") else Path(__file__).resolve().parent.parent / "data"

EVENTS = {
    "CNS-LAB-A2": {"name": "Cryptography Lab, Batch A2", "venue": "Lab 412", "kind": "Attendance"},
    "TECHFEST-D1": {"name": "Tech Fest Day 1, Main Gate", "venue": "Auditorium", "kind": "Event entry"},
}

STUDENTS = {
    "IT-4101": "Aarav Kulkarni",
    "IT-4102": "Sanika Deshpande",
    "IT-4103": "Rohan Patil",
    "IT-4104": "Meera Iyer",
    "IT-4105": "Kabir Shaikh",
    "IT-4106": "Tanvi Joshi",
}

PASS_LIFETIME = 12 * 3600


class System:
    def __init__(self, data_dir: Path = DATA):
        pki.ensure_pki()
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        km = self.data_dir / "k_master.bin"
        if os.environ.get("K_MASTER"):
            km.write_bytes(bytes.fromhex(os.environ["K_MASTER"]))
        elif not km.exists():
            km.write_bytes(secrets.token_bytes(32))
        self.root_cert = pki.load_cert("root")
        self.authority_cert = pki.load_cert("authority")
        self.authority = PassAuthority(pki.load_private_scalar("authority"), km.read_bytes())
        self.state_file = self.data_dir / "state.json"
        self.state = self._load()
        self.scans = []  # recent verification results, newest last (memory only)

    # ---- persistence -------------------------------------------------
    def _load(self):
        empty = {"passes": {}, "revoked": [], "admitted": {e: {} for e in EVENTS}, "ledger": []}
        if self.state_file.exists():
            try:
                saved = json.loads(self.state_file.read_text())
                empty.update(saved)
            except ValueError:
                pass
        for e in EVENTS:
            empty["admitted"].setdefault(e, {})
        return empty

    def save(self):
        self.state_file.write_text(json.dumps(self.state, indent=1))

    # ---- operations --------------------------------------------------
    def enrol(self, student_id: str, event_id: str) -> dict:
        if student_id not in STUDENTS or event_id not in EVENTS:
            raise KeyError("unknown student or event")
        now = int(time.time())
        with self.lock:
            existing = next((p for pid, p in self.state["passes"].items()
                             if p["student"] == student_id and p["event"] == event_id
                             and pid not in self.state["revoked"] and p["not_after"] > now), None)
            trace = {}
            if existing:
                rec = existing
            else:
                body, raw, sig = self.authority.issue(student_id, event_id, now - 300, now + PASS_LIFETIME, trace)
                pid = body.pass_id.hex()
                rec = {"pass_id": pid, "student": student_id, "event": event_id, "issued": now,
                       "not_before": body.not_before, "not_after": body.not_after,
                       "raw": raw.hex(), "sig": sig.hex()}
                self.state["passes"][pid] = rec
                self.save()
        return {
            "pass_id": rec["pass_id"],
            "static": passfmt.static_part(bytes.fromhex(rec["raw"]), bytes.fromhex(rec["sig"])),
            "k_se": self.authority.student_key(event_id, student_id).hex(),
            "student": student_id, "student_name": STUDENTS[student_id],
            "event": event_id, "event_name": EVENTS[event_id]["name"],
            "not_after": rec["not_after"], "server_time": time.time(),
            "reused": bool(existing),
            "signing": {k: (f"{v:064x}" if isinstance(v, int) else None) for k, v in trace.items() if k in ("e", "s")},
        }

    def gate(self, event_id: str, gate_name: str) -> GateVerifier:
        return GateVerifier(gate_name, event_id, self.authority.event_key(event_id),
                            self.authority_cert, self.root_cert, set(self.state["revoked"]),
                            self.state["admitted"][event_id], self.state["ledger"])

    def verify(self, event_id: str, gate_name: str, text: str) -> dict:
        if event_id not in EVENTS:
            raise KeyError("unknown event")
        with self.lock:
            res = self.gate(event_id, gate_name).verify(text)
            if res["admitted"]:
                self.save()
            res["time"] = time.time()
            res["student_name"] = STUDENTS.get(res["student"] or "", None)
            res["gate_event"] = event_id
            res["seq"] = (self.scans[-1]["seq"] + 1) if self.scans else 1
            self.scans.append(res)
            del self.scans[:-60]
        return res

    def revoke(self, pass_id: str):
        with self.lock:
            if pass_id not in self.state["revoked"]:
                self.state["revoked"].append(pass_id)
                self.save()

    def reset(self):
        with self.lock:
            self.state["admitted"] = {e: {} for e in EVENTS}
            self.state["ledger"] = []
            self.state["revoked"] = []
            self.scans.clear()
            self.save()

    def ledger_status(self):
        ok, bad = ledger.verify_chain(self.state["ledger"])
        return {"ok": ok, "first_bad": bad, "length": len(self.state["ledger"]),
                "head": self.state["ledger"][-1]["hash"] if self.state["ledger"] else ledger.GENESIS}
