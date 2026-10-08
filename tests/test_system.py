import time

import pytest

from core import ledger, passfmt
from core.selftest import run_all
from core.system import System
from core.threats import ThreatLab


@pytest.fixture(scope="module")
def system(tmp_path_factory):
    return System(tmp_path_factory.mktemp("data"))


@pytest.fixture(scope="module")
def lab(system):
    return ThreatLab(system)


def _live(system, enrolment):
    blob = passfmt.b64d(enrolment["static"].split(".")[1])
    raw, sig = blob[:-64], blob[-64:]
    body = passfmt.PassBody.from_bytes(raw)
    return system.authority.live_qr(raw, sig, bytes.fromhex(enrolment["k_se"]), body.pass_id)


def test_selftest_all_green(system):
    bad = [r for r in run_all(system) if not r["ok"]]
    assert not bad, bad


def test_enrol_and_admit_once(system):
    e = system.enrol("IT-4101", "CNS-LAB-A2")
    qr = _live(system, e)
    first = system.verify("CNS-LAB-A2", "Gate 1", qr)
    assert first["admitted"], first["reason"]
    again = system.verify("CNS-LAB-A2", "Gate 2", qr)
    assert not again["admitted"] and again["failed_step"] == "once"
    assert system.enrol("IT-4101", "CNS-LAB-A2")["pass_id"] == e["pass_id"]  # same pass reused
    assert system.ledger_status()["ok"]


def test_revocation(system):
    e = system.enrol("IT-4103", "TECHFEST-D1")
    system.revoke(e["pass_id"])
    res = system.verify("TECHFEST-D1", "Main", _live(system, e))
    assert res["failed_step"] == "revoked"
    assert system.enrol("IT-4103", "TECHFEST-D1")["pass_id"] != e["pass_id"]  # a new pass is issued


@pytest.mark.parametrize("attack,expected", [
    ("screenshot", ["fresh", "tag"]),
    ("relay", [None, "once"]),
    ("tamper", ["signature"]),
    ("forge", ["signature", "chain"]),
    ("wrong_event", ["event"]),
    ("expired", ["window"]),
    ("stolen_gate", ["signature"]),
    ("revoked", ["revoked"]),
    ("brute_force", ["tag"]),
])
def test_each_attack_stopped_at_expected_step(lab, attack, expected):
    out = lab.run(attack)
    assert [a["result"]["failed_step"] for a in out["attempts"]] == expected


def test_ledger_tamper_detected(lab):
    out = lab.ledger_edit()
    assert not out["ok"] and out["first_bad"] == 1


def test_ledger_delete_and_reorder_detected():
    chain = []
    for i in range(4):
        ledger.append(chain, int(time.time()), "E", f"S{i}", f"p{i}", "g")
    assert ledger.verify_chain(chain) == (True, None)
    assert not ledger.verify_chain(chain[:1] + chain[2:])[0]
    assert not ledger.verify_chain([chain[1], chain[0]] + chain[2:])[0]


def test_garbage_codes_rejected_at_parse(system):
    gate = system.gate("CNS-LAB-A2", "fuzz")
    for text in ["", "hello", "SP1.x.y.z", "SP1.AAAA.1.AAAA", "SP2." + "A" * 200 + ".1.AA"]:
        res = gate.verify(text, commit=False)
        assert res["failed_step"] == "parse", text


def test_qr_text_is_compact(system):
    qr = _live(system, system.enrol("IT-4104", "CNS-LAB-A2"))
    assert len(qr) < 230  # about QR version 10 at medium error correction
