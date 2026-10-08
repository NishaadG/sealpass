"""The browser code (static/js/crypto.js) must give the same bytes as the Python code."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sealcrypto import keys, schnorr
from sealcrypto.ec import P256, TOY
from sealcrypto.hmac_ import hmac_sha256
from sealcrypto.sha256 import sha256

ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

SCRIPT = r"""
const SP = require(process.argv[1]);
const out = {};
out.sha = ["", "abc", "x".repeat(55), "x".repeat(56), "x".repeat(200)].map(s => SP.hex(SP.sha256(SP.utf8(s))));
out.hmac = SP.hex(SP.hmacSha256(SP.utf8("k".repeat(70)), SP.utf8("message")));
out.tag = SP.hex(SP.liveTag(SP.fromHex("11".repeat(32)), SP.fromHex("0102030405060708"), 178000000));
const x = 0x1234567890abcdefn;
const P = SP.P256.mul(x);
out.pub = [P[0].toString(16), P[1].toString(16)];
const sig = SP.schnorrSign(x, SP.utf8("hello"));
out.sig = [sig.e.toString(16), sig.s.toString(16)];
out.verify = SP.schnorrVerify(P, SP.utf8("hello"), sig).ok;
const ts = SP.schnorrSign(7n, SP.utf8("toy"), SP.TOY);
out.toy = [Number(ts.e), Number(ts.s)];
console.log(JSON.stringify(out));
"""


def test_js_matches_python():
    res = subprocess.run(["node", "-e", SCRIPT, str(ROOT / "static" / "js" / "crypto.js")],
                         capture_output=True, text=True, check=True)
    js = json.loads(res.stdout)
    assert js["sha"] == [sha256(s.encode()).hex() for s in ["", "abc", "x" * 55, "x" * 56, "x" * 200]]
    assert js["hmac"] == hmac_sha256(b"k" * 70, b"message").hex()
    assert js["tag"] == keys.live_tag(bytes.fromhex("11" * 32), bytes.fromhex("0102030405060708"), 178000000).hex()
    x = 0x1234567890ABCDEF
    pub = P256.mul(x)
    assert js["pub"] == [f"{pub[0]:x}", f"{pub[1]:x}"]
    e, s = schnorr.sign(x, b"hello")
    assert js["sig"] == [f"{e:x}", f"{s:x}"]
    assert js["verify"] is True
    assert js["toy"] == list(schnorr.sign(7, b"toy", TOY))
