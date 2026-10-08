import hashlib
import hmac
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec as cec

from core import selftest
from sealcrypto import keys, schnorr
from sealcrypto.ec import P256, TOY
from sealcrypto.hmac_ import constant_time_equal, hmac_sha256
from sealcrypto.numtheory import crt, egcd, inverse_euclid, inverse_fermat, miller_rabin
from sealcrypto.sha256 import sha256


@pytest.mark.parametrize("msg,want", selftest.SHA_VECTORS)
def test_sha256_fips_vectors(msg, want):
    assert sha256(msg).hex() == want


def test_sha256_million_a():
    assert sha256(b"a" * 1_000_000).hex() == selftest.SHA_MILLION_A


@pytest.mark.parametrize("n", [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000])
def test_sha256_matches_hashlib(n):
    m = secrets.token_bytes(n)
    assert sha256(m) == hashlib.sha256(m).digest()


@pytest.mark.parametrize("key,msg,want", selftest.HMAC_VECTORS)
def test_hmac_rfc4231(key, msg, want):
    assert hmac_sha256(key, msg).hex() == want


@pytest.mark.parametrize("klen", [0, 1, 32, 64, 65, 300])
def test_hmac_matches_stdlib(klen):
    k, m = secrets.token_bytes(klen), secrets.token_bytes(100)
    assert hmac_sha256(k, m) == hmac.new(k, m, "sha256").digest()


def test_constant_time_equal():
    assert constant_time_equal(b"abc", b"abc")
    assert not constant_time_equal(b"abc", b"abd")
    assert not constant_time_equal(b"abc", b"ab")


def test_number_theory():
    assert inverse_fermat(5, 97) * 5 % 97 == 1
    assert inverse_euclid(17, 3120) == 2753  # the textbook RSA example
    g, x, y = egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2
    assert crt([2, 3, 2], [3, 5, 7]) == 23
    assert miller_rabin(P256.p)[0] and miller_rabin(P256.n)[0]
    assert not miller_rabin(561)[0]  # a Carmichael number fools the Fermat test, not Miller-Rabin


def test_p256_matches_openssl():
    for _ in range(4):
        x = secrets.randbelow(P256.n - 1) + 1
        nums = cec.derive_private_key(x, cec.SECP256R1()).public_key().public_numbers()
        assert P256.mul(x) == (nums.x, nums.y)


def test_point_encoding_roundtrip():
    for _ in range(4):
        pt = P256.mul(secrets.randbelow(P256.n - 1) + 1)
        assert P256.decode(P256.encode(pt)) == pt


def test_toy_curve_has_prime_order():
    pts = [(x, y) for x in range(TOY.p) for y in range(TOY.p) if TOY.contains((x, y))]
    assert len(pts) + 1 == TOY.n == 103
    assert TOY.mul(TOY.n) is None


def test_schnorr_p256():
    x, pub = schnorr.generate_keypair()
    m = b"pass body"
    sig = schnorr.sign(x, m)
    assert schnorr.verify(pub, m, sig)
    assert not schnorr.verify(pub, b"pass bodY", sig)
    assert not schnorr.verify(pub, m, (sig[0], (sig[1] + 1) % P256.n))


def test_schnorr_toy_curve_roundtrip():
    # On a 103-element group a forged pair passes 1 time in 103, so only the
    # honest path is asserted here; the visual demo uses this curve.
    for _ in range(10):
        x, pub = schnorr.generate_keypair(TOY)
        assert schnorr.verify(pub, b"m", schnorr.sign(x, b"m", TOY), TOY)


def test_schnorr_rejects_wrong_key_and_bad_ranges():
    x, pub = schnorr.generate_keypair()
    sig = schnorr.sign(x, b"m")
    assert not schnorr.verify(schnorr.generate_keypair()[1], b"m", sig)
    assert not schnorr.verify(pub, b"m", (sig[0], 0))
    assert not schnorr.verify(pub, b"m", (sig[0], P256.n))


def test_nonce_is_deterministic_and_reuse_leaks_key():
    x, _ = schnorr.generate_keypair()
    assert schnorr.sign(x, b"a") == schnorr.sign(x, b"a")
    assert schnorr.derive_nonce(x, b"a") != schnorr.derive_nonce(x, b"b")
    s1, s2 = schnorr.sign(x, b"a", nonce=12345), schnorr.sign(x, b"b", nonce=12345)
    assert schnorr.recover_key_from_nonce_reuse(s1, s2) == x


def test_key_hierarchy_separates_events():
    km = secrets.token_bytes(32)
    a, b = keys.event_key(km, "A"), keys.event_key(km, "B")
    assert a != b
    assert keys.student_key(a, "S1") != keys.student_key(b, "S1")
    assert len(keys.live_tag(keys.student_key(a, "S1"), b"12345678", 1)) == keys.TAG_BYTES
