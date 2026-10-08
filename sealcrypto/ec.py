"""Elliptic-curve arithmetic over a prime field: y^2 = x^3 + ax + b (mod p).

Points are (x, y) tuples in affine coordinates; None is the point at infinity
(the group identity). Division is multiplication by an inverse found with
Fermat's little theorem, which is why p must be prime.
"""

from dataclasses import dataclass

from .numtheory import inverse_fermat


@dataclass(frozen=True)
class Curve:
    name: str
    p: int   # field prime
    a: int
    b: int
    g: tuple  # generator point
    n: int   # order of g
    size: int  # bytes per coordinate

    def contains(self, pt) -> bool:
        if pt is None:
            return True
        x, y = pt
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def neg(self, pt):
        if pt is None:
            return None
        return (pt[0], (-pt[1]) % self.p)

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None  # P + (-P) = O
        if p1 == p2:
            # Tangent slope: (3x^2 + a) / 2y
            lam = (3 * x1 * x1 + self.a) * inverse_fermat(2 * y1, self.p) % self.p
        else:
            # Chord slope: (y2 - y1) / (x2 - x1)
            lam = (y2 - y1) * inverse_fermat(x2 - x1, self.p) % self.p
        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def mul(self, k: int, pt=None):
        """Scalar multiplication kP by double-and-add, scanning bits high to low."""
        pt = self.g if pt is None else pt
        k %= self.n
        if k == 0:
            return None
        result = None
        for bit in bin(k)[2:]:
            result = self.add(result, result)
            if bit == "1":
                result = self.add(result, pt)
        return result

    def encode(self, pt) -> bytes:
        """SEC1 compressed form: 02/03 prefix (parity of y) then x."""
        x, y = pt
        return bytes([2 + (y & 1)]) + x.to_bytes(self.size, "big")

    def decode(self, data: bytes):
        if len(data) != self.size + 1 or data[0] not in (2, 3):
            raise ValueError("bad point encoding")
        x = int.from_bytes(data[1:], "big")
        if x >= self.p:
            raise ValueError("x out of range")
        rhs = (x * x * x + self.a * x + self.b) % self.p
        # p = 3 (mod 4) for P-256, so a square root is rhs^((p+1)/4).
        y = pow(rhs, (self.p + 1) // 4, self.p)
        if y * y % self.p != rhs:
            raise ValueError("point not on curve")
        if (y & 1) != (data[0] & 1):
            y = self.p - y
        return (x, y)


# NIST P-256 (FIPS 186-4, also called secp256r1 / prime256v1 in OpenSSL).
P256 = Curve(
    name="P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3 % 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    g=(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
       0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    size=32,
)

# A toy curve small enough to draw: y^2 = x^3 + 3x + 2 over F_97.
# It has 103 points (including O). 103 is prime, so every point other than O
# generates the whole group, the same property P-256 has with its order n.
TOY = Curve(name="toy-97", p=97, a=3, b=2, g=(2, 4), n=103, size=1)
