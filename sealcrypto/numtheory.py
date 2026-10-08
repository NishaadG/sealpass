"""The number theory the elliptic-curve code leans on (Unit 2)."""

import random


def inverse_fermat(a: int, p: int) -> int:
    """a^(p-2) mod p. By Fermat's little theorem a^(p-1) = 1 (mod p) for prime p,
    so a^(p-2) is the multiplicative inverse of a."""
    if a % p == 0:
        raise ZeroDivisionError("0 has no inverse")
    return pow(a, p - 2, p)


def egcd(a: int, b: int):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverse_euclid(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ZeroDivisionError("not invertible")
    return x % m


def miller_rabin(n: int, rounds: int = 40, rng=None):
    """Probabilistic primality test. Returns (is_probable_prime, trace).

    Write n - 1 = 2^s * d with d odd. For a random base a, n passes the round if
    a^d = 1 or a^(2^r * d) = -1 (mod n) for some r < s. A composite passes one
    round with probability at most 1/4, so 40 rounds leave at most 2^-80.
    """
    if n < 2:
        return False, []
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small, []
    rng = rng or random.SystemRandom()
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    trace = []
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        passed = x in (1, n - 1)
        r = 0
        while not passed and r < s - 1:
            x = pow(x, 2, n)
            r += 1
            passed = x == n - 1
        trace.append({"base": a, "passed": passed})
        if not passed:
            return False, trace
    return True, trace


def crt(remainders, moduli):
    """Chinese Remainder Theorem for pairwise coprime moduli."""
    m_total = 1
    for m in moduli:
        m_total *= m
    x = 0
    for r, m in zip(remainders, moduli):
        mi = m_total // m
        x += r * mi * inverse_euclid(mi, m)
    return x % m_total
