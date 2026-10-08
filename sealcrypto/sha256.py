"""SHA-256 written out step by step, following FIPS 180-4.

The message is padded to a multiple of 512 bits, each 512-bit block is
expanded into a 64-word message schedule, and 64 rounds of the compression
function mix that schedule into eight 32-bit working variables.
"""

MASK = 0xFFFFFFFF

# First 32 bits of the fractional parts of the cube roots of the first 64 primes.
K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

# First 32 bits of the fractional parts of the square roots of the first 8 primes.
H0 = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

BLOCK_SIZE = 64   # bytes
DIGEST_SIZE = 32  # bytes


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def pad(message: bytes) -> bytes:
    """Append a 1 bit, zeros, then the 64-bit message length (in bits)."""
    bit_len = len(message) * 8
    padded = message + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    return padded + bit_len.to_bytes(8, "big")


def schedule(block: bytes) -> list:
    """Expand one 64-byte block into the 64-word message schedule W."""
    w = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & MASK)
    return w


def compress(state: list, block: bytes) -> list:
    """Run the 64 rounds on one block and return the new chaining state."""
    w = schedule(block)
    a, b, c, d, e, f, g, h = state
    for t in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)
        t1 = (h + big_s1 + ch + K[t] + w[t]) & MASK
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + maj) & MASK
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MASK, c, b, a, (t1 + t2) & MASK
    return [(x + y) & MASK for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def sha256(message: bytes) -> bytes:
    state = list(H0)
    padded = pad(message)
    for i in range(0, len(padded), BLOCK_SIZE):
        state = compress(state, padded[i:i + BLOCK_SIZE])
    return b"".join(x.to_bytes(4, "big") for x in state)
