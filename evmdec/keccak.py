"""Pure-Python Keccak-256 (the pre-NIST variant Ethereum uses).

Note: this is NOT SHA3-256. They differ only in the domain-separation padding
byte (Keccak uses 0x01, SHA3 uses 0x06), but that makes every digest different.
Used for function selectors, event topics, and mapping/array storage slots.
"""

from __future__ import annotations

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(state: list[list[int]]) -> None:
    for rnd in range(24):
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    rate = 136  # bytes (1088 bits) for Keccak-256
    # pad10*1 with Keccak domain byte 0x01
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] ^= 0x80

    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off : off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f(state)

    out = bytearray()
    for i in range(4):  # 4 lanes = 32 bytes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def selector(signature: str) -> int:
    """4-byte function selector for a canonical signature like 'transfer(address,uint256)'."""
    return int.from_bytes(keccak256(signature.encode())[:4], "big")
