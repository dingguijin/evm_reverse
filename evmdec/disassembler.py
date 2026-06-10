"""M1 - Disassembler: raw bytecode -> linear list of instructions.

The single tricky part of disassembly is that PUSH1..PUSH32 are followed by
1..32 bytes of *inline data* that must NOT be decoded as opcodes. We advance the
program counter past those bytes so they are never mistaken for instructions.

We also strip the Solidity metadata trailer (CBOR-encoded compiler/source hash)
so it is not disassembled as code.
"""

from __future__ import annotations

from dataclasses import dataclass

from .opcodes import OpInfo, lookup


@dataclass(frozen=True)
class Instruction:
    offset: int          # byte position in the bytecode (the "address")
    op: OpInfo
    operand: int | None = None       # immediate value for PUSH*, else None
    operand_bytes: bytes = b""       # raw immediate bytes (preserves leading zeros)

    @property
    def next_offset(self) -> int:
        return self.offset + self.op.size

    def __str__(self) -> str:
        loc = f"0x{self.offset:04x}"
        if self.operand is not None:
            return f"{loc}  {self.op.name} 0x{self.operand:x}"
        return f"{loc}  {self.op.name}"


def strip_metadata(code: bytes) -> bytes:
    """Remove the Solidity CBOR metadata trailer if present.

    Layout: <runtime code> <cbor metadata> <2-byte big-endian length of cbor>.
    We sanity-check the declared length and that the CBOR begins with the typical
    'a1'/'a2'/'a3' map header before trusting it.
    """
    if len(code) < 2:
        return code
    cbor_len = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - cbor_len
    if 0 < start < len(code) - 2 and code[start] in (0xA1, 0xA2, 0xA3):
        return code[:start]
    return code


def disassemble(code: bytes, *, strip_meta: bool = True) -> list[Instruction]:
    """Decode bytecode into an ordered list of Instructions."""
    if strip_meta:
        code = strip_metadata(code)

    instructions: list[Instruction] = []
    pc = 0
    n = len(code)
    while pc < n:
        op = lookup(code[pc])
        if op.immediate:
            data = code[pc + 1 : pc + 1 + op.immediate]
            # Truncated push at end-of-code: pad logically, keep what we have.
            value = int.from_bytes(data, "big") if data else 0
            instructions.append(Instruction(pc, op, value, data))
        else:
            instructions.append(Instruction(pc, op))
        pc += op.size
    return instructions


def from_hex(s: str) -> bytes:
    """Parse a hex string (with or without 0x prefix, whitespace tolerant)."""
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = "".join(s.split())
    return bytes.fromhex(s)
