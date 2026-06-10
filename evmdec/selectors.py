"""M3 - Function selector / dispatcher recovery.

Solidity routes calls by comparing the first 4 bytes of calldata (the *selector*,
= keccak256("name(types)")[:4]) against a list of constants. The canonical shape,
visible directly in the disassembly, is:

    PUSH4 <selector> EQ PUSH2 <dest> JUMPI      # one comparison per public fn
    DUP1 PUSH4 <selector> EQ PUSH2 <dest> JUMPI # (DUP1 keeps the selector around)

We scan the instruction stream for `PUSH4 ... EQ ... PUSH2 ... JUMPI` windows and
collect (selector, handler_offset) pairs. Selectors are then turned back into
human-readable signatures via an offline lookup table (extensible / optionally
backed by an online 4byte database).
"""

from __future__ import annotations

from dataclasses import dataclass

from .disassembler import disassemble
from .fourbyte import resolve_signature


@dataclass
class Function:
    selector: int            # 4-byte selector
    entry: int               # offset of the handler block (jump target)
    signature: str | None = None   # e.g. "transfer(address,uint256)" if known

    @property
    def selector_hex(self) -> str:
        return f"0x{self.selector:08x}"

    @property
    def name(self) -> str:
        if self.signature:
            return self.signature
        return f"func_{self.selector:08x}"


def find_functions(code: bytes) -> list[Function]:
    """Recover the dispatcher table as an ordered list of Functions."""
    instrs = disassemble(code)
    functions: list[Function] = []
    seen: set[int] = set()

    for i, ins in enumerate(instrs):
        if ins.op.name != "PUSH4":
            continue
        # Look ahead a short window for the EQ ... PUSH(dest) JUMPI tail.
        window = instrs[i + 1 : i + 6]
        names = [w.op.name for w in window]
        if "EQ" not in names or "JUMPI" not in names:
            continue
        eq_idx = names.index("EQ")
        # The jump destination is the PUSH immediately before JUMPI.
        dest = None
        for w in window[eq_idx:]:
            if w.op.is_push:
                dest = w.operand
            if w.op.name == "JUMPI":
                break
        if dest is None or ins.operand in seen:
            continue
        seen.add(ins.operand)
        functions.append(
            Function(
                selector=ins.operand,
                entry=dest,
                signature=resolve_signature(ins.operand),
            )
        )

    return functions
