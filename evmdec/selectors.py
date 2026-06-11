"""M3 - Function selector / dispatcher recovery.

Solidity routes calls by comparing the first 4 bytes of calldata (the *selector*,
= keccak256("name(types)")[:4]) against a list of constants. The canonical shape,
visible directly in the disassembly, is:

    PUSH4 <selector> EQ PUSH2 <dest> JUMPI      # one comparison per public fn
    DUP1 PUSH4 <selector> EQ PUSH2 <dest> JUMPI # (DUP1 keeps the selector around)

solc >=0.8.20's optimizer also emits a shifted form that compares against the
selector left-aligned in a full word (the pushed constant is kept odd):

    PUSH4 <selector >> n> PUSH1 <0xe0 + n> SHL EQ PUSH2 <dest> JUMPI

We scan the instruction stream for `PUSH4 ... EQ ... PUSH2 ... JUMPI` windows,
undoing the SHL where present, and collect (selector, handler_offset) pairs. Selectors are then turned back into
human-readable signatures via an offline lookup table (extensible / optionally
backed by an online 4byte database).
"""

from __future__ import annotations

from dataclasses import dataclass

from .disassembler import disassemble
from .fourbyte import resolve_signature

# PUSH4 constants that show up in EQ-JUMPI windows but are never dispatcher
# entries: the Error(string) tag (revert-reason matching in try/catch) and
# 0xffffffff (ERC-165 invalid-interface sentinel / pre-0.5 selector mask).
_NON_SELECTORS = {0x08C379A0, 0xFFFFFFFF}


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
        sel = ins.operand
        # Look ahead a short window for the EQ ... PUSH(dest) JUMPI tail.
        window = instrs[i + 1 : i + 6]
        names = [w.op.name for w in window]
        # Shifted form: undo `PUSH <n> SHL`. The result must be a selector
        # left-aligned in the word (low 224 bits clear) — anything else means
        # this PUSH4 is building an unrelated constant, not a dispatcher compare.
        if len(window) >= 2 and window[0].op.is_push and names[1] == "SHL":
            word = (sel << (window[0].operand or 0)) % (1 << 256)
            if word == 0 or word & ((1 << 224) - 1):
                continue
            sel = word >> 224
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
        if dest is None or sel in seen or sel in _NON_SELECTORS:
            continue
        seen.add(sel)
        functions.append(
            Function(
                selector=sel,
                entry=dest,
                signature=resolve_signature(sel),
            )
        )

    return functions
