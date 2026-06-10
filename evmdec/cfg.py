"""M2 - Control Flow Graph: instructions -> basic blocks + edges.

A *basic block* is a maximal run of instructions with a single entry and single
exit: execution enters at the top and leaves only at the bottom. Block boundaries
("leaders") are:

  - the very first instruction,
  - every JUMPDEST (a legal jump target),
  - the instruction following any JUMP / JUMPI / terminator.

Edges between blocks:
  - fall-through: a block that ends without an unconditional jump/terminator
    flows into the next block (this includes the not-taken side of JUMPI),
  - static jump: when a JUMP/JUMPI is immediately preceded by `PUSH <dest>`,
    the target is known at disassembly time -> add an edge,
  - dynamic jump: target comes from a computed stack value; left UNRESOLVED here
    and recovered later by symbolic execution (M4).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .disassembler import Instruction, disassemble


@dataclass
class BasicBlock:
    start: int                      # offset of the first instruction
    instructions: list[Instruction]
    succ: set[int] = field(default_factory=set)   # offsets of successor blocks
    pred: set[int] = field(default_factory=set)   # offsets of predecessor blocks
    has_unresolved_jump: bool = False             # dynamic JUMP target unknown

    @property
    def end(self) -> int:
        last = self.instructions[-1]
        return last.next_offset

    @property
    def last(self) -> Instruction:
        return self.instructions[-1]

    def __str__(self) -> str:
        return f"Block@0x{self.start:04x} ({len(self.instructions)} ins)"


class CFG:
    def __init__(self, blocks: dict[int, BasicBlock], jumpdests: set[int]):
        self.blocks = blocks
        self.jumpdests = jumpdests

    @property
    def entry(self) -> BasicBlock | None:
        return self.blocks.get(0)

    def block_at(self, offset: int) -> BasicBlock | None:
        return self.blocks.get(offset)

    def _link(self, src: int, dst: int) -> None:
        if dst in self.blocks:
            self.blocks[src].succ.add(dst)
            self.blocks[dst].pred.add(src)


def _find_leaders(instructions: list[Instruction]) -> set[int]:
    leaders: set[int] = {instructions[0].offset} if instructions else set()
    for i, ins in enumerate(instructions):
        if ins.op.name == "JUMPDEST":
            leaders.add(ins.offset)
        if ins.op.branch or ins.op.terminator:
            # instruction after a branch/terminator starts a new block
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1].offset)
    return leaders


def build_cfg(code: bytes) -> CFG:
    instructions = disassemble(code)
    if not instructions:
        return CFG({}, set())

    leaders = _find_leaders(instructions)
    jumpdests = {i.offset for i in instructions if i.op.name == "JUMPDEST"}

    # Slice the linear instruction list into blocks at every leader.
    blocks: dict[int, BasicBlock] = {}
    current: list[Instruction] | None = None
    start = 0
    for ins in instructions:
        if ins.offset in leaders:
            if current:
                blocks[start] = BasicBlock(start, current)
            current = []
            start = ins.offset
        current.append(ins)  # type: ignore[union-attr]
    if current:
        blocks[start] = BasicBlock(start, current)

    cfg = CFG(blocks, jumpdests)

    # Wire up edges using only statically-knowable information.
    block_starts = sorted(blocks)
    for idx, s in enumerate(block_starts):
        block = blocks[s]
        last = block.last
        next_start = block_starts[idx + 1] if idx + 1 < len(block_starts) else None

        if last.op.name == "JUMP":
            target = _static_jump_target(block)
            if target is not None and target in jumpdests:
                cfg._link(s, target)
            else:
                block.has_unresolved_jump = True
        elif last.op.name == "JUMPI":
            target = _static_jump_target(block)
            if target is not None and target in jumpdests:
                cfg._link(s, target)
            else:
                block.has_unresolved_jump = True
            if next_start is not None:           # not-taken fall-through
                cfg._link(s, next_start)
        elif not last.op.terminator:
            if next_start is not None:           # plain fall-through
                cfg._link(s, next_start)

    return cfg


def _static_jump_target(block: BasicBlock) -> int | None:
    """If the jump's target was pushed immediately before it, return it.

    Covers the dominant `PUSH <dest> JUMP` / `PUSH <dest> ... JUMPI` patterns.
    Anything else (target computed on the stack) returns None -> resolved in M4.
    """
    instrs = block.instructions
    if len(instrs) < 2:
        return None
    prev = instrs[-2]
    if prev.op.is_push:
        return prev.operand
    return None
