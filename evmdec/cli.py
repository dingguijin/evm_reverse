"""Command-line entry point.

Usage:
  python -m evmdec disasm <hex|file>
"""

from __future__ import annotations

import sys

from .cfg import build_cfg
from .decompiler import decompile
from .disassembler import disassemble, from_hex
from .selectors import find_functions
from .symbolic import complete_cfg


def _read_input(arg: str) -> bytes:
    """Treat the argument as a file path if it exists, otherwise as raw hex."""
    import os

    if os.path.exists(arg):
        with open(arg) as f:
            return from_hex(f.read())
    return from_hex(arg)


def cmd_disasm(arg: str) -> int:
    code = _read_input(arg)
    for ins in disassemble(code):
        print(ins)
    return 0


def cmd_cfg(arg: str) -> int:
    code = _read_input(arg)
    cfg = build_cfg(code)
    for start in sorted(cfg.blocks):
        block = cfg.blocks[start]
        succ = ", ".join(f"0x{s:04x}" for s in sorted(block.succ)) or "-"
        flags = " [unresolved-jump]" if block.has_unresolved_jump else ""
        print(f"Block 0x{start:04x} -> {succ}{flags}")
        for ins in block.instructions:
            print(f"    {ins}")
    return 0


def cmd_functions(arg: str) -> int:
    code = _read_input(arg)
    funcs = find_functions(code)
    print(f"{len(funcs)} function(s):")
    for f in funcs:
        named = f.signature or "(unknown)"
        print(f"  {f.selector_hex}  ->  entry 0x{f.entry:04x}   {named}")
    return 0


def cmd_symbolic(arg: str) -> int:
    code = _read_input(arg)
    before = sum(1 for b in build_cfg(code).blocks.values() if b.has_unresolved_jump)
    cfg, resolved = complete_cfg(code)
    after = sum(1 for b in cfg.blocks.values() if b.has_unresolved_jump)
    print(f"dynamic jump sites resolved: {len(resolved)}")
    print(f"blocks with unresolved jumps: {before} -> {after}")
    for off in sorted(resolved):
        targets = ", ".join(f"0x{t:04x}" for t in sorted(resolved[off]))
        print(f"  jump@0x{off:04x} -> {targets}")
    return 0


def cmd_decompile(arg: str) -> int:
    print(decompile(_read_input(arg)))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        print(
            "usage: python -m evmdec <disasm|cfg|functions|symbolic|decompile> <hex|file>",
            file=sys.stderr,
        )
        return 2
    cmd, arg = argv[0], argv[1]
    if cmd == "disasm":
        return cmd_disasm(arg)
    if cmd == "cfg":
        return cmd_cfg(arg)
    if cmd == "functions":
        return cmd_functions(arg)
    if cmd == "symbolic":
        return cmd_symbolic(arg)
    if cmd == "decompile":
        return cmd_decompile(arg)
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
