"""EVM opcode table.

This is the foundation every other layer depends on. For each opcode we record:
  - name:         mnemonic (e.g. "ADD", "PUSH1")
  - immediate:    number of bytes of inline data following the opcode (only PUSH1..32)
  - ins / outs:   how many stack items it pops / pushes (needed by symbolic execution)
  - terminator:   ends a basic block by stopping/returning/reverting execution
  - branch:       ends a basic block by jumping (JUMP / JUMPI)

Anything not in the table is treated as an unknown/invalid byte.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OpInfo:
    opcode: int
    name: str
    immediate: int = 0      # bytes of inline push data
    ins: int = 0            # stack items consumed
    outs: int = 0           # stack items produced
    terminator: bool = False  # STOP/RETURN/REVERT/INVALID/SELFDESTRUCT
    branch: bool = False      # JUMP/JUMPI

    @property
    def is_push(self) -> bool:
        return self.name.startswith("PUSH") and self.name != "PUSH0"

    @property
    def is_dup(self) -> bool:
        return self.name.startswith("DUP")

    @property
    def is_swap(self) -> bool:
        return self.name.startswith("SWAP")

    @property
    def size(self) -> int:
        """Total bytes occupied: the opcode itself plus any immediate data."""
        return 1 + self.immediate


# (opcode, name, ins, outs, [immediate], [terminator], [branch])
_TABLE: list[OpInfo] = [
    # 0x00 - 0x0b  arithmetic / stop
    OpInfo(0x00, "STOP", ins=0, outs=0, terminator=True),
    OpInfo(0x01, "ADD", ins=2, outs=1),
    OpInfo(0x02, "MUL", ins=2, outs=1),
    OpInfo(0x03, "SUB", ins=2, outs=1),
    OpInfo(0x04, "DIV", ins=2, outs=1),
    OpInfo(0x05, "SDIV", ins=2, outs=1),
    OpInfo(0x06, "MOD", ins=2, outs=1),
    OpInfo(0x07, "SMOD", ins=2, outs=1),
    OpInfo(0x08, "ADDMOD", ins=3, outs=1),
    OpInfo(0x09, "MULMOD", ins=3, outs=1),
    OpInfo(0x0A, "EXP", ins=2, outs=1),
    OpInfo(0x0B, "SIGNEXTEND", ins=2, outs=1),
    # 0x10 - 0x1d  comparison / bitwise
    OpInfo(0x10, "LT", ins=2, outs=1),
    OpInfo(0x11, "GT", ins=2, outs=1),
    OpInfo(0x12, "SLT", ins=2, outs=1),
    OpInfo(0x13, "SGT", ins=2, outs=1),
    OpInfo(0x14, "EQ", ins=2, outs=1),
    OpInfo(0x15, "ISZERO", ins=1, outs=1),
    OpInfo(0x16, "AND", ins=2, outs=1),
    OpInfo(0x17, "OR", ins=2, outs=1),
    OpInfo(0x18, "XOR", ins=2, outs=1),
    OpInfo(0x19, "NOT", ins=1, outs=1),
    OpInfo(0x1A, "BYTE", ins=2, outs=1),
    OpInfo(0x1B, "SHL", ins=2, outs=1),
    OpInfo(0x1C, "SHR", ins=2, outs=1),
    OpInfo(0x1D, "SAR", ins=2, outs=1),
    # 0x20  keccak
    OpInfo(0x20, "KECCAK256", ins=2, outs=1),
    # 0x30 - 0x3f  environment
    OpInfo(0x30, "ADDRESS", ins=0, outs=1),
    OpInfo(0x31, "BALANCE", ins=1, outs=1),
    OpInfo(0x32, "ORIGIN", ins=0, outs=1),
    OpInfo(0x33, "CALLER", ins=0, outs=1),
    OpInfo(0x34, "CALLVALUE", ins=0, outs=1),
    OpInfo(0x35, "CALLDATALOAD", ins=1, outs=1),
    OpInfo(0x36, "CALLDATASIZE", ins=0, outs=1),
    OpInfo(0x37, "CALLDATACOPY", ins=3, outs=0),
    OpInfo(0x38, "CODESIZE", ins=0, outs=1),
    OpInfo(0x39, "CODECOPY", ins=3, outs=0),
    OpInfo(0x3A, "GASPRICE", ins=0, outs=1),
    OpInfo(0x3B, "EXTCODESIZE", ins=1, outs=1),
    OpInfo(0x3C, "EXTCODECOPY", ins=4, outs=0),
    OpInfo(0x3D, "RETURNDATASIZE", ins=0, outs=1),
    OpInfo(0x3E, "RETURNDATACOPY", ins=3, outs=0),
    OpInfo(0x3F, "EXTCODEHASH", ins=1, outs=1),
    # 0x40 - 0x4a  block
    OpInfo(0x40, "BLOCKHASH", ins=1, outs=1),
    OpInfo(0x41, "COINBASE", ins=0, outs=1),
    OpInfo(0x42, "TIMESTAMP", ins=0, outs=1),
    OpInfo(0x43, "NUMBER", ins=0, outs=1),
    OpInfo(0x44, "PREVRANDAO", ins=0, outs=1),  # formerly DIFFICULTY
    OpInfo(0x45, "GASLIMIT", ins=0, outs=1),
    OpInfo(0x46, "CHAINID", ins=0, outs=1),
    OpInfo(0x47, "SELFBALANCE", ins=0, outs=1),
    OpInfo(0x48, "BASEFEE", ins=0, outs=1),
    OpInfo(0x49, "BLOBHASH", ins=1, outs=1),
    OpInfo(0x4A, "BLOBBASEFEE", ins=0, outs=1),
    # 0x50 - 0x5e  stack / memory / storage / flow
    OpInfo(0x50, "POP", ins=1, outs=0),
    OpInfo(0x51, "MLOAD", ins=1, outs=1),
    OpInfo(0x52, "MSTORE", ins=2, outs=0),
    OpInfo(0x53, "MSTORE8", ins=2, outs=0),
    OpInfo(0x54, "SLOAD", ins=1, outs=1),
    OpInfo(0x55, "SSTORE", ins=2, outs=0),
    OpInfo(0x56, "JUMP", ins=1, outs=0, branch=True),
    OpInfo(0x57, "JUMPI", ins=2, outs=0, branch=True),
    OpInfo(0x58, "PC", ins=0, outs=1),
    OpInfo(0x59, "MSIZE", ins=0, outs=1),
    OpInfo(0x5A, "GAS", ins=0, outs=1),
    OpInfo(0x5B, "JUMPDEST", ins=0, outs=0),
    OpInfo(0x5C, "TLOAD", ins=1, outs=1),
    OpInfo(0x5D, "TSTORE", ins=2, outs=0),
    OpInfo(0x5E, "MCOPY", ins=3, outs=0),
    OpInfo(0x5F, "PUSH0", ins=0, outs=1),
    # 0xf0 - 0xff  system
    OpInfo(0xF0, "CREATE", ins=3, outs=1),
    OpInfo(0xF1, "CALL", ins=7, outs=1),
    OpInfo(0xF2, "CALLCODE", ins=7, outs=1),
    OpInfo(0xF3, "RETURN", ins=2, outs=0, terminator=True),
    OpInfo(0xF4, "DELEGATECALL", ins=6, outs=1),
    OpInfo(0xF5, "CREATE2", ins=4, outs=1),
    OpInfo(0xFA, "STATICCALL", ins=6, outs=1),
    OpInfo(0xFD, "REVERT", ins=2, outs=0, terminator=True),
    OpInfo(0xFE, "INVALID", ins=0, outs=0, terminator=True),
    OpInfo(0xFF, "SELFDESTRUCT", ins=1, outs=0, terminator=True),
]


def _build() -> dict[int, OpInfo]:
    table = {op.opcode: op for op in _TABLE}
    # PUSH1..PUSH32 (0x60..0x7f): immediate = n bytes, pushes 1.
    for n in range(1, 33):
        table[0x5F + n] = OpInfo(0x5F + n, f"PUSH{n}", immediate=n, ins=0, outs=1)
    # DUP1..DUP16 (0x80..0x8f): duplicates the n-th item -> reads n, leaves n+1.
    for n in range(1, 17):
        table[0x7F + n] = OpInfo(0x7F + n, f"DUP{n}", ins=n, outs=n + 1)
    # SWAP1..SWAP16 (0x90..0x9f): swaps top with the (n+1)-th -> touches n+1, leaves n+1.
    for n in range(1, 17):
        table[0x8F + n] = OpInfo(0x8F + n, f"SWAP{n}", ins=n + 1, outs=n + 1)
    # LOG0..LOG4 (0xa0..0xa4): pops 2 (offset,size) + n topics.
    for n in range(0, 5):
        table[0xA0 + n] = OpInfo(0xA0 + n, f"LOG{n}", ins=2 + n, outs=0)
    return table


OPCODES: dict[int, OpInfo] = _build()


def lookup(byte: int) -> OpInfo:
    """Return OpInfo for a byte, synthesising an UNKNOWN entry for undefined opcodes."""
    op = OPCODES.get(byte)
    if op is not None:
        return op
    return OpInfo(byte, f"UNKNOWN_{byte:02x}", ins=0, outs=0, terminator=True)
