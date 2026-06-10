"""evmdec - an EVM bytecode decompiler, built bottom-up.

Layers:
  opcodes       opcode table (foundation)
  disassembler  M1  bytecode -> instructions
  cfg           M2  instructions -> basic blocks + control flow graph
  selectors     M3  function selector / dispatcher recovery
  symbolic      M4  stack symbolic execution + dynamic jump resolution
  ir / decompiler  M5  SSA IR -> Solidity-like pseudocode
"""

from .disassembler import Instruction, disassemble, from_hex

__all__ = ["Instruction", "disassemble", "from_hex"]
