# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`evmdec` is an EVM bytecode decompiler written in pure Python (no runtime deps).
It is built **bottom-up as a stack of layers**, each consuming the layer below and
producing an independently inspectable artifact. The guiding principle: every layer
has its own CLI subcommand so intermediate results (`disasm -> cfg -> functions ->
... -> pseudocode`) can be viewed and tested in isolation.

## Commands

```bash
# run a layer on a hex string or a file containing hex
python3 -m evmdec disasm    <hex|file>   # M1: bytecode -> instruction listing
python3 -m evmdec cfg        <hex|file>   # M2: basic blocks + edges
python3 -m evmdec functions  <hex|file>   # M3: selector table + recovered signatures
python3 -m evmdec symbolic   <hex|file>   # M4: resolved dynamic jumps + completed CFG
python3 -m evmdec decompile  <hex|file>   # M5: Solidity-like pseudocode

# tests
python3 -m pytest tests/ -q              # full suite
python3 -m pytest tests/test_cfg.py -q   # one file
python3 -m pytest tests/test_cfg.py::test_static_jump_edges_resolved   # one test

# regenerate the test fixture (needs: pip install py-solc-x --break-system-packages)
# tests/storage.bin is the bin-runtime of a 4-function sample contract.
```

Two pinned fixtures (solc 0.8.26 bin-runtime; tests assert exact offsets/selectors):
- `tests/storage.bin` — `set(uint256)`, `get()`, `add(uint256,uint256)`, `owner()`.
- `tests/token.bin` — mapping + events + revert strings + a for-loop (`mint`,
  `balanceOf`, `transfer`, `totalSupply`, `sumTo`); exercises M4/M5 edge cases.

## Architecture (layers, bottom to top)

- `opcodes.py` — **foundation.** `OPCODES: dict[int, OpInfo]` maps every byte to its
  mnemonic, immediate length (PUSH data), and stack in/out counts. Stack counts exist
  specifically so symbolic execution (M4) can model stack effects generically. Use
  `lookup(byte)` — it synthesises an `UNKNOWN_xx` terminator for undefined bytes.
- `disassembler.py` — **M1.** `disassemble(code)` -> `list[Instruction]`. The one
  correctness-critical detail: PUSHn immediates are skipped, never decoded as opcodes.
  `strip_metadata()` removes the trailing CBOR solc metadata before decoding.
- `cfg.py` — **M2.** `build_cfg(code)` -> `CFG`. Leaders = offset 0, every JUMPDEST,
  and the instruction after any branch/terminator. Edges resolved statically only for
  the `PUSH <dest>; JUMP/JUMPI` pattern (`_static_jump_target`). Computed jump targets
  are flagged `has_unresolved_jump` and deferred to M4.
- `keccak.py` — pure-Python **Keccak-256** (Ethereum variant, padding byte 0x01 — NOT
  hashlib's SHA3). Powers selectors, event topics, and mapping storage-slot math.
- `fourbyte.py` / `selectors.py` — **M3.** `find_functions(code)` scans for
  `PUSH4 <sel> EQ ... PUSH <dest> JUMPI` dispatcher windows. Selectors are named via an
  offline keccak-computed table (`resolve_signature`, optional `online=True` 4byte API);
  `resolve_event(topic0)` does the same for LOG topic hashes.
- `symbolic.py` — **M4.** Path-forking symbolic execution. `Const`/`Expr` values with a
  constant-folding smart constructor `mk()` (this is what resolves dynamic jumps: pushed
  return addresses fold to constants, so internal call/return "just works"). Forks at
  symbolic JUMPI. Loops are recovered by *widening* (`_enter_block`): block revisits are
  keyed by (dest, call-site fingerprint of return-address consts on the stack) so shared
  internal helpers re-entered from many call sites aren't mistaken for loops; on the 2nd
  same-key entry, stack slots / memory words that changed become fresh `LOOPVAR`s and the
  body runs once on that generalized state; the 3rd entry emits a `LoopBack` marker that
  M5 renders as `while`. If a changed slot is a return address (call sites the fingerprint
  missed) widening is skipped and the old count-and-cut applies. Word-granular symbolic
  memory recovers ABI returns / revert reasons (Error string + Panic code); RETURNDATA
  values carry (call id, offset) and RETURNDATACOPY invalidates stale words — stale
  aliasing used to create false equalities that pruned live branches. Products: `complete_cfg()` and a `TraceNode` tree of effect
  statements (SStore/Return/Revert/Log/Call/...) for M5. Expression args are stored in
  **pop order** (args[0] = stack top) — renderers must respect operand semantics.
  Bounded by `max_nodes` (default 8000, path-explosion guard) and a `max_seconds`
  wall-clock budget (default 5s, checked every 64 nodes); either sets `ex.truncated`
  and cuts the trace. These bound BOTH M4 and the M5 post-processing that walks the
  tree — a 20000-node tree made 1inch AggregationRouterV5 take ~22s end-to-end
  (M4 ~9s + M5 tree-walks ~8s); 8000 nodes brings it to ~6s. Normal contracts have
  far fewer nodes (WETH ~900) and are unaffected.
  Carries a per-path *assumptions* map (`_known`/`_fork_assumptions`): when a JUMPI forks,
  the condition is recorded true/false down each arm, so re-testing the same symbolic
  condition folds instead of forking again. This kills degenerate `if (x){ if (x){} }`
  nesting (e.g. WETH transferFrom). It does NOT merge common path *suffixes*, so shared
  tails are still duplicated across arms — that needs real control-flow merging.
- `ir.py` — **M5a.** Renders Sym/Stmt to source-level text: `CALLER`->`msg.sender`,
  `SLOAD(k)`->`storage[k]`, `CALLDATALOAD(4+32i)`->`arg{i}`, negation-aware `ISZERO`
  (`ISZERO(LT)` -> `>=`), address masks dropped, panic codes annotated.
- `decompiler.py` — **M5b.** `decompile(code)`: walks the dispatcher spine of the trace
  tree (selector-EQ branch -> function body; pure-revert arm -> `require(...)`), emits
  per-function pseudocode with mutability inference (view/pure) and a storage-layout
  summary (const slots + mapping base slots from `SHA3(key, slot)`). Per function it also
  runs **CSE naming** (`_cse_bindings`): sub-expressions used 2+ times that are
  *function-invariant* (read only state the function never writes, nothing call-volatile
  after a call) are hoisted to `vN = <expr>;` bindings and `ir.set_cse_names` makes
  `render` substitute the name. Soundness rests on invariance — a value that can't change
  is safe to name once; mutated mappings/slots are deliberately left inline. Bounded by
  `_CSE_BUDGET` subexpression visits (recursive Sym hashing is O(size^2)); huge functions
  skip CSE entirely. The body is then lowered to a **Block IR** (stmt/req/if/while items
  with sub-blocks): `_merge_tails` hoists the common suffix shared by an if's two arms out
  past the if (sound because the suffix subtrees are *structurally identical* across arms —
  symbolic execution proved they compute the same thing), collapsing path-fork duplication;
  `_name_locals` then does **span-local SSA** — within a straight-line run it names a value
  read 2+ times as `sN` for the span between its first use and the first write to state it
  reads (so it is only named while provably stable; read-modify-write works because the
  store is the last use). Both are bounded; span-local naming is checked corpus-wide for
  scope soundness (no use-before-def / scope leak).

## Milestone status

**All five milestones implemented** (M1 disasm, M2 CFG, M3 functions/ABI, M4 symbolic,
M5 decompile). Known limitations / future work:
- loops render as `while` via widening, but loop bodies show only *effect* statements —
  pure stack arithmetic (accumulators) is invisible until SSA-style assignments exist,
  so e.g. a sum loop shows `while (i1 <= arg0) { continue; }` with the accumulation implicit;
- repeated values are named: function-invariant repeats as `vN` (CSE), and span-local
  repeats (incl. read-modify-write of mutable storage) as `sN`; branch arms' common tails
  are merged. Not yet: merging shared tails that aren't structurally identical, and
  cross-block value naming;
- return types are *inferred* (`_infer_return_type` in decompiler.py) — `returns (...)`
  is emitted from how each function builds its value: address/bool/narrow-uint masks,
  address literals (160-bit constants), dynamic memory ranges (bytes/string, which are
  bytecode-identical), and contract-wide storage-slot types learned from masked
  writes / onlyOwner comparisons / call targets (`_collect_slot_types`). Verified at
  *class* granularity vs solc ABI outputs: ~86% scalar match, ~92% void
  (`scripts/verify_returns.py`). Still unrecoverable: narrow-uint/bool read from a slot
  set only in the constructor (no runtime mask to learn from), and signedness;
- dynamic calldata params (bytes/string/T[]) recover `arg{i}.length` and `arg{i}[k]`
  (`_dyn_calldata` in ir.py, driven by `_dynamic_params` from the recovered signature);
  the raw ABI offset word and data-region copies still show as offset arithmetic, and
  unnamed functions get no param types so no decode.

When extending: keep each layer pure and independently testable, add a CLI subcommand
and a `tests/test_<layer>.py` pinned to the fixtures, and run the full suite.
