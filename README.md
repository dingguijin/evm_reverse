# evmdec

A small **EVM bytecode decompiler** in pure Python — no runtime dependencies.

Give it the runtime bytecode of an Ethereum contract and it recovers a
Solidity-like view of what the contract does: functions, storage layout,
`require` guards, events, and control flow. It is built **bottom-up as a stack
of layers**, each one independently runnable so you can inspect every
intermediate step.

```
bytecode → disasm → CFG → functions → symbolic execution → pseudocode
```

## Install

```bash
git clone git@github.com:dingguijin/evm_reverse.git
cd evm_reverse
# no dependencies; Python 3.10+
python3 -m pytest tests/ -q        # (pip install pytest)
```

## Usage

Each layer is its own subcommand and takes either a hex string or a file of hex:

```bash
python3 -m evmdec disasm    <hex|file>   # bytecode -> instruction listing
python3 -m evmdec cfg       <hex|file>   # basic blocks + control-flow edges
python3 -m evmdec functions <hex|file>   # selector table + recovered signatures
python3 -m evmdec symbolic  <hex|file>   # resolved dynamic jumps
python3 -m evmdec decompile <hex|file>   # Solidity-like pseudocode
```

Example, decompiling real mainnet WETH9:

```solidity
function withdraw(uint256 arg0) public {  // selector 0x2e1a7d4d
    require((msg.value == 0));
    require((storage[keccak256(msg.sender, 3)] >= arg0));
    storage[keccak256(msg.sender, 3)] = (storage[keccak256(msg.sender, 3)] - arg0);
    success1 = msg.sender.call{value: arg0}();
    require((success1 != 0));
    emit Withdrawal(msg.sender, arg0);
    return;
}
```

## How it works

| Layer | File | What it does |
|-------|------|--------------|
| opcodes | `opcodes.py` | opcode table with stack in/out counts |
| **M1** disasm | `disassembler.py` | bytecode → instructions (skips PUSH immediates, strips metadata) |
| **M2** CFG | `cfg.py` | basic blocks + statically-resolvable edges |
| keccak | `keccak.py` | pure-Python Keccak-256 (selectors, mapping slots) |
| **M3** functions | `selectors.py`, `fourbyte.py` | dispatcher scan → selectors + signatures |
| **M4** symbolic | `symbolic.py` | path-forking stack execution; resolves dynamic jumps, recovers storage/calldata/memory |
| **M5** decompile | `ir.py`, `decompiler.py` | lift to source-level expressions, structure into functions + pseudocode |

The hard part is **M4**: the EVM is a stack machine with computed jump targets,
so a symbolic executor folds constants (which resolves the `PUSH addr; JUMP`
call/return pattern), forks at symbolic branches, and recovers high-level facts
like mapping slots `storage[keccak256(key, slot)]` and revert reasons.

`scripts/onchain_batch.py` pulls verified contracts from a block and decompiles
them in bulk — used to stress-test against real mainnet code.

## Offline test corpus

The decompiler is stress-tested against real mainnet contracts without hitting
any RPC at test time. Build a local corpus once, then replay it offline as many
times as you like:

```bash
# build: pull N verified contracts starting at a block, saving each one's
# runtime bytecode (.bin) + verified source (.sol) into corpus/
python3 scripts/onchain_batch.py <block> <N> <max_blocks>
#   e.g.  python3 scripts/onchain_batch.py 21100000 1000 60

# replay: decompile every corpus/*.bin locally — no network, ~tens of seconds
python3 scripts/run_corpus.py
```

The corpus (`corpus/`, ~60 MB for 1000 contracts) is **gitignored** — it is not
committed; rebuild it on any machine with the command above. Each contract is
stored as `corpus/<addr>.bin` + `corpus/<addr>.sol`, with `corpus/manifest.json`
listing metadata (name, function count, decompile time, source block).

## Limitations

- Loops are unrolled then truncated, not recovered as `while`/`for`.
- No SSA / common-subexpression naming, so repeated expressions are verbose.
- Shared path *suffixes* aren't merged (control-flow merging is the biggest open item).
- Function return types are unknown (4-byte signatures don't carry them).

## License

MIT
