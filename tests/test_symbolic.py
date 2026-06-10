import os
import time

from evmdec.cfg import build_cfg
from evmdec.decompiler import decompile
from evmdec.disassembler import from_hex
from evmdec.symbolic import MAX_EXPR_SIZE, Const, Expr, SymExec, complete_cfg, mk

FIXTURE = os.path.join(os.path.dirname(__file__), "storage.bin")


def _load_file(name: str) -> bytes:
    with open(os.path.join(os.path.dirname(__file__), name)) as f:
        return from_hex(f.read())


def _load() -> bytes:
    return _load_file("storage.bin")


def test_constant_folding():
    assert mk("ADD", Const(2), Const(3)) == Const(5)
    assert mk("SUB", Const(2), Const(3)) == Const(2**256 - 1)  # wraps
    assert mk("SHR", Const(0xE0), Const(0x12345678 << 224)) == Const(0x12345678)
    assert mk("EXP", Const(0x100), Const(0)) == Const(1)


def test_simplifications():
    x = Expr("CALLDATALOAD", (Const(4),))
    assert mk("DIV", x, Const(1)) == x
    assert mk("EQ", x, x) == Const(1)
    assert mk("ADD", Const(0), x) == x
    # SUB(ADD(c, x), c) -> x
    assert mk("SUB", mk("ADD", Const(4), x), Const(4)) == x
    # double negation of a comparison collapses
    cmp = Expr("LT", (x, Const(32)))
    assert mk("ISZERO", mk("ISZERO", cmp)) == cmp


def test_all_dynamic_jumps_resolved_on_fixture():
    code = _load()
    ex = SymExec(code)
    ex.run()
    assert ex.unresolved == set()
    assert len(ex.resolved) > 20  # dispatcher + internal call/return sites


def test_complete_cfg_clears_unresolved_flags():
    code = _load()
    before = sum(1 for b in build_cfg(code).blocks.values() if b.has_unresolved_jump)
    cfg, resolved = complete_cfg(code)
    after = sum(1 for b in cfg.blocks.values() if b.has_unresolved_jump)
    assert before > 0
    assert after == 0
    # the internal call into the calldata-decode helper was dynamic
    assert 0x01B0 in {t for ts in resolved.values() for t in ts}


def test_mk_collapses_runaway_dag():
    # Doubling builds an exponentially-large expansion; mk() must collapse it so
    # size (and therefore hash/eq/render cost) stays bounded.
    x = Expr("CALLDATALOAD", (Const(0),))
    collapsed = False
    for _ in range(80):
        x = mk("ADD", x, x)
        collapsed = collapsed or x.op == "HUGE"
    # without bounding, 80 doublings would be 2**80 nodes; it must stay bounded
    assert x.size <= MAX_EXPR_SIZE
    assert collapsed  # the runaway DAG was collapsed at least once


def test_pathological_contract_decompiles_fast():
    # Regression: this real EIP-712 contract (mainnet 0x14778860...) took 357s
    # before expression-size bounding; must now finish in a couple of seconds.
    code = _load_file("eip712_slow.bin")
    t = time.time()
    out = decompile(code)
    dt = time.time() - t
    assert dt < 20, f"decompile took {dt:.0f}s, expected ~2s (exponential blowup regressed?)"
    assert "/* complex expr */" in out


def test_node_budget_truncates_cleanly():
    # A tiny node budget forces the path explosion guard; it must set the
    # truncated flag and return rather than blowing up (regression: real
    # Chainlink OCR2 bytecode otherwise ran ~14s before the wall-clock guard).
    code = _load()
    ex = SymExec(code, max_nodes=5)   # fixture explores ~21 nodes, so this trips
    ex.run()
    assert ex.truncated is True


def test_normal_contract_not_truncated():
    code = _load()
    ex = SymExec(code)
    ex.run()
    assert ex.truncated is False


def test_internal_call_return_pattern():
    # PUSH the return address, call helper, helper jumps back: both resolve.
    #   0x00: PUSH1 0x08 ; PUSH1 0x06 ; JUMP   (call helper at 6, return to 8)
    #   0x05: STOP                              (unreachable padding)
    #   0x06: JUMPDEST   ; JUMP                 (return via stack value)
    #   0x08: JUMPDEST   ; STOP
    code = bytes.fromhex("600860065600" "5b56" "5b00")
    ex = SymExec(code)
    ex.run()
    assert ex.unresolved == set()
    assert ex.resolved[0x04] == {0x06}   # call site jumps to helper
    assert ex.resolved[0x07] == {0x08}   # helper returns to pushed address
