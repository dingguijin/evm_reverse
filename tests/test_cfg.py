import os

from evmdec.cfg import build_cfg
from evmdec.disassembler import from_hex

FIXTURE = os.path.join(os.path.dirname(__file__), "storage.bin")


def _load():
    with open(FIXTURE) as f:
        return from_hex(f.read())


def test_entry_block_splits_on_jumpi():
    cfg = build_cfg(_load())
    entry = cfg.entry
    assert entry is not None and entry.start == 0
    # nonpayable check: JUMPI to 0x000f, fall-through to the revert block 0x000c
    assert entry.succ == {0x000C, 0x000F}


def test_static_jump_edges_resolved():
    cfg = build_cfg(_load())
    # dispatcher block comparing the first selector links to its handler 0x004e
    disp = cfg.block_at(0x0019)
    assert disp is not None
    assert 0x004E in disp.succ


def test_predecessors_are_symmetric():
    cfg = build_cfg(_load())
    for start, block in cfg.blocks.items():
        for s in block.succ:
            assert start in cfg.blocks[s].pred


def test_jumpdests_collected():
    cfg = build_cfg(_load())
    assert 0x000F in cfg.jumpdests
    assert 0x004E in cfg.jumpdests
