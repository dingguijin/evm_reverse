import os
import re

from evmdec.decompiler import decompile
from evmdec.disassembler import from_hex

FIXTURE = os.path.join(os.path.dirname(__file__), "storage.bin")


def _output():
    with open(FIXTURE) as f:
        return decompile(from_hex(f.read()))


def test_all_four_functions_emitted():
    out = _output()
    assert "function set(uint256 arg0) public" in out
    assert "function get() public view" in out
    assert "function add(uint256 arg0, uint256 arg1) public pure" in out
    assert "function owner() public view" in out


def test_storage_semantics_recovered():
    out = _output()
    assert "storage[0] = arg0;" in out          # set() writes slot 0
    assert "return storage[0];" in out          # get() reads slot 0
    assert "return storage[1];" in out          # owner() reads slot 1


def test_owner_guard_becomes_require():
    out = _output()
    assert "require((msg.sender == storage[1]));" in out


def test_checked_add_recovered_with_panic():
    out = _output()
    assert "return (arg0 + arg1);" in out
    assert "Panic(0x11)" in out                 # overflow check annotated


def test_nonpayable_guard_and_fallback():
    out = _output()
    assert "require((msg.value == 0));" in out
    assert "fallback() external" in out


# --- second fixture: token.bin (mapping, loop, events, revert strings) ----

TOKEN = os.path.join(os.path.dirname(__file__), "token.bin")


def _token_output():
    with open(TOKEN) as f:
        return decompile(from_hex(f.read()))


def test_mapping_slot_recovered():
    out = _token_output()
    # balanceOf[msg.sender] lives at keccak256(key . slot0)
    assert "storage[keccak256(msg.sender, 0)]" in out
    assert "return storage[keccak256(arg0, 0)];" in out
    assert "mapping(s) at slot 0" in out


def test_revert_string_becomes_require_message():
    out = _token_output()
    assert 'require((storage[keccak256(msg.sender, 0)] >= arg1), "insufficient");' in out


def test_transfer_event_named():
    out = _token_output()
    assert "emit Transfer(msg.sender, arg0, arg1);" in out


def test_loop_recovered_as_while():
    out = _token_output()
    # sumTo()'s for-loop is widened after one concrete iteration and rendered
    # as a while over fresh loop variables — no unroll-and-truncate
    assert "while (" in out
    assert "truncated" not in out


def test_shifted_dispatcher_selector_named():
    # OZ v5 proxy (solc 0.8.20+): the dispatcher compares the selector
    # left-aligned in a full word; it must still resolve to upgradeToAndCall.
    path = os.path.join(os.path.dirname(__file__), "proxy_shifted.bin")
    with open(path) as f:
        out = decompile(from_hex(f.read()))
    assert "function upgradeToAndCall(address arg0, bytes arg1) public" in out
    assert "// selector 0x4f1ef286" in out


def test_cse_names_repeated_invariants():
    # WETH's name()/symbol() unpack the same string-length expression many
    # times; CSE must hoist it to a `vN = ...;` binding and reuse the name.
    path = os.path.join(os.path.dirname(__file__), "weth.bin")
    with open(path) as f:
        out = decompile(from_hex(f.read()))
    defs = re.findall(r"^ *(v\d+) = .+;$", out, re.M)
    assert defs, "expected at least one CSE binding"
    for name in defs:
        uses = len(re.findall(rf"\b{name}\b", out))
        assert uses >= 2, f"{name} defined but never reused ({uses} occurrence)"
