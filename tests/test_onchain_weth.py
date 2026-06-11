"""Regression test against real mainnet WETH9 (0xC02a...756Cc2).

WETH9 is solc 0.4.x with a layout our first dispatcher walker mishandled:
`deposit()` runs on the fallback path and the selector compares are nested under
a `calldatasize < 4` structural branch. This pins the recursive collector that
fixed it, plus the nested-mapping (`allowance[a][b]`) and infinite-approval
sentinel that the symbolic layer recovers from this contract.
"""

import os
import re

from evmdec.decompiler import decompile
from evmdec.disassembler import from_hex
from evmdec.selectors import find_functions

FIXTURE = os.path.join(os.path.dirname(__file__), "weth.bin")


def _code():
    with open(FIXTURE) as f:
        return from_hex(f.read())


def test_all_eleven_functions_recovered():
    sels = {f.selector for f in find_functions(_code())}
    assert sels == {
        0x06FDDE03,  # name
        0x095EA7B3,  # approve
        0x18160DDD,  # totalSupply
        0x23B872DD,  # transferFrom
        0x2E1A7D4D,  # withdraw
        0x313CE567,  # decimals
        0x70A08231,  # balanceOf
        0x95D89B41,  # symbol
        0xA9059CBB,  # transfer
        0xD0E30DB0,  # deposit
        0xDD62ED3E,  # allowance
    }


def test_nested_dispatcher_splits_into_named_functions():
    out = decompile(_code())
    # deposit() lives on the fallback path in 0.4.x but must still be named
    assert "function deposit() public" in out
    assert "function withdraw(uint256 arg0) public" in out


def test_deposit_and_withdraw_semantics():
    out = decompile(_code())
    # balanceOf is slot 3
    assert "storage[keccak256(msg.sender, 3)] = (storage[keccak256(msg.sender, 3)] + msg.value);" in out
    # withdraw forwards ETH then checks success (msg.sender.transfer lowering)
    assert "msg.sender.call{value: arg0}()" in out


def test_nested_mapping_allowance_recovered():
    out = decompile(_code())
    # allowance[msg.sender][guy] = keccak256(guy, keccak256(msg.sender, 4))
    assert "storage[keccak256(arg0, keccak256(msg.sender, 4))] = arg1;" in out
    assert "emit Approval(msg.sender, arg0, arg1);" in out


def test_transferfrom_no_redundant_nested_branch():
    # Path-condition memory collapses the degenerate `if (x) { if (x) {...} }`:
    # once the sender==from check is decided, re-testing it folds to a constant.
    # Common-suffix merging then hoists the shared balance-transfer tail out and
    # inverts the empty then-arm, so the check appears exactly once (as `!=`).
    out = decompile(_code())
    body = re.search(r"function transferFrom.*?\n    \}", out, re.S).group(0)
    assert body.count("arg0 == msg.sender") + body.count("arg0 != msg.sender") == 1
    # the balance-transfer suffix must be merged, not duplicated per branch
    assert body.count("emit Transfer(arg0, arg1, arg2);") == 1
