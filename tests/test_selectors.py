import os

from evmdec.fourbyte import resolve_signature
from evmdec.keccak import keccak256, selector
from evmdec.selectors import find_functions
from evmdec.disassembler import from_hex

FIXTURE = os.path.join(os.path.dirname(__file__), "storage.bin")


def _load():
    with open(FIXTURE) as f:
        return from_hex(f.read())


def test_keccak_known_answer():
    # The canonical empty-input Keccak-256 digest.
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )


def test_selectors_match_signatures():
    assert selector("transfer(address,uint256)") == 0xA9059CBB
    assert selector("set(uint256)") == 0x60FE47B1


def test_find_all_four_functions():
    funcs = find_functions(_load())
    table = {f.selector: f for f in funcs}
    assert set(table) == {0x60FE47B1, 0x6D4CE63C, 0x771602F7, 0x8DA5CB5B}
    assert table[0x60FE47B1].entry == 0x004E
    assert table[0x60FE47B1].signature == "set(uint256)"


def test_resolve_known_erc20_signature():
    assert resolve_signature(0xA9059CBB) == "transfer(address,uint256)"
    assert resolve_signature(0xDEADBEEF) is None
