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


def test_shifted_selector_compare_decoded():
    # solc >=0.8.20 optimizer keeps the constant odd and left-aligns it at
    # compare time: PUSH4 (sel>>1) PUSH1 0xe1 SHL EQ PUSH2 dest JUMPI.
    code = from_hex("63278f794360e11b1461007157")
    funcs = find_functions(code)
    assert [(f.selector, f.entry) for f in funcs] == [(0x4F1EF286, 0x71)]
    assert funcs[0].signature == "upgradeToAndCall(address,bytes)"


def test_shift_leaving_low_bits_is_not_a_selector():
    # PUSH4 0xDEADBEEF PUSH1 0x02 SHL EQ PUSH2 dest JUMPI: the shifted word is
    # not a left-aligned selector, so this is constant-building, not dispatch.
    assert find_functions(from_hex("63deadbeef60021b1461007157")) == []


def test_error_string_and_erc165_sentinels_skipped():
    # PUSH4 0x08c379a0 EQ ... JUMPI (try/catch revert-reason match) and
    # PUSH4 0xffffffff (ERC-165 sentinel) must not be reported as functions.
    assert find_functions(from_hex("6308c379a01461038257")) == []
    assert find_functions(from_hex("63ffffffff1461038257")) == []


def test_oz_v5_transparent_proxy_dispatcher():
    # Real OZ v5 proxy runtime (solc 0.8.20+): the only dispatched function is
    # upgradeToAndCall, compared via the shifted-PUSH4 form.
    with open(os.path.join(os.path.dirname(__file__), "proxy_shifted.bin")) as f:
        funcs = find_functions(from_hex(f.read()))
    assert [(f.selector, f.entry) for f in funcs] == [(0x4F1EF286, 0x71)]
