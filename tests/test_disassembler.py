from evmdec.disassembler import disassemble, from_hex, strip_metadata


def test_push_immediate_not_decoded_as_opcode():
    # PUSH1 0x80 ; PUSH1 0x40 ; MSTORE
    ins = disassemble(from_hex("6080604052"))
    assert [i.op.name for i in ins] == ["PUSH1", "PUSH1", "MSTORE"]
    assert ins[0].operand == 0x80
    assert ins[1].operand == 0x40
    # offsets account for the 1-byte immediates
    assert [i.offset for i in ins] == [0x00, 0x02, 0x04]


def test_push32_consumes_32_bytes():
    code = b"\x7f" + b"\x11" * 32 + b"\x00"  # PUSH32 <32 bytes> STOP
    ins = disassemble(code, strip_meta=False)
    assert [i.op.name for i in ins] == ["PUSH32", "STOP"]
    assert ins[0].operand == int("11" * 32, 16)
    assert ins[1].offset == 33


def test_dispatcher_prelude():
    ins = disassemble(from_hex("6080604052348015600f57600080fd5b50"))
    names = [i.op.name for i in ins]
    assert names == [
        "PUSH1", "PUSH1", "MSTORE", "CALLVALUE", "DUP1", "ISZERO",
        "PUSH1", "JUMPI", "PUSH1", "DUP1", "REVERT", "JUMPDEST", "POP",
    ]


def test_strip_metadata_removes_cbor_trailer():
    body = from_hex("6080604052")
    # a1 <...> with a 2-byte length trailer
    meta = bytes([0xA1, 0x65]) + b"solc" + bytes([0x00])
    full = body + meta + len(meta).to_bytes(2, "big")
    assert strip_metadata(full) == body


def test_truncated_push_does_not_crash():
    ins = disassemble(b"\x61\xff", strip_meta=False)  # PUSH2 but only 1 byte left
    assert ins[0].op.name == "PUSH2"
    assert ins[0].operand == 0xFF
