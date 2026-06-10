"""M5a - Lifting: render symbolic expressions / statements as readable IR text.

This is where stack-machine noise becomes source-level vocabulary:
  CALLER                          -> msg.sender
  SLOAD(Const(0))                 -> storage[0]
  CALLDATALOAD(Const(4 + 32*i))   -> arg{i}
  SHR(0xe0, CALLDATALOAD(0))      -> msg.sig
  ISZERO(LT(a, b))                -> (a >= b)        (negation-aware)
  AND(x, 2**160-1)                -> x               (address-mask dropped)
"""

from __future__ import annotations

from .fourbyte import resolve_event
from .symbolic import (
    Call, Comment, Const, Create, Expr, Log, Return, Revert, SStore,
    SelfDestruct, Stop, Stmt, Sym, TStore,
)

ADDRESS_MASK = (1 << 160) - 1

_ENV = {
    "CALLER": "msg.sender",
    "CALLVALUE": "msg.value",
    "CALLDATASIZE": "msg.data.length",
    "ORIGIN": "tx.origin",
    "GASPRICE": "tx.gasprice",
    "ADDRESS": "address(this)",
    "SELFBALANCE": "address(this).balance",
    "TIMESTAMP": "block.timestamp",
    "NUMBER": "block.number",
    "COINBASE": "block.coinbase",
    "PREVRANDAO": "block.prevrandao",
    "GASLIMIT": "block.gaslimit",
    "CHAINID": "block.chainid",
    "BASEFEE": "block.basefee",
    "BLOBBASEFEE": "block.blobbasefee",
    "GAS": "gasleft()",
    "MSIZE": "msize()",
    "CODESIZE": "address(this).code.length",
    "RETURNDATASIZE": "returndata.length",
}

_INFIX = {
    "ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "SDIV": "/",
    "MOD": "%", "SMOD": "%", "AND": "&", "OR": "|", "XOR": "^",
    "LT": "<", "GT": ">", "SLT": "<", "SGT": ">", "EQ": "==",
}

# how to render ISZERO(<comparison>) without a leading "!"
_NEGATED = {"EQ": "!=", "LT": ">=", "GT": "<=", "SLT": ">=", "SGT": "<="}

PANIC_DESCRIPTIONS = {
    0x01: "assertion failed",
    0x11: "arithmetic overflow/underflow",
    0x12: "division by zero",
    0x21: "invalid enum value",
    0x22: "storage byte array malformed",
    0x31: "pop on empty array",
    0x32: "array index out of bounds",
    0x41: "out of memory",
    0x51: "uninitialized function pointer",
}


def _is_msg_sig(sym: Sym) -> bool:
    return (
        isinstance(sym, Expr)
        and sym.op == "SHR"
        and len(sym.args) == 2
        and sym.args[0] == Const(0xE0)
        and isinstance(sym.args[1], Expr)
        and sym.args[1].op == "CALLDATALOAD"
        and sym.args[1].args[0] == Const(0)
    )


def render(sym: Sym) -> str:
    if isinstance(sym, Const):
        v = sym.value
        return str(v) if v < 4096 else f"0x{v:x}"

    assert isinstance(sym, Expr)
    op, args = sym.op, sym.args

    if op in _ENV:
        return _ENV[op]

    if _is_msg_sig(sym):
        return "msg.sig"

    if op == "CALLDATALOAD":
        off = args[0]
        if isinstance(off, Const):
            if off.value >= 4 and (off.value - 4) % 32 == 0:
                return f"arg{(off.value - 4) // 32}"
            return f"calldata[{render(off)}]"
        return f"calldata[{render(off)}]"

    if op == "SLOAD":
        return f"storage[{render(args[0])}]"
    if op == "TLOAD":
        return f"transient[{render(args[0])}]"
    if op == "MLOAD":
        return f"memory[{render(args[0])}]"
    if op == "SHA3":
        return f"keccak256({', '.join(render(a) for a in args)})"
    if op == "SHA3RAW":
        return f"keccak256(memory[{render(args[0])} : +{render(args[1])}])"
    if op == "BALANCE":
        return f"{render(args[0])}.balance"
    if op == "EXTCODESIZE":
        return f"{render(args[0])}.code.length"
    if op == "EXTCODEHASH":
        return f"{render(args[0])}.codehash"
    if op == "BLOCKHASH":
        return f"blockhash({render(args[0])})"
    if op == "BLOBHASH":
        return f"blobhash({render(args[0])})"

    if op == "AND":
        # solc masks addresses after loads; the mask is pure noise to a reader
        a, b = args
        if a == Const(ADDRESS_MASK):
            return render(b)
        if b == Const(ADDRESS_MASK):
            return render(a)

    if op in _INFIX:
        a, b = args
        return f"({render(a)} {_INFIX[op]} {render(b)})"

    if op in ("SHL", "SHR", "SAR"):
        shift, value = args  # pop order: shift first
        sign = "<<" if op == "SHL" else ">>"
        return f"({render(value)} {sign} {render(shift)})"

    if op == "ISZERO":
        inner = args[0]
        if isinstance(inner, Expr):
            if inner.op in _NEGATED:
                a, b = inner.args
                return f"({render(a)} {_NEGATED[inner.op]} {render(b)})"
            if inner.op == "ISZERO":
                return f"({render(inner.args[0])} != 0)"
        return f"({render(inner)} == 0)"

    if op == "NOT":
        return f"~{render(args[0])}"
    if op == "STACK_IN":
        return f"stack_in{args[0].value}"
    if op == "CALLRET":
        return f"success{args[0].value}"
    if op == "RETURNDATA":
        return f"returndata{args[0].value}"
    if op == "NEWADDR":
        return f"new_contract{args[0].value}"

    return f"{op.lower()}({', '.join(render(a) for a in args)})"


def negate(cond: Sym) -> Sym:
    """Logical negation; the renderer's ISZERO rules keep the output tidy."""
    if isinstance(cond, Expr) and cond.op == "ISZERO":
        inner = cond.args[0]
        if isinstance(inner, Expr) and (inner.op in _NEGATED or inner.op == "ISZERO"):
            return inner
    return Expr("ISZERO", (cond,))


# ---------------------------------------------------------------- statements

def render_revert(stmt: Revert) -> str:
    if stmt.kind == "panic":
        code = stmt.panic_code
        if code is not None:
            desc = PANIC_DESCRIPTIONS.get(code, "panic")
            return f"revert Panic(0x{code:02x});  // {desc}"
        return "revert Panic(?);"
    if stmt.kind == "error":
        if stmt.message is not None:
            return f'revert("{stmt.message}");'
        return "revert(Error(...));"
    if stmt.kind == "invalid":
        return "revert();  // INVALID opcode"
    if stmt.kind == "plain":
        return "revert();"
    if stmt.values:
        return f"revert({', '.join(render(v) for v in stmt.values)});"
    return "revert();"


def revert_annotation(stmt: Revert) -> str:
    """Short suffix explaining a require's failure mode, '' if unremarkable."""
    if stmt.kind == "panic" and stmt.panic_code is not None:
        desc = PANIC_DESCRIPTIONS.get(stmt.panic_code, "panic")
        return f"  // Panic(0x{stmt.panic_code:02x}): {desc}"
    if stmt.kind == "error" and stmt.message is not None:
        return ""  # message goes into require(cond, "msg") itself
    return ""


def render_stmt(stmt: Stmt) -> str:
    if isinstance(stmt, SStore):
        return f"storage[{render(stmt.slot)}] = {render(stmt.value)};"
    if isinstance(stmt, TStore):
        return f"transient[{render(stmt.slot)}] = {render(stmt.value)};"
    if isinstance(stmt, Return):
        if stmt.values is None:
            return f"return memory[{render(stmt.offset)} : +{render(stmt.size)}];"
        if not stmt.values:
            return "return;"
        if len(stmt.values) == 1:
            return f"return {render(stmt.values[0])};"
        return f"return ({', '.join(render(v) for v in stmt.values)});"
    if isinstance(stmt, Stop):
        return "return;"
    if isinstance(stmt, Revert):
        return render_revert(stmt)
    if isinstance(stmt, Log):
        if stmt.topics and isinstance(stmt.topics[0], Const):
            sig = resolve_event(stmt.topics[0].value)
            if sig:
                name = sig.partition("(")[0]
                parts = [render(t) for t in stmt.topics[1:]]
                parts += [render(d) for d in stmt.data] if stmt.data else []
                return f"emit {name}({', '.join(parts)});"
        topics = ", ".join(render(t) for t in stmt.topics)
        data = ", ".join(render(d) for d in stmt.data) if stmt.data else ""
        inner = ", ".join(x for x in (topics, data) if x)
        return f"emit log({inner});"
    if isinstance(stmt, Call):
        target = render(stmt.to)
        args = ", ".join(render(a) for a in stmt.args) if stmt.args else ""
        if stmt.kind == "CALL":
            value = f"{{value: {render(stmt.value)}}}" if stmt.value != Const(0) else ""
            return f"success{stmt.result_id} = {target}.call{value}({args});"
        return f"success{stmt.result_id} = {target}.{stmt.kind.lower()}({args});"
    if isinstance(stmt, Create):
        args = ", ".join(render(a) for a in stmt.args) if stmt.args else "..."
        kind = "create2" if stmt.kind == "CREATE2" else "create"
        return f"new_contract{stmt.result_id} = {kind}({args});  // value: {render(stmt.value)}"
    if isinstance(stmt, SelfDestruct):
        return f"selfdestruct({render(stmt.to)});"
    if isinstance(stmt, Comment):
        return f"// {stmt.text}"
    return f"// <{type(stmt).__name__}>"


def reads_state(sym: Sym) -> bool:
    if isinstance(sym, Expr):
        if sym.op in ("SLOAD", "TLOAD", "BALANCE", "EXTCODESIZE", "EXTCODEHASH", "CALLRET", "RETURNDATA"):
            return True
        return any(reads_state(a) for a in sym.args)
    return False
