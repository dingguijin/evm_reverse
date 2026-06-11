"""M5b - Decompiler: structure the symbolic trace tree into pseudocode.

Pipeline:
  1. symbolically execute from offset 0 -> trace tree (M4),
  2. walk the dispatcher spine of the tree:
       - a branch on `EQ(msg.sig, <const>)` starts a function body,
       - a branch with one pure-revert arm collapses into `require(...)`
         (these are the contract-level msg.value / calldatasize guards),
       - whatever remains at the end of the spine is the fallback,
  3. render each function: requires from the spine first, then the body,
     recursively turning Branches into require / if / else.

Function names and parameter types come from M3's selector recovery.
"""

from __future__ import annotations

from .ir import negate, render, render_revert, render_stmt, revert_annotation
from .selectors import find_functions
from .symbolic import (
    Branch, Call, Comment, Const, Create, Expr, Log, Revert, SStore,
    SelfDestruct, Stmt, Sym, SymExec, TStore, TraceNode, is_pure_revert,
)

INDENT = "    "


# ---------------------------------------------------------------- tree walking

def _selector_of(cond: Sym) -> int | None:
    """If cond is the dispatcher's `selector == 0x...` compare, return it."""
    if isinstance(cond, Expr) and cond.op == "EQ" and len(cond.args) == 2:
        a, b = cond.args
        for const, other in ((a, b), (b, a)):
            if isinstance(const, Const) and _mentions_calldata0(other):
                val = const.value
                # solc >=0.8.20 compares against the selector left-aligned in
                # a full word; normalise back down to the 4-byte value.
                if val > 0xFFFFFFFF and val & ((1 << 224) - 1) == 0:
                    val >>= 224
                return val
    return None


def _mentions_calldata0(sym: Sym) -> bool:
    if isinstance(sym, Expr):
        if sym.op == "CALLDATALOAD" and sym.args and sym.args[0] == Const(0):
            return True
        return any(_mentions_calldata0(a) for a in sym.args)
    return False


def _first_revert(node: TraceNode) -> Revert | None:
    for s in node.stmts:
        if isinstance(s, Revert):
            return s
    return None


Guard = tuple[Sym, "Revert | None"]
FnEntry = tuple[int, TraceNode, list[Guard]]


def _collect_dispatcher(node: TraceNode, guards: list[Guard]):
    """Recursively pull selector-dispatched function bodies out of the trace.

    Returns (functions, fallbacks):
      - functions: list of (selector, body, guards-on-the-path-to-it),
      - fallbacks: nodes reached without matching any selector.

    Handles both the modern flat dispatcher (a chain of selector compares down
    one spine) and older layouts where the selector compares are nested under a
    `calldatasize < 4` style structural branch (e.g. WETH's deposit-on-fallback).
    """
    br = node.branch
    if br is None:
        return [], [node]

    sel = _selector_of(br.cond)
    if sel is not None:
        fns, fbs = _collect_dispatcher(br.false, guards)
        return [(sel, br.true, list(guards))] + fns, fbs

    if is_pure_revert(br.false):
        return _collect_dispatcher(br.true, guards + [(br.cond, _first_revert(br.false))])
    if is_pure_revert(br.true):
        return _collect_dispatcher(br.false, guards + [(negate(br.cond), _first_revert(br.true))])

    # Structural branch (not a selector, neither arm a bare revert): the selector
    # table may live on either side, so search both and keep whatever yields
    # functions; the function-free side(s) are fallback logic.
    fns_t, fbs_t = _collect_dispatcher(br.true, guards)
    fns_f, fbs_f = _collect_dispatcher(br.false, guards)
    fns = fns_t + fns_f
    if fns:
        fbs = (fbs_t if not fns_t else []) + (fbs_f if not fns_f else [])
        return fns, fbs
    return [], [node]


# ---------------------------------------------------------------- body emission

def _require_line(cond: Sym, revert: Revert | None) -> str:
    if revert is not None and revert.kind == "error" and revert.message is not None:
        return f'require({render(cond)}, "{revert.message}");'
    suffix = revert_annotation(revert) if revert is not None else ""
    return f"require({render(cond)});{suffix}"


def _emit_node(node: TraceNode, out: list[str], depth: int) -> None:
    pad = INDENT * depth
    for stmt in node.stmts:
        out.append(pad + render_stmt(stmt))
    br = node.branch
    if br is None:
        return
    if is_pure_revert(br.false):
        out.append(pad + _require_line(br.cond, _first_revert(br.false)))
        _emit_node(br.true, out, depth)
        return
    if is_pure_revert(br.true):
        out.append(pad + _require_line(negate(br.cond), _first_revert(br.true)))
        _emit_node(br.false, out, depth)
        return
    out.append(pad + f"if ({render(br.cond)}) {{")
    _emit_node(br.true, out, depth + 1)
    if br.false.stmts or br.false.branch:
        out.append(pad + "} else {")
        _emit_node(br.false, out, depth + 1)
    out.append(pad + "}")


# ---------------------------------------------------------------- analysis

# opcodes whose presence in an expression means the function reads chain state
_STATE_READING = {"SLOAD", "TLOAD", "BALANCE", "EXTCODESIZE", "EXTCODEHASH",
                  "CALLRET", "RETURNDATA"}


class _Analysis:
    __slots__ = ("writes", "reads", "slots", "mappings")

    def __init__(self):
        self.writes = False
        self.reads = False
        self.slots: set[int] = set()
        self.mappings: set[int] = set()

    @property
    def mutability(self) -> str:
        if self.writes:
            return ""
        return " view" if self.reads else " pure"


def _analyze(node: TraceNode, acc: _Analysis | None = None) -> _Analysis:
    """Single tree walk gathering state-read/write flags + storage slots/mappings.

    Replaces the old separate `_mutability` + `_storage_slots` passes; on huge
    path-exploded trees those O(tree) walks dominated M5 runtime.
    """
    acc = acc or _Analysis()

    def scan(sym: Sym) -> None:
        if isinstance(sym, Expr):
            if sym.op in _STATE_READING:
                acc.reads = True
            if sym.op == "SLOAD" and isinstance(sym.args[0], Const):
                acc.slots.add(sym.args[0].value)
            elif sym.op == "SHA3" and len(sym.args) == 2 and isinstance(sym.args[1], Const):
                acc.mappings.add(sym.args[1].value)   # mapping slot keccak256(key . slot)
            for a in sym.args:
                scan(a)

    def visit(n: TraceNode) -> None:
        for s in n.stmts:
            if isinstance(s, (SStore, TStore, Log, SelfDestruct, Create)):
                acc.writes = True
            elif isinstance(s, Call) and s.kind != "STATICCALL":
                acc.writes = True
            if isinstance(s, SStore) and isinstance(s.slot, Const):
                acc.slots.add(s.slot.value)
            for v in s.__dict__.values():
                if isinstance(v, Sym):
                    scan(v)
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, Sym):
                            scan(x)
        if n.branch:
            scan(n.branch.cond)
            visit(n.branch.true)
            visit(n.branch.false)

    visit(node)
    return acc


# ---------------------------------------------------------------- top level

def _signature_header(selector: int, signature: str | None) -> str:
    if signature:
        name, _, params = signature.partition("(")
        params = params.rstrip(")")
        types = [t for t in params.split(",") if t]
        args = ", ".join(f"{t} arg{i}" for i, t in enumerate(types))
        return f"function {name}({args}) public"
    return f"function func_{selector:08x}() public"


def decompile(code: bytes) -> str:
    known = {f.selector: f for f in find_functions(code)}
    ex = SymExec(code)
    tree = ex.run()
    functions, fallbacks = _collect_dispatcher(tree, [])
    fallbacks = [f for f in fallbacks if f.stmts or f.branch]

    # Phase 1: analyze each body/fallback exactly once, accumulating the global
    # storage layout as we go (one walk per subtree instead of a separate
    # full-tree storage pass plus a per-function mutability pass).
    overall = _Analysis()
    fn_render: list[tuple] = []   # (selector, body, guards, mutability)
    seen: set[int] = set()
    for selector, body, guards in functions:
        if selector in seen:
            continue
        seen.add(selector)
        info = _analyze(body)
        overall.slots |= info.slots
        overall.mappings |= info.mappings
        fn_render.append((selector, body, guards, info.mutability))
    for fb in fallbacks:
        info = _analyze(fb, overall)   # folds straight into the global layout

    # Phase 2: render.
    lines: list[str] = ["// decompiled by evmdec", "contract Decompiled {"]
    summary = []
    if overall.slots:
        summary.append("slots " + ", ".join(str(s) for s in sorted(overall.slots)))
    if overall.mappings:
        summary.append("mapping(s) at slot " + ", ".join(str(s) for s in sorted(overall.mappings)))
    if summary:
        lines.append(f"{INDENT}// storage layout: " + "; ".join(summary))
        lines.append("")

    for selector, body, guards, mutability in fn_render:
        fn = known.get(selector)
        header = _signature_header(selector, fn.signature if fn else None)
        lines.append(f"{INDENT}{header}{mutability} {{  // selector 0x{selector:08x}")
        for cond, rev in guards:
            lines.append(INDENT * 2 + _require_line(cond, rev))
        _emit_node(body, lines, 2)
        lines.append(f"{INDENT}}}")
        lines.append("")

    if fallbacks:
        lines.append(f"{INDENT}fallback() external payable {{")
        for fb in fallbacks:
            _emit_node(fb, lines, 2)
        lines.append(f"{INDENT}}}")
        lines.append("")

    if ex.unresolved:
        lines.append(f"{INDENT}// WARNING: {len(ex.unresolved)} unresolved dynamic jump site(s)")

    lines.append("}")
    return "\n".join(lines)
