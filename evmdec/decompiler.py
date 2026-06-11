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

from .ir import (
    negate, render, render_def, render_revert, render_stmt, revert_annotation,
    set_cse_names,
)
from .selectors import find_functions
from .symbolic import (
    Branch, Call, Comment, Const, Create, Expr, Log, LoopBack, Return, Revert,
    SStore, SelfDestruct, Stmt, Stop, Sym, SymExec, TStore, TraceNode,
    is_pure_revert,
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


def _is_loop_body(node: TraceNode) -> bool:
    """True if every leaf of this subtree loops back (or bails via revert)."""
    found = [False]

    def walk(n: TraceNode) -> bool:
        if n.branch is not None:
            return walk(n.branch.true) and walk(n.branch.false)
        if any(isinstance(s, LoopBack) for s in n.stmts):
            found[0] = True
            return True
        return is_pure_revert(n)

    return walk(node) and found[0]


def _emit_node(node: TraceNode, out: list[str], depth: int) -> None:
    pad = INDENT * depth
    for stmt in node.stmts:
        out.append(pad + render_stmt(stmt))
    br = node.branch
    if br is None:
        return
    # recovered loop: the arm whose every path jumps back is the body,
    # the other arm is the code after the loop
    t_loops, f_loops = _is_loop_body(br.true), _is_loop_body(br.false)
    if t_loops and not f_loops:
        out.append(pad + f"while ({render(br.cond)}) {{")
        _emit_node(br.true, out, depth + 1)
        out.append(pad + "}")
        _emit_node(br.false, out, depth)
        return
    if f_loops and not t_loops:
        out.append(pad + f"while ({render(negate(br.cond))}) {{")
        _emit_node(br.false, out, depth + 1)
        out.append(pad + "}")
        _emit_node(br.true, out, depth)
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
    __slots__ = ("writes", "reads", "truncated", "cut", "success",
                 "slots", "mappings")

    def __init__(self):
        self.writes = False
        self.reads = False
        self.truncated = False   # global budget cut: code genuinely unseen
        self.cut = False         # any loop/path cut inside this subtree
        self.success = False     # some path completed (Stop/Return)
        self.slots: set[int] = set()
        self.mappings: set[int] = set()

    @property
    def mutability(self) -> str:
        # A truncated trace can't prove the unexplored paths don't write.
        # Loop cuts are tolerated only if some sibling path completed —
        # otherwise the happy path (and its writes) was never explored,
        # e.g. arg-decoding helpers re-entered past max_block_visits.
        if self.writes or self.truncated or (self.cut and not self.success):
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
            elif isinstance(s, (Stop, Return)):
                acc.success = True
            elif isinstance(s, Comment) and "truncated" in s.text:
                if "budget exceeded" in s.text:
                    acc.truncated = True
                else:
                    acc.cut = True
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


# ---------------------------------------------------------------- return types

ADDRESS_MASK = (1 << 160) - 1
_BOOL_OPS = {"LT", "GT", "SLT", "SGT", "EQ", "ISZERO"}


def _scalar_type(sym: Sym, slot_types: dict | None = None) -> str:
    """Best-effort solidity type of a single returned word."""
    if isinstance(sym, Const):
        # an immutable/literal address: 160-bit value with nonzero high bytes.
        # plain uint amounts almost never land in (2^96, 2^160).
        if 96 < sym.value.bit_length() <= 160:
            return "address"
        return "uint256"
    if isinstance(sym, Expr):
        if slot_types:
            # a value read straight from a typed storage slot keeps that type
            # (addresses/narrow-uints/bools lose their mask on read, but the
            # slot was written masked — so the write site tells us the type)
            if sym.op == "SLOAD":
                k = sym.args[0]
                if isinstance(k, Const) and k.value in slot_types:
                    return slot_types[k.value]
                base = _mapping_base(k)
                if base is not None and ("m", base) in slot_types:
                    return slot_types[("m", base)]
        if sym.op == "AND" and len(sym.args) == 2:
            for mask, other in ((sym.args[0], sym.args[1]), (sym.args[1], sym.args[0])):
                if isinstance(mask, Const):
                    if mask.value == ADDRESS_MASK:
                        return "address"
                    if mask.value == 1:
                        return "bool"
                    # 0xff, 0xffff, ... -> uintN (skip the full-width all-ones)
                    n = mask.value.bit_length()
                    if mask.value == (1 << n) - 1 and n % 8 == 0 and n < 256:
                        # the inner value's own type wins if it's narrower still
                        inner = _scalar_type(other, slot_types)
                        return inner if inner.startswith(("uint", "address", "bool")) \
                            and inner != "uint256" else f"uint{n}"
        if sym.op in _BOOL_OPS:
            return "bool"
    return "uint256"


def _slot_key(load: Sym):
    """Storage key (const slot or ('m', base)) addressed by an SLOAD, else None."""
    if isinstance(load, Expr) and load.op == "SLOAD":
        k = load.args[0]
        if isinstance(k, Const):
            return k.value
        base = _mapping_base(k)
        if base is not None:
            return ("m", base)
    return None


_ADDRESSY = {"CALLER", "ORIGIN", "ADDRESS", "COINBASE"}


def _collect_slot_types(bodies) -> dict:
    """Map const slot / ('m', base) -> solidity type, learned contract-wide.

    Evidence (any of, must be consistent):
      - a masked value written to the slot (`storage[k] = addr & MASK`);
      - a masked *read* of the slot (`addr & MASK`, `x & 0xff`);
      - the slot compared to an address env value (`msg.sender == storage[k]`,
        the onlyOwner pattern);
      - the slot used as an external-call target.
    A slot with conflicting specific evidence is left untyped (uint256)."""
    seen: dict = {}
    conflict: set = set()

    def note(key, t: str) -> None:
        if key is None or t == "uint256" or key in conflict:
            return
        if key in seen and seen[key] != t:
            conflict.add(key)
            seen.pop(key, None)
        else:
            seen[key] = t

    def scan(sym: Sym) -> None:
        if not isinstance(sym, Expr):
            return
        if sym.op == "AND" and len(sym.args) == 2:
            a, b = sym.args
            for mask, other in ((a, b), (b, a)):
                if isinstance(mask, Const):
                    t = _scalar_type(sym)            # reuse mask->type logic
                    if t != "uint256":
                        note(_slot_key(other), t)
        elif sym.op == "EQ" and len(sym.args) == 2:
            a, b = sym.args
            for x, y in ((a, b), (b, a)):
                if isinstance(x, Expr) and x.op in _ADDRESSY:
                    note(_slot_key(y), "address")
        for a in sym.args:
            scan(a)

    def visit(n: TraceNode) -> None:
        for s in n.stmts:
            if isinstance(s, SStore):
                t = _scalar_type(s.value)
                if isinstance(s.slot, Const):
                    note(s.slot.value, t)
                elif (base := _mapping_base(s.slot)) is not None:
                    note(("m", base), t)
            if isinstance(s, Call):
                note(_slot_key(s.to), "address")
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

    for b in bodies:
        visit(b)
    return seen


def _return_columns(r, slot_types: dict) -> list[str] | None:
    """Per-word inferred types for one Return, or None if it's a dynamic
    (offset+length) ABI encoding whose shape we can't split."""
    if r.values is not None:
        return [_scalar_type(v, slot_types) for v in r.values]
    # raw memory range: a constant whole-word size is a scalar/struct we just
    # couldn't reconstruct symbolically (-> uint256 words); a symbolic or
    # ragged size is a genuine dynamic value.
    if isinstance(r.size, Const) and r.size.value % 32 == 0:
        return ["uint256"] * (r.size.value // 32)
    return None


def _infer_return_type(node: TraceNode, slot_types: dict) -> str:
    """Inferred `returns (...)` clause (without the keyword), or "" for void."""
    rets: list = []

    def visit(n: TraceNode) -> None:
        for s in n.stmts:
            if isinstance(s, Return):
                rets.append(s)
        if n.branch:
            visit(n.branch.true)
            visit(n.branch.false)

    visit(node)
    if not rets:
        return ""
    col_lists = [_return_columns(r, slot_types) for r in rets]
    if any(c is None for c in col_lists):           # a truly dynamic return
        return "bytes"
    arity = max((len(c) for c in col_lists), default=0)
    if arity == 0:
        return ""                                   # explicit `return;` only
    cols: list[set[str]] = [set() for _ in range(arity)]
    all_const_bit = True
    for r, c in zip(rets, col_lists):
        if r.values is None or len(r.values) != 1:
            all_const_bit = False
        for i, t in enumerate(c):
            cols[i].add(t)
        if r.values is not None:
            for v in r.values:
                if not (isinstance(v, Const) and v.value in (0, 1)):
                    all_const_bit = False

    def merge(types: set[str]) -> str:
        types.discard("uint256")
        if len(types) == 1:
            return types.pop()
        return "uint256"                            # disagreement / all-default

    parts = [merge(c) for c in cols]
    if arity == 1 and parts[0] == "uint256" and all_const_bit:
        parts[0] = "bool"                            # `return true/false;`
    return ", ".join(parts)                          # caller wraps in returns(...)


# ---------------------------------------------------------------- CSE naming

# Reading these means a value can change across an external call, so it is not
# invariant once the function makes any call.
_CALL_VOLATILE = {"BALANCE", "SELFBALANCE", "EXTCODESIZE", "EXTCODEHASH",
                  "EXTCODEHASH", "RETURNDATA", "CALLRET"}
# Naming these adds nothing (already short / unique) or is unsafe to hoist.
_CSE_SKIP_OPS = {"CALLDATALOAD", "LOOPVAR", "STACK_IN", "HUGE", "SHA3", "SHA3RAW"}


def _mapping_base(slot: Sym) -> int | None:
    """Base storage slot of a mapping access keccak256(key, base), else None."""
    if (isinstance(slot, Expr) and slot.op == "SHA3" and len(slot.args) == 2
            and isinstance(slot.args[1], Const)):
        return slot.args[1].value
    return None


def _written_state(node: TraceNode):
    """(written const slots, written mapping bases, unknown_write, has_call)."""
    slots: set[int] = set()
    maps: set[int] = set()
    flags = {"unknown": False, "call": False}

    def visit(n: TraceNode) -> None:
        for s in n.stmts:
            if isinstance(s, SStore):
                if isinstance(s.slot, Const):
                    slots.add(s.slot.value)
                elif (base := _mapping_base(s.slot)) is not None:
                    maps.add(base)
                else:
                    flags["unknown"] = True
            elif isinstance(s, (TStore, Call, Create, SelfDestruct)):
                flags["call"] = True
        if n.branch:
            visit(n.branch.true)
            visit(n.branch.false)

    visit(node)
    return slots, maps, flags["unknown"], flags["call"]


def _invariant(sym: Sym, wslots: set[int], wmaps: set[int],
               unknown: bool, has_call: bool) -> bool:
    """True if `sym` evaluates to the same value throughout the function: it
    reads no state that the function (might) write, and nothing call-volatile
    once a call has happened."""
    ok = True

    def walk(s: Sym) -> None:
        nonlocal ok
        if not ok or not isinstance(s, Expr):
            return
        op = s.op
        if op in ("SLOAD", "TLOAD"):
            if op == "TLOAD" or unknown:
                ok = False
            elif isinstance(s.args[0], Const):
                if s.args[0].value in wslots:
                    ok = False
            else:
                base = _mapping_base(s.args[0])
                if base is None or base in wmaps:
                    ok = False
        elif op in _CALL_VOLATILE and has_call:
            ok = False
        for a in s.args:
            walk(a)

    walk(sym)
    return ok


def _size(sym: Sym) -> int:
    return 1 + sum(_size(a) for a in sym.args) if isinstance(sym, Expr) else 1


def _contains(outer: Sym, inner: Sym) -> bool:
    return isinstance(outer, Expr) and any(
        a == inner or _contains(a, inner) for a in outer.args)


# Bound on subexpression visits per function. Beyond this the function is huge
# (path-exploded / pathological) — skip CSE: recursive Sym hashing makes the
# counting pass O(size^2), and verbose pseudocode there is not the win anyway.
_CSE_BUDGET = 15000


def _cse_bindings(node: TraceNode, guards):
    """Pick invariant sub-expressions used 2+ times and worth naming; return
    (ordered [(name, def_text)], names map for ir.render)."""
    counts: dict[Sym, int] = {}
    budget = [_CSE_BUDGET]

    def count(sym: Sym) -> None:
        if budget[0] <= 0 or not isinstance(sym, Expr):
            return
        budget[0] -= 1
        counts[sym] = counts.get(sym, 0) + 1
        for a in sym.args:
            count(a)

    def visit(n: TraceNode) -> None:
        for s in n.stmts:
            for v in s.__dict__.values():
                if isinstance(v, Sym):
                    count(v)
                elif isinstance(v, list):
                    for x in v:
                        if isinstance(x, Sym):
                            count(x)
        if n.branch and budget[0] > 0:
            count(n.branch.cond)
            visit(n.branch.true)
            visit(n.branch.false)

    for cond, _ in guards:
        count(cond)
    visit(node)
    if budget[0] <= 0:                          # too big: don't name anything
        set_cse_names({})
        return [], {}

    wslots, wmaps, unknown, has_call = _written_state(node)
    cand = []
    for sym, c in counts.items():
        if c < 2 or sym.op in _CSE_SKIP_OPS or _size(sym) < 3:
            continue
        if not _invariant(sym, wslots, wmaps, unknown, has_call):
            continue
        if len(render_def(sym)) < 16:        # too cheap to bother naming
            continue
        cand.append(sym)

    # Bound the O(n^2) containment pass: keep the most-repeated candidates.
    cand.sort(key=lambda s: counts[s], reverse=True)
    cand = cand[:200]

    # Drop a candidate fully absorbed by a larger one (same occurrence count and
    # always nested inside it): naming it would just add a redundant line.
    kept = []
    for sym in cand:
        parent_max = max((counts[o] for o in cand
                          if o is not sym and _contains(o, sym)), default=0)
        if counts[sym] > parent_max:
            kept.append(sym)

    kept.sort(key=_size)                      # define smaller (inner) names first
    names = {sym: f"v{i}" for i, sym in enumerate(kept)}
    set_cse_names(names)                       # so render_def substitutes nested names
    bindings = [(names[sym], render_def(sym)) for sym in kept]
    return bindings, names


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

    # storage-slot types, learned contract-wide, sharpen return-type inference
    slot_types = _collect_slot_types([b for _, b, _, _ in fn_render] + fallbacks)

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
        ret = _infer_return_type(body, slot_types)
        ret_clause = f" returns ({ret})" if ret else ""
        lines.append(f"{INDENT}{header}{mutability}{ret_clause} {{  "
                     f"// selector 0x{selector:08x}")
        bindings, _ = _cse_bindings(body, guards)
        for name, defn in bindings:
            lines.append(INDENT * 2 + f"{name} = {defn};")
        for cond, rev in guards:
            lines.append(INDENT * 2 + _require_line(cond, rev))
        _emit_node(body, lines, 2)
        set_cse_names({})
        lines.append(f"{INDENT}}}")
        lines.append("")

    if fallbacks:
        lines.append(f"{INDENT}fallback() external payable {{")
        for fb in fallbacks:
            set_cse_names({})
            _emit_node(fb, lines, 2)
        lines.append(f"{INDENT}}}")
        lines.append("")

    if ex.unresolved:
        lines.append(f"{INDENT}// WARNING: {len(ex.unresolved)} unresolved dynamic jump site(s)")

    lines.append("}")
    return "\n".join(lines)
