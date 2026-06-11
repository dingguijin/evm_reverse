"""M4 - Symbolic stack execution.

Executes bytecode over an abstract machine whose stack holds *symbolic
expressions* instead of concrete words. Two products:

  1. resolved dynamic jump targets, completing the M2 CFG (`complete_cfg`),
  2. a *trace tree* of effect statements (SSTORE / RETURN / CALL / ...) with a
     branch condition at every forked JUMPI - the input to the M5 decompiler.

Design notes:
  - Values are `Const` (concrete) or `Expr(op, args)`. The smart constructor
    `mk()` constant-folds, so jump-target arithmetic collapses to constants and
    the `PUSH <ret-addr> ... JUMP` internal call/return pattern resolves itself.
  - Execution forks at JUMPI when the condition is symbolic; a constant
    condition follows only the decided side. Loops are cut after a path
    revisits the same JUMPDEST `max_block_visits` times.
  - Memory is a word-granular dict {offset_sym: value_sym} - precise enough to
    recover ABI-encoded return values and revert reasons, which is essentially
    all solc uses memory for.
  - Expression args are stored in *pop order*: args[0] is what was on top of
    the stack. Renderers must respect each opcode's operand semantics.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .cfg import CFG, build_cfg
from .disassembler import disassemble

U256 = 1 << 256
MASK = U256 - 1
_ERROR_SELECTOR = 0x08C379A0   # Error(string)
_PANIC_SELECTOR = 0x4E487B71   # Panic(uint256)


# ---------------------------------------------------------------- values

class Sym:
    """Base class for symbolic values."""

    size = 1   # number of expression nodes; overridden on Expr


# Cap on expression node count. Symbolic execution can build exponentially
# large expression DAGs (e.g. repeated DUP+arithmetic in EIP-712 hashing or ABI
# offset math); since Sym is a frozen dataclass its hash/eq recurse without
# memoizing, so a single `mk()` on a huge DAG could take *minutes*. Collapsing
# anything past this bound keeps every later hash/eq/render O(MAX_EXPR_SIZE).
MAX_EXPR_SIZE = 1500


@dataclass(frozen=True)
class Const(Sym):
    value: int


@dataclass(frozen=True)
class Expr(Sym):
    op: str
    args: tuple = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "size", 1 + sum(getattr(a, "size", 1) for a in self.args))


def _signed(x: int) -> int:
    return x - U256 if x >= (U256 >> 1) else x


def _sdiv(a: int, b: int) -> int:
    if b == 0:
        return 0
    sa, sb = _signed(a), _signed(b)
    q = abs(sa) // abs(sb)
    return (-q if (sa < 0) != (sb < 0) else q) & MASK


def _smod(a: int, b: int) -> int:
    if b == 0:
        return 0
    sa, sb = _signed(a), _signed(b)
    r = abs(sa) % abs(sb)
    return (-r if sa < 0 else r) & MASK


def _byte(i: int, x: int) -> int:
    return (x >> (8 * (31 - i))) & 0xFF if i < 32 else 0


def _signextend(b: int, x: int) -> int:
    if b >= 31:
        return x
    bit = 8 * (b + 1) - 1
    if x & (1 << bit):
        return (x | (MASK << bit)) & MASK
    return x & ((1 << (bit + 1)) - 1)


def _sar(shift: int, value: int) -> int:
    s = _signed(value)
    if shift >= 256:
        return MASK if s < 0 else 0
    return (s >> shift) & MASK


# args appear in pop order: lambda(a=top-of-stack, b=next, ...)
_FOLD = {
    "ADD": lambda a, b: (a + b) & MASK,
    "MUL": lambda a, b: (a * b) & MASK,
    "SUB": lambda a, b: (a - b) & MASK,
    "DIV": lambda a, b: a // b if b else 0,
    "SDIV": _sdiv,
    "MOD": lambda a, b: a % b if b else 0,
    "SMOD": _smod,
    "ADDMOD": lambda a, b, n: (a + b) % n if n else 0,
    "MULMOD": lambda a, b, n: (a * b) % n if n else 0,
    "EXP": lambda a, b: pow(a, b, U256),
    "SIGNEXTEND": _signextend,
    "LT": lambda a, b: int(a < b),
    "GT": lambda a, b: int(a > b),
    "SLT": lambda a, b: int(_signed(a) < _signed(b)),
    "SGT": lambda a, b: int(_signed(a) > _signed(b)),
    "EQ": lambda a, b: int(a == b),
    "ISZERO": lambda a: int(a == 0),
    "AND": lambda a, b: a & b,
    "OR": lambda a, b: a | b,
    "XOR": lambda a, b: a ^ b,
    "NOT": lambda a: (~a) & MASK,
    "BYTE": _byte,
    "SHL": lambda shift, v: (v << shift) & MASK if shift < 256 else 0,
    "SHR": lambda shift, v: v >> shift if shift < 256 else 0,
    "SAR": _sar,
}

_COMPARISONS = {"LT", "GT", "SLT", "SGT", "EQ", "ISZERO"}


def mk(op: str, *args: Sym) -> Sym:
    """Build an expression, constant-folding and simplifying where safe."""
    if op in _FOLD and all(isinstance(a, Const) for a in args):
        return Const(_FOLD[op](*[a.value for a in args]) & MASK)

    a = args[0] if args else None
    b = args[1] if len(args) > 1 else None

    if op == "ISZERO" and isinstance(a, Expr) and a.op == "ISZERO":
        inner = a.args[0]
        # ISZERO(ISZERO(cmp)) == cmp for boolean-valued comparisons
        if isinstance(inner, Expr) and inner.op in _COMPARISONS:
            return inner
    if op == "EQ" and a == b:
        return Const(1)
    if op == "ADD":
        if a == Const(0):
            return b
        if b == Const(0):
            return a
    if op == "SUB":
        if b == Const(0):
            return a
        # SUB(ADD(c, x), c) -> x  (solc's offset arithmetic round-trips a lot)
        if isinstance(a, Expr) and a.op == "ADD":
            if a.args[0] == b:
                return a.args[1]
            if a.args[1] == b:
                return a.args[0]
    if op == "DIV" and b == Const(1):
        return a
    if op == "MUL":
        if a == Const(1):
            return b
        if b == Const(1):
            return a
    if op in ("AND", "OR") and a == b:
        return a
    if op == "AND":
        # Address-cleaning masks over values that are already address-typed are
        # identity; dropping them lets solc's `arg == and(arg, mask)` calldata
        # validity checks fold away entirely.
        mask = Const((1 << 160) - 1)
        for m, val in ((a, b), (b, a)):
            if m == mask and isinstance(val, Expr) and val.op in (
                "CALLER", "ORIGIN", "ADDRESS", "COINBASE", "CALLDATALOAD"
            ):
                return val

    result = Expr(op, tuple(args))
    if result.size > MAX_EXPR_SIZE:
        # Runaway DAG: collapse to an opaque, bounded node so every later
        # hash/eq/render stays cheap. The size is kept for diagnostics.
        return Expr("HUGE", (Const(result.size),))
    return result


def contains(sym: Sym, op: str) -> bool:
    """True if `sym` or any sub-expression has opcode `op`."""
    if isinstance(sym, Expr):
        if sym.op == op:
            return True
        return any(contains(a, op) for a in sym.args)
    return False


# ---------------------------------------------------------------- statements

@dataclass
class Stmt:
    pass


@dataclass
class SStore(Stmt):
    slot: Sym
    value: Sym


@dataclass
class TStore(Stmt):
    slot: Sym
    value: Sym


@dataclass
class Return(Stmt):
    values: list[Sym] | None     # decoded memory words, or None if unknown
    offset: Sym | None = None
    size: Sym | None = None


@dataclass
class Stop(Stmt):
    pass


@dataclass
class Revert(Stmt):
    kind: str = "raw"            # plain | panic | error | invalid | raw
    panic_code: int | None = None
    message: str | None = None
    values: list[Sym] | None = None
    offset: Sym | None = None
    size: Sym | None = None


@dataclass
class Log(Stmt):
    topics: list[Sym]
    data: list[Sym] | None


@dataclass
class Call(Stmt):
    kind: str                    # CALL | CALLCODE | DELEGATECALL | STATICCALL
    result_id: int
    gas: Sym
    to: Sym
    value: Sym | None
    args: list[Sym] | None       # decoded input memory words


@dataclass
class Create(Stmt):
    kind: str                    # CREATE | CREATE2
    result_id: int
    value: Sym
    args: list[Sym] | None


@dataclass
class SelfDestruct(Stmt):
    to: Sym


@dataclass
class Comment(Stmt):
    text: str


@dataclass
class LoopBack(Stmt):
    """Back-edge of a recovered loop: jump to `header` after a widened pass.

    Emitted instead of unrolling further once the loop body has executed once
    with widened (fresh symbolic) induction state; the renderer turns the
    enclosing branch into a `while`.
    """
    header: int


# ---------------------------------------------------------------- trace tree

@dataclass
class Branch:
    cond: Sym                    # condition under which `true` is taken
    true: "TraceNode"
    false: "TraceNode"


@dataclass
class TraceNode:
    stmts: list[Stmt] = field(default_factory=list)
    branch: Branch | None = None


def is_pure_revert(node: TraceNode) -> bool:
    """A node that does nothing but revert (the `require` failure arm)."""
    if node.branch is not None:
        return False
    has_revert = any(isinstance(s, Revert) for s in node.stmts)
    only_revert = all(isinstance(s, (Revert, Comment)) for s in node.stmts)
    return has_revert and only_revert


# ---------------------------------------------------------------- executor

class SymExec:
    def __init__(self, code: bytes, *, max_nodes: int = 8000,
                 max_block_visits: int = 8, max_seconds: float = 5.0):
        self.instrs = disassemble(code)
        self.by_offset = {ins.offset: idx for idx, ins in enumerate(self.instrs)}
        self.jumpdests = {ins.offset for ins in self.instrs if ins.op.name == "JUMPDEST"}
        self.max_nodes = max_nodes
        self.max_block_visits = max_block_visits
        self.max_seconds = max_seconds
        self.resolved: dict[int, set[int]] = {}   # jump instr offset -> taken targets
        self.unresolved: set[int] = set()         # jump sites we could not resolve
        self.truncated = False                    # hit a node/time budget
        self.nodes = 0
        self._deadline = 0.0
        self._fresh = 0
        self._ctr = 0

    # -- public API -------------------------------------------------------

    def run(self, start: int = 0, stack: list[Sym] | None = None) -> TraceNode:
        self._deadline = time.monotonic() + self.max_seconds
        return self._explore(start, list(stack or []), {}, {}, {})

    # -- loop / revisit accounting ------------------------------------------

    def _enter_block(self, visits: dict, dest: int,
                     stack: list[Sym], memory: dict) -> str | None:
        """Account for entering block `dest`; possibly widen or end a loop.

        Revisits are counted per (dest, call-site fingerprint) — the nearest
        return-address constants on the stack — so an internal helper entered
        from many call sites along one path (e.g. per-argument calldata
        decoders) is not mistaken for a loop: each call site pushes a
        different return address.

        Genuine loops (same fingerprint) are *widened*, not unrolled: on the
        second entry every stack slot / memory word that changed since the
        first entry becomes a fresh loop variable, the body runs once more on
        that generalized state, and the third entry returns "loopback" so the
        renderer can close a `while`. Irregular revisits (stack shape changed)
        fall back to counting and return "cut" at max_block_visits; a loose
        per-dest total bounds pathological fingerprint churn.
        """
        ctx: tuple[int, ...] = ()
        for s in reversed(stack[-8:]):
            if isinstance(s, Const) and s.value in self.jumpdests:
                ctx += (s.value,)
                if len(ctx) == 2:
                    break
        key = (dest, ctx)
        n = visits[key] = visits.get(key, 0) + 1
        visits[dest] = visits.get(dest, 0) + 1
        if visits[dest] > self.max_block_visits * 8:
            return "cut"
        if n == 1:
            visits[("snap", key)] = (list(stack), dict(memory))
            return None
        if n == 2:
            snap_stack, snap_mem = visits.get(("snap", key), (None, None))
            diffs = []
            if snap_stack is not None and len(snap_stack) == len(stack):
                for i, (old, new) in enumerate(zip(snap_stack, stack)):
                    if old == new:
                        continue
                    if any(isinstance(v, Const) and v.value in self.jumpdests
                           for v in (old, new)):
                        # a return address changed: different call sites the
                        # fingerprint missed, not a loop — don't widen
                        diffs = None
                        break
                    diffs.append(i)
            if diffs is not None and snap_stack is not None \
                    and len(snap_stack) == len(stack):
                for i in diffs:              # induction values: generalize
                    self._fresh += 1
                    stack[i] = Expr("LOOPVAR", (Const(self._fresh),))
                for k in list(memory):
                    if snap_mem.get(k) != memory[k]:
                        del memory[k]        # changed per iteration: forget
                visits[("widened", key)] = True
            return None                      # irregular shape: keep unrolling
        if visits.get(("widened", key)):
            return "loopback"
        return "cut" if n > self.max_block_visits else None

    # -- path-condition memory --------------------------------------------

    def _known(self, cond: Sym, asm: dict) -> int | None:
        """Value of `cond` implied by branch decisions already made on this path."""
        if cond in asm:
            return asm[cond]
        if isinstance(cond, Expr) and cond.op == "ISZERO":
            v = asm.get(cond.args[0])
            if v in (0, 1):
                return 1 - v
        return None

    def _fork_assumptions(self, cond: Sym, asm: dict) -> tuple[dict, dict]:
        """Assumptions to carry into the taken (true) and not-taken (false) arms."""
        t, f = dict(asm), dict(asm)
        t[cond] = 1
        f[cond] = 0
        # `ISZERO(x)` true means x is exactly 0 (x false means only "x != 0").
        if isinstance(cond, Expr) and cond.op == "ISZERO":
            t[cond.args[0]] = 0
        return t, f

    # -- helpers ----------------------------------------------------------

    def _pop(self, stack: list[Sym]) -> Sym:
        if stack:
            return stack.pop()
        self._fresh += 1
        return Expr("STACK_IN", (Const(self._fresh),))

    def _need(self, stack: list[Sym], n: int) -> None:
        while len(stack) < n:
            self._fresh += 1
            stack.insert(0, Expr("STACK_IN", (Const(self._fresh),)))

    def _read_words(self, memory: dict, off: Sym, size: Sym) -> list[Sym] | None:
        if not (isinstance(off, Const) and isinstance(size, Const)):
            return None
        if size.value == 0:
            return []
        if size.value > 0x600:
            return None
        words = []
        for i in range((size.value + 31) // 32):
            key = Const(off.value + 32 * i)
            words.append(memory.get(key, Expr("MLOAD", (key,))))
        return words

    def _make_revert(self, memory: dict, off: Sym, size: Sym) -> Revert:
        words = self._read_words(memory, off, size)
        if isinstance(size, Const) and size.value == 0:
            return Revert(kind="plain", offset=off, size=size)
        if isinstance(off, Const):
            w0 = memory.get(Const(off.value))
            if isinstance(w0, Const):
                sel = w0.value >> 224
                if sel == _PANIC_SELECTOR:
                    code = memory.get(Const(off.value + 4))
                    return Revert(
                        kind="panic",
                        panic_code=code.value if isinstance(code, Const) else None,
                        values=words, offset=off, size=size,
                    )
                if sel == _ERROR_SELECTOR:
                    msg = None
                    ln = memory.get(Const(off.value + 0x24))
                    data = memory.get(Const(off.value + 0x44))
                    if isinstance(ln, Const) and isinstance(data, Const) and ln.value <= 32:
                        try:
                            msg = data.value.to_bytes(32, "big")[: ln.value].decode()
                        except (UnicodeDecodeError, OverflowError):
                            msg = None
                    return Revert(kind="error", message=msg, values=words, offset=off, size=size)
        return Revert(kind="raw", values=words, offset=off, size=size)

    # -- core path exploration --------------------------------------------

    def _explore(self, offset: int, stack: list[Sym], memory: dict, visits: dict,
                 assumptions: dict) -> TraceNode:
        node = TraceNode()
        self.nodes += 1
        # Node budget guards against pathological path explosion; the wall-clock
        # budget (checked only periodically, it's not free) bounds latency on
        # huge real contracts like Chainlink OCR2 that otherwise run ~14s.
        if self.nodes > self.max_nodes or (
            self.nodes % 64 == 0 and time.monotonic() > self._deadline
        ):
            self.truncated = True
            node.stmts.append(Comment("path/time budget exceeded; trace truncated"))
            return node
        idx = self.by_offset.get(offset)
        if idx is None:
            node.stmts.append(Comment(f"jump into unmapped offset 0x{offset:x}"))
            return node

        while True:
            ins = self.instrs[idx]
            op = ins.op
            name = op.name

            # ---- control flow -------------------------------------------
            if name == "JUMP":
                dest = self._pop(stack)
                if isinstance(dest, Const) and dest.value in self.jumpdests:
                    self.resolved.setdefault(ins.offset, set()).add(dest.value)
                    act = self._enter_block(visits, dest.value, stack, memory)
                    if act == "cut":
                        node.stmts.append(Comment(f"loop back to 0x{dest.value:x} truncated"))
                        return node
                    if act == "loopback":
                        node.stmts.append(LoopBack(dest.value))
                        return node
                    idx = self.by_offset[dest.value]
                    continue
                self.unresolved.add(ins.offset)
                node.stmts.append(Comment("unresolved dynamic jump"))
                return node

            if name == "JUMPI":
                dest = self._pop(stack)
                cond = self._pop(stack)
                # Resolve the condition if it is constant or already decided on
                # this path; only a genuinely unknown condition forks.
                cval = cond.value if isinstance(cond, Const) else self._known(cond, assumptions)
                if cval is not None:
                    if cval == 0:
                        idx += 1
                        continue
                    if isinstance(dest, Const) and dest.value in self.jumpdests:
                        self.resolved.setdefault(ins.offset, set()).add(dest.value)
                        act = self._enter_block(visits, dest.value, stack, memory)
                        if act == "cut":
                            node.stmts.append(Comment(f"loop back to 0x{dest.value:x} truncated"))
                            return node
                        if act == "loopback":
                            node.stmts.append(LoopBack(dest.value))
                            return node
                        idx = self.by_offset[dest.value]
                        continue
                    self.unresolved.add(ins.offset)
                    node.stmts.append(Comment("unresolved dynamic jump (taken JUMPI)"))
                    return node
                if isinstance(dest, Const) and dest.value in self.jumpdests:
                    self.resolved.setdefault(ins.offset, set()).add(dest.value)
                    t_visits = dict(visits)
                    t_stack, t_mem = list(stack), dict(memory)
                    t_asm, f_asm = self._fork_assumptions(cond, assumptions)
                    act = self._enter_block(t_visits, dest.value, t_stack, t_mem)
                    if act == "cut":
                        true_node = TraceNode([Comment(f"loop back to 0x{dest.value:x} truncated")])
                    elif act == "loopback":
                        true_node = TraceNode([LoopBack(dest.value)])
                    else:
                        true_node = self._explore(dest.value, t_stack, t_mem, t_visits, t_asm)
                    false_node = self._explore(ins.next_offset, list(stack), dict(memory), dict(visits), f_asm)
                    node.branch = Branch(cond, true_node, false_node)
                    return node
                self.unresolved.add(ins.offset)
                node.stmts.append(Comment("unresolved conditional jump"))
                return node

            # ---- terminators ---------------------------------------------
            if name == "STOP":
                node.stmts.append(Stop())
                return node
            if name == "RETURN":
                off, size = self._pop(stack), self._pop(stack)
                node.stmts.append(Return(self._read_words(memory, off, size), off, size))
                return node
            if name == "REVERT":
                off, size = self._pop(stack), self._pop(stack)
                node.stmts.append(self._make_revert(memory, off, size))
                return node
            if name == "INVALID" or name.startswith("UNKNOWN_"):
                node.stmts.append(Revert(kind="invalid"))
                return node
            if name == "SELFDESTRUCT":
                node.stmts.append(SelfDestruct(self._pop(stack)))
                return node

            # ---- everything else ----------------------------------------
            self._step(ins, stack, memory, node)
            idx += 1
            if idx >= len(self.instrs):
                node.stmts.append(Stop())
                return node

    def _step(self, ins, stack: list[Sym], memory: dict, node: TraceNode) -> None:
        """Execute one non-control-flow instruction against the abstract state."""
        op = ins.op
        name = op.name

        if op.is_push or name == "PUSH0":
            stack.append(Const(ins.operand or 0))
        elif op.is_dup:
            n = int(name[3:])
            self._need(stack, n)
            stack.append(stack[-n])
        elif op.is_swap:
            n = int(name[4:])
            self._need(stack, n + 1)
            stack[-1], stack[-n - 1] = stack[-n - 1], stack[-1]
        elif name == "POP":
            self._pop(stack)
        elif name == "JUMPDEST":
            pass
        elif name == "PC":
            stack.append(Const(ins.offset))
        elif name == "MSTORE":
            off, val = self._pop(stack), self._pop(stack)
            memory[off] = val
        elif name == "MSTORE8":
            off, val = self._pop(stack), self._pop(stack)
            memory[off] = mk("AND", val, Const(0xFF))
        elif name == "MLOAD":
            off = self._pop(stack)
            stack.append(memory.get(off, Expr("MLOAD", (off,))))
        elif name == "SSTORE":
            slot, val = self._pop(stack), self._pop(stack)
            node.stmts.append(SStore(slot, val))
        elif name == "TSTORE":
            slot, val = self._pop(stack), self._pop(stack)
            node.stmts.append(TStore(slot, val))
        elif name == "KECCAK256":
            off, size = self._pop(stack), self._pop(stack)
            words = self._read_words(memory, off, size)
            if words is not None:
                stack.append(Expr("SHA3", tuple(words)))
            else:
                stack.append(Expr("SHA3RAW", (off, size)))
        elif name.startswith("LOG"):
            n = int(name[3:])
            off, size = self._pop(stack), self._pop(stack)
            topics = [self._pop(stack) for _ in range(n)]
            node.stmts.append(Log(topics, self._read_words(memory, off, size)))
        elif name in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            gas, to = self._pop(stack), self._pop(stack)
            value = self._pop(stack) if name in ("CALL", "CALLCODE") else None
            in_off, in_size = self._pop(stack), self._pop(stack)
            out_off, out_size = self._pop(stack), self._pop(stack)
            self._ctr += 1
            node.stmts.append(
                Call(name, self._ctr, gas, to, value, self._read_words(memory, in_off, in_size))
            )
            if isinstance(out_off, Const) and isinstance(out_size, Const) and out_size.value:
                for i in range(0, min(out_size.value, 0x200), 32):
                    memory[Const(out_off.value + i)] = \
                        Expr("RETURNDATA", (Const(self._ctr), Const(i)))
            stack.append(Expr("CALLRET", (Const(self._ctr),)))
        elif name in ("CREATE", "CREATE2"):
            value, off, size = self._pop(stack), self._pop(stack), self._pop(stack)
            if name == "CREATE2":
                self._pop(stack)  # salt
            self._ctr += 1
            node.stmts.append(Create(name, self._ctr, value, self._read_words(memory, off, size)))
            stack.append(Expr("NEWADDR", (Const(self._ctr),)))
        elif name == "CALLDATACOPY":
            dst, src, length = self._pop(stack), self._pop(stack), self._pop(stack)
            if isinstance(dst, Const) and isinstance(src, Const) and isinstance(length, Const) \
                    and length.value <= 0x200:
                for i in range(0, length.value, 32):
                    memory[Const(dst.value + i)] = Expr("CALLDATALOAD", (Const(src.value + i),))
        elif name == "RETURNDATACOPY":
            dst, src, length = self._pop(stack), self._pop(stack), self._pop(stack)
            if isinstance(dst, Const) and isinstance(src, Const) \
                    and isinstance(length, Const) and length.value <= 0x200:
                for i in range(0, length.value, 32):
                    memory[Const(dst.value + i)] = \
                        Expr("RETURNDATA", (Const(self._ctr), Const(src.value + i)))
            else:
                # unknown destination: drop tracked words rather than let later
                # loads read stale data (false equalities prune live branches);
                # keep the free-memory pointer, solc reads it everywhere
                fmp = memory.get(Const(0x40))
                memory.clear()
                if fmp is not None:
                    memory[Const(0x40)] = fmp
        elif name in ("CODECOPY", "EXTCODECOPY", "MCOPY"):
            for _ in range(op.ins):
                self._pop(stack)
        else:
            # generic pure op: pop ins, push mk(...) if it produces a value
            args = [self._pop(stack) for _ in range(op.ins)]
            if op.outs:
                stack.append(mk(name, *args))


# ---------------------------------------------------------------- CFG completion

def complete_cfg(code: bytes) -> tuple[CFG, dict[int, set[int]]]:
    """Run symbolic execution and merge resolved dynamic jumps into the CFG."""
    cfg = build_cfg(code)
    ex = SymExec(code)
    ex.run()
    last_to_block = {blk.last.offset: start for start, blk in cfg.blocks.items()}
    for jump_offset, targets in ex.resolved.items():
        start = last_to_block.get(jump_offset)
        if start is None:
            continue
        for t in targets:
            cfg._link(start, t)
        if jump_offset not in ex.unresolved:
            cfg.blocks[start].has_unresolved_jump = False
    return cfg, ex.resolved
