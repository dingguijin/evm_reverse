"""Lifting/rendering unit tests, incl. regressions found on real mainnet code."""

from evmdec.ir import negate, render
from evmdec.symbolic import Const, Expr


def test_negate_iszero_of_comparison_no_crash():
    # regression: negate() did `_NEGATED | {"ISZERO"}` (dict | set) and raised
    # TypeError on real contracts (e.g. UniswapV2Router02) that reach this path.
    cmp = Expr("LT", (Const(1), Const(2)))
    assert negate(Expr("ISZERO", (cmp,))) == cmp


def test_negate_double_iszero():
    inner = Expr("ISZERO", (Expr("EQ", (Const(1), Const(2))),))
    assert negate(Expr("ISZERO", (inner,))) == inner


def test_negate_plain_condition_wraps():
    c = Expr("CALLER", ())
    assert negate(c) == Expr("ISZERO", (c,))


def test_render_environment_and_storage():
    assert render(Expr("CALLER", ())) == "msg.sender"
    assert render(Expr("SLOAD", (Const(0),))) == "storage[0]"
    assert render(Expr("CALLDATALOAD", (Const(4),))) == "arg0"
    assert render(Expr("CALLDATALOAD", (Const(36),))) == "arg1"


def test_render_address_mask_dropped():
    masked = Expr("AND", (Expr("CALLER", ()), Const((1 << 160) - 1)))
    assert render(masked) == "msg.sender"


def test_render_negated_comparison():
    # ISZERO(LT(a,b)) renders as (a >= b), not !(a < b)
    e = Expr("ISZERO", (Expr("LT", (Const(1), Const(2))),))
    assert render(e) == "(1 >= 2)"
