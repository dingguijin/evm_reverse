#!/usr/bin/env python3
"""Check decompiled function BODIES against the recompiled ABI and source.

Full pseudocode equivalence can't be machine-checked (the output isn't
compilable), but three semantic facets of the bodies have authoritative
ground truth:

  mutability — the ABI carries stateMutability per function; the decompiler
               independently infers view/pure from the effect trace
  events     — every topic0 constant the decompiled code emits must be the
               keccak256 of an event declared in the recompiled ABI
  reverts    — every revert string in the pseudocode must appear verbatim in
               the verified source

  python3 scripts/verify_semantics.py [limit] [corpus_dir]
"""

from __future__ import annotations

import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evmdec.decompiler import decompile            # noqa: E402
from evmdec.disassembler import from_hex            # noqa: E402
from evmdec.keccak import keccak256, selector as keccak_sel   # noqa: E402

from verify_abi import _canon, compile_abi_items, is_vyper    # noqa: E402

_FN_HEADER = re.compile(
    r"function \w*\([^)]*\) public( view| pure)?(?: returns \([^)]*\))?"
    r" \{  // selector 0x([0-9a-f]{8})")
_RAW_EMIT = re.compile(r"emit log\((0x[0-9a-f]+)[,)]")
_NAMED_EMIT = re.compile(r"emit (?!log\b)(\w+)\(")
_REVERT_STR = re.compile(r'(?:require\([^\n]*?, |revert\()"([^"\\]+)"\)')


def abi_facts(text: str):
    """(selector -> stateMutability set, event topic0 set, event name set)."""
    muts: dict[int, set[str]] = {}
    topics: set[int] = set()
    names: set[str] = set()
    for item in compile_abi_items(text):
        if item.get("type") == "function":
            args = ",".join(_canon(i) for i in item["inputs"])
            sel = keccak_sel(f"{item['name']}({args})")
            muts.setdefault(sel, set()).add(item.get("stateMutability", ""))
        elif item.get("type") == "event":
            args = ",".join(_canon(i) for i in item["inputs"])
            topics.add(int.from_bytes(
                keccak256(f"{item['name']}({args})".encode()), "big"))
            names.add(item["name"])
    return muts, topics, names


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    corpus = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    if limit:
        bins = bins[:limit]
    print(f"checking decompiled semantics for {len(bins)} contracts\n", flush=True)

    checked = skipped = 0
    # mutability confusion: (abi readonly?, rendered readonly?) -> count
    mut = {(a, r): 0 for a in (True, False) for r in (True, False)}
    ev_hit = ev_total = 0
    nv_hit = nv_total = 0
    rv_hit = rv_total = 0
    bad_mut: list[str] = []
    bad_ev: list[str] = []
    bad_rv: list[str] = []
    for i, path in enumerate(bins, 1):
        addr = os.path.basename(path)[:-4]
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        src = open(src_path, errors="ignore").read()
        if is_vyper(src):
            skipped += 1
            continue
        try:
            muts, topics, names = abi_facts(src)
        except Exception:  # noqa: BLE001
            skipped += 1
            continue
        out = decompile(from_hex(open(path).read()))
        checked += 1

        for m in _FN_HEADER.finditer(out):
            sel = int(m.group(2), 16)
            if sel not in muts:
                continue
            abi_ro = bool(muts[sel] & {"view", "pure"})
            ours_ro = m.group(1) is not None
            mut[(abi_ro, ours_ro)] += 1
            if abi_ro != ours_ro and len(bad_mut) < 8:
                bad_mut.append(f"{addr} sel 0x{sel:08x} abi={sorted(muts[sel])} "
                               f"rendered={'view/pure' if ours_ro else 'mutating'}")

        for m in _RAW_EMIT.finditer(out):
            ev_total += 1
            if int(m.group(1), 16) in topics:
                ev_hit += 1
            elif len(bad_ev) < 8:
                bad_ev.append(f"{addr} topic {m.group(1)[:20]}...")
        for m in _NAMED_EMIT.finditer(out):
            nv_total += 1
            if m.group(1) in names:
                nv_hit += 1
            elif len(bad_ev) < 8:
                bad_ev.append(f"{addr} named event {m.group(1)}")

        for m in _REVERT_STR.finditer(out):
            rv_total += 1
            if m.group(1) in src:
                rv_hit += 1
            elif len(bad_rv) < 8:
                bad_rv.append(f"{addr} {m.group(1)[:50]!r}")

        if i % 50 == 0:
            print(f"  ...{i}/{len(bins)} (checked={checked})", flush=True)

    print(f"\n{'='*66}")
    print(f"contracts checked: {checked}  (skipped: {skipped} vyper/no-compile)")
    tot = sum(mut.values())
    agree = mut[(True, True)] + mut[(False, False)]
    print(f"\nMUTABILITY (per function, vs ABI stateMutability): "
          f"{agree}/{tot} = {100*agree/max(tot,1):.1f}% agree")
    print(f"  abi read-only & rendered view/pure : {mut[(True, True)]}")
    print(f"  abi mutating  & rendered mutating  : {mut[(False, False)]}")
    print(f"  abi read-only but rendered mutating: {mut[(True, False)]}  (missed inference)")
    print(f"  abi mutating but rendered view/pure: {mut[(False, True)]}  (MISSED WRITE — bug)")
    print(f"\nEVENTS: raw topic0s in ABI: {ev_hit}/{ev_total} "
          f"= {100*ev_hit/max(ev_total,1):.1f}%   "
          f"named events in ABI: {nv_hit}/{nv_total} "
          f"= {100*nv_hit/max(nv_total,1):.1f}%")
    print(f"\nREVERT STRINGS found verbatim in source: {rv_hit}/{rv_total} "
          f"= {100*rv_hit/max(rv_total,1):.1f}%")
    for label, rows in (("mutability mismatches", bad_mut),
                        ("unmatched events", bad_ev),
                        ("unmatched revert strings", bad_rv)):
        if rows:
            print(f"\nfirst {label}:")
            for r in rows:
                print(f"   {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
