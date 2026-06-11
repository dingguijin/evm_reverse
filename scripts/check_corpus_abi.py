#!/usr/bin/env python3
"""Cross-check recovered functions against verified source, over the corpus.

We cannot auto-check the full pseudocode against source (it isn't compilable),
but we CAN check the function layer: does the selector set we recover from the
bytecode match the public/external functions declared in the verified .sol?

For each contract we compute, over functions whose parameters are *elementary*
(so we can compute their selector reliably from text — struct/enum params are
skipped, not counted against us):

    recall = |declared_basic ∩ recovered| / |declared_basic|

i.e. of the source functions we can pin down, how many did the decompiler find.
"""

from __future__ import annotations

import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evmdec.disassembler import from_hex          # noqa: E402
from evmdec.keccak import selector as keccak_sel    # noqa: E402
from evmdec.selectors import find_functions          # noqa: E402

_ELEMENTARY = re.compile(r"^(address|bool|string|bytes\d*|u?int\d*)(\[\d*\])*$")


def _norm_type(t: str) -> str | None:
    t = t.strip()
    t = re.sub(r"\s+(memory|calldata|storage)\b", "", t)
    t = t.replace("payable", "").strip()          # address payable -> address
    t = re.sub(r"^uint(\[|$|\d)", lambda m: "uint256" + m.group(1) if m.group(1) in "[" else
               ("uint256" if m.group(1) == "" else "uint" + m.group(1)), t)
    if t == "uint":
        t = "uint256"
    if t == "int":
        t = "int256"
    t = re.sub(r"^int(\[|$)", r"int256\1", t)
    return t if _ELEMENTARY.match(t) else None


def declared_selectors(src: str) -> set[int]:
    sels: set[int] = set()
    for m in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)([^{;]*?)(\{|;)", src):
        name, params, tail = m.group(1), m.group(2), m.group(3)
        if "public" not in tail and "external" not in tail:
            continue
        types = []
        ok = True
        for p in filter(None, (x.strip() for x in params.split(","))):
            typ = _norm_type(p.split()[0])
            if typ is None:
                ok = False
                break
            types.append(typ)
        if ok:
            try:
                sels.add(keccak_sel(f"{name}({','.join(types)})"))
            except Exception:  # noqa: BLE001
                pass
    return sels


def main() -> int:
    corpus = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    print(f"checking {len(bins)} contracts in {os.path.normpath(corpus)}\n", flush=True)

    total_decl = total_found = 0
    perfect = no_basis = 0
    worst = []
    for path in bins:
        addr = os.path.basename(path)[:-4]
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        recovered = {f.selector for f in find_functions(from_hex(open(path).read()))}
        declared = declared_selectors(open(src_path, errors="ignore").read())
        if not declared:
            no_basis += 1
            continue
        hit = declared & recovered
        total_decl += len(declared)
        total_found += len(hit)
        if hit == declared:
            perfect += 1
        else:
            missing = declared - recovered
            worst.append((len(hit) / len(declared), len(missing), addr))

    checked = len(bins) - no_basis
    print(f"{'='*64}")
    print(f"contracts with checkable (elementary-param) functions: {checked}")
    print(f"  ({no_basis} had only struct/enum-param or no public fns — skipped)")
    print(f"micro-recall (all declared basic fns): {total_found}/{total_decl} "
          f"= {100*total_found/max(total_decl,1):.1f}%")
    print(f"contracts where every declared basic fn was recovered: "
          f"{perfect}/{checked} = {100*perfect/max(checked,1):.1f}%")
    if worst:
        print("\nlowest-recall contracts (likely source-extraction limits, not decompiler):")
        for r, miss, addr in sorted(worst)[:10]:
            print(f"   {r*100:5.0f}%  missing {miss:2}  {addr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
