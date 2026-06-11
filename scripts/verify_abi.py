#!/usr/bin/env python3
"""Verify recovered function selectors against the AUTHORITATIVE ABI from solc.

Naive regex scraping of verified source is unreliable (flattened multi-contract
sources, old syntax, struct params). Instead we recompile each corpus contract's
verified source with a matching solc version and take the union of every compiled
contract's function selectors as ground truth, then check what the decompiler
recovered from the bytecode against it:

    precision = |recovered ∩ abi| / |recovered|   (did we invent functions?)
    recall    = |recovered ∩ abi| / |abi_deployed| is NOT computed here because the
                union over-counts (interfaces/bases); precision is the honest metric.

Only contracts that actually compile are scored; compile failures are reported,
not hidden.

  python3 scripts/verify_abi.py [limit] [corpus_dir]
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import solcx  # noqa: E402

from evmdec.disassembler import from_hex          # noqa: E402
from evmdec.keccak import selector as keccak_sel    # noqa: E402
from evmdec.selectors import find_functions          # noqa: E402

# one representative patch release per minor; pragma picks the minor
VERSIONS = {"4": "0.4.26", "5": "0.5.17", "6": "0.6.12", "7": "0.7.6", "8": "0.8.26"}
_installed: set[str] = set()


def _ensure(v: str) -> None:
    if v not in _installed:
        solcx.install_solc(v)
        _installed.add(v)


def _pick_version(text: str) -> str:
    m = re.search(r"pragma solidity[^\d]*0\.(\d)", text)
    return VERSIONS.get(m.group(1) if m else "8", "0.8.26")


def _standard_input(text: str) -> dict:
    """Wrap a source string as a solc standard-json input (already-json passes through)."""
    if text.lstrip().startswith("{"):
        inp = json.loads(text)
    else:
        inp = {"language": "Solidity", "sources": {"main.sol": {"content": text}}}
    inp.setdefault("settings", {})["outputSelection"] = {"*": {"*": ["abi"]}}
    return inp


def _canon(inp: dict) -> str:
    """Canonical ABI type, expanding tuples to (t1,t2,...) for selector hashing."""
    t = inp["type"]
    if t.startswith("tuple"):
        inner = "(" + ",".join(_canon(c) for c in inp.get("components", [])) + ")"
        return inner + t[len("tuple"):]   # preserve any array suffix, e.g. tuple[]
    return t


def abi_selectors(text: str) -> set[int]:
    """Compile and return the union of all contracts' function selectors."""
    version = _pick_version(text)
    _ensure(version)
    out = solcx.compile_standard(_standard_input(text), solc_version=version)
    sels: set[int] = set()
    for fdict in out.get("contracts", {}).values():
        for c in fdict.values():
            for item in c.get("abi", []):
                if item.get("type") == "function":
                    args = ",".join(_canon(i) for i in item["inputs"])
                    sels.add(keccak_sel(f"{item['name']}({args})"))
    return sels


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    corpus = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    if limit:
        bins = bins[:limit]
    print(f"verifying {len(bins)} contracts against recompiled ABI\n", flush=True)

    compiled = failed = proxies = 0
    fail_kinds: dict[str, int] = {}
    tot_rec = tot_hit = 0
    perfect = 0
    imperfect = []
    for i, path in enumerate(bins, 1):
        addr = os.path.basename(path)[:-4]
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        recovered = {f.selector for f in find_functions(from_hex(open(path).read()))}
        try:
            abi = abi_selectors(open(src_path, errors="ignore").read())
        except Exception as e:  # noqa: BLE001
            failed += 1
            kind = type(e).__name__
            fail_kinds[kind] = fail_kinds.get(kind, 0) + 1
            continue
        compiled += 1
        if not recovered:
            proxies += 1
            continue
        hit = recovered & abi
        tot_rec += len(recovered)
        tot_hit += len(hit)
        if hit == recovered:
            perfect += 1
        else:
            imperfect.append((len(hit) / len(recovered),
                              [hex(x) for x in sorted(recovered - abi)][:4], addr))
        if i % 50 == 0:
            print(f"  ...{i}/{len(bins)} (compiled={compiled} failed={failed})", flush=True)

    scored = compiled - proxies
    print(f"\n{'='*66}")
    print(f"compiled OK: {compiled}/{compiled+failed}   "
          f"(compile failures: {failed})")
    if fail_kinds:
        print("  failure kinds: " + ", ".join(f"{k}×{v}" for k, v in fail_kinds.items()))
    print(f"proxies (0 fns recovered, not scored): {proxies}")
    print(f"contracts scored (have a dispatcher + compiled): {scored}")
    if tot_rec:
        print(f"\nPRECISION (recovered selectors present in authoritative ABI): "
              f"{tot_hit}/{tot_rec} = {100*tot_hit/tot_rec:.1f}%")
        print(f"contracts with 100% precision: {perfect}/{scored} = "
              f"{100*perfect/max(scored,1):.1f}%")
    if imperfect:
        print("\nlowest-precision (recovered selectors NOT in ABI — investigate):")
        for r, miss, addr in sorted(imperfect)[:10]:
            print(f"   {r*100:5.0f}%  e.g. {miss}  {addr}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
