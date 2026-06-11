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

# one representative patch release per minor, tried first (already cached);
# exact pins fall back to installing the precise version on demand.
VERSIONS = {"4": "0.4.26", "5": "0.5.17", "6": "0.6.12", "7": "0.7.6", "8": "0.8.26"}
_installed: set[str] = set()

_VER_TOKEN = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)")


def _ensure(v: str) -> None:
    if v not in _installed:
        solcx.install_solc(v)
        _installed.add(v)


def _pragma_constraints(text: str) -> list[str]:
    """Every `pragma solidity ...;` constraint in the (possibly flattened) text."""
    # JSON-wrapped sources escape the range operators (>= for >=)
    text = text.replace("\\u003e", ">").replace("\\u003c", "<")
    return [m.group(1).strip()
            for m in re.finditer(r"pragma\s+solidity\s+([^;]+);", text)]


def _satisfies(ver: str, constraint: str) -> bool:
    v = tuple(int(x) for x in ver.split("."))
    for alt in constraint.split("||"):           # || alternatives: any side may match
        toks = _VER_TOKEN.findall(alt)
        if not toks:
            continue
        ok = True
        for op, a, b, c in toks:
            t = (int(a), int(b), int(c))
            if op in ("", "="):
                ok = v == t
            elif op == ">=":
                ok = v >= t
            elif op == ">":
                ok = v > t
            elif op == "<=":
                ok = v <= t
            elif op == "<":
                ok = v < t
            else:                                # ^ / ~: same minor, >= patch (0.x semver)
                ok = t <= v < (t[0], t[1] + 1, 0)
            if not ok:
                break
        if ok:
            return True
    return False


def _version_literals(text: str) -> list[str]:
    """All version numbers mentioned in pragmas, highest first."""
    lits = {f"{a}.{b}.{c}"
            for con in _pragma_constraints(text)
            for _, a, b, c in _VER_TOKEN.findall(con)}
    return sorted(lits, key=lambda s: tuple(int(x) for x in s.split(".")),
                  reverse=True)


def _pick_version(text: str) -> str:
    """Pick a solc version satisfying every pragma in the source.

    Cached per-minor representatives are preferred; otherwise the highest
    version literal that satisfies all constraints (typically the project's
    own exact pin, with library carets ranging over it) is installed.
    """
    cons = _pragma_constraints(text)
    if not cons:
        return "0.4.26"   # pragma-less source predates the pragma convention
    for cand in list(VERSIONS.values()) + _version_literals(text):
        if all(_satisfies(cand, c) for c in cons):
            return cand
    lits = _version_literals(text)               # contradictory flatten: best effort
    return lits[0] if lits else "0.8.26"


def _standard_input(text: str) -> dict:
    """Wrap a source string as a solc standard-json input (already-json passes through)."""
    if text.lstrip().startswith("{"):
        inp = json.loads(text)
        if "sources" not in inp:
            # Etherscan "bare sources map": {"File.sol": {"content": ...}, ...}
            inp = {"language": "Solidity", "sources": inp}
    else:
        inp = {"language": "Solidity", "sources": {"main.sol": {"content": text}}}
    inp.setdefault("settings", {})["outputSelection"] = {"*": {"*": ["abi"]}}
    return inp


def _strip_key(tree, key: str) -> None:
    """Recursively delete `key` anywhere in a dict tree (unknown-settings retry)."""
    if isinstance(tree, dict):
        tree.pop(key, None)
        for v in tree.values():
            _strip_key(v, key)


def is_vyper(text: str) -> bool:
    if re.search(r"^\s*#\s*(pragma\s+version|@version)", text, re.MULTILINE):
        return True
    # old Vyper carries no version marker: a leading '#' comment is impossible
    # in Solidity, as are top-level `Name: event(...)` declarations
    head = text.lstrip()
    return head.startswith("#") or bool(
        re.search(r"^\w+\s*:\s*event\(", head, re.MULTILINE))


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
    try:
        _ensure(version)
    except Exception:        # picked a non-existent release: start from cached
        version = "0.8.26"
    inp = _standard_input(text)
    # version fallbacks for dialect errors: every version named in a pragma,
    # oldest first (early-0.8 code often needs the patch it was written for),
    # then each era's representative — the ABI doesn't depend on which
    # compiler accepts the source.
    fallbacks = _version_literals(text)[::-1] + list(VERSIONS.values())
    for _ in range(16):
        try:
            out = solcx.compile_standard(inp, solc_version=version)
            break
        except solcx.exceptions.SolcError as e:
            msg = str(e)
            m = re.search(r'Unknown key "(\w+)"', msg)
            if m:                                # setting unsupported by this solc
                _strip_key(inp.get("settings", {}), m.group(1))
                continue
            if "Invalid EVM version" in msg:
                inp.get("settings", {}).pop("evmVersion", None)
                continue
            if "Multiple SPDX license identifiers" in msg:
                for s in inp["sources"].values():
                    s["content"] = re.sub(r"//\s*SPDX-License-Identifier:[^\n]*",
                                          "", s["content"])
                continue
            while fallbacks:
                cand = fallbacks.pop(0)
                if (cand != version
                        and tuple(int(x) for x in cand.split(".")) >= (0, 4, 11)):
                    try:
                        _ensure(cand)   # range bounds (e.g. <0.9.0) may not exist
                    except Exception:   # noqa: BLE001
                        continue
                    version = cand
                    break
            else:
                raise
    else:
        raise RuntimeError("solc retry budget exhausted")
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

    compiled = failed = proxies = vyper = 0
    fail_kinds: dict[str, int] = {}
    tot_rec = tot_hit = 0
    perfect = 0
    imperfect = []
    for i, path in enumerate(bins, 1):
        addr = os.path.basename(path)[:-4]
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        text = open(src_path, errors="ignore").read()
        if is_vyper(text):
            vyper += 1            # solc can't ground-truth these; skip, don't fail
            continue
        recovered = {f.selector for f in find_functions(from_hex(open(path).read()))}
        try:
            abi = abi_selectors(text)
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
          f"(compile failures: {failed}, Vyper skipped: {vyper})")
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
