#!/usr/bin/env python3
"""Check inferred function return types against the recompiled ABI's outputs.

4byte signatures don't carry return types, so the decompiler infers them from
how each function builds its return value (address/bool masks, narrow-uint
masks, dynamic memory ranges). solc's ABI is the authoritative answer. We
compare at *class* granularity, because some distinctions are not recoverable
from bytecode:

  - string and bytes are encoded identically -> both class "bytes";
  - sign is not recoverable -> intN and uintN compare by width only ("i<N>");
  - address / bool are exact.

Only functions whose ABI outputs are all elementary scalars are scored;
array/tuple/bytesN returns (which the decompiler renders as raw bytes/uint)
are reported separately, not counted against precision.

  python3 scripts/verify_returns.py [limit] [corpus_dir]
"""

from __future__ import annotations

import glob
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evmdec.decompiler import decompile             # noqa: E402
from evmdec.disassembler import from_hex             # noqa: E402
from evmdec.keccak import selector as keccak_sel      # noqa: E402

from verify_abi import _canon, compile_abi_items, is_vyper   # noqa: E402

_HEADER = re.compile(
    r"function \w*\([^)]*\) public(?: view| pure)?"
    r"(?: returns \(([^)]*)\))? \{  // selector 0x([0-9a-f]{8})")
_ELEMENTARY = re.compile(r"^(address|bool|string|bytes|u?int\d*)$")


def _cls(t: str) -> str:
    """Comparison class of a single elementary type."""
    if t in ("string", "bytes"):
        return "bytes"
    if t == "address":
        return "address"
    if t == "bool":
        return "bool"
    m = re.match(r"u?int(\d*)$", t)
    if m:
        return "i" + (m.group(1) or "256")
    return t


def _abi_returns(text: str) -> dict[int, tuple[str, ...] | None]:
    """selector -> tuple of output classes, or None if non-elementary outputs."""
    out: dict[int, tuple[str, ...] | None] = {}
    for item in compile_abi_items(text):
        if item.get("type") != "function":
            continue
        args = ",".join(_canon(i) for i in item["inputs"])
        sel = keccak_sel(f"{item['name']}({args})")
        outs = [_canon(o) for o in item.get("outputs", [])]
        if all(_ELEMENTARY.match(o) for o in outs):
            out[sel] = tuple(_cls(o) for o in outs)
        else:
            out[sel] = None                          # array/tuple/bytesN: skip
    return out


def _ours(out_text: str) -> dict[int, tuple[str, ...]]:
    """selector -> tuple of inferred return classes ([] = void)."""
    res: dict[int, tuple[str, ...]] = {}
    for m in _HEADER.finditer(out_text):
        clause, sel = m.group(1), int(m.group(2), 16)
        if not clause:
            res[sel] = ()
        else:
            parts = [p.strip() for p in clause.strip("()").split(",")]
            res[sel] = tuple(_cls(p) for p in parts)
    return res


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    corpus = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    if limit:
        bins = bins[:limit]
    print(f"checking inferred return types for {len(bins)} contracts\n", flush=True)

    checked = skipped = 0
    void_ok = void_tot = 0
    scal_ok = scal_tot = 0
    nonelem = 0
    bad: list[str] = []
    for i, path in enumerate(bins, 1):
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        src = open(src_path, errors="ignore").read()
        if is_vyper(src):
            skipped += 1
            continue
        try:
            abi = _abi_returns(src)
        except Exception:  # noqa: BLE001
            skipped += 1
            continue
        ours = _ours(decompile(from_hex(open(path).read())))
        checked += 1
        addr = os.path.basename(path)[:10]
        for sel, got in ours.items():
            if sel not in abi:
                continue
            want = abi[sel]
            if want is None:
                nonelem += 1
                continue
            if not want:                             # ABI: void
                void_tot += 1
                void_ok += (got == ())
                continue
            scal_tot += 1
            if got == want:
                scal_ok += 1
            elif len(bad) < 12:
                bad.append(f"{addr} 0x{sel:08x} abi={want} got={got or '(void)'}")
        if i % 50 == 0:
            print(f"  ...{i}/{len(bins)} (checked={checked})", flush=True)

    print(f"\n{'='*66}")
    print(f"contracts checked: {checked}  (skipped {skipped} vyper/no-compile)")
    print(f"\nVALUE-RETURNING functions (ABI elementary outputs): "
          f"{scal_ok}/{scal_tot} = {100*scal_ok/max(scal_tot,1):.1f}% class-match")
    print(f"VOID functions (ABI no outputs): "
          f"{void_ok}/{void_tot} = {100*void_ok/max(void_tot,1):.1f}% agree")
    print(f"non-elementary ABI returns (array/tuple/bytesN, not scored): {nonelem}")
    if bad:
        print("\nfirst mismatches:")
        for r in bad:
            print(f"   {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
