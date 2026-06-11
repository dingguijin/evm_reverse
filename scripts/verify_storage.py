#!/usr/bin/env python3
"""Check the decompiler's storage-layout summary against solc's storageLayout.

solc (>=0.5.13) emits the authoritative slot assignment for every state
variable. The decompiler independently reports which constant slots and
mapping base slots the bytecode touches. Precision check, per contract:

  - every small constant slot we report must fall inside a slot span some
    declared variable occupies;
  - every mapping base slot we report must hold a declared mapping.

Huge slots (keccak-derived, e.g. ERC-1967) have no source-level counterpart
and are counted separately, not as mismatches. The deployed contract is
identified as the compiled contract whose ABI covers all recovered selectors
(largest layout wins ties); without full coverage we fall back to the union
of all candidates' layouts.

  python3 scripts/verify_storage.py [limit] [corpus_dir]
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
from evmdec.selectors import find_functions            # noqa: E402

from verify_abi import _canon, compile_output, is_vyper   # noqa: E402

_SMALL = 1 << 32           # above this a slot is keccak-derived, not declared
_SUMMARY = re.compile(
    r"// storage layout: (?:slots ([^;\n]+))?(?:; )?(?:mapping\(s\) at slot ([^\n]+))?")


def _layout_facts(layout: dict) -> tuple[set[int], set[int]]:
    """(occupied slot numbers incl. struct/array spans, mapping base slots)."""
    occupied: set[int] = set()
    mappings: set[int] = set()
    types = layout.get("types") or {}

    def expand(slot: int, t: str) -> None:
        info = types.get(t, {})
        nbytes = int(info.get("numberOfBytes", 32))
        occupied.update(range(slot, slot + max(1, (nbytes + 31) // 32)))
        if t.startswith("t_mapping"):
            mappings.add(slot)
        for m in info.get("members") or []:   # struct fields live at base+offset
            expand(slot + int(m["slot"]), m["type"])

    for var in layout.get("storage", []):
        expand(int(var["slot"]), var["type"])
    return occupied, mappings


def _deployed_layout(out: dict, recovered: set[int]) -> tuple[dict | None, bool]:
    """Pick the compiled contract implementing all recovered selectors."""
    best, best_n = None, -1
    union: dict = {"storage": [], "types": {}}
    seen_any = False
    for fdict in out.get("contracts", {}).values():
        for c in fdict.values():
            layout = c.get("storageLayout")
            if layout is None:      # solc < 0.5.13 emits no layout at all
                continue
            seen_any = True
            sels = set()
            for item in c.get("abi", []):
                if item.get("type") == "function":
                    args = ",".join(_canon(i) for i in item["inputs"])
                    sels.add(keccak_sel(f"{item['name']}({args})"))
            union["storage"] += layout.get("storage", [])
            union["types"].update(layout.get("types") or {})
            if recovered <= sels and len(layout.get("storage", [])) > best_n:
                best, best_n = layout, len(layout.get("storage", []))
    if best is not None:
        return best, True
    return (union if seen_any else None), False


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    corpus = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    if limit:
        bins = bins[:limit]
    print(f"checking storage layouts for {len(bins)} contracts\n", flush=True)

    checked = skipped = no_layout = union_basis = 0
    slot_hit = slot_total = map_hit = map_total = raw = 0
    perfect = 0
    bad: list[str] = []
    for i, path in enumerate(bins, 1):
        addr = os.path.basename(path)[:-4]
        src_path = path[:-4] + ".sol"
        if not os.path.exists(src_path):
            continue
        src = open(src_path, errors="ignore").read()
        if is_vyper(src):
            skipped += 1
            continue
        code = from_hex(open(path).read())
        try:
            out = compile_output(src, ("abi", "storageLayout"))
        except Exception:  # noqa: BLE001
            skipped += 1
            continue
        recovered = {f.selector for f in find_functions(code)}
        layout, confident = _deployed_layout(out, recovered)
        if layout is None:     # solc too old for storageLayout, or no vars
            no_layout += 1
            continue
        union_basis += not confident

        m = _SUMMARY.search(decompile(code))
        ours_slots = {int(s) for s in (m.group(1) or "").split(",") if s.strip()} \
            if m else set()
        ours_maps = {int(s) for s in (m.group(2) or "").split(",") if s.strip()} \
            if m else set()
        if not ours_slots and not ours_maps:
            continue           # proxy / pure-fallback: nothing claimed
        checked += 1

        occupied, mappings = _layout_facts(layout)
        ok = True
        for s in ours_slots:
            if s >= _SMALL:
                raw += 1
                continue
            slot_total += 1
            if s in occupied:
                slot_hit += 1
            else:
                ok = False
                if len(bad) < 10:
                    bad.append(f"{addr} slot {s} not in declared layout")
        for s in ours_maps:
            if s >= _SMALL:
                raw += 1
                continue
            map_total += 1
            if s in mappings:
                map_hit += 1
            else:
                ok = False
                if len(bad) < 10:
                    bad.append(f"{addr} mapping base {s} not a declared mapping")
        perfect += ok

        if i % 50 == 0:
            print(f"  ...{i}/{len(bins)} (checked={checked})", flush=True)

    print(f"\n{'='*66}")
    print(f"contracts scored: {checked}  (skipped: {skipped} vyper/no-compile, "
          f"{no_layout} no storageLayout, {union_basis}/{checked} on union basis)")
    print(f"\nCONST SLOTS in declared layout:   {slot_hit}/{slot_total} "
          f"= {100*slot_hit/max(slot_total,1):.1f}%")
    print(f"MAPPING BASES are declared maps:  {map_hit}/{map_total} "
          f"= {100*map_hit/max(map_total,1):.1f}%")
    print(f"keccak-derived raw slots (no source counterpart, not scored): {raw}")
    print(f"contracts with every claim matching: {perfect}/{checked} "
          f"= {100*perfect/max(checked,1):.1f}%")
    if bad:
        print("\nfirst mismatches:")
        for r in bad:
            print(f"   {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
