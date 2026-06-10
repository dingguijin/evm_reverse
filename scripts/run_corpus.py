#!/usr/bin/env python3
"""Offline corpus runner: decompile every contract in corpus/ with NO network.

The corpus is built by `onchain_batch.py` (each verified contract saved as
<address>.bin runtime bytecode + <address>.sol source + manifest.json). This
script replays it locally — a fast, reproducible regression/stability check that
never touches an RPC or block explorer.

  python3 scripts/run_corpus.py [corpus_dir]
"""

from __future__ import annotations

import glob
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evmdec.decompiler import decompile          # noqa: E402
from evmdec.disassembler import from_hex          # noqa: E402

SLOW_MS = 3000


def _pct(vals: list, p: float):
    return vals[min(len(vals) - 1, int(len(vals) * p))] if vals else 0


def main() -> int:
    corpus = sys.argv[1] if len(sys.argv) > 1 else \
        os.path.join(os.path.dirname(__file__), "..", "corpus")
    bins = sorted(glob.glob(os.path.join(corpus, "*.bin")))
    if not bins:
        print(f"no .bin files in {corpus} (build it with onchain_batch.py first)")
        return 1
    print(f"replaying {len(bins)} contracts from {os.path.normpath(corpus)} (offline)\n", flush=True)

    times: list[float] = []
    lines: list[int] = []
    errors: dict[str, int] = {}
    slow = []
    t0 = time.time()
    for i, path in enumerate(bins, 1):
        addr = os.path.basename(path)[:-4]
        code = from_hex(open(path).read())
        try:
            t = time.time()
            out = decompile(code)
            dt = (time.time() - t) * 1000
            nlines = out.count("\n") + 1
            times.append(dt)
            lines.append(nlines)
            if dt > SLOW_MS:
                slow.append((dt, nlines, addr))
            if dt > SLOW_MS or i % 100 == 0:
                print(f"[{i:4}] {addr[:12]}…  {nlines:6} L  {dt:7.0f}ms", flush=True)
        except Exception as e:  # noqa: BLE001
            errors[type(e).__name__] = errors.get(type(e).__name__, 0) + 1
            print(f"[{i:4}] {addr}  ERROR {type(e).__name__}: {e}", flush=True)

    n_ok = len(times)
    times.sort()
    lines.sort()
    print(f"\n{'='*64}")
    print(f"decompiled {n_ok}/{len(bins)} in {time.time()-t0:.0f}s   "
          f"({len(errors)} error type(s))")
    if errors:
        for k, v in sorted(errors.items(), key=lambda x: -x[1]):
            print(f"    {v:4}x  {k}")
    if times:
        print(f"time   p50/p90/p99/max = "
              f"{_pct(times,.5):.0f} / {_pct(times,.9):.0f} / "
              f"{_pct(times,.99):.0f} / {times[-1]:.0f} ms")
        print(f"lines  p50/p90/max     = {_pct(lines,.5)} / {_pct(lines,.9)} / {lines[-1]}")
        print(f"contracts > {SLOW_MS}ms: {len(slow)}")
        for dt, nl, addr in sorted(slow, reverse=True)[:10]:
            print(f"    {dt:7.0f}ms  {nl:6}L  {addr}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
