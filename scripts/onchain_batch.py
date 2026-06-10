#!/usr/bin/env python3
"""Batch-test the decompiler against real verified mainnet contracts.

Starting from a given block, collect contract addresses touched by its
transactions, keep the ones with verified source (via blockscan's srcapi),
decompile each, and print a summary. Fully unattended.

  python3 scripts/onchain_batch.py [block_number] [count]
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

sys.path.insert(0, __file__.rsplit("/scripts/", 1)[0])

from evmdec.decompiler import decompile          # noqa: E402
from evmdec.disassembler import from_hex          # noqa: E402
from evmdec.selectors import find_functions        # noqa: E402

RPCS = [
    "https://eth-mainnet.public.blastapi.io",
    "https://1rpc.io/eth",
    "https://rpc.flashbots.net",
    "https://ethereum-rpc.publicnode.com",
]
SRCAPI = "https://vscode.blockscan.com/srcapi/1/{}"
UA = "Mozilla/5.0"   # blockscan/some RPCs reject the default python-urllib UA


def rpc(method: str, params: list, *, retries: int = 3):
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
    last = None
    for _ in range(retries):
        for url in RPCS:
            try:
                req = urllib.request.Request(
                    url, body, {"Content-Type": "application/json", "User-Agent": UA}
                )
                with urllib.request.urlopen(req, timeout=20) as r:
                    out = json.load(r)
                if "result" in out:
                    return out["result"]
                last = out.get("error")
            except Exception as e:  # noqa: BLE001
                last = e
        time.sleep(1.0)            # back off before retrying the whole pool
    raise RuntimeError(f"all RPCs failed: {last}")


def fetch_source(addr: str):
    try:
        req = urllib.request.Request(SRCAPI.format(addr), headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        if str(data.get("status")) == "1" and data.get("result"):
            return data["result"]
    except Exception:  # noqa: BLE001
        return None
    return None


def contract_name(src: str) -> str:
    # require the name be followed by `is` or `{` so we skip the word "contract"
    # appearing in comments/strings; take the last real declaration (usually the
    # most-derived contract in a flattened source).
    names = re.findall(r"\bcontract\s+([A-Za-z_]\w*)\s*(?:is\b|\{)", src)
    return names[-1] if names else "?"


SLOW_MS = 3000   # only dump source for slow/error cases, to keep disk/memory bounded


def _scan_block(bn: int, seen: set, want: int, results: list, stats: dict, outdir: str,
                corpus_dir: str | None = None, manifest: list | None = None) -> None:
    """Scan one block's call targets, appending verified decompile *stats* to results.

    For scale (1000s of contracts) we keep only numeric stats in memory, never the
    full source; source is dumped to disk solely for slow or failing contracts so
    they can be inspected afterwards.

    If `corpus_dir` is given, every verified contract's runtime bytecode (.bin),
    verified source (.sol) and a manifest row are saved there, building a reusable
    offline test corpus (see scripts/run_corpus.py).
    """
    blk = rpc("eth_getBlockByNumber", [hex(bn), True])
    addrs = []
    for tx in blk["transactions"]:
        to = tx.get("to")
        if to and to.lower() not in seen:
            seen.add(to.lower())
            addrs.append(to)
    print(f"block {bn}: {len(blk['transactions'])} txs, {len(addrs)} new addrs "
          f"(have {len(results)}/{want})", flush=True)

    for addr in addrs:
        if len(results) >= want:
            return
        stats["scanned"] += 1
        # Source check FIRST (blockscan is lenient); only hit rate-limited RPC on hits.
        src = fetch_source(addr)
        time.sleep(0.15)
        if src is None:
            continue
        try:
            code = rpc("eth_getCode", [addr, "latest"])
        except Exception:  # noqa: BLE001
            stats["rpc_fail"] += 1
            continue
        if not code or code == "0x" or len(code) < 100:
            continue

        name = contract_name(src)
        codeb = from_hex(code)

        # Save into the reusable offline corpus (bytecode + source + manifest row).
        if corpus_dir is not None:
            try:
                with open(os.path.join(corpus_dir, f"{addr}.bin"), "w") as f:
                    f.write(code)
                with open(os.path.join(corpus_dir, f"{addr}.sol"), "w") as f:
                    f.write(src)
            except Exception:  # noqa: BLE001
                pass

        try:
            t = time.time()
            out = decompile(codeb)
            dt = (time.time() - t) * 1000
            funcs = find_functions(codeb)
            nfuncs, named = len(funcs), sum(1 for f in funcs if f.signature)
            unresolved = out.count("unresolved dynamic jump site")
            nlines = out.count("\n") + 1
            status = "ok"
        except Exception as e:  # noqa: BLE001
            dt, nfuncs, named, unresolved, nlines, status = 0, 0, 0, 0, 0, type(e).__name__
            out = f"// ERROR: {type(e).__name__}: {e}"
            stats["errors"][type(e).__name__] = stats["errors"].get(type(e).__name__, 0) + 1

        n = len(results) + 1
        notable = status != "ok" or dt > SLOW_MS
        if notable:
            try:
                with open(os.path.join(outdir, f"{name}_{addr[:10]}.sol"), "w") as f:
                    f.write(out)
            except Exception:  # noqa: BLE001
                pass
        if notable or n % 50 == 0:
            flag = "  <<<" if status != "ok" else ("  <slow>" if dt > SLOW_MS else "")
            print(f"[{n:4}] {addr}  {(name or '?')[:18]:18}  {nfuncs:3} fns  "
                  f"{nlines:6} L  {dt:7.0f}ms  {status}{flag}", flush=True)
        if manifest is not None:
            manifest.append({"address": addr, "name": name, "block": bn,
                             "functions": nfuncs, "named": named, "lines": nlines,
                             "decompile_ms": round(dt), "status": status})
        results.append((addr, name, nfuncs, named, unresolved, dt, nlines, status))


def _pct(sorted_vals: list, p: float):
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p))]


def main() -> int:
    block = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000_000
    want = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    max_blocks = int(sys.argv[3]) if len(sys.argv) > 3 else 60

    root = os.path.dirname(os.path.dirname(__file__))
    outdir = os.path.join(root, "out_batch")
    corpus_dir = os.path.join(root, "corpus")
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)
    print(f"target: {want} verified contracts from block {block} "
          f"(dumping source only for errors / >{SLOW_MS}ms)\n"
          f"corpus (bytecode+source) -> {corpus_dir}/\n", flush=True)
    seen: set[str] = set()
    results: list = []
    manifest: list = []
    stats = {"scanned": 0, "rpc_fail": 0, "errors": {}}

    start = time.time()
    boff = 0
    for boff in range(max_blocks):
        if len(results) >= want:
            break
        try:
            _scan_block(block + boff, seen, want, results, stats, outdir, corpus_dir, manifest)
        except Exception as e:  # noqa: BLE001
            print(f"block {block + boff} skipped: {e}", flush=True)
            time.sleep(1.0)

    with open(os.path.join(corpus_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    # ---- summary -------------------------------------------------------
    ok = [r for r in results if r[7] == "ok"]
    elapsed = time.time() - start
    print(f"\n{'='*72}")
    print(f"scanned {stats['scanned']} addresses across {boff + 1} block(s) in {elapsed:.0f}s")
    print(f"decompiled: {len(results)} verified contracts")
    print(f"clean: {len(ok)}/{len(results)}   "
          f"({100*len(ok)//max(len(results),1)}%)   rpc_fail={stats['rpc_fail']}")
    if stats["errors"]:
        print("error breakdown:")
        for etype, cnt in sorted(stats["errors"].items(), key=lambda x: -x[1]):
            print(f"    {cnt:4}x  {etype}")
    if ok:
        times = sorted(r[5] for r in ok)
        lines = sorted(r[6] for r in ok)
        print(f"decompile time  p50/p90/p99/max = "
              f"{_pct(times,.5):.0f} / {_pct(times,.9):.0f} / "
              f"{_pct(times,.99):.0f} / {times[-1]:.0f} ms")
        print(f"output lines    p50/p90/max = "
              f"{_pct(lines,.5)} / {_pct(lines,.9)} / {lines[-1]}")
        print(f"contracts > {SLOW_MS}ms: {sum(1 for r in ok if r[5] > SLOW_MS)}")
        print(f"total functions recovered: {sum(r[2] for r in ok)}, "
              f"unresolved-jump contracts: {sum(1 for r in ok if r[4])}")
        slow = sorted((r for r in ok if r[5] > SLOW_MS), key=lambda r: -r[5])[:10]
        if slow:
            print("slowest:")
            for r in slow:
                print(f"   {r[5]:7.0f}ms  {r[6]:6}L  {(r[1] or '?')[:22]:22}  {r[0]}")
    print(f"source dumps (errors/slow only) -> {os.path.normpath(outdir)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
