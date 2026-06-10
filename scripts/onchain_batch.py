#!/usr/bin/env python3
"""Batch-test the decompiler against real verified mainnet contracts.

Starting from a given block, collect contract addresses touched by its
transactions, keep the ones with verified source (via blockscan's srcapi),
decompile each, and print a summary. Fully unattended.

  python3 scripts/onchain_batch.py [block_number] [count]
"""

from __future__ import annotations

import json
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


def _scan_block(bn: int, seen: set, want: int, results: list, stats: dict) -> None:
    """Scan one block's call targets, appending verified decompiles to `results`."""
    blk = rpc("eth_getBlockByNumber", [hex(bn), True])
    addrs = []
    for tx in blk["transactions"]:
        to = tx.get("to")
        if to and to.lower() not in seen:
            seen.add(to.lower())
            addrs.append(to)
    print(f"block {bn}: {len(blk['transactions'])} txs, {len(addrs)} new addresses", flush=True)

    for addr in addrs:
        if len(results) >= want:
            return
        stats["scanned"] += 1
        # Source check FIRST (blockscan is lenient); only hit rate-limited RPC on hits.
        src = fetch_source(addr)
        time.sleep(0.2)
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
        try:
            t = time.time()
            out = decompile(codeb)
            dt = (time.time() - t) * 1000
            funcs = find_functions(codeb)
            named = sum(1 for f in funcs if f.signature)
            unresolved = out.count("unresolved dynamic jump site")
            status = "ok"
        except Exception as e:  # noqa: BLE001
            dt, funcs, named, unresolved, status = 0, [], 0, 0, f"ERROR: {type(e).__name__}: {e}"
            out = ""
            stats["errors"][type(e).__name__] = stats["errors"].get(type(e).__name__, 0) + 1

        n = len(results) + 1
        flag = "" if status == "ok" else "  <<<"
        print(
            f"[{n:2}] {addr}  {(name or '?')[:20]:20}  "
            f"{len(funcs):3} fns ({named:2} named)  {len(out.splitlines()):5} lines  "
            f"{dt:6.0f}ms  unres={unresolved}  {status}{flag}",
            flush=True,
        )
        results.append((addr, name, len(funcs), named, unresolved, dt, out, status))


def main() -> int:
    import os

    block = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000_000
    want = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    max_blocks = int(sys.argv[3]) if len(sys.argv) > 3 else 60

    print(f"target: {want} verified contracts, starting at block {block}\n", flush=True)
    seen: set[str] = set()
    results: list = []
    stats = {"scanned": 0, "rpc_fail": 0, "errors": {}}

    for boff in range(max_blocks):
        if len(results) >= want:
            break
        try:
            _scan_block(block + boff, seen, want, results, stats)
        except Exception as e:  # noqa: BLE001
            print(f"block {block + boff} skipped: {e}", flush=True)
            time.sleep(1.0)

    # ---- summary -------------------------------------------------------
    ok = [r for r in results if r[7] == "ok"]
    print(f"\n{'='*70}")
    print(f"scanned {stats['scanned']} addresses across {boff + 1} block(s)")
    print(f"decompiled: {len(results)} verified contracts")
    print(f"clean: {len(ok)}/{len(results)}   "
          f"({100*len(ok)//max(len(results),1)}%)   rpc_fail={stats['rpc_fail']}")
    if stats["errors"]:
        print("error breakdown:")
        for etype, cnt in sorted(stats["errors"].items(), key=lambda x: -x[1]):
            print(f"    {cnt:3}x  {etype}")
    if ok:
        times = sorted(r[5] for r in ok)
        lines = sorted(len(r[6].splitlines()) for r in ok)
        print(f"decompile time  min/median/max = "
              f"{times[0]:.0f} / {times[len(times)//2]:.0f} / {times[-1]:.0f} ms")
        print(f"output lines    min/median/max = "
              f"{lines[0]} / {lines[len(lines)//2]} / {lines[-1]}")
        print(f"total functions recovered: {sum(r[2] for r in ok)}, "
              f"with unresolved jumps: {sum(1 for r in ok if r[4])}")

    outdir = os.path.join(os.path.dirname(__file__), "..", "out_batch")
    os.makedirs(outdir, exist_ok=True)
    for addr, name, *_mid, out, status in results:
        if out:
            with open(os.path.join(outdir, f"{name}_{addr[:10]}.sol"), "w") as f:
                f.write(out)
    print(f"full sources -> {os.path.normpath(outdir)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
