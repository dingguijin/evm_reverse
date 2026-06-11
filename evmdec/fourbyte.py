"""M3 helper - selector -> human-readable signature.

Selectors are a one-way hash (keccak256(sig)[:4]), so we can't invert them. We
instead keep a dictionary of *known* signatures, computing each one's selector
with our own keccak. The table seeds common ERC-20/721/ownable signatures plus
anything registered at runtime; an optional online 4byte lookup can be enabled.
"""

from __future__ import annotations

from .keccak import selector as _selector

# Common signatures worth recognising out of the box.
_COMMON_SIGNATURES = [
    # ERC-20
    "totalSupply()", "balanceOf(address)", "transfer(address,uint256)",
    "transferFrom(address,address,uint256)", "approve(address,uint256)",
    "allowance(address,address)", "name()", "symbol()", "decimals()",
    # ERC-721
    "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)",
    "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)",
    "getApproved(uint256)", "tokenURI(uint256)",
    # Ownable / common
    "owner()", "transferOwnership(address)", "renounceOwnership()",
    "mint(address,uint256)", "burn(uint256)", "pause()", "unpause()",
    "deposit()", "withdraw(uint256)", "implementation()", "admin()",
    "upgradeToAndCall(address,bytes)",
    # our sample contract
    "set(uint256)", "get()", "add(uint256,uint256)",
]


# Common event signatures, matched against LOG topic0 (the full keccak hash).
_COMMON_EVENTS = [
    "Transfer(address,address,uint256)",
    "Approval(address,address,uint256)",
    "ApprovalForAll(address,address,bool)",
    "TransferSingle(address,address,address,uint256,uint256)",
    "OwnershipTransferred(address,address)",
    "Paused(address)", "Unpaused(address)",
    "Deposit(address,uint256)", "Withdrawal(address,uint256)",
]


def _build_table() -> dict[int, str]:
    table: dict[int, str] = {}
    for sig in _COMMON_SIGNATURES:
        table[_selector(sig)] = sig
    return table


def _build_event_table() -> dict[int, str]:
    from .keccak import keccak256

    return {int.from_bytes(keccak256(s.encode()), "big"): s for s in _COMMON_EVENTS}


_TABLE: dict[int, str] = _build_table()
_EVENT_TABLE: dict[int, str] = _build_event_table()


def resolve_event(topic0: int) -> str | None:
    """Return the event signature for a LOG topic0 hash, or None if unknown."""
    return _EVENT_TABLE.get(topic0)


def register_signature(sig: str) -> None:
    """Add a known signature so future lookups can name it."""
    _TABLE[_selector(sig)] = sig


def resolve_signature(sel: int, *, online: bool = False) -> str | None:
    """Return a signature string for a selector, or None if unknown."""
    if sel in _TABLE:
        return _TABLE[sel]
    if online:
        return _lookup_online(sel)
    return None


def _lookup_online(sel: int) -> str | None:
    """Best-effort lookup against the public 4byte directory (network required)."""
    try:
        import json
        import urllib.request

        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{sel:08x}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.load(resp)
        results = data.get("results", [])
        if results:
            # earliest id = most likely original signature
            results.sort(key=lambda r: r["id"])
            sig = results[0]["text_signature"]
            _TABLE[sel] = sig
            return sig
    except Exception:
        return None
    return None
