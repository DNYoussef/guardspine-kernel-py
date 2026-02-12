"""
Bundle summary utilities for human-readable inspection.

Extracts key metadata from sealed bundles without modifying them.
"""

from typing import Any


def bundle_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a human-readable summary from a sealed evidence bundle.

    Args:
        bundle: A sealed evidence bundle dict

    Returns:
        Dict with bundle_id, version, item_count, content_types,
        root_hash, and created_at
    """
    items = bundle.get("items", [])
    proof = bundle.get("immutability_proof", {})

    content_types = sorted(set(
        item.get("content_type", "unknown") for item in items
    ))

    return {
        "bundle_id": bundle.get("bundle_id", ""),
        "version": bundle.get("version", ""),
        "created_at": bundle.get("created_at", ""),
        "item_count": len(items),
        "content_types": content_types,
        "root_hash": proof.get("root_hash", ""),
        "chain_length": len(proof.get("hash_chain", [])),
    }


def format_bundle_summary(bundle: dict[str, Any]) -> str:
    """
    Format a sealed bundle as a single-line human-readable string.

    Args:
        bundle: A sealed evidence bundle dict

    Returns:
        String like "bundle-001 (v0.2.1) | 3 items | sha256:abc123..."
    """
    s = bundle_summary(bundle)
    root_short = s["root_hash"][:20] + "..." if len(s["root_hash"]) > 20 else s["root_hash"]
    types = ", ".join(s["content_types"]) if s["content_types"] else "none"
    return f"{s['bundle_id']} (v{s['version']}) | {s['item_count']} items [{types}] | {root_short}"
