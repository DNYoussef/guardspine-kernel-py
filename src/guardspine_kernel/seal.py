"""
Bundle sealing and hash-chain construction for guardspine-kernel.

Uses hashlib for SHA-256. Zero external dependencies.

CRITICAL: All hash computations MUST produce identical output to
@guardspine/kernel/seal.ts for cross-language parity.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

from .canonical import canonical_json


# Sentinel value for the first link in a hash chain (no predecessor)
GENESIS_HASH = "genesis"


def compute_content_hash(content: dict[str, Any]) -> str:
    """
    Compute SHA-256 of the canonical JSON representation of an object.

    Args:
        content: Object to hash

    Returns:
        "sha256:<hex>" formatted hash
    """
    canonical = canonical_json(content)
    hash_bytes = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{hash_bytes}"


def _sha256(data: str) -> str:
    """Internal: compute SHA-256 of a raw string. Returns 'sha256:<hex>'."""
    hash_bytes = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return f"sha256:{hash_bytes}"


@dataclass
class ChainInput:
    """Input for building a hash chain."""
    content: dict[str, Any]
    content_type: str
    content_id: str


ProofVersion = Literal["v0.2.0", "legacy"]


@dataclass
class SealOptions:
    """Options for sealing a bundle."""
    proof_version: ProofVersion = "v0.2.0"


@dataclass
class HashChainLink:
    """A single link in the hash chain."""
    sequence: int
    item_id: str
    content_type: str
    content_hash: str
    previous_hash: str
    chain_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "item_id": self.item_id,
            "content_type": self.content_type,
            "content_hash": self.content_hash,
            "previous_hash": self.previous_hash,
            "chain_hash": self.chain_hash,
        }


@dataclass
class ImmutabilityProof:
    """Immutability proof containing hash chain and root hash."""
    hash_chain: list[HashChainLink]
    root_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash_chain": [link.to_dict() for link in self.hash_chain],
            "root_hash": self.root_hash,
        }


@dataclass
class EvidenceItem:
    """A single evidence item in a bundle."""
    item_id: str
    content_type: str
    content: dict[str, Any]
    content_hash: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "content_type": self.content_type,
            "content": self.content,
            "content_hash": self.content_hash,
            "sequence": self.sequence,
        }


@dataclass
class SealResult:
    """Result of sealing a bundle."""
    immutability_proof: ImmutabilityProof
    items: list[EvidenceItem]

    def to_dict(self) -> dict[str, Any]:
        return {
            "immutability_proof": self.immutability_proof.to_dict(),
            "items": [item.to_dict() for item in self.items],
        }


def _chain_hash_v020(
    sequence: int,
    item_id: str,
    content_type: str,
    content_hash: str,
    previous_hash: str,
) -> str:
    """
    Compute chain hash for v0.2.0 proof format.

    MUST match @guardspine/kernel/seal.ts chainHashV020 exactly.
    """
    chain_input = f"{sequence}|{item_id}|{content_type}|{content_hash}|{previous_hash}"
    return _sha256(chain_input)


def _chain_hash_legacy(
    sequence: int,
    content_hash: str,
    previous_hash: str,
) -> str:
    """
    Compute chain hash for legacy proof format.

    MUST match @guardspine/kernel/seal.ts chainHashLegacy exactly.
    """
    chain_input = f"{sequence}|{content_hash}|{previous_hash}"
    return _sha256(chain_input)


def build_hash_chain(
    items: list[ChainInput],
    options: SealOptions | None = None,
) -> list[HashChainLink]:
    """
    Build a hash chain from an ordered list of items.

    Each link's chain_hash depends on proof_version (v0.2.0 by default).

    Args:
        items: Ordered list of chain inputs
        options: Sealing options (default: v0.2.0 proof version)

    Returns:
        List of hash chain links
    """
    chain: list[HashChainLink] = []
    version = options.proof_version if options else "v0.2.0"

    for seq, item in enumerate(items):
        item_content_hash = compute_content_hash(item.content)
        previous_hash = GENESIS_HASH if seq == 0 else chain[seq - 1].chain_hash

        if version == "legacy":
            chain_hash = _chain_hash_legacy(seq, item_content_hash, previous_hash)
        else:
            chain_hash = _chain_hash_v020(
                seq,
                item.content_id,
                item.content_type,
                item_content_hash,
                previous_hash,
            )

        chain.append(HashChainLink(
            sequence=seq,
            item_id=item.content_id,
            content_type=item.content_type,
            content_hash=item_content_hash,
            previous_hash=previous_hash,
            chain_hash=chain_hash,
        ))

    return chain


def compute_root_hash(chain: list[HashChainLink]) -> str:
    """
    Compute the root hash over an entire chain.

    root_hash = SHA-256(concatenation of all chain_hash values).

    Args:
        chain: List of hash chain links

    Returns:
        "sha256:<hex>" formatted root hash
    """
    concat = "".join(link.chain_hash for link in chain)
    return _sha256(concat)


def seal_bundle(
    items: list[dict[str, Any]],
    options: SealOptions | None = None,
) -> dict[str, Any]:
    """
    Seal a list of items: compute content hashes, build hash chain,
    and produce the immutability proof.

    Args:
        items: List of dicts with 'content', 'content_type', and 'item_id' keys
        options: Sealing options (default: v0.2.0 proof version)

    Returns:
        Dict with immutability_proof and sealed items (JSON-serializable)
    """
    chain_inputs = [
        ChainInput(
            content=item.get("content", {}),
            content_type=item.get("content_type", "unknown"),
            content_id=item.get("item_id", f"item-{idx}"),
        )
        for idx, item in enumerate(items)
    ]

    chain = build_hash_chain(chain_inputs, options)
    root_hash = compute_root_hash(chain)

    sealed_items = [
        {
            "item_id": item.get("item_id", f"item-{idx}"),
            "content_type": item.get("content_type", "unknown"),
            "content": item.get("content", {}),
            "content_hash": chain[idx].content_hash,
            "sequence": idx,
        }
        for idx, item in enumerate(items)
    ]

    return {
        "immutability_proof": {
            "hash_chain": [link.to_dict() for link in chain],
            "root_hash": root_hash,
        },
        "items": sealed_items,
    }
