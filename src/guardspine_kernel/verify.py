"""
Offline bundle verification for guardspine-kernel.

Verifies hash chains, root hashes, and content integrity.

CRITICAL: All verification logic MUST match @guardspine/kernel/verify.ts
exactly for cross-language consistency.
"""

import hashlib
import hmac
import base64
from typing import Any, Literal

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

from .canonical import canonical_json
from .errors import ErrorCode, VerificationError, VerificationResult
from .seal import GENESIS_HASH, HashChainLink


# Supported bundle versions.
# v0.2.1 adds optional sanitization metadata; proof format is unchanged from v0.2.0.
SUPPORTED_VERSIONS = ["0.2.0", "0.2.1"]

ProofVersion = Literal["v0.2.0", "legacy"]


def _sha256(data: str) -> str:
    """Internal: compute SHA-256 of a raw string. Returns 'sha256:<hex>'."""
    hash_bytes = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return f"sha256:{hash_bytes}"


def _content_hash(content: dict[str, Any]) -> str:
    """Compute content hash of an object."""
    return _sha256(canonical_json(content))


def _safe_equal(left: str, right: str) -> bool:
    """
    Constant-time string comparison to prevent timing side-channel attacks.
    """
    left = left if isinstance(left, str) else str(left or "")
    right = right if isinstance(right, str) else str(right or "")
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _chain_hash_v020(
    sequence: int,
    item_id: str,
    content_type: str,
    content_hash: str,
    previous_hash: str,
) -> str:
    """Compute chain hash for v0.2.0 proof format."""
    chain_input = f"{sequence}|{item_id}|{content_type}|{content_hash}|{previous_hash}"
    return _sha256(chain_input)


def _chain_hash_legacy(
    sequence: int,
    content_hash: str,
    previous_hash: str,
) -> str:
    """Compute chain hash for legacy proof format."""
    chain_input = f"{sequence}|{content_hash}|{previous_hash}"
    return _sha256(chain_input)


def verify_content_hashes(items: list[dict[str, Any]]) -> VerificationResult:
    """
    Verify that each item's content_hash matches SHA-256 of its canonical content.

    Detects content tampering.
    """
    errors: list[VerificationError] = []

    if not isinstance(items, list) or len(items) == 0:
        errors.append(VerificationError(
            code=ErrorCode.INPUT_VALIDATION_FAILED,
            message="Items must be a non-empty array",
            details={"received": "empty array" if isinstance(items, list) else type(items).__name__},
        ))
        return VerificationResult(valid=False, errors=errors)

    for item in items:
        expected = _content_hash(item.get("content", {}))
        actual = item.get("content_hash", "")

        if not _safe_equal(actual, expected):
            errors.append(VerificationError(
                code=ErrorCode.CONTENT_HASH_MISMATCH,
                message=f"Content hash mismatch for item {item.get('item_id', 'unknown')}",
                details={
                    "item_id": item.get("item_id"),
                    "expected": expected,
                    "actual": actual,
                },
            ))

    return VerificationResult(valid=len(errors) == 0, errors=errors)


def verify_hash_chain(
    chain: list[dict[str, Any]],
    accept_proof_versions: list[ProofVersion] | None = None,
) -> VerificationResult:
    """
    Verify that each link in the chain correctly references the previous link
    and that the chain_hash is computed correctly.
    """
    errors: list[VerificationError] = []
    accepted_versions = accept_proof_versions or ["v0.2.0"]

    if not isinstance(chain, list) or len(chain) == 0:
        errors.append(VerificationError(
            code=ErrorCode.INPUT_VALIDATION_FAILED,
            message="Hash chain must be a non-empty array",
            details={"received": "empty array" if isinstance(chain, list) else type(chain).__name__},
        ))
        return VerificationResult(valid=False, errors=errors)

    for seq in range(len(chain)):
        link = chain[seq]

        # Check sequence
        if link.get("sequence") != seq:
            errors.append(VerificationError(
                code=ErrorCode.SEQUENCE_GAP,
                message=f"Expected sequence {seq}, got {link.get('sequence')}",
                details={"expected": seq, "actual": link.get("sequence")},
            ))

        # Check previous_hash
        expected_prev = GENESIS_HASH if seq == 0 else chain[seq - 1].get("chain_hash", "")
        if not _safe_equal(link.get("previous_hash", ""), expected_prev):
            errors.append(VerificationError(
                code=ErrorCode.HASH_CHAIN_BROKEN,
                message=f"Chain broken at sequence {seq}: previous_hash mismatch",
                details={
                    "sequence": seq,
                    "expected": expected_prev,
                    "actual": link.get("previous_hash"),
                },
            ))

        # Check chain_hash computation
        allow_v020 = "v0.2.0" in accepted_versions
        allow_legacy = "legacy" in accepted_versions
        has_v020_fields = (
            isinstance(link.get("item_id"), str) and
            isinstance(link.get("content_type"), str)
        )

        chain_valid = False

        if allow_v020:
            if not has_v020_fields and not allow_legacy:
                errors.append(VerificationError(
                    code=ErrorCode.HASH_CHAIN_BROKEN,
                    message=f"Chain hash missing item_id/content_type at sequence {seq}",
                    details={"sequence": seq},
                ))
            elif has_v020_fields:
                expected_v020 = _chain_hash_v020(
                    link.get("sequence", seq),
                    link.get("item_id") or "",
                    link.get("content_type") or "",
                    link.get("content_hash") or "",
                    link.get("previous_hash") or "",
                )
                if _safe_equal(link.get("chain_hash", ""), expected_v020):
                    chain_valid = True

        if not chain_valid and allow_legacy:
            expected_legacy = _chain_hash_legacy(
                link.get("sequence", seq),
                link.get("content_hash", ""),
                link.get("previous_hash", ""),
            )
            if _safe_equal(link.get("chain_hash", ""), expected_legacy):
                chain_valid = True

        if not chain_valid:
            expected_hint = "v0.2.0" if allow_v020 else ("legacy" if allow_legacy else "none")
            errors.append(VerificationError(
                code=ErrorCode.HASH_CHAIN_BROKEN,
                message=f"Chain hash mismatch at sequence {seq}",
                details={
                    "sequence": seq,
                    "expected_version": expected_hint,
                    "actual": link.get("chain_hash"),
                },
            ))

    return VerificationResult(valid=len(errors) == 0, errors=errors)


def verify_root_hash(proof: dict[str, Any]) -> VerificationResult:
    """
    Verify the root hash matches the concatenation of all chain hashes.
    """
    errors: list[VerificationError] = []

    if not proof or not isinstance(proof.get("hash_chain"), list) or len(proof.get("hash_chain", [])) == 0:
        errors.append(VerificationError(
            code=ErrorCode.INPUT_VALIDATION_FAILED,
            message="Immutability proof must contain a non-empty hash_chain",
            details={"received": type(proof.get("hash_chain")).__name__ if proof else "null proof"},
        ))
        return VerificationResult(valid=False, errors=errors)

    chain = proof["hash_chain"]
    concat = "".join(link.get("chain_hash", "") for link in chain)
    expected = _sha256(concat)

    if not _safe_equal(proof.get("root_hash", ""), expected):
        errors.append(VerificationError(
            code=ErrorCode.ROOT_HASH_MISMATCH,
            message="Root hash does not match computed value",
            details={"expected": expected, "actual": proof.get("root_hash")},
        ))

    return VerificationResult(valid=len(errors) == 0, errors=errors)


def verify_signatures(
    bundle: dict[str, Any],
    public_keys: dict[str, str] | None = None,
    hmac_secret: str | None = None,
) -> VerificationResult:
    """
    Verify bundle signatures (if present).

    Supports:
    - hmac-sha256
    - ed25519
    - rsa-sha256
    - ecdsa-p256
    """
    errors: list[VerificationError] = []
    signatures = bundle.get("signatures", [])

    if not signatures:
        return VerificationResult(valid=True, errors=[])

    # Create bundle copy without signatures for verification
    bundle_copy = {k: v for k, v in bundle.items() if k != "signatures"}
    content = canonical_json(bundle_copy).encode("utf-8")

    for sig in signatures:
        signature_value = sig.get("signature_value")
        if not signature_value:
            errors.append(VerificationError(
                code=ErrorCode.SIGNATURE_INVALID,
                message="Signature missing signature_value",
                details={"signature_id": sig.get("signature_id")},
            ))
            continue

        algo = sig.get("algorithm")

        if algo == "hmac-sha256":
            if not hmac_secret:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message="HMAC signature present but no hmac_secret provided",
                    details={"signature_id": sig.get("signature_id")},
                ))
                continue

            expected = base64.b64encode(
                hmac.new(hmac_secret.encode("utf-8"), content, hashlib.sha256).digest()
            ).decode("utf-8")

            if not hmac.compare_digest(expected, signature_value):
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message="HMAC signature verification failed",
                    details={"signature_id": sig.get("signature_id")},
                ))
            continue

        if algo in ("ed25519", "rsa-sha256", "ecdsa-p256"):
            if not _HAS_CRYPTOGRAPHY:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message=f"Algorithm {algo} requires cryptography package",
                    details={"signature_id": sig.get("signature_id")},
                ))
                continue

            key_id = sig.get("public_key_id")
            if not key_id:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message="Asymmetric signature missing public_key_id",
                    details={"signature_id": sig.get("signature_id")},
                ))
                continue

            if not public_keys or key_id not in public_keys:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message=f"Missing public key for key_id={key_id}",
                    details={"signature_id": sig.get("signature_id"), "public_key_id": key_id},
                ))
                continue

            key_value = public_keys[key_id]
            try:
                public_key = _load_public_key_for_algo(key_value, algo)
            except ValueError as exc:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message=f"Invalid public key for {algo}: {exc}",
                    details={"signature_id": sig.get("signature_id"), "public_key_id": key_id},
                ))
                continue

            try:
                signature_bytes = base64.b64decode(signature_value, validate=True)
            except Exception:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message="Signature is not valid base64",
                    details={"signature_id": sig.get("signature_id")},
                ))
                continue

            try:
                _verify_asymmetric_signature(algo, public_key, signature_bytes, content)
            except InvalidSignature:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message=f"{algo} signature verification failed",
                    details={"signature_id": sig.get("signature_id"), "public_key_id": key_id},
                ))
            except ValueError as exc:
                errors.append(VerificationError(
                    code=ErrorCode.SIGNATURE_INVALID,
                    message=str(exc),
                    details={"signature_id": sig.get("signature_id"), "public_key_id": key_id},
                ))
            continue

        errors.append(VerificationError(
            code=ErrorCode.SIGNATURE_INVALID,
            message=f"Unsupported signature algorithm: {algo}",
            details={"signature_id": sig.get("signature_id")},
        ))

    return VerificationResult(valid=len(errors) == 0, errors=errors)


def _load_public_key_for_algo(key_value: str, algorithm: str):
    """Load a public key from PEM text or base64/DER bytes for a specific algorithm."""
    if not _HAS_CRYPTOGRAPHY:
        raise ValueError("cryptography package is not installed")

    key_text = (key_value or "").strip()
    if not key_text:
        raise ValueError("empty public key")

    key_obj = None
    if "BEGIN" in key_text:
        try:
            key_obj = serialization.load_pem_public_key(key_text.encode("utf-8"))
        except Exception as exc:
            raise ValueError(f"invalid PEM public key ({exc})")
    else:
        decoded: bytes
        try:
            decoded = base64.b64decode(key_text, validate=True)
        except Exception:
            raise ValueError("public key must be PEM or base64")

        # Ed25519 commonly uses raw 32-byte public key encoding.
        if algorithm == "ed25519" and len(decoded) == 32:
            try:
                key_obj = ed25519.Ed25519PublicKey.from_public_bytes(decoded)
            except Exception as exc:
                raise ValueError(f"invalid raw Ed25519 key ({exc})")
        else:
            try:
                key_obj = serialization.load_der_public_key(decoded)
            except Exception as exc:
                raise ValueError(f"invalid DER public key ({exc})")

    if algorithm == "ed25519" and not isinstance(key_obj, ed25519.Ed25519PublicKey):
        raise ValueError("expected Ed25519 public key")
    if algorithm == "rsa-sha256" and not isinstance(key_obj, rsa.RSAPublicKey):
        raise ValueError("expected RSA public key")
    if algorithm == "ecdsa-p256" and not isinstance(key_obj, ec.EllipticCurvePublicKey):
        raise ValueError("expected ECDSA public key")
    return key_obj


def _verify_asymmetric_signature(algorithm: str, public_key, signature: bytes, content: bytes) -> None:
    if algorithm == "ed25519":
        public_key.verify(signature, content)
        return
    if algorithm == "rsa-sha256":
        public_key.verify(signature, content, padding.PKCS1v15(), hashes.SHA256())
        return
    if algorithm == "ecdsa-p256":
        curve = getattr(public_key, "curve", None)
        if curve and not isinstance(curve, ec.SECP256R1):
            raise ValueError("ecdsa-p256 requires P-256 public key")
        public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
        return
    raise ValueError(f"unsupported signature algorithm: {algorithm}")


def verify_bundle(
    bundle: dict[str, Any],
    accept_proof_versions: list[ProofVersion] | None = None,
    public_keys: dict[str, str] | None = None,
    hmac_secret: str | None = None,
    require_signatures: bool = False,
) -> dict[str, Any]:
    """
    Full bundle verification: required fields, content hashes, chain, root.

    Args:
        bundle: The evidence bundle to verify
        accept_proof_versions: Accepted proof versions (default: ["v0.2.0"])
        public_keys: Map of public_key_id -> PEM or base64 key for signatures
        hmac_secret: Shared secret for HMAC-SHA256 signatures
        require_signatures: If True, bundle MUST have valid signatures

    Returns:
        VerificationResult with valid flag and list of errors
    """
    errors: list[VerificationError] = []

    # Check required fields
    required_fields = ["bundle_id", "version", "created_at", "items", "immutability_proof"]
    for field in required_fields:
        if bundle.get(field) is None:
            errors.append(VerificationError(
                code=ErrorCode.MISSING_REQUIRED_FIELD,
                message=f"Missing required field: {field}",
                details={"field": field},
            ))

    # Verify bundle version VALUE (not just presence)
    version = bundle.get("version")
    if version and version not in SUPPORTED_VERSIONS:
        errors.append(VerificationError(
            code=ErrorCode.UNSUPPORTED_VERSION,
            message=f"Unsupported bundle version: {version}. Supported: {', '.join(SUPPORTED_VERSIONS)}",
            details={"version": version, "supported": SUPPORTED_VERSIONS},
        ))

    # If critical fields missing, return early
    items = bundle.get("items")
    proof = bundle.get("immutability_proof")
    if not items or not proof:
        return {"valid": False, "errors": [e.to_dict() for e in errors]}

    # Verify content hashes
    content_result = verify_content_hashes(items)
    errors.extend(content_result.errors)

    # Verify hash chain
    chain = proof.get("hash_chain", [])
    chain_result = verify_hash_chain(chain, accept_proof_versions)
    errors.extend(chain_result.errors)

    # Verify root hash
    root_result = verify_root_hash(proof)
    errors.extend(root_result.errors)

    # Verify items count matches chain length
    if len(items) != len(chain):
        errors.append(VerificationError(
            code=ErrorCode.LENGTH_MISMATCH,
            message=f"Items count ({len(items)}) does not match chain length ({len(chain)})",
            details={"items": len(items), "chain": len(chain)},
        ))

    # Cross-check: chain content_hash, item_id, content_type, sequence should match items
    for seq in range(min(len(items), len(chain))):
        item = items[seq]
        link = chain[seq]

        # Verify item.sequence matches its position
        if item.get("sequence") != seq:
            errors.append(VerificationError(
                code=ErrorCode.SEQUENCE_GAP,
                message=f"Item {seq} has sequence {item.get('sequence')}, expected {seq}",
                details={"sequence": seq, "item_sequence": item.get("sequence")},
            ))

        if not _safe_equal(item.get("content_hash", ""), link.get("content_hash", "")):
            errors.append(VerificationError(
                code=ErrorCode.CONTENT_HASH_MISMATCH,
                message=f"Item {seq} content_hash does not match chain link",
                details={
                    "sequence": seq,
                    "item_hash": item.get("content_hash"),
                    "chain_hash": link.get("content_hash"),
                },
            ))

        # v0.2.0: verify item_id and content_type are bound to the chain
        link_item_id = link.get("item_id")
        if link_item_id is not None and not _safe_equal(item.get("item_id", ""), link_item_id):
            errors.append(VerificationError(
                code=ErrorCode.CONTENT_HASH_MISMATCH,
                message=f"Item {seq} item_id does not match chain link",
                details={
                    "sequence": seq,
                    "item_id": item.get("item_id"),
                    "chain_item_id": link_item_id,
                },
            ))

        link_content_type = link.get("content_type")
        if link_content_type is not None and not _safe_equal(item.get("content_type", ""), link_content_type):
            errors.append(VerificationError(
                code=ErrorCode.CONTENT_HASH_MISMATCH,
                message=f"Item {seq} content_type does not match chain link",
                details={
                    "sequence": seq,
                    "content_type": item.get("content_type"),
                    "chain_content_type": link_content_type,
                },
            ))

    # Verify signatures
    sig_result = verify_signatures(bundle, public_keys, hmac_secret)
    errors.extend(sig_result.errors)

    # Check signature requirement
    if require_signatures and not bundle.get("signatures"):
        errors.append(VerificationError(
            code=ErrorCode.SIGNATURE_REQUIRED,
            message="Bundle must have signatures when require_signatures is True",
            details={},
        ))

    return {"valid": len(errors) == 0, "errors": [e.to_dict() for e in errors]}
