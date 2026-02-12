"""
Bundle signing for guardspine-kernel.

Produces HMAC-SHA256 signatures over canonical bundle content.
Used by CI pipelines and governance workflows to create non-repudiable
evidence of bundle origin.

SECURITY: The shared secret MUST be stored in a secrets manager (Vault,
AWS Secrets Manager, K8s Secret). Never hardcode or commit secrets.
"""

import hashlib
import hmac
import base64
import uuid
from datetime import datetime, timezone
from typing import Any

from .canonical import canonical_json


def sign_bundle_hmac(
    bundle: dict[str, Any],
    secret: str,
    signer_id: str = "ci-pipeline",
    key_id: str = "default",
) -> dict[str, Any]:
    """
    Sign a bundle with HMAC-SHA256 and return a signature object.

    The signature covers the canonical JSON of the bundle (excluding
    any existing signatures field). This matches the verification
    logic in @guardspine/kernel/verify.ts.

    Args:
        bundle: Sealed evidence bundle dict
        secret: HMAC shared secret (must match verifier)
        signer_id: Identity of the signer (e.g., "ci-pipeline", "deploy-bot")
        key_id: Key identifier for key rotation support

    Returns:
        Signature dict matching guardspine-spec Signature schema

    Raises:
        ValueError: If secret is empty or bundle is missing required fields
    """
    if not secret:
        raise ValueError("HMAC secret must not be empty")

    if not bundle.get("bundle_id"):
        raise ValueError("Bundle missing bundle_id")

    # Exclude existing signatures before computing HMAC
    bundle_copy = {k: v for k, v in bundle.items() if k != "signatures"}
    content = canonical_json(bundle_copy).encode("utf-8")

    # Compute HMAC-SHA256
    mac = hmac.new(secret.encode("utf-8"), content, hashlib.sha256)
    signature_value = base64.b64encode(mac.digest()).decode("ascii")

    # Compute content hash for cross-reference
    content_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"

    return {
        "signature_id": f"sig-{uuid.uuid4()}",
        "signer_id": signer_id,
        "algorithm": "hmac-sha256",
        "public_key_id": key_id,
        "signature_value": signature_value,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "content_hash": content_hash,
    }


def attach_signature(
    bundle: dict[str, Any],
    signature: dict[str, Any],
) -> dict[str, Any]:
    """
    Attach a signature to a bundle, returning a new bundle dict.

    Does not mutate the original bundle.

    Args:
        bundle: Sealed evidence bundle
        signature: Signature dict from sign_bundle_hmac

    Returns:
        New bundle dict with signature appended to signatures list
    """
    new_bundle = dict(bundle)
    existing = list(new_bundle.get("signatures", []))
    existing.append(signature)
    new_bundle["signatures"] = existing
    return new_bundle
