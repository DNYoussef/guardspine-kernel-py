"""Signature verification tests for asymmetric algorithms."""

import base64
from datetime import datetime, timezone
from pathlib import Path

import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from guardspine_kernel import ErrorCode, canonical_json, seal_bundle, verify_bundle


def _build_signed_bundle(bundle: dict, private_key, algorithm: str, key_id: str = "key-1") -> dict:
    payload_bundle = {k: v for k, v in bundle.items() if k != "signatures"}
    payload = canonical_json(payload_bundle).encode("utf-8")

    if algorithm == "ed25519":
        signature = private_key.sign(payload)
    elif algorithm == "rsa-sha256":
        signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    elif algorithm == "ecdsa-p256":
        signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError(f"Unsupported algorithm for test: {algorithm}")

    signed = dict(bundle)
    signed["signatures"] = [
        {
            "signature_id": "sig-001",
            "signer_id": "test-signer",
            "algorithm": algorithm,
            "public_key_id": key_id,
            "signature_value": base64.b64encode(signature).decode("utf-8"),
            "signed_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    return signed


def _public_key_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _error_codes(result: dict) -> list[str]:
    return [err["code"] for err in result.get("errors", [])]


def _base_bundle() -> dict:
    return seal_bundle(
        [
            {
                "item_id": "item-001",
                "content_type": "guardspine/test",
                "content": {"message": "signed-test"},
            }
        ]
    )


def test_ed25519_valid_signature_passes():
    private_key = ed25519.Ed25519PrivateKey.generate()
    bundle = _build_signed_bundle(_base_bundle(), private_key, "ed25519")
    result = verify_bundle(bundle, public_keys={"key-1": _public_key_pem(private_key)}, require_signatures=True)

    assert result["valid"], f"Expected valid bundle, got: {result['errors']}"


def test_rsa_sha256_valid_signature_passes():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bundle = _build_signed_bundle(_base_bundle(), private_key, "rsa-sha256")
    result = verify_bundle(bundle, public_keys={"key-1": _public_key_pem(private_key)}, require_signatures=True)

    assert result["valid"], f"Expected valid bundle, got: {result['errors']}"


def test_ecdsa_p256_valid_signature_passes():
    private_key = ec.generate_private_key(ec.SECP256R1())
    bundle = _build_signed_bundle(_base_bundle(), private_key, "ecdsa-p256")
    result = verify_bundle(bundle, public_keys={"key-1": _public_key_pem(private_key)}, require_signatures=True)

    assert result["valid"], f"Expected valid bundle, got: {result['errors']}"


def test_tampered_signature_fails():
    private_key = ed25519.Ed25519PrivateKey.generate()
    bundle = _build_signed_bundle(_base_bundle(), private_key, "ed25519")
    bundle["signatures"][0]["signature_value"] = "AAAA"

    result = verify_bundle(bundle, public_keys={"key-1": _public_key_pem(private_key)}, require_signatures=True)
    codes = _error_codes(result)

    assert not result["valid"]
    assert ErrorCode.SIGNATURE_INVALID.value in codes
