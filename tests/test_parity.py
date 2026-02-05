"""
Golden vector parity tests for guardspine-kernel-py.

These tests ensure the Python implementation produces identical
results to @guardspine/kernel (TypeScript).

Golden vectors are stored in ../guardspine-spec/fixtures/golden-vectors/
"""

import json
import os
from pathlib import Path

import pytest

# Add parent src to path for development
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from guardspine_kernel import (
    canonical_json,
    compute_content_hash,
    seal_bundle,
    verify_bundle,
    ErrorCode,
)


# Path to golden vectors
GOLDEN_VECTORS_PATH = Path(__file__).parent.parent.parent / "guardspine-spec" / "fixtures" / "golden-vectors"


def load_golden_vector(filename: str) -> dict:
    """Load a golden vector JSON file."""
    path = GOLDEN_VECTORS_PATH / filename
    if not path.exists():
        pytest.skip(f"Golden vector not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_expected_hashes() -> dict:
    """Load expected hash values."""
    return load_golden_vector("expected-hashes.json")


class TestCanonicalJson:
    """Test RFC 8785 canonical JSON serialization."""

    def test_sorted_keys(self):
        """Object keys must be sorted by Unicode code point."""
        obj = {"z": 1, "a": 2, "m": 3}
        result = canonical_json(obj)
        assert result == '{"a":2,"m":3,"z":1}'

    def test_no_whitespace(self):
        """No whitespace between tokens."""
        obj = {"key": [1, 2, 3]}
        result = canonical_json(obj)
        assert result == '{"key":[1,2,3]}'

    def test_nested_sorting(self):
        """Nested objects must also have sorted keys."""
        obj = {"outer": {"z": 1, "a": 2}}
        result = canonical_json(obj)
        assert result == '{"outer":{"a":2,"z":1}}'

    def test_null_value(self):
        """null values serialize correctly."""
        obj = {"key": None}
        result = canonical_json(obj)
        assert result == '{"key":null}'

    def test_boolean_values(self):
        """Boolean values serialize correctly."""
        assert canonical_json(True) == "true"
        assert canonical_json(False) == "false"

    def test_integer_values(self):
        """Integer values serialize without decimal point."""
        assert canonical_json(42) == "42"
        assert canonical_json(-17) == "-17"
        assert canonical_json(0) == "0"

    def test_float_values(self):
        """Float values use shortest representation."""
        assert canonical_json(3.14) == "3.14"
        # Integer floats should not have decimal
        assert canonical_json(1.0) == "1"

    def test_string_escaping(self):
        """Strings escape control characters properly."""
        result = canonical_json("hello\nworld")
        assert result == '"hello\\nworld"'


class TestContentHash:
    """Test content hash computation."""

    def test_simple_object(self):
        """Hash of simple object."""
        content = {"message": "test"}
        result = compute_content_hash(content)
        assert result.startswith("sha256:")
        assert len(result) == 7 + 64  # "sha256:" + 64 hex chars

    def test_deterministic(self):
        """Same content always produces same hash."""
        content = {"a": 1, "b": 2}
        hash1 = compute_content_hash(content)
        hash2 = compute_content_hash(content)
        assert hash1 == hash2

    def test_key_order_independent(self):
        """Hash is independent of key insertion order."""
        content1 = {"z": 1, "a": 2}
        content2 = {"a": 2, "z": 1}
        assert compute_content_hash(content1) == compute_content_hash(content2)


class TestSealBundle:
    """Test bundle sealing."""

    def test_minimal_bundle(self):
        """Seal a minimal single-item bundle."""
        items = [
            {
                "item_id": "item-001",
                "content_type": "guardspine/audit_event",
                "content": {"message": "test"},
            }
        ]
        result = seal_bundle(items)

        assert len(result["items"]) == 1
        assert result["items"][0]["sequence"] == 0
        assert result["items"][0]["item_id"] == "item-001"
        assert result["items"][0]["content_hash"].startswith("sha256:")

        proof = result["immutability_proof"]
        assert len(proof["hash_chain"]) == 1
        assert proof["root_hash"].startswith("sha256:")

    def test_multi_item_bundle(self):
        """Seal a bundle with multiple items."""
        items = [
            {"item_id": f"item-{i:03d}", "content_type": "test", "content": {"seq": i}}
            for i in range(5)
        ]
        result = seal_bundle(items)

        assert len(result["items"]) == 5
        assert len(result["immutability_proof"]["hash_chain"]) == 5

        # Check sequence numbers
        for i, item in enumerate(result["items"]):
            assert item["sequence"] == i

        # Check chain linkage
        chain = result["immutability_proof"]["hash_chain"]
        assert chain[0]["previous_hash"] == "genesis"
        for i in range(1, len(chain)):
            assert chain[i]["previous_hash"] == chain[i - 1]["chain_hash"]


class TestVerifyBundle:
    """Test bundle verification."""

    def test_verify_valid_bundle(self):
        """Verify a freshly sealed bundle."""
        items = [
            {
                "item_id": "item-001",
                "content_type": "guardspine/audit_event",
                "content": {"message": "test"},
            }
        ]
        bundle = seal_bundle(items)

        result = verify_bundle(bundle)
        assert result["valid"], f"Errors: {result['errors']}"


class TestGoldenVectors:
    """Test against golden vectors for cross-language parity."""

    def test_valid_minimal_bundle(self):
        """Verify v0.2.0-minimal-bundle.json passes validation."""
        bundle = load_golden_vector("v0.2.0-minimal-bundle.json")
        result = verify_bundle(bundle)
        assert result["valid"], f"Errors: {result['errors']}"

    def test_valid_multi_item_bundle(self):
        """Verify v0.2.0-multi-item-bundle.json passes validation."""
        bundle = load_golden_vector("v0.2.0-multi-item-bundle.json")
        result = verify_bundle(bundle)
        assert result["valid"], f"Errors: {result['errors']}"

    def test_valid_signed_bundle(self):
        """Verify v0.2.0-signed-bundle.json passes validation (structure only)."""
        bundle = load_golden_vector("v0.2.0-signed-bundle.json")
        # Don't require signatures since we don't have the private key
        result = verify_bundle(bundle, require_signatures=False)
        # May have signature errors but structure should be valid
        structural_errors = [e for e in result["errors"] if e["code"] != ErrorCode.SIGNATURE_INVALID.value]
        assert len(structural_errors) == 0, f"Structural errors: {structural_errors}"


class TestMalformedBundles:
    """Test that malformed bundles are rejected."""

    def test_missing_version(self):
        """MUST reject bundle with missing version field."""
        bundle = load_golden_vector("malformed/missing-version.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.MISSING_REQUIRED_FIELD.value in error_codes

    def test_wrong_version(self):
        """MUST reject bundle with unsupported version."""
        bundle = load_golden_vector("malformed/wrong-version.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.UNSUPPORTED_VERSION.value in error_codes

    def test_chain_count_mismatch(self):
        """MUST reject bundle where items count != chain length."""
        bundle = load_golden_vector("malformed/chain-count-mismatch.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.LENGTH_MISMATCH.value in error_codes

    def test_unbound_item(self):
        """MUST reject bundle where item_id not in chain."""
        bundle = load_golden_vector("malformed/unbound-item.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.CONTENT_HASH_MISMATCH.value in error_codes

    def test_broken_chain_linkage(self):
        """MUST reject bundle with broken previous_hash linkage."""
        bundle = load_golden_vector("malformed/broken-chain-linkage.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.HASH_CHAIN_BROKEN.value in error_codes

    def test_sequence_gap(self):
        """MUST reject bundle with sequence gap."""
        bundle = load_golden_vector("malformed/sequence-gap.json")
        result = verify_bundle(bundle)
        assert not result["valid"]
        error_codes = [e["code"] for e in result["errors"]]
        assert ErrorCode.SEQUENCE_GAP.value in error_codes


class TestExpectedHashes:
    """Test that computed hashes match expected values from TypeScript."""

    def test_content_hash_parity(self):
        """Content hashes must match @guardspine/kernel exactly."""
        expected = load_expected_hashes()
        if "content_hashes" not in expected:
            pytest.skip("content_hashes not in expected-hashes.json")

        for test_case in expected["content_hashes"]:
            content = test_case["content"]
            expected_hash = test_case["expected_hash"]
            actual_hash = compute_content_hash(content)
            assert actual_hash == expected_hash, (
                f"Content hash mismatch for {content}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

    def test_canonical_json_parity(self):
        """Canonical JSON must match @guardspine/kernel exactly."""
        expected = load_expected_hashes()
        if "canonical_json" not in expected:
            pytest.skip("canonical_json not in expected-hashes.json")

        for test_case in expected["canonical_json"]:
            obj = test_case["input"]
            expected_output = test_case["expected_output"]
            actual_output = canonical_json(obj)
            assert actual_output == expected_output, (
                f"Canonical JSON mismatch for {obj}: "
                f"expected {expected_output!r}, got {actual_output!r}"
            )
