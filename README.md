# guardspine-kernel-py

**Python port of the GuardSpine kernel for evidence-bundle verification and sealing.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Zero external dependencies. Supports v0.2.0 and v0.2.1 bundle formats.

## Language Implementations

| Language | Package | Purpose |
|----------|---------|---------|
| **TypeScript** | [@guardspine/kernel](https://github.com/DNYoussef/guardspine-kernel) | Reference implementation (canonical) |
| **Python** (this repo) | `guardspine-kernel` | For Python integrations (FastAPI, CLI, ML pipelines) |

This Python library MUST produce **byte-identical hashes** to the TypeScript reference. Both use RFC 8785 canonical JSON serialization. Golden vector parity tests in `guardspine-spec` validate cross-language consistency.

v0.2.1 adds optional sanitization metadata (PII/secret redaction attestation). The proof format is unchanged from v0.2.0.

## Installation

```bash
pip install guardspine-kernel
```

Or install from source:

```bash
pip install -e .
```

## Usage

### Sealing a Bundle

```python
from guardspine_kernel import seal_bundle

items = [
    {
        "item_id": "audit-001",
        "content_type": "guardspine/audit_event",
        "content": {"action": "user_login", "user_id": "u123"},
    },
    {
        "item_id": "audit-002",
        "content_type": "guardspine/audit_event",
        "content": {"action": "data_access", "resource": "customers"},
    },
]

result = seal_bundle(items)
print(result.immutability_proof.root_hash)
# sha256:...
```

### Verifying a Bundle

```python
from guardspine_kernel import verify_bundle

bundle = {
    "bundle_id": "bundle-001",
    "version": "0.2.0",
    "created_at": "2026-01-15T10:30:00.000Z",
    "items": [...],
    "immutability_proof": {...},
}

result = verify_bundle(bundle)
if result.valid:
    print("Bundle is valid!")
else:
    for error in result.errors:
        print(f"{error.code}: {error.message}")
```

### Canonical JSON

```python
from guardspine_kernel import canonical_json

# RFC 8785 compliant JSON serialization
obj = {"z": 1, "a": 2}
print(canonical_json(obj))  # {"a":2,"z":1}
```

## Cross-Language Parity

This package MUST produce identical hashes to `@guardspine/kernel` (TypeScript). Run parity tests:

```bash
pytest tests/test_parity.py -v
```

Golden vectors are stored in `../guardspine-spec/fixtures/golden-vectors/`.

## Hardening

Security audit fixes (matching the TS kernel):

- **Seal validation guards**: `seal_bundle` validates `item_id` and `content_type` presence before processing, raises `ValueError` with the offending index
- **Max chain items**: `build_hash_chain` rejects inputs exceeding 10,000 items
- **Proof version support**: both `v0.2.0` (current) and `legacy` (deprecated 3-field chain hash)
- **Non-empty items**: `seal_bundle` raises on empty items list
- **Version enforcement**: `verify_bundle` rejects versions other than `"0.2.0"` or `"0.2.1"`

## Signature Verification

`verify_signatures` supports the same algorithms as the TS kernel:

| Algorithm | Implementation |
|-----------|---------------|
| `ed25519` | `cryptography` library Ed25519 verification |
| `rsa-sha256` | RSA PKCS1v15 with SHA-256 |
| `ecdsa-p256` | ECDSA with SECP256R1 and SHA-256 |
| `hmac-sha256` | `hmac.compare_digest` with shared secret |

Public keys are passed via `public_keys` dict (key_id -> PEM string). HMAC secrets via `hmac_secret` parameter.

## API Reference

### Sealing Functions

- `seal_bundle(items, options, bundle_id, version, created_at)` - Seal items into a bundle dict
- `build_hash_chain(items, options)` - Build hash chain from `ChainInput` list
- `compute_content_hash(content)` - SHA-256 of canonical JSON (`"sha256:<hex>"`)
- `compute_root_hash(chain)` - Root hash over concatenated chain hashes

### Verification Functions

- `verify_bundle(bundle, ...)` - Full bundle verification (fields, content, chain, root, cross-check, signatures)
- `verify_hash_chain(chain, ...)` - Verify chain linkage and recompute chain hashes
- `verify_root_hash(proof)` - Verify root hash matches chain
- `verify_content_hashes(items)` - Verify item content hashes via canonical JSON
- `verify_signatures(bundle, ...)` - Verify Ed25519/RSA/ECDSA/HMAC signatures

### Error Codes

All error codes match `@guardspine/kernel/errors.ts`:

- `MISSING_REQUIRED_FIELD` - Bundle missing required field
- `UNSUPPORTED_VERSION` - Bundle version not "0.2.0" or "0.2.1"
- `INPUT_VALIDATION_FAILED` - Invalid input format
- `CONTENT_HASH_MISMATCH` - Content hash doesn't match
- `HASH_CHAIN_BROKEN` - Chain linkage broken
- `ROOT_HASH_MISMATCH` - Root hash doesn't match
- `SEQUENCE_GAP` - Sequence numbers have gaps
- `LENGTH_MISMATCH` - Items count != chain length
- `SIGNATURE_INVALID` - Signature verification failed
- `SIGNATURE_REQUIRED` - Bundle must have signatures

## License

Apache-2.0
