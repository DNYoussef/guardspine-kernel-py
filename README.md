# guardspine-kernel-py

Python port of the GuardSpine kernel for evidence-bundle verification and sealing.

## Language Implementations

| Language | Package | Purpose |
|----------|---------|---------|
| **TypeScript** | [@guardspine/kernel](https://github.com/DNYoussef/guardspine-kernel) | Reference implementation - used by OpenClaw plugin |
| **Python** (this repo) | `guardspine-kernel` | For Python integrations (FastAPI, scripts, ML pipelines) |

This Python library MUST produce **byte-identical hashes** to the TypeScript reference. Use golden vector parity tests to verify cross-language consistency.

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

## API Reference

### Sealing Functions

- `seal_bundle(items, options)` - Seal a list of items into a bundle
- `build_hash_chain(items, options)` - Build a hash chain from items
- `compute_content_hash(content)` - SHA-256 of canonical JSON
- `compute_root_hash(chain)` - Root hash of a chain

### Verification Functions

- `verify_bundle(bundle, ...)` - Full bundle verification
- `verify_hash_chain(chain, ...)` - Verify chain linkage
- `verify_root_hash(proof)` - Verify root hash
- `verify_content_hashes(items)` - Verify item content hashes
- `verify_signatures(bundle, ...)` - Verify bundle signatures

### Error Codes

All error codes match `@guardspine/kernel/errors.ts`:

- `MISSING_REQUIRED_FIELD` - Bundle missing required field
- `UNSUPPORTED_VERSION` - Bundle version not supported
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
