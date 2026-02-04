"""
guardspine-kernel: Offline evidence-bundle verification and sealing.

This is the canonical Python implementation that MUST produce identical
results to @guardspine/kernel (TypeScript). Use golden vector parity
tests to verify cross-language consistency.
"""

from .canonical import canonical_json
from .seal import (
    GENESIS_HASH,
    compute_content_hash,
    build_hash_chain,
    compute_root_hash,
    seal_bundle,
)
from .verify import (
    verify_bundle,
    verify_hash_chain,
    verify_root_hash,
    verify_content_hashes,
    verify_signatures,
)
from .errors import (
    ErrorCode,
    VerificationError,
    VerificationResult,
)

__version__ = "0.2.0"
__all__ = [
    # Canonical JSON
    "canonical_json",
    # Sealing
    "GENESIS_HASH",
    "compute_content_hash",
    "build_hash_chain",
    "compute_root_hash",
    "seal_bundle",
    # Verification
    "verify_bundle",
    "verify_hash_chain",
    "verify_root_hash",
    "verify_content_hashes",
    "verify_signatures",
    # Errors
    "ErrorCode",
    "VerificationError",
    "VerificationResult",
]
