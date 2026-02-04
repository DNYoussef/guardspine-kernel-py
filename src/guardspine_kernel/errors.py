"""
Error codes and types for guardspine-kernel.

Error codes MUST match @guardspine/kernel (TypeScript) exactly for
cross-language consistency in audit trails.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    """
    Verification error codes.
    MUST match @guardspine/kernel/errors.ts exactly.
    """
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INPUT_VALIDATION_FAILED = "INPUT_VALIDATION_FAILED"
    CONTENT_HASH_MISMATCH = "CONTENT_HASH_MISMATCH"
    HASH_CHAIN_BROKEN = "HASH_CHAIN_BROKEN"
    ROOT_HASH_MISMATCH = "ROOT_HASH_MISMATCH"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    LENGTH_MISMATCH = "LENGTH_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SIGNATURE_REQUIRED = "SIGNATURE_REQUIRED"


@dataclass
class VerificationError:
    """
    A single verification error with typed code and audit details.
    """
    code: ErrorCode
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class VerificationResult:
    """
    Result of a verification operation.
    """
    valid: bool
    errors: list[VerificationError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
        }
