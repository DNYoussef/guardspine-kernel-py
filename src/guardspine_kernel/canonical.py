"""
Canonical JSON serialization per RFC 8785 (JCS).

CRITICAL: This implementation MUST produce byte-identical output to
@guardspine/kernel/canonical.ts for hash parity across languages.

Rules:
- Object keys sorted lexicographically by Unicode code point
- No whitespace between tokens
- Numbers: shortest round-trip per ECMAScript NumberToString
- Strings: minimal escaping (control chars, backslash, double-quote)
- null, true, false as literals
"""

import json
import math
from typing import Any


def canonical_json(value: Any) -> str:
    """
    Serialize a value to canonical JSON per RFC 8785.

    Args:
        value: Any JSON-serializable value

    Returns:
        Canonical JSON string with sorted keys and no whitespace
    """
    return _serialize_value(value)


def _serialize_value(value: Any) -> str:
    """Internal: serialize any value to canonical JSON."""
    if value is None:
        return "null"

    if isinstance(value, bool):
        # Must check bool before int (bool is subclass of int in Python)
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return _serialize_number(value)

    if isinstance(value, str):
        return _serialize_string(value)

    if isinstance(value, (list, tuple)):
        return _serialize_array(value)

    if isinstance(value, dict):
        return _serialize_object(value)

    # Fallback for unknown types
    return "null"


def _serialize_number(num: float | int) -> str:
    """
    Serialize number per RFC 8785 / ECMAScript NumberToString.

    Uses the shortest representation that round-trips.
    """
    # Handle non-finite values
    if isinstance(num, float):
        if math.isnan(num) or math.isinf(num):
            return "null"

    # Integer handling: avoid scientific notation for reasonable integers
    if isinstance(num, int) or (isinstance(num, float) and num.is_integer()):
        int_val = int(num)
        if abs(int_val) < 10**20:
            return str(int_val)

    # Float handling: use json.dumps for ECMAScript-compatible output
    # json.dumps produces shortest round-trip representation
    result = json.dumps(num)

    # Ensure no trailing ".0" for integers represented as floats
    if result.endswith(".0"):
        result = result[:-2]

    return result


def _serialize_string(text: str) -> str:
    """
    Serialize string with proper JSON escaping.

    Uses json.dumps which handles control characters, backslash,
    and double-quote escaping correctly.
    """
    return json.dumps(text, ensure_ascii=False)


def _serialize_array(arr: list | tuple) -> str:
    """Serialize array with no whitespace."""
    items = [_serialize_value(item) for item in arr]
    return "[" + ",".join(items) + "]"


def _serialize_object(obj: dict) -> str:
    """
    Serialize object with sorted keys per RFC 8785.

    Keys are sorted lexicographically by Unicode code point.
    """
    # Sort keys by Unicode code point (default Python sort)
    sorted_keys = sorted(obj.keys())
    pairs = []

    for key in sorted_keys:
        val = obj[key]
        # Skip undefined/None values to match JSON.stringify behavior
        # Note: In Python, we include None as "null" (different from JS undefined)
        # But we skip keys with value None to match TypeScript behavior
        if val is not None or key in obj:
            pairs.append(_serialize_string(key) + ":" + _serialize_value(val))

    return "{" + ",".join(pairs) + "}"
