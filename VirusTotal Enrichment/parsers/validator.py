"""
Shared IOC validation — single source of truth for detecting IOC types
by value alone.

Every parser in this package uses these functions so that validation
logic is never duplicated.
"""

import re

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Octet must be 0–255; we validate numerically after the pattern match.
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _is_hex(value: str) -> bool:
    return bool(_HEX_RE.match(value))


def is_md5(value: str) -> bool:
    return len(value) == 32 and _is_hex(value)


def is_sha1(value: str) -> bool:
    return len(value) == 40 and _is_hex(value)


def is_sha256(value: str) -> bool:
    return len(value) == 64 and _is_hex(value)


def is_hash(value: str) -> bool:
    """Any MD5 / SHA-1 / SHA-256 hex string."""
    return len(value) in (32, 40, 64) and _is_hex(value)


def is_ipv4(value: str) -> bool:
    m = _IPV4_RE.match(value)
    if not m:
        return False
    return all(0 <= int(m.group(i)) <= 255 for i in range(1, 5))


def is_cert_hash(value: str) -> bool:
    """Certificate SHA-1 — a 40-char hex string (value-identical to SHA-1)."""
    return is_sha1(value)


def is_ja3(value: str) -> bool:
    """JA3 fingerprint — a 32-char hex string (value-identical to MD5)."""
    return is_md5(value)
