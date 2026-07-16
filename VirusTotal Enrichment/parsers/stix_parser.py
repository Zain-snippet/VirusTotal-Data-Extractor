"""
STIX 2.1 pattern parser — extracts IOC values from indicator patterns.

Handles the common variations (quote style, spacing, AND/OR joins,
parentheses) that the old regex-only approach could not cope with.
"""

import re
from typing import Optional

from parsers.validator import is_hash, is_ipv4, is_cert_hash, is_ja3

# Split a comparison expression on the operator.
# The operator is one of: =  !=  <>  <=  >=
_OP_RE = re.compile(r"\s*(!=|<>|<=|>=|=)\s*")


def _split_top_level(text: str) -> list[str]:
    """Split a STIX pattern on AND / OR at depth 0 (outside parentheses).

    Returns individual comparison-expression strings with outer
    parentheses stripped.
    """
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if ch in ("(", "[", "{"):
            depth += 1
            buf.append(ch)
            i += 1
        elif ch in (")", "]", "}"):
            depth -= 1
            buf.append(ch)
            i += 1
        elif depth == 0 and i + 3 <= n and text[i : i + 3].upper() == "AND":
            parts.append("".join(buf).strip())
            buf.clear()
            i += 3
        elif depth == 0 and i + 2 <= n and text[i : i + 2].upper() == "OR":
            parts.append("".join(buf).strip())
            buf.clear()
            i += 2
        else:
            buf.append(ch)
            i += 1

    remaining = "".join(buf).strip()
    if remaining:
        parts.append(remaining)

    return parts


def _strip_brackets(pattern: str) -> str:
    """Remove outer STIX brackets ``[…]`` if present."""
    s = pattern.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    return s.strip()


def _strip_parens(expr: str) -> str:
    """Strip matching outer parentheses from an expression."""
    s = expr.strip()
    while s.startswith("(") and s.endswith(")"):
        inner = s[1:-1].strip()
        depth = 0
        balanced = True
        for ch in s[1:-1]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth < 0:
                balanced = False
                break
        if balanced and depth == 0:
            s = inner
        else:
            break
    return s


def _classify_path(path: str) -> Optional[str]:
    """Map a STIX object-path string to an IOC type key.

    Returns one of ``"hash"``, ``"ip"``, ``"cert_hash"``, ``"ja3"``,
    or *None* if the path is not recognised.
    """
    lower = path.lower().replace(" ", "")

    if lower.startswith("file:hashes"):
        return "hash"
    if lower.startswith("ipv4-addr:value"):
        return "ip"
    if lower.startswith("x509-certificate:hashes"):
        return "cert_hash"
    if lower.startswith("x-ja3-fingerprint:hash"):
        return "ja3"

    return None


def _validate_value(ioc_type: str, value: str) -> bool:
    """Confirm that a value matches the expected format for its type."""
    if ioc_type == "ip":
        return is_ipv4(value)
    if ioc_type in ("hash", "cert_hash"):
        return is_hash(value)
    if ioc_type == "ja3":
        return is_ja3(value)
    return False


def parse_pattern(pattern: str) -> list[tuple[str, str]]:
    """Parse a STIX 2.1 indicator pattern and return extracted IOCs.

    Returns a list of ``(ioc_type, value)`` tuples, e.g.::

        [("hash", "d41d8cd98f00b204e9800998ecf8427e"),
         ("ip", "1.2.3.4")]

    Handles joined expressions (AND / OR), parentheses, and the common
    quoting / spacing variations that the old regex approach missed.
    Duplicate detection is left to the caller.
    """
    body = _strip_brackets(pattern)
    exprs = _split_top_level(body)

    results: list[tuple[str, str]] = []

    for expr in exprs:
        expr = _strip_parens(expr)
        if not expr:
            continue

        m = _OP_RE.search(expr)
        if not m:
            continue

        path = expr[: m.start()].strip()
        value = expr[m.end() :].strip().strip("'\"")

        if not path or not value:
            continue

        ioc_type = _classify_path(path)
        if ioc_type is None:
            continue

        if not _validate_value(ioc_type, value):
            continue

        results.append((ioc_type, value))

    return results


def parse_stix_bundle(data: dict) -> dict[str, list[dict]]:
    """Extract all IOCs from a STIX 2.1 bundle dict.

    Returns the standard four-key dict: ``hash``, ``ip``, ``cert_hash``,
    ``ja3``.  Every key is present (empty list if none found).

    Each list holds dicts with keys ``value`` (the IOC string) and
    ``origin_data`` (relevant fields from the parent indicator object,
    e.g. labels, description, valid_from).
    """
    by_type: dict[str, list[dict]] = {
        "hash": [],
        "ip": [],
        "cert_hash": [],
        "ja3": [],
    }

    seen: dict[str, set[str]] = {k: set() for k in by_type}

    for obj in data.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        if not isinstance(pattern, str) or not pattern:
            continue

        origin_data = {
            k: obj.get(k)
            for k in ("labels", "description", "valid_from", "pattern", "created", "modified", "indicator_types")
            if obj.get(k) is not None
        }

        for ioc_type, value in parse_pattern(pattern):
            key = value.lower()
            if key not in seen[ioc_type]:
                seen[ioc_type].add(key)
                by_type[ioc_type].append({"value": value, "origin_data": origin_data})

    return by_type
