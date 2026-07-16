"""
Input handlers — two independent, swappable sources of hash values.

Both functions return the same shape: list[str] of valid hash strings
(deduplicated, preserving first-seen order). Downstream code does not
need to know which one supplied the input.

Switching between them in main() is a one-line comment/uncomment:

    hashes = get_hashes_from_user_input()
    # hashes = get_hashes_from_file("path/to/file.json")

Each function is fully self-contained. Deleting one has zero effect on
the other or on any code that consumes the returned list.
"""

import sys
from pathlib import Path

from parsers.validator import is_hash
from parsers.parser_factory import detect_and_parse


# ── Input method 1: interactive prompt ───────────────────────────────

def get_hashes_from_user_input() -> list[str]:
    """Prompt the user to enter file hashes interactively.

    All fields are optional — pressing Enter on a blank line ends input.
    Invalid values (wrong length, non-hex) are skipped with a warning.
    Duplicates (case-insensitive) are silently deduplicated.

    Returns a list of valid hash strings (may be empty if the user
    skips everything).
    """
    print("\nEnter file hashes to look up (MD5 / SHA-1 / SHA-256).")
    print("One hash per line. Press Enter on a blank line when done.")
    print("All fields are optional — you can press Enter immediately to skip.\n")

    hashes: list[str] = []
    seen: set[str] = set()

    while True:
        try:
            line = input("  Hash (or Enter to finish): ").strip()
        except EOFError:
            break

        if not line:
            break

        if not is_hash(line):
            print(
                f"    [skip] not a valid MD5/SHA-1/SHA-256 hash "
                f"(got {len(line)} chars, expected 32/40/64 hex): {line[:32]}"
            )
            continue

        key = line.lower()
        if key in seen:
            print(f"    [skip] duplicate: {line[:16]}...")
            continue

        seen.add(key)
        hashes.append(line)

    return hashes


# ── Input method 2: JSON file extraction ─────────────────────────────

def get_hashes_from_file(filepath: str) -> list[str]:
    """Parse a JSON file and extract every hash value anywhere in the structure.

    Recursively walks the entire parsed JSON tree. Any string that is
    32, 40, or 64 hex characters is treated as a hash (MD5, SHA-1,
    SHA-256 respectively). The walk is structure-agnostic — it does not
    rely on key names, array positions, or nesting depth.

    Duplicates are removed (case-insensitive). Order reflects the first
    occurrence found during depth-first traversal.

    Args:
        filepath: Path to a JSON file (str or path-like).

    Returns:
        A deduplicated list of hash strings. Returns an empty list if the
        file cannot be read, does not exist, or contains no matching values.
    """
    iocs = detect_and_parse(filepath)
    return [item["value"] for item in iocs["hash"]]


# ── Input method 3: multi-IOC-type extraction (auto-detected format) ──

def extract_iocs_from_file(filepath: str) -> dict[str, list[dict]]:
    """Parse a JSON file and return all detected IOCs categorised by type.

    The input format is detected automatically:

    1. **STIX 2.1 bundle** (has ``"type": "bundle"`` and an ``"objects"``
       list) — each indicator's ``pattern`` field is parsed robustly,
       handling variations in quoting, spacing, AND/OR joins, and
       parentheses.

    2. **Generic JSON** — every string value is inspected; IPv4 addresses
       go into ``ip``; 32/40/64 hex strings go into ``hash``.

    Returns a dict with keys ``hash``, ``ip``, ``cert_hash``, ``ja3``,
    each holding a deduplicated list of dicts with ``value`` and
    ``origin_data`` keys. Every key is always present (empty list if
    none found).
    """
    return detect_and_parse(filepath)
