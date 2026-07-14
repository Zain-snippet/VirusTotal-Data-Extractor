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

import json
import re
import sys
from pathlib import Path

# ── Hash validation ───────────────────────────────────────────────────

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_VALID_LENGTHS = {32, 40, 64}  # MD5, SHA-1, SHA-256


def _is_hash(value: str) -> bool:
    return len(value) in _VALID_LENGTHS and bool(_HEX_RE.match(value))


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

        if not _is_hash(line):
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

# ── Shared hash-walk helper ──────────────────────────────────────────

def _walk_json_for_hashes(data: object) -> list[str]:
    """Recursively walk a parsed JSON tree and extract hex hash strings.

    Returns a deduplicated list (case-insensitive, first-seen order) of
    strings that are 32, 40, or 64 hex characters (MD5 / SHA-1 / SHA-256).
    """
    hashes: list[str] = []
    seen: set[str] = set()

    def _walk(obj: object) -> None:
        if isinstance(obj, str):
            if _is_hash(obj):
                key = obj.lower()
                if key not in seen:
                    seen.add(key)
                    hashes.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(data)
    return hashes


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
    path = Path(filepath)

    if not path.exists():
        print(f"[error] File not found: {filepath}", file=sys.stderr)
        return []

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[error] Failed to parse JSON from '{filepath}': {e}", file=sys.stderr)
        return []
    except OSError as e:
        print(f"[error] Could not read '{filepath}': {e}", file=sys.stderr)
        return []

    return _walk_json_for_hashes(data)


# ── Input method 3: multi-IOC-type extraction from STIX / flat JSON ──

# Patterns used for extracting values from STIX indicator patterns.
# Each group captures the quoted value (without surrounding single quotes).
_RE_IP = re.compile(r"""ipv4-addr:value\s*=\s*'([^']+)'""", re.IGNORECASE)
_RE_CERT_HASH = re.compile(
    r"""x509-certificate:hashes\s*\.\s*'SHA-1'\s*=\s*'([^']+)'""", re.IGNORECASE
)
_RE_JA3 = re.compile(r"""x-ja3-fingerprint:hash\s*=\s*'([^']+)'""", re.IGNORECASE)
_RE_FILE_HASH = re.compile(r"""file:hashes\s*\.\s*'[^']+'\s*=\s*'([^']+)'""", re.IGNORECASE)


def _dedup(values: list[str]) -> list[str]:
    """Deduplicate strings case-insensitively, preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            result.append(v)
    return result


def extract_iocs_from_file(filepath: str) -> dict[str, list[str]]:
    """Parse a JSON file and return all detected IOCs categorised by type.

    Returns a dict with keys ``hash``, ``ip``, ``cert_hash``, ``ja3``,
    each holding a deduplicated list of string values. Every key is
    always present (empty list if none found).

    Two file shapes are handled automatically (distinguished by structure):

    1. STIX 2.1 bundle (has ``"type": "bundle"`` and an ``"objects"``
       list) — each indicator's ``pattern`` field is parsed to classify and
       extract the IOC value.

    2. Flat / nested JSON without a STIX structure — falls back to the
       same recursive hex-hash walk as ``get_hashes_from_file()``, placing
       everything into the ``hash`` key only.
    """
    path = Path(filepath)

    if not path.exists():
        print(f"[error] File not found: {filepath}", file=sys.stderr)
        return {"hash": [], "ip": [], "cert_hash": [], "ja3": []}

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[error] Failed to parse JSON from '{filepath}': {e}", file=sys.stderr)
        return {"hash": [], "ip": [], "cert_hash": [], "ja3": []}
    except OSError as e:
        print(f"[error] Could not read '{filepath}': {e}", file=sys.stderr)
        return {"hash": [], "ip": [], "cert_hash": [], "ja3": []}

    # Detect STIX 2.1 bundle by structure
    is_stix_bundle = (
        isinstance(data, dict)
        and data.get("type") == "bundle"
        and "objects" in data
    )

    if not is_stix_bundle:
        # Flat JSON — walk for hash-shaped strings only
        return {
            "hash": _walk_json_for_hashes(data),
            "ip": [],
            "cert_hash": [],
            "ja3": [],
        }

    # STIX bundle — classify each indicator by its pattern
    ips: list[str] = []
    cert_hashes: list[str] = []
    ja3s: list[str] = []
    hashes: list[str] = []

    objects = data.get("objects", [])
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        if not isinstance(pattern, str):
            continue

        m = _RE_IP.search(pattern)
        if m:
            ips.append(m.group(1))
            continue
        m = _RE_CERT_HASH.search(pattern)
        if m:
            cert_hashes.append(m.group(1))
            continue
        m = _RE_JA3.search(pattern)
        if m:
            ja3s.append(m.group(1))
            continue
        m = _RE_FILE_HASH.search(pattern)
        if m:
            hashes.append(m.group(1))

    return {
        "hash": _dedup(hashes),
        "ip": _dedup(ips),
        "cert_hash": _dedup(cert_hashes),
        "ja3": _dedup(ja3s),
    }
