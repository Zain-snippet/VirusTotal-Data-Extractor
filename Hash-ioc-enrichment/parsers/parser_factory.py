"""
Parser factory — auto-detects file format and dispatches to the
appropriate parser.

The rest of the project calls exactly one function
(``extract_iocs_from_file`` from *input_handlers.py*); this module is
the internal dispatch mechanism that keeps the caller format-agnostic.
"""

import json
import sys
from pathlib import Path
from typing import Any

from parsers.stix_parser import parse_stix_bundle
from parsers.json_parser import parse_json


def _load_json(path: Path) -> Any:
    """Load and return parsed JSON, or *None* on failure."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[error] Failed to parse JSON from '{path}': {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"[error] Could not read '{path}': {e}", file=sys.stderr)
        return None


def _is_stix_bundle(data: Any) -> bool:
    """Detect a STIX 2.1 bundle by structure (not filename)."""
    return (
        isinstance(data, dict)
        and data.get("type") == "bundle"
        and "objects" in data
    )


def detect_and_parse(filepath: str) -> dict[str, list[str]]:
    """Detect the input format and return categorised IOCs.

    Returns the standard four-key dict — every key present, possibly
    with an empty list.
    """
    path = Path(filepath)

    if not path.exists():
        print(f"[error] File not found: {filepath}", file=sys.stderr)
        return {"hash": [], "ip": [], "cert_hash": [], "ja3": []}

    data = _load_json(path)
    if data is None:
        return {"hash": [], "ip": [], "cert_hash": [], "ja3": []}

    if _is_stix_bundle(data):
        return parse_stix_bundle(data)

    return parse_json(data)
