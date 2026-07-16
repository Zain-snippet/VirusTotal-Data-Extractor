"""
Generic JSON parser — walks any JSON structure and extracts IOC values
by their string format alone.

The parser does not rely on key names or schema.  It classifies every
scalar string value by inspecting its length and character set.
"""

from typing import Any

from parsers.validator import is_hash, is_ipv4


def parse_json(data: Any) -> dict[str, list[dict]]:
    """Walk a parsed JSON tree and return detected IOCs by type.

    Classification rules (value-based only, no field-name heuristics):

    * IPv4 address   → ``ip``
    * 32/40/64 hex   → ``hash``   (MD5 / SHA-1 / SHA-256; JA3 and
      certificate SHA-1 are value-identical to MD5 and SHA-1 respectively,
      so they are collected under ``hash`` — only STIX-pattern context
      can distinguish them.)

    Returns the standard four-key dict (``hash``, ``ip``, ``cert_hash``,
    ``ja3``).  ``cert_hash`` and ``ja3`` are always empty for generic
    JSON since they cannot be distinguished by value alone.

    Each list holds dicts with keys ``value`` (the IOC string) and
    ``origin_data`` (the nearest enclosing parent dict, or ``{}`` if the
    match was not inside a dict).
    """
    iocs: dict[str, list[dict]] = {
        "hash": [],
        "ip": [],
        "cert_hash": [],
        "ja3": [],
    }
    seen: dict[str, set[str]] = {k: set() for k in iocs}

    def _walk(obj: object, parent_dict: object = None) -> None:
        if isinstance(obj, str):
            if is_ipv4(obj):
                key = obj.lower()
                if key not in seen["ip"]:
                    seen["ip"].add(key)
                    origin = dict(parent_dict) if isinstance(parent_dict, dict) else {}
                    iocs["ip"].append({"value": obj, "origin_data": origin})
            elif is_hash(obj):
                key = obj.lower()
                if key not in seen["hash"]:
                    seen["hash"].add(key)
                    origin = dict(parent_dict) if isinstance(parent_dict, dict) else {}
                    iocs["hash"].append({"value": obj, "origin_data": origin})
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v, obj)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, parent_dict)

    _walk(data)
    return iocs
