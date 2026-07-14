"""
STIX 2.1 converter — maps VT IOCResult (file hash) objects to STIX Indicator SDOs.

One Indicator per hash result. The shared TOOL_IDENTITY is included once
in every bundle as the created_by_ref anchor.
"""

from datetime import datetime, timezone
from typing import Optional

import stix2

from normalizers.schema import IOCResult

TOOL_IDENTITY = stix2.Identity(
    name="IOC-Enrichment-Pipeline",
    identity_class="system",
    description="VirusTotal file-hash enrichment and STIX 2.1 export tool",
)


def _detect_hash_type(hash_value: str) -> Optional[str]:
    length = len(hash_value)
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    return None


def _build_pattern(hash_value: str) -> str:
    """Return a STIX pattern string for a file hash.

    Raises ValueError if the hash length doesn't map to MD5 / SHA-1 / SHA-256.
    """
    algo = _detect_hash_type(hash_value)
    if algo is None:
        raise ValueError(
            f"Cannot determine hash algorithm for '{hash_value}' "
            f"(length {len(hash_value)}, expected 32 / 40 / 64 hex chars)"
        )
    return f"[file:hashes.'{algo}' = '{hash_value}']"


def _fmt_ts(iso_str: Optional[str]) -> Optional[str]:
    """Normalise an ISO-8601 timestamp to end with 'Z' as STIX expects."""
    if not iso_str:
        return None
    s = iso_str.strip().replace("+00:00", "Z").replace("-00:00", "Z")
    if s.endswith("Z"):
        return s
    if "+" in s[10:] or "-" in s[10:]:
        return s
    return s + "Z"


def _build_custom_properties(result: IOCResult) -> dict:
    """Map the additional VT fields on IOCResult to STIX 2.1 custom
    properties (the spec-compliant way to extend an SDO — every key must
    be prefixed 'x_'). Only non-empty values are included so the
    Indicator doesn't get cluttered with nulls/empty lists.
    """
    candidates = {
        "x_vt_md5": result.md5,
        "x_vt_sha1": result.sha1,
        "x_vt_sha256": result.sha256,
        "x_vt_vhash": result.vhash,
        "x_vt_ssdeep": result.ssdeep,
        "x_vt_tlsh": result.tlsh,
        "x_vt_authentihash": result.authentihash,
        "x_vt_size": result.size,
        "x_vt_type_description": result.type_description,
        "x_vt_type_tag": result.type_tag,
        "x_vt_type_extension": result.type_extension,
        "x_vt_magic": result.magic,
        "x_vt_names": result.names,
        "x_vt_times_submitted": result.times_submitted,
        "x_vt_last_submission_date": result.last_submission_date,
        "x_vt_reputation": result.reputation,
        "x_vt_total_votes": result.total_votes,
        "x_vt_popular_threat_classification": result.popular_threat_classification,
        "x_vt_engine_detections": result.engine_detections,
        "x_vt_pe_info": result.pe_info,
        "x_vt_signature_info": result.signature_info,
        "x_vt_exiftool": result.exiftool,
        "x_vt_trid": result.trid,
        "x_vt_sandbox_verdicts": result.sandbox_verdicts,
    }
    return {k: v for k, v in candidates.items() if v not in (None, [], {}, "")}


def to_stix_indicator(
    result: IOCResult,
    identity: stix2.Identity = TOOL_IDENTITY,
) -> Optional[stix2.Indicator]:
    """Convert a VT IOCResult for a file hash into a STIX 2.1 Indicator SDO.

    Returns None when there is no actionable verdict (query failed or
    malicious is None), so callers can safely filter with ``if indicator``.
    """
    if not result.query_success or result.malicious is None:
        return None

    try:
        pattern = _build_pattern(result.ioc)
    except ValueError:
        return None

    indicator_type = "malicious-activity" if result.malicious else "benign"

    display_ioc = (result.ioc[:48] + "...") if len(result.ioc) > 48 else result.ioc
    name = f"{display_ioc} (hash) - virustotal"

    description_parts = ["Source: virustotal"]
    if result.source_url:
        description_parts.append(f"Report: {result.source_url}")
    if result.raw_score is not None:
        description_parts.append(f"Detection ratio: {result.raw_score:.2%}")
    description = "; ".join(description_parts)

    valid_from = _fmt_ts(result.first_seen) or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    valid_until = _fmt_ts(result.last_seen)

    kwargs: dict = {
        "name": name,
        "description": description,
        "pattern": pattern,
        "pattern_type": "stix",
        "created_by_ref": str(identity.id),
        "valid_from": valid_from,
        "indicator_types": [indicator_type],
        "labels": list(result.tags),
    }

    if result.confidence is not None:
        kwargs["confidence"] = result.confidence
    if valid_until is not None and valid_until > valid_from:
        kwargs["valid_until"] = valid_until

    kwargs.update(_build_custom_properties(result))

    return stix2.Indicator(**kwargs, allow_custom=True)


def to_stix_bundle(
    results: list[IOCResult],
    identity: stix2.Identity = TOOL_IDENTITY,
) -> stix2.Bundle:
    """Convert a list of VT IOCResults into a STIX 2.1 Bundle.

    The shared Identity is included first, followed by one Indicator per
    result that has a usable verdict. Results without a verdict are silently
    excluded (query failed, or VT returned no engine data).
    """
    objects: list = [identity]

    for result in results:
        indicator = to_stix_indicator(result, identity)
        if indicator is not None:
            objects.append(indicator)

    return stix2.Bundle(*objects, allow_custom=True)
