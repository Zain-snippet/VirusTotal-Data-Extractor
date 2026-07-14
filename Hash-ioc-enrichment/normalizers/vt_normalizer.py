"""
vt_normalizer.py
VirusTotal normalizer — maps VirusTotal v3 raw JSON to IOCResult.

Key judgment calls are documented as module-level constants.

VirusTotal aggregates detections from ~70+ AV engines. Using a threshold
of >= 3 malicious detections reduces the impact of single-engine false
positives (which are common — one engine flagging a benign file as
malware does not make it malicious). The 3-engine threshold is a common
industry heuristic; many TIP platforms default to this or similar values.
"""

import datetime
from typing import Optional

from normalizers.schema import IOCResult, NormalizationError

# Minimum number of AV engines flagging the IOC as malicious before we
# consider it malicious. Single-engine hits are often false positives
# (e.g., generic/heuristic detections on clean files). 3 engines provides
# reasonable confidence that multiple independent vendors agree.
VT_MALICIOUS_ENGINE_THRESHOLD = 3

# URL path segment mapping for VT web UI links
VT_UI_PATH: dict[str, str] = {
    "hash": "file",
    "ip": "ip-address",
    "cert_hash": "file",
}


def _ts_to_iso(ts: Optional[int]) -> Optional[str]:
    if ts is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return None


def _extract_engine_detections(last_analysis_results: dict) -> list[dict]:
    """Trim VT's ~70-engine `last_analysis_results` down to just the
    engines that actually flagged the file (malicious/suspicious).

    The full per-engine dump is mostly "undetected" noise already
    summarized in last_analysis_stats; keeping only the hits preserves
    the useful signal (family/label agreement across vendors) without
    bloating every record with ~65 uninformative entries.
    """
    detections = []
    for engine_name, engine_result in (last_analysis_results or {}).items():
        category = engine_result.get("category")
        if category in ("malicious", "suspicious"):
            detections.append({
                "engine": engine_name,
                "category": category,
                "result": engine_result.get("result"),
            })
    return detections


def _extract_pe_info(pe_info: Optional[dict]) -> Optional[dict]:
    """Pull key structural features out of VT's pe_info block.

    Skips the full imports/resources dump (large, inconsistent across
    files) in favor of a compact set of fields useful as ML features.
    """
    if not pe_info:
        return None

    sections = pe_info.get("sections") or []
    section_summary = [
        {
            "name": s.get("name"),
            "entropy": s.get("entropy"),
            "raw_size": s.get("raw_size"),
        }
        for s in sections
    ]

    import_list = pe_info.get("import_list") or []
    imported_libraries = [
        lib.get("library_name") for lib in import_list if lib.get("library_name")
    ]

    return {
        "imphash": pe_info.get("imphash"),
        "compile_timestamp": pe_info.get("timestamp"),
        "machine_type": pe_info.get("machine_type"),
        "entry_point": pe_info.get("entry_point"),
        "sections": section_summary,
        "imported_libraries": imported_libraries,
        "overlay": pe_info.get("overlay"),
    }


def _extract_signature_info(signature_info: Optional[dict]) -> Optional[dict]:
    """Pull key fields out of VT's signature_info block (signer identity
    and verification status), skipping the full certificate chain dump.
    """
    if not signature_info:
        return None

    return {
        "verified": signature_info.get("verified"),
        "signers": signature_info.get("signers"),
        "counter_signers": signature_info.get("counter signers"),
        "signing_date": signature_info.get("signing date"),
    }


def _extract_shared(attrs: dict) -> tuple:
    """Extract fields common to both file and IP VT responses.

    Returns a tuple of (malicious, raw_score, confidence, tags, first_seen,
    last_seen, source_url, total_votes, engine_detections, reputation).
    """
    stats = attrs.get("last_analysis_stats", {})
    malicious_count: int = stats.get("malicious", 0)
    suspicious_count: int = stats.get("suspicious", 0)
    harmless_count: int = stats.get("harmless", 0)
    undetected_count: int = stats.get("undetected", 0)

    total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

    malicious = malicious_count >= VT_MALICIOUS_ENGINE_THRESHOLD

    if total_engines > 0:
        raw_score = round(malicious_count / total_engines, 4)
    else:
        raw_score = None

    confidence = None
    tags: list[str] = attrs.get("tags", []) or []

    first_ts = (
        attrs.get("first_submission_date")
        or attrs.get("first_seen_itw_date")
        or attrs.get("creation_date")
    )
    last_ts = (
        attrs.get("last_analysis_date")
        or attrs.get("last_modification_date")
    )

    first_seen = _ts_to_iso(first_ts)
    last_seen = _ts_to_iso(last_ts)

    total_votes = attrs.get("total_votes")
    reputation = attrs.get("reputation")
    engine_detections = _extract_engine_detections(
        attrs.get("last_analysis_results", {})
    )

    return malicious, raw_score, confidence, tags, first_seen, last_seen, total_votes, engine_detections, reputation


def normalize(raw: dict, ioc: str, ioc_type: str) -> IOCResult:
    try:
        data = raw.get("data", {})
        attrs = data.get("attributes", {})

        (malicious, raw_score, confidence, tags, first_seen, last_seen,
         total_votes, engine_detections, reputation) = _extract_shared(attrs)

        ui_path = VT_UI_PATH.get(ioc_type, ioc_type)
        source_url = f"https://www.virustotal.com/gui/{ui_path}/{ioc}/detection"

        if ioc_type == "ip":
            return IOCResult(
                source="virustotal",
                ioc=ioc,
                ioc_type=ioc_type,
                malicious=malicious,
                confidence=confidence,
                raw_score=raw_score,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                source_url=source_url,
                query_success=True,
                error=None,
                reputation=reputation,
                total_votes=total_votes,
                engine_detections=engine_detections,
                asn=attrs.get("asn"),
                as_owner=attrs.get("as_owner"),
                country=attrs.get("country"),
                continent=attrs.get("continent"),
                network=attrs.get("network"),
                regional_internet_registry=attrs.get("regional_internet_registry"),
                whois=attrs.get("whois"),
            )

        # ioc_type in ("hash", "cert_hash") — identical file-attribute extraction
        last_submission_date = _ts_to_iso(attrs.get("last_submission_date"))
        pe_info = _extract_pe_info(attrs.get("pe_info"))
        signature_info = _extract_signature_info(attrs.get("signature_info"))

        return IOCResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            malicious=malicious,
            confidence=confidence,
            raw_score=raw_score,
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            source_url=source_url,
            query_success=True,
            error=None,
            md5=attrs.get("md5"),
            sha1=attrs.get("sha1"),
            sha256=attrs.get("sha256"),
            vhash=attrs.get("vhash"),
            ssdeep=attrs.get("ssdeep"),
            tlsh=attrs.get("tlsh"),
            authentihash=attrs.get("authentihash"),
            size=attrs.get("size"),
            type_description=attrs.get("type_description"),
            type_tag=attrs.get("type_tag"),
            type_extension=attrs.get("type_extension"),
            magic=attrs.get("magic"),
            names=attrs.get("names", []) or [],
            times_submitted=attrs.get("times_submitted"),
            last_submission_date=last_submission_date,
            reputation=reputation,
            total_votes=total_votes,
            popular_threat_classification=attrs.get("popular_threat_classification"),
            engine_detections=engine_detections,
            pe_info=pe_info,
            signature_info=signature_info,
            exiftool=attrs.get("exiftool"),
            trid=attrs.get("trid", []) or [],
            sandbox_verdicts=attrs.get("sandbox_verdicts"),
        )

    except (KeyError, TypeError, IndexError, ValueError) as e:
        try:
            return IOCResult(
                source="virustotal",
                ioc=ioc,
                ioc_type=ioc_type,
                malicious=None,
                confidence=None,
                raw_score=None,
                tags=[],
                first_seen=None,
                last_seen=None,
                source_url=None,
                query_success=False,
                error=f"Normalization failed: {e}",
            )
        except Exception:
            raise NormalizationError(
                f"Unexpected failure normalizing VirusTotal result for {ioc}"
            ) from e