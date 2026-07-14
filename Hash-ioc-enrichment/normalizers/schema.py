from dataclasses import dataclass, field
from typing import Optional


class NormalizationError(Exception):
    pass


@dataclass
class IOCResult:
    source: str
    ioc: str
    ioc_type: str
    malicious: Optional[bool] = None
    confidence: Optional[int] = None
    raw_score: Optional[float] = None
    tags: list[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_url: Optional[str] = None
    query_success: bool = True
    error: Optional[str] = None

    # ── Additional VirusTotal data (free tier, same /files/{hash} call) ──
    # File identity / alternate + fuzzy hashes
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    vhash: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    authentihash: Optional[str] = None

    # File type / structural metadata
    size: Optional[int] = None
    type_description: Optional[str] = None
    type_tag: Optional[str] = None
    type_extension: Optional[str] = None
    magic: Optional[str] = None
    names: list[str] = field(default_factory=list)

    # Submission / activity metadata
    times_submitted: Optional[int] = None
    last_submission_date: Optional[str] = None

    # Community reputation
    reputation: Optional[int] = None
    total_votes: Optional[dict] = None

    # VT's own threat classification
    popular_threat_classification: Optional[dict] = None

    # Trimmed per-engine detections — only engines that flagged the file as
    # malicious/suspicious (the full ~70-engine dump is redundant with
    # last_analysis_stats and adds little beyond this).
    engine_detections: list[dict] = field(default_factory=list)

    # PE structural features (PE files only) — key subfields, not a full
    # raw dump (imports/sections can be very large and inconsistent).
    pe_info: Optional[dict] = None

    # Digital signature summary (key subfields only)
    signature_info: Optional[dict] = None

    # Small/bounded fields — passed through as-is
    exiftool: Optional[dict] = None
    trid: list[dict] = field(default_factory=list)
    sandbox_verdicts: Optional[dict] = None

    # ── IP-address-specific fields (populated when ioc_type == "ip") ──
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    country: Optional[str] = None
    continent: Optional[str] = None
    network: Optional[str] = None
    regional_internet_registry: Optional[str] = None
    whois: Optional[str] = None