import logging
from datetime import datetime, timezone

from stix2 import Bundle, CustomObservable, Indicator
from stix2.properties import StringProperty

logger = logging.getLogger("sslbl_pipeline")

# Register custom observable for JA3 fingerprints so the library recognises it
# in indicator patterns.
CustomObservable(
    "x-ja3-fingerprint",
    properties={
        "hash": StringProperty(required=True),
    },
)

_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d")


def _parse_timestamp(date_str: str) -> datetime:
    """Parse an SSLBL date string into an aware datetime.

    Args:
        date_str: Date string in ``YYYY-MM-DD`` or ``YYYY-MM-DD HH:MM:SS``
                  format.

    Returns:
        Timezone-aware datetime (UTC).
    """
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.warning("Unrecognised date format '%s', using current UTC time.", date_str)
    return datetime.now(timezone.utc)


def build_indicator(feed_name: str, row: dict) -> Indicator:
    """Build a STIX 2.1 Indicator from one parsed row.

    Args:
        feed_name: One of ``ssl_cert``, ``botnet_ip``, ``ja3``.
        row: Dictionary of column name -> value from the parsed CSV.

    Returns:
        A stix2 Indicator object.
    """
    if feed_name == "ssl_cert":
        pattern = "[x509-certificate:hashes.'SHA-1' = '{}']".format(row["SHA1"])
        valid_from = _parse_timestamp(row["Listingdate"])
        kwargs: dict = {
            "x_sslbl_listing_reason": row["Listingreason"],
        }
        label_suffix = "ssl-cert"

    elif feed_name == "botnet_ip":
        pattern = "[ipv4-addr:value = '{}']".format(row["DstIP"])
        valid_from = _parse_timestamp(row["Firstseen"])
        kwargs = {
            "x_sslbl_dst_port": row["DstPort"],
        }
        label_suffix = "botnet-ip"

    elif feed_name == "ja3":
        pattern = "[x-ja3-fingerprint:hash = '{}']".format(row["ja3_md5"])
        valid_from = _parse_timestamp(row["Firstseen"])
        kwargs = {
            "x_sslbl_ja3_md5": row["ja3_md5"],
            "x_sslbl_listing_reason": row["Listingreason"],
        }
        label_suffix = "ja3"

    else:
        raise ValueError("Unknown feed name: {}".format(feed_name))

    return Indicator(
        name="SSLBL {} indicator".format(feed_name),
        pattern=pattern,
        pattern_type="stix",
        valid_from=valid_from,
        labels=["malicious-activity", "sslbl-" + label_suffix],
        created=valid_from,
        modified=valid_from,
        allow_custom=True,
        **kwargs,
    )


def build_bundle(all_rows: dict[str, list[dict]]) -> Bundle:
    """Build a STIX 2.1 Bundle containing Indicators for every parsed row.

    Args:
        all_rows: Dict mapping feed name -> list of parsed row dicts.

    Returns:
        A stix2 Bundle object (JSON-serialisable dict subclass).
    """
    indicators: list[Indicator] = []
    for feed_name, rows in all_rows.items():
        for row in rows:
            indicators.append(build_indicator(feed_name, row))
    bundle = Bundle(objects=indicators, allow_custom=True)
    logger.info("Created bundle with %d indicators", len(indicators))
    return bundle
