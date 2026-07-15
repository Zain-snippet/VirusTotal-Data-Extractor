import argparse
import json
import logging
from datetime import datetime, timezone

from stix2 import Bundle, Indicator

logger = logging.getLogger(__name__)


def convert_checkpoint_to_stix(checkpoint_path: str, output_path: str) -> int:
    """Read a JSONL checkpoint file and write a STIX 2.1 bundle.

    Returns the count of successfully converted records.
    """
    logger.info("Starting STIX conversion...")
    indicators: list[Indicator] = []
    converted = 0
    skipped = 0

    with open(checkpoint_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(
                    "Skipping malformed JSON at line %d of %s",
                    line_num,
                    checkpoint_path,
                )
                skipped += 1
                continue

            ip = record.get("ipAddress", "")
            confidence = record.get("abuseConfidenceScore", 0)
            total_reports = record.get("totalReports", 0)
            last_reported = record.get("lastReportedAt", "")

            if last_reported:
                try:
                    valid_from = datetime.fromisoformat(last_reported)
                except (ValueError, TypeError):
                    valid_from = datetime.now(timezone.utc)
            else:
                valid_from = datetime.now(timezone.utc)

            description = (
                f"IP {ip} has {total_reports} total abuse report(s), "
                f"last reported on {last_reported}."
            )

            indicator = Indicator(
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                labels=["malicious-activity"],
                confidence=confidence,
                description=description,
                valid_from=valid_from,
            )
            indicators.append(indicator)
            converted += 1
            if converted % 500 == 0:
                logger.info("Converted %d indicators...", converted)

    logger.info("Building STIX bundle...")
    bundle = Bundle(*indicators)
    logger.info("Writing STIX bundle to output file...")
    with open(output_path, "w", encoding="utf-8") as f:
        logger.info("Serializing STIX bundle...")
        f.write(bundle.serialize(pretty=False))

    logger.info("STIX conversion completed successfully.")
    logger.info(
        "Converted %d records (%d skipped) to STIX bundle at %s",
        converted,
        skipped,
        output_path,
    )
    return converted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convert AbuseIPDB checkpoint JSONL to STIX 2.1 bundle"
    )
    parser.add_argument("checkpoint_path", help="Path to the JSONL checkpoint file")
    parser.add_argument("output_path", help="Path for the output STIX JSON file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    convert_checkpoint_to_stix(args.checkpoint_path, args.output_path)
