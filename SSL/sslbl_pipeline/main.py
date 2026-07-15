#!/usr/bin/env python3
"""SSLBL Data Pull + STIX 2.1 Conversion Script."""

import os
import sys
import traceback

from config import FEEDS, RAW_DIR, OUTPUT_DIR, OUTPUT_STIX_FILE
from fetch import fetch_all
from logger import setup_logger
from parse import parse_feed_csv
from stix_convert import build_bundle

logger = setup_logger()


def main() -> None:
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Stage 1 — Pull all raw feeds (crash-safe: each file saved before next
    # download begins).
    results = fetch_all(FEEDS)
    failed = [name for name, ok in results.items() if not ok]
    if failed:
        logger.error(
            "Feed download failed for: %s. "
            "Raw files that succeeded remain on disk. Re-run after fixing.",
            ", ".join(failed),
        )
        sys.exit(1)

    # Stage 2 — Parse and convert.  If this stage crashes, the raw CSVs on
    # disk are unaffected; the script can be re-run to re-attempt conversion
    # without re-downloading.
    try:
        all_rows: dict[str, list[dict]] = {}
        for feed in FEEDS:
            rows = parse_feed_csv(feed.raw_path)
            all_rows[feed.name] = rows
            logger.info("Parsed %d rows from %s", len(rows), feed.raw_path)

        bundle = build_bundle(all_rows)

        with open(OUTPUT_STIX_FILE, "w", encoding="utf-8") as f:
            f.write(bundle.serialize(indent=2))
            f.write("\n")

        total = sum(len(rows) for rows in all_rows.values())
        parts = ", ".join(
            "{}: {}".format(name, len(rows)) for name, rows in all_rows.items()
        )
        logger.info("STIX bundle written to %s (%d total: %s)", OUTPUT_STIX_FILE, total, parts)

    except Exception:
        logger.error("Conversion failed:\n%s", traceback.format_exc())
        logger.error(
            "Raw CSV files on disk are unaffected. "
            "Re-running will retry conversion from saved data."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
