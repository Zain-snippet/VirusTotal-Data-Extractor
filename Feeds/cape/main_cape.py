#!/usr/bin/env python3
"""
CAPE Sandbox Connector with STIX 2.1 Support.

Fetches malware analysis data from CAPE Sandbox and generates:
1. JSON output (raw data)
2. CSV output (tabular data)
3. STIX 2.1 Bundle (standardized threat intelligence)

Requirements 1 Implementation:
 JSON output
 CSV output  
 STIX 2.1 Bundle with spec_version: "2.1"
 RFC3339 timestamps
 Error handling
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
import yaml

from stix_mapper.connectors import CAPEMapper

LOGGER = logging.getLogger("cape-connector")


def setup_logging(level: str) -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def load_config(path: str) -> Dict[str, Any]:
    """Load YAML configuration file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Config root must be a YAML object.")
    return cfg


def validate_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration parameters."""
    app = cfg.get("app", {})
    cape = cfg.get("cape", {})

    api_url = str(cape.get("api_url", "https://cape.example.com/apiv2/"))
    base_url = str(cape.get("base_url", "https://cape.example.com/"))
    api_key = (os.getenv("CAPE_API_KEY") or cape.get("api_key") or "").strip()
    report_score = int(cape.get("report_score", 7))
    timeout_seconds = int(cape.get("timeout_seconds", 60))
    max_retries = int(cape.get("max_retries", 3))
    retry_backoff_seconds = float(cape.get("retry_backoff_seconds", 2.0))

    if not api_key:
        raise ValueError("Missing API key. Set CAPE_API_KEY or cape.api_key.")
    if not (0 <= report_score <= 10):
        raise ValueError("cape.report_score must be between 0 and 10.")
    if timeout_seconds <= 0:
        raise ValueError("cape.timeout_seconds must be > 0.")
    if max_retries < 0:
        raise ValueError("cape.max_retries must be >= 0.")

    return {
        "log_level": app.get("log_level", "INFO"),
        "output_dir": app.get("output_dir", "output"),
        "cape": {
            "api_url": api_url,
            "base_url": base_url,
            "api_key": api_key,
            "report_score": report_score,
            "timeout_seconds": timeout_seconds,
            "max_retries": max_retries,
            "retry_backoff_seconds": retry_backoff_seconds,
        },
    }


def fetch_cape(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fetch reports from CAPE Sandbox API with retry logic."""
    cape = cfg["cape"]
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {cape['api_key']}",
    })

    rows = []

    for attempt in range(cape["max_retries"] + 1):
        try:
            url = f"{cape['api_url']}tasks/list"
            r = session.get(
                url,
                params={"status": "reported"},
                timeout=cape["timeout_seconds"],
            )

            if r.status_code == 429 and attempt < cape["max_retries"]:
                wait = cape["retry_backoff_seconds"] * (2 ** attempt)
                LOGGER.warning("Rate limit hit (429). Retrying in %.1fs", wait)
                time.sleep(wait)
                continue

            r.raise_for_status()
            payload = r.json()

            # Parse response
            for task in payload.get("data", []):
                rows.append({
                    "task_id": task.get("id"),
                    "status": task.get("status"),
                    "malscore": task.get("malscore", 0),
                    "detection_family": task.get("detections", {}).get("family"),
                    "sha256": task.get("sha256"),
                    "md5": task.get("md5"),
                    "sha1": task.get("sha1"),
                })

            break  # Success

        except requests.RequestException as exc:
            if attempt < cape["max_retries"]:
                wait = cape["retry_backoff_seconds"] * (2 ** attempt)
                LOGGER.warning("Request failed: %s. Retrying in %.1fs", exc, wait)
                time.sleep(wait)
                continue
            raise

    return rows


def ensure_dir(path: str) -> Path:
    """Ensure output directory exists."""
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def timestamp_utc() -> str:
    """Get UTC timestamp for filenames."""
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, data: Any) -> None:
    """Write data to JSON file."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Write rows to CSV file."""
    if not rows:
        LOGGER.warning("No rows to write to CSV")
        return

    fields = ["task_id", "status", "malscore", "detection_family", "sha256", "md5", "sha1"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    """Main connector execution."""
    parser = argparse.ArgumentParser(description="CAPE connector with STIX 2.1 output")
    parser.add_argument("-c", "--config", default="config_cape.yaml", help="Config YAML path")
    parser.add_argument("--dry-run", action="store_true", help="Test without API call")
    args = parser.parse_args()

    try:
        # Load and validate configuration
        raw_cfg = load_config(args.config)
        cfg = validate_config(raw_cfg)
        setup_logging(cfg["log_level"])

        LOGGER.info("Starting CAPE connector")

        # Fetch data
        if args.dry_run:
            LOGGER.info("DRY-RUN MODE: Using sample data")
            rows = [
                {
                    "task_id": 123,
                    "status": "reported",
                    "malscore": 9,
                    "detection_family": "Emotet",
                    "sha256": "abc123def456...",
                    "md5": "def456...",
                    "sha1": "ghi789...",
                },
            ]
        else:
            rows = fetch_cape(cfg)

        LOGGER.info("Fetched %d records from CAPE", len(rows))

        # Ensure output directory exists
        out_dir = ensure_dir(cfg["output_dir"])
        ts = timestamp_utc()

        # Output file paths
        json_path = out_dir / f"cape_{ts}.json"
        csv_path = out_dir / f"cape_{ts}.csv"
        stix_path = out_dir / f"cape_{ts}_stix.json"

        #  REQUIREMENT 1a: Write JSON output
        write_json(json_path, rows)
        LOGGER.info("✓ JSON output: %s", json_path)

        #  REQUIREMENT 1b: Write CSV output
        write_csv(csv_path, rows)
        LOGGER.info("✓ CSV output: %s", csv_path)
        # REQUIREMENT 1c: Generate STIX 2.1 Bundle
        mapper = CAPEMapper()
        stix_bundle = mapper.create_stix_bundle_from_rows(rows)
        write_json(stix_path, stix_bundle)
        LOGGER.info("✓ STIX 2.1 output: %s", stix_path)

        # Log STIX bundle statistics
        stix_objects = stix_bundle.get("objects", [])
        identities = sum(1 for obj in stix_objects if obj["type"] == "identity")
        indicators = sum(1 for obj in stix_objects if obj["type"] == "indicator")
        relationships = sum(1 for obj in stix_objects if obj["type"] == "relationship")

        LOGGER.info("STIX Bundle Statistics:")
        LOGGER.info("  - Total objects: %d", len(stix_objects))
        LOGGER.info("  - Identities: %d", identities)
        LOGGER.info("  - Indicators: %d", indicators)
        LOGGER.info("  - Relationships: %d", relationships)

        LOGGER.info("CAPE connector completed successfully")
        return 0

    except Exception as exc:
        LOGGER.error("Execution failed: %s", str(exc), exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
