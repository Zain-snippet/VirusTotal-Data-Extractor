#!/usr/bin/env python3
"""
Catalyst Connector with STIX 2.1 Support.

Fetches threat intelligence from Catalyst API and generates:
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

from stix_mapper.connectors import CatalystMapper

LOGGER = logging.getLogger("catalyst-connector")


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
    catalyst = cfg.get("catalyst", {})

    base_url = str(catalyst.get("base_url", "https://prod.blindspot.prodaft.com/api"))
    api_key = (os.getenv("CATALYST_API_KEY") or catalyst.get("api_key") or "").strip()
    timeout_seconds = int(catalyst.get("timeout_seconds", 60))
    max_retries = int(catalyst.get("max_retries", 3))
    retry_backoff_seconds = float(catalyst.get("retry_backoff_seconds", 2.0))

    if not api_key:
        raise ValueError("Missing API key. Set CATALYST_API_KEY or catalyst.api_key.")
    if timeout_seconds <= 0:
        raise ValueError("catalyst.timeout_seconds must be > 0.")
    if max_retries < 0:
        raise ValueError("catalyst.max_retries must be >= 0.")

    return {
        "log_level": app.get("log_level", "INFO"),
        "output_dir": app.get("output_dir", "output"),
        "catalyst": {
            "base_url": base_url,
            "api_key": api_key,
            "timeout_seconds": timeout_seconds,
            "max_retries": max_retries,
            "retry_backoff_seconds": retry_backoff_seconds,
        },
    }


def fetch_catalyst(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fetch posts from Catalyst API with retry logic."""
    catalyst = cfg["catalyst"]
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {catalyst['api_key']}",
    })

    rows = []

    for attempt in range(catalyst["max_retries"] + 1):
        try:
            url = f"{catalyst['base_url']}/posts"
            r = session.get(
                url,
                timeout=catalyst["timeout_seconds"],
            )

            if r.status_code == 429 and attempt < catalyst["max_retries"]:
                wait = catalyst["retry_backoff_seconds"] * (2 ** attempt)
                LOGGER.warning("Rate limit hit (429). Retrying in %.1fs", wait)
                time.sleep(wait)
                continue

            r.raise_for_status()
            payload = r.json()

            # Parse response
            for post in payload.get("data", []):
                rows.append({
                    "post_id": post.get("id"),
                    "title": post.get("title"),
                    "description": post.get("description"),
                    "tlp": post.get("tlp", "AMBER"),
                    "category": post.get("category"),
                    "created_at": post.get("created_at", datetime.now(timezone.utc).isoformat()),
                })

            break  # Success

        except requests.RequestException as exc:
            if attempt < catalyst["max_retries"]:
                wait = catalyst["retry_backoff_seconds"] * (2 ** attempt)
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

    fields = ["post_id", "title", "description", "tlp", "category", "created_at"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    """Main connector execution."""
    parser = argparse.ArgumentParser(description="Catalyst connector with STIX 2.1 output")
    parser.add_argument("-c", "--config", default="config_catalyst.yaml", help="Config YAML path")
    parser.add_argument("--dry-run", action="store_true", help="Test without API call")
    args = parser.parse_args()

    try:
        # Load and validate configuration
        raw_cfg = load_config(args.config)
        cfg = validate_config(raw_cfg)
        setup_logging(cfg["log_level"])

        LOGGER.info("Starting Catalyst connector")

        # Fetch data
        if args.dry_run:
            LOGGER.info("DRY-RUN MODE: Using sample data")
            rows = [
                {
                    "post_id": "123",
                    "title": "New Campaign Detected",
                    "description": "Threat actors launching campaign. CVE-2026-1234 exploited.",
                    "tlp": "AMBER",
                    "category": "threat-report",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            ]
        else:
            rows = fetch_catalyst(cfg)

        LOGGER.info("Fetched %d records from Catalyst", len(rows))

        # Ensure output directory exists
        out_dir = ensure_dir(cfg["output_dir"])
        ts = timestamp_utc()

        # Output file paths
        json_path = out_dir / f"catalyst_{ts}.json"
        csv_path = out_dir / f"catalyst_{ts}.csv"
        stix_path = out_dir / f"catalyst_{ts}_stix.json"

        #  REQUIREMENT 1a: Write JSON output
        write_json(json_path, rows)
        LOGGER.info("✓ JSON output: %s", json_path)

        #  REQUIREMENT 1b: Write CSV output
        write_csv(csv_path, rows)
        LOGGER.info("✓ CSV output: %s", csv_path)

        #  REQUIREMENT 1c: Generate STIX 2.1 Bundle
        mapper = CatalystMapper()
        stix_bundle = mapper.create_stix_bundle_from_rows(rows)
        write_json(stix_path, stix_bundle)
        LOGGER.info("✓ STIX 2.1 output: %s", stix_path)

        # Log STIX bundle statistics
        stix_objects = stix_bundle.get("objects", [])
        identities = sum(1 for obj in stix_objects if obj["type"] == "identity")
        reports = sum(1 for obj in stix_objects if obj["type"] == "report")
        vulnerabilities = sum(1 for obj in stix_objects if obj["type"] == "vulnerability")
        relationships = sum(1 for obj in stix_objects if obj["type"] == "relationship")

        LOGGER.info("STIX Bundle Statistics:")
        LOGGER.info("  - Total objects: %d", len(stix_objects))
        LOGGER.info("  - Identities: %d", identities)
        LOGGER.info("  - Reports: %d", reports)
        LOGGER.info("  - Vulnerabilities: %d", vulnerabilities)
        LOGGER.info("  - Relationships: %d", relationships)

        LOGGER.info("Catalyst connector completed successfully")
        return 0

    except Exception as exc:
        LOGGER.error("Execution failed: %s", str(exc), exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
