#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pycountry
import requests
import yaml

from stix_mapper.connectors import CriminalIPC2DailyFeedMapper

LOGGER = logging.getLogger("criminalip-c2-daily-feed")


def setup_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def load_config(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Config root must be YAML object.")
    return cfg


def env_or(cfg_val: Any, env_name: str, default: Any = None) -> Any:
    ev = os.getenv(env_name)
    return ev if ev is not None and str(ev).strip() != "" else (cfg_val if cfg_val is not None else default)


def validate_and_normalize(cfg: Dict[str, Any]) -> Dict[str, Any]:
    app = cfg.get("app", {})
    c = cfg.get("criminalipc2dailyfeed", {})
    csv_url = str(env_or(c.get("csv_url"), "CRIMINALIP_CSV_URL", "https://raw.githubusercontent.com/criminalip/C2-Daily-Feed/refs/heads/main")).strip().rstrip("/")
    confidence_score = int(env_or(c.get("score"), "CRIMINALIP_CONFIDENCE_SCORE", 100))
    interval_days = int(env_or(c.get("interval"), "CRIMINALIP_INTERVAL", 1))
    timeout_seconds = int(c.get("timeout_seconds", 60))
    max_retries = int(c.get("max_retries", 3))
    retry_backoff_seconds = float(c.get("retry_backoff_seconds", 2.0))
    if confidence_score < 0 or confidence_score > 100:
        raise ValueError("confidence_score must be between 0 and 100.")
    if interval_days <= 0 or timeout_seconds <= 0 or max_retries < 0:
        raise ValueError("Invalid CriminalIP timing/retry settings.")
    return {"log_level": app.get("log_level", "INFO"), "output_dir": app.get("output_dir", "output"), "criminalip": {"csv_url": csv_url, "confidence_score": confidence_score, "interval_days": interval_days, "timeout_seconds": timeout_seconds, "max_retries": max_retries, "retry_backoff_seconds": retry_backoff_seconds}}


def build_csv_url(base_url: str, target_date: str) -> str:
    return f"{base_url}/{target_date}.csv"


def request_text_with_retry(url: str, timeout_seconds: int, max_retries: int, retry_backoff_seconds: float) -> str:
    for attempt in range(max_retries + 1):
        try:
            r = requests.get(url, timeout=timeout_seconds)
            if r.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                time.sleep(retry_backoff_seconds * (2 ** attempt))
                continue
            r.raise_for_status()
            return r.text
        except requests.RequestException:
            if attempt < max_retries:
                time.sleep(retry_backoff_seconds * (2 ** attempt))
                continue
            raise
    return ""


def get_country_name(alpha2: str) -> str:
    country = pycountry.countries.get(alpha_2=alpha2.upper()) if alpha2 else None
    return country.name if country else ""


def normalize_c2_label(raw_c2: str) -> str:
    return raw_c2.split("_", 1)[1] if raw_c2 and "_" in raw_c2 else raw_c2


def parse_csv_rows(csv_text: str, confidence_score: int, file_date: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(csv_text.strip().splitlines())
    rows: List[Dict[str, Any]] = []
    for row in reader:
        ip = (row.get("IP") or "").strip()
        if not ip:
            continue
        raw_c2 = (row.get("Target C2") or "").strip()
        open_ports = (row.get("OpenPorts") or "").strip()
        country_code = (row.get("Country") or "").strip().upper()
        rows.append({"file_date": file_date, "ip": ip, "target_c2_raw": raw_c2, "c2_label": normalize_c2_label(raw_c2), "country_code": country_code, "country_name": get_country_name(country_code), "open_ports": open_ports, "description": f"CriminalIP C2 Feed - Traffic seen on port {open_ports or 'Unknown'}", "confidence_score": confidence_score, "stix_pattern": f"[ipv4-addr:value = '{ip}']"})
    return rows


def ensure_output_dir(path: str) -> Path:
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def ts_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = ["file_date", "ip", "target_c2_raw", "c2_label", "country_code", "country_name", "open_ports", "description", "confidence_score", "stix_pattern"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description="Criminal IP C2 Daily Feed standalone runner")
    parser.add_argument("-c", "--config", default="config_criminalip_c2_daily_feed.yaml", help="Config YAML path")
    parser.add_argument("--date", default="", help="Target date YYYY-MM-DD")
    parser.add_argument("--validate-only", action="store_true", help="Validate config only.")
    parser.add_argument("--dry-run", action="store_true", help="No HTTP call; write sample output.")
    args = parser.parse_args()
    try:
        cfg = validate_and_normalize(load_config(args.config))
        setup_logging(cfg["log_level"])
        out_dir = ensure_output_dir(cfg["output_dir"])
        ts = ts_utc()
        json_path = out_dir / f"criminalip_c2_daily_feed_{ts}.json"
        csv_path = out_dir / f"criminalip_c2_daily_feed_{ts}.csv"
        stix_path = out_dir / f"criminalip_c2_daily_feed_{ts}_stix.json"
        if args.validate_only:
            LOGGER.info("Validation successful.")
            return 0
        c = cfg["criminalip"]
        target_date = args.date.strip() or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        datetime.strptime(target_date, "%Y-%m-%d")
        if args.dry_run:
            rows = parse_csv_rows("IP,Target C2,Country,OpenPorts\n203.0.113.20,c2_test,US,443\n", c["confidence_score"], target_date)
            source_url = "dry-run"
        else:
            source_url = build_csv_url(c["csv_url"], target_date)
            rows = parse_csv_rows(request_text_with_retry(source_url, c["timeout_seconds"], c["max_retries"], c["retry_backoff_seconds"]), c["confidence_score"], target_date)
        payload = {"connector": "criminalip-c2-daily-feed", "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "source_url": source_url, "row_count": len(rows), "rows": rows}
        write_json(json_path, payload)
        write_csv(csv_path, rows)
        write_json(stix_path, CriminalIPC2DailyFeedMapper().create_stix_bundle_from_rows(rows))
        LOGGER.info("JSON: %s", json_path)
        LOGGER.info("CSV:  %s", csv_path)
        LOGGER.info("STIX: %s", stix_path)
        return 0
    except Exception as exc:
        LOGGER.error("Execution failed: %s", str(exc), exc_info=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
