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

import requests
import yaml

LOGGER = logging.getLogger("cape-connector")


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def load_config(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        raise ValueError("Config root must be a YAML object.")
    return cfg


def env_or(cfg_value: Any, env_name: str, default: Any = None) -> Any:
    val = os.getenv(env_name)
    if val is not None and str(val).strip() != "":
        return val
    return cfg_value if cfg_value is not None else default


def to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def validate_and_normalize(cfg: Dict[str, Any]) -> Dict[str, Any]:
    app = cfg.get("app", {})
    cape = cfg.get("cape", {})

    api_url = str(env_or(cape.get("api_url"), "CAPE_API_URL", "")).strip()
    base_url = str(env_or(cape.get("base_url"), "CAPE_BASE_URL", "")).strip()

    if not api_url:
        raise ValueError("Missing CAPE_API_URL (or cape.api_url).")
    if not base_url:
        raise ValueError("Missing CAPE_BASE_URL (or cape.base_url).")

    interval_minutes = int(env_or(cape.get("interval"), "CAPE_INTERVAL", 30))
    start_task_id = int(env_or(cape.get("start_task_id"), "CAPE_START_TASK_ID", 0))
    report_score = int(env_or(cape.get("report_score"), "CAPE_REPORT_SCORE", 7))

    create_indicators = to_bool(env_or(cape.get("create_indicators"), "CAPE_CREATE_INDICATORS", True), True)
    enable_network_traffic = to_bool(env_or(cape.get("enable_network_traffic"), "CAPE_ENABLE_NETWORK_TRAFFIC", False), False)
    enable_registry_keys = to_bool(env_or(cape.get("enable_registry_keys"), "CAPE_ENABLE_REGISTRY_KEYS", False), False)
    verify_ssl = to_bool(env_or(cape.get("verify_ssl"), "VERIFY_SSL", True), True)

    timeout_seconds = int(cape.get("timeout_seconds", 60))
    max_retries = int(cape.get("max_retries", 3))
    retry_backoff_seconds = float(cape.get("retry_backoff_seconds", 2.0))

    if interval_minutes <= 0:
        raise ValueError("interval must be > 0 minutes.")
    if start_task_id < 0:
        raise ValueError("start_task_id must be >= 0.")
    if not (0 <= report_score <= 10):
        raise ValueError("report_score must be between 0 and 10.")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be > 0.")
    if max_retries < 0:
        raise ValueError("max_retries must be >= 0.")

    return {
        "log_level": app.get("log_level", "INFO"),
        "output_dir": app.get("output_dir", "output"),
        "cape": {
            "api_url": api_url.rstrip("/") + "/",
            "base_url": base_url.rstrip("/") + "/",
            "interval": interval_minutes,
            "start_task_id": start_task_id,
            "report_score": report_score,
            "create_indicators": create_indicators,
            "enable_network_traffic": enable_network_traffic,
            "enable_registry_keys": enable_registry_keys,
            "verify_ssl": verify_ssl,
            "timeout_seconds": timeout_seconds,
            "max_retries": max_retries,
            "retry_backoff_seconds": retry_backoff_seconds,
        },
    }


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    verify_ssl: bool,
    timeout_seconds: int,
    max_retries: int,
    retry_backoff_seconds: float,
) -> Dict[str, Any]:
    for attempt in range(max_retries + 1):
        try:
            resp = session.request(method, url, verify=verify_ssl, timeout=timeout_seconds)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                wait = retry_backoff_seconds * (2 ** attempt)
                LOGGER.warning("HTTP %s for %s, retrying in %.1fs", resp.status_code, url, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            if attempt < max_retries:
                wait = retry_backoff_seconds * (2 ** attempt)
                LOGGER.warning("Request failed %s: %s, retrying in %.1fs", url, exc, wait)
                time.sleep(wait)
                continue
            raise
    return {}


def get_tasks(session: requests.Session, c: Dict[str, Any]) -> List[Dict[str, Any]]:
    url = c["api_url"] + "tasks/list"
    data = request_json(
        session=session,
        method="GET",
        url=url,
        verify_ssl=c["verify_ssl"],
        timeout_seconds=c["timeout_seconds"],
        max_retries=c["max_retries"],
        retry_backoff_seconds=c["retry_backoff_seconds"],
    )
    tasks = data.get("data", [])
    return tasks if isinstance(tasks, list) else []


def get_task_report(session: requests.Session, c: Dict[str, Any], task_id: int) -> Dict[str, Any]:
    url = c["api_url"] + f"tasks/get/report/{task_id}"
    return request_json(
        session=session,
        method="GET",
        url=url,
        verify_ssl=c["verify_ssl"],
        timeout_seconds=c["timeout_seconds"],
        max_retries=c["max_retries"],
        retry_backoff_seconds=c["retry_backoff_seconds"],
    )


def normalize_report_row(task: Dict[str, Any], report: Dict[str, Any], score_threshold: int) -> Dict[str, Any]:
    malscore = report.get("malscore")
    info = report.get("info", {}) if isinstance(report.get("info"), dict) else {}
    target = report.get("target", {}) if isinstance(report.get("target"), dict) else {}

    category = target.get("category")
    target_name = None
    if category == "file":
        file_info = target.get("file", {}) if isinstance(target.get("file"), dict) else {}
        target_name = file_info.get("name")
    elif category == "url":
        target_name = target.get("url")

    detections = report.get("detections", [])
    family = ""
    if isinstance(detections, list) and detections:
        first = detections[0]
        if isinstance(first, dict):
            family = str(first.get("family", ""))

    return {
        "task_id": task.get("id"),
        "status": task.get("status"),
        "completed_on": task.get("completed_on"),
        "malscore": malscore,
        "above_report_score": bool((malscore is not None) and (float(malscore) >= score_threshold)),
        "category": category,
        "target_name": target_name,
        "sha256": ((target.get("file") or {}).get("sha256") if isinstance(target.get("file"), dict) else ""),
        "md5": ((target.get("file") or {}).get("md5") if isinstance(target.get("file"), dict) else ""),
        "sha1": ((target.get("file") or {}).get("sha1") if isinstance(target.get("file"), dict) else ""),
        "tlp": info.get("tlp"),
        "detection_family": family,
    }


def ensure_output_dir(path: str) -> Path:
    p = Path(path).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def timestamp_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields = [
        "task_id",
        "status",
        "completed_on",
        "malscore",
        "above_report_score",
        "category",
        "target_name",
        "sha256",
        "md5",
        "sha1",
        "tlp",
        "detection_family",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main() -> int:
    parser = argparse.ArgumentParser(description="CAPE standalone connector runner")
    parser.add_argument("-c", "--config", default="config_cape.yaml", help="Config YAML path")
    parser.add_argument("--validate-only", action="store_true", help="Validate config only; no API call.")
    parser.add_argument("--dry-run", action="store_true", help="No API call; writes sample empty outputs.")
    args = parser.parse_args()

    try:
        raw_cfg = load_config(args.config)
        cfg = validate_and_normalize(raw_cfg)
        setup_logging(cfg["log_level"])

        out_dir = ensure_output_dir(cfg["output_dir"])
        ts = timestamp_utc()
        json_path = out_dir / f"cape_{ts}.json"
        csv_path = out_dir / f"cape_{ts}.csv"

        if args.validate_only:
            LOGGER.info("Validation successful.")
            return 0

        if args.dry_run:
            sample = {
                "connector": "cape",
                "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tasks": [],
                "reports": [],
                "rows": [],
            }
            write_json(json_path, sample)
            write_csv(csv_path, [])
            LOGGER.info("Dry-run successful. JSON: %s", json_path)
            LOGGER.info("Dry-run successful. CSV:  %s", csv_path)
            return 0

        c = cfg["cape"]
        session = requests.Session()

        tasks = get_tasks(session, c)
        LOGGER.info("Fetched %d CAPE tasks", len(tasks))

        rows: List[Dict[str, Any]] = []
        raw_reports: List[Dict[str, Any]] = []

        for task in tasks:
            task_id = task.get("id")
            if not isinstance(task_id, int):
                continue
            if task_id <= c["start_task_id"]:
                continue
            if task.get("status") != "reported":
                continue
            if not task.get("completed_on"):
                continue

            try:
                report = get_task_report(session, c, task_id)
                raw_reports.append({"task_id": task_id, "report": report})
                rows.append(normalize_report_row(task, report, c["report_score"]))
            except Exception as e:
                LOGGER.warning("Failed task %s: %s", task_id, e)

        payload = {
            "connector": "cape",
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "config_effective": {
                "start_task_id": c["start_task_id"],
                "report_score": c["report_score"],
                "create_indicators": c["create_indicators"],
                "enable_network_traffic": c["enable_network_traffic"],
                "enable_registry_keys": c["enable_registry_keys"],
                "verify_ssl": c["verify_ssl"],
            },
            "tasks": tasks,
            "reports": raw_reports,
            "rows": rows,
        }

        write_json(json_path, payload)
        write_csv(csv_path, rows)

        LOGGER.info("Processed reports: %d", len(rows))
        LOGGER.info("JSON: %s", json_path)
        LOGGER.info("CSV:  %s", csv_path)
        return 0

    except Exception as exc:
        LOGGER.error("Execution failed: %s", str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
