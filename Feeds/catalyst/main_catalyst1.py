#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from python_catalyst import CatalystClient, PostCategory, TLPLevel

LOGGER = logging.getLogger("catalyst-connector")


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
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError("Config root must be a YAML object.")
    return data


def env_or(cfg_val: Any, env_name: str, default: Any = None) -> Any:
    ev = os.getenv(env_name)
    if ev is not None and str(ev).strip() != "":
        return ev
    return cfg_val if cfg_val is not None else default


def to_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def parse_tlp_filters(raw: Optional[str]) -> List[TLPLevel]:
    if not raw:
        return []
    value = raw.strip().upper()
    if value == "ALL":
        return [TLPLevel.CLEAR, TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.RED]
    out: List[TLPLevel] = []
    for item in value.split(","):
        name = item.strip().upper()
        if hasattr(TLPLevel, name):
            out.append(getattr(TLPLevel, name))
        else:
            LOGGER.warning("Invalid TLP level ignored: %s", name)
    return out


def parse_category_filters(raw: Optional[str]) -> List[PostCategory]:
    if not raw:
        return []
    value = raw.strip().upper()
    if value == "ALL":
        return [
            PostCategory.DISCOVERY,
            PostCategory.ATTRIBUTION,
            PostCategory.RESEARCH,
            PostCategory.FLASH_ALERT,
        ]
    out: List[PostCategory] = []
    for item in value.split(","):
        name = item.strip().upper()
        if hasattr(PostCategory, name):
            out.append(getattr(PostCategory, name))
        else:
            LOGGER.warning("Invalid category ignored: %s", name)
    return out


def validate_and_normalize(cfg: Dict[str, Any]) -> Dict[str, Any]:
    app = cfg.get("app", {})
    cat = cfg.get("catalyst", {})

    base_url = str(env_or(cat.get("base_url"), "CATALYST_BASE_URL", "https://prod.blindspot.prodaft.com/api")).strip()
    api_key = str(env_or(cat.get("api_key"), "CATALYST_API_KEY", "")).strip()

    tlp_filter_raw = str(env_or(cat.get("tlp_filter"), "CATALYST_TLP_FILTER", "ALL"))
    category_filter_raw = str(env_or(cat.get("category_filter"), "CATALYST_CATEGORY_FILTER", "ALL"))

    sync_days_back = int(env_or(cat.get("sync_days_back"), "CATALYST_SYNC_DAYS_BACK", 730))
    create_observables = to_bool(env_or(cat.get("create_observables"), "CATALYST_CREATE_OBSERVABLES", True), True)
    create_indicators = to_bool(env_or(cat.get("create_indicators"), "CATALYST_CREATE_INDICATORS", False), False)

    if sync_days_back < 0:
        raise ValueError("sync_days_back must be >= 0.")
    if not base_url:
        raise ValueError("catalyst.base_url (or CATALYST_BASE_URL) is required.")

    return {
        "log_level": app.get("log_level", "INFO"),
        "output_dir": app.get("output_dir", "output"),
        "catalyst": {
            "base_url": base_url.rstrip("/"),
            "api_key": api_key,
            "tlp_filter_raw": tlp_filter_raw,
            "category_filter_raw": category_filter_raw,
            "sync_days_back": sync_days_back,
            "create_observables": create_observables,
            "create_indicators": create_indicators,
        },
    }


def compute_since(sync_days_back: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=sync_days_back)


def fetch_member_contents(client: CatalystClient, since: datetime, tlps: List[TLPLevel], cats: List[PostCategory]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    if not tlps and not cats:
        return client.get_updated_member_contents(since=since, tlp=None, category=None)

    if tlps and not cats:
        for t in tlps:
            LOGGER.info("Fetching with TLP=%s", t.value)
            results += client.get_updated_member_contents(since=since, tlp=[t], category=None)
        return results

    if cats and not tlps:
        for c in cats:
            LOGGER.info("Fetching with category=%s", c.value)
            results += client.get_updated_member_contents(since=since, tlp=None, category=c)
        return results

    for t in tlps:
        for c in cats:
            LOGGER.info("Fetching with TLP=%s and category=%s", t.value, c.value)
            results += client.get_updated_member_contents(since=since, tlp=[t], category=c)
    return results


def deduplicate_by_id(contents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique: Dict[str, Dict[str, Any]] = {}
    for item in contents:
        cid = item.get("id")
        if cid and cid not in unique:
            unique[cid] = item
    return list(unique.values())


def convert_to_stix(client: CatalystClient, contents: List[Dict[str, Any]]) -> Tuple[List[Any], List[Dict[str, Any]]]:
    """
    Returns:
      - stix_objects (native objects from python-catalyst)
      - normalized_rows (for flat CSV)
    """
    stix_objects: List[Any] = []
    rows: List[Dict[str, Any]] = []

    for c in contents:
        try:
            report, related = client.create_report_from_member_content(c)
            if report:
                stix_objects.append(report)
                rows.append({
                    "content_id": c.get("id"),
                    "stix_type": getattr(report, "type", "report"),
                    "stix_id": getattr(report, "id", ""),
                    "title": getattr(report, "name", ""),
                    "category": c.get("category"),
                    "tlp": c.get("tlp"),
                    "updated_at": c.get("updated_at"),
                })
            if related:
                for obj in related:
                    stix_objects.append(obj)
                    rows.append({
                        "content_id": c.get("id"),
                        "stix_type": getattr(obj, "type", ""),
                        "stix_id": getattr(obj, "id", ""),
                        "title": getattr(obj, "name", ""),
                        "category": c.get("category"),
                        "tlp": c.get("tlp"),
                        "updated_at": c.get("updated_at"),
                    })
        except Exception as err:
            LOGGER.warning("Failed content id=%s: %s", c.get("id"), err)

    # Add identity + TLP marking used by converter
    try:
        stix_objects.append(client.converter.identity)
        stix_objects.append(client.converter.tlp_marking)
    except Exception:
        pass

    return stix_objects, rows


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
    fields = ["content_id", "stix_type", "stix_id", "title", "category", "tlp", "updated_at"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    parser = argparse.ArgumentParser(description="CATALYST standalone connector runner")
    parser.add_argument("-c", "--config", default="config_catalyst.yaml", help="Config YAML path")
    parser.add_argument("--validate-only", action="store_true", help="Validate config only; no API call.")
    parser.add_argument("--dry-run", action="store_true", help="No API call; writes empty outputs.")
    args = parser.parse_args()

    try:
        raw_cfg = load_config(args.config)
        cfg = validate_and_normalize(raw_cfg)
        setup_logging(cfg["log_level"])

        out_dir = ensure_output_dir(cfg["output_dir"])
        ts = ts_utc()
        json_path = out_dir / f"catalyst_{ts}.json"
        csv_path = out_dir / f"catalyst_{ts}.csv"

        if args.validate_only:
            LOGGER.info("Validation successful.")
            return 0

        if args.dry_run:
            sample = {
                "connector": "catalyst",
                "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "member_contents": [],
                "stix_count": 0,
                "notes": "dry-run mode",
            }
            write_json(json_path, sample)
            write_csv(csv_path, [])
            LOGGER.info("Dry-run successful. JSON: %s", json_path)
            LOGGER.info("Dry-run successful. CSV:  %s", csv_path)
            return 0

        c = cfg["catalyst"]

        if not c["api_key"]:
            LOGGER.warning("CATALYST_API_KEY not set, using public endpoint mode.")

        client = CatalystClient(
            api_key=c["api_key"],
            base_url=c["base_url"],
            logger=LOGGER,
            create_observables=c["create_observables"],
            create_indicators=c["create_indicators"],
        )

        since = compute_since(c["sync_days_back"])
        tlps = parse_tlp_filters(c["tlp_filter_raw"])
        cats = parse_category_filters(c["category_filter_raw"])

        contents = fetch_member_contents(client, since, tlps, cats)
        unique_contents = deduplicate_by_id(contents)

        stix_objects, rows = convert_to_stix(client, unique_contents)

        payload = {
            "connector": "catalyst",
            "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "since": since.isoformat(),
            "filters": {
                "tlp": [t.value for t in tlps] if tlps else [],
                "category": [c.value for c in cats] if cats else [],
            },
            "member_contents_count": len(unique_contents),
            "stix_count": len(stix_objects),
            "member_contents": unique_contents,
        }

        write_json(json_path, payload)
        write_csv(csv_path, rows)

        LOGGER.info("Fetched unique contents: %d", len(unique_contents))
        LOGGER.info("Generated STIX objects: %d", len(stix_objects))
        LOGGER.info("JSON: %s", json_path)
        LOGGER.info("CSV:  %s", csv_path)
        return 0

    except Exception as exc:
        LOGGER.error("Execution failed: %s", str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
