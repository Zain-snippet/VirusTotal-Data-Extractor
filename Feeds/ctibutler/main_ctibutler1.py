#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin

import requests
import yaml


KNOWLEDGE_BASES = [
    "cwe",
    "capec",
    "location",
    "attack-mobile",
    "attack-ics",
    "attack-enterprise",
    "disarm",
    "atlas",
]


def load_yaml(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def env_or(cfg: dict, key: str, default=None):
    return cfg.get(key) if cfg.get(key) is not None else os.environ.get(key, default)


def parse_knowledgebases(value: str) -> list[str]:
    if not value:
        return []
    values = [v.strip() for v in value.split(",") if v.strip()]
    for v in values:
        if v not in KNOWLEDGE_BASES:
            raise ValueError(f"Unsupported knowledge base: {v}")
    return values


def validate_config(raw: dict) -> dict:
    cfg = {
        "CTIBUTLER_BASE_URL": env_or(raw, "CTIBUTLER_BASE_URL", "https://api.ctibutler.com/"),
        "CTIBUTLER_API_KEY": env_or(raw, "CTIBUTLER_API_KEY"),
        "CTIBUTLER_KNOWLEDGEBASES": env_or(raw, "CTIBUTLER_KNOWLEDGEBASES", ""),
        "CTIBUTLER_INTERVAL_DAYS": int(env_or(raw, "CTIBUTLER_INTERVAL_DAYS", 7)),
        "OUTPUT_DIR": env_or(raw, "OUTPUT_DIR", "output"),
        "STATE_FILE": env_or(raw, "STATE_FILE", ".ctibutler_state.json"),
    }

    if not cfg["CTIBUTLER_API_KEY"]:
        raise ValueError("CTIBUTLER_API_KEY is required")

    cfg["CTIBUTLER_BASE_URL"] = cfg["CTIBUTLER_BASE_URL"].strip("/") + "/"
    cfg["KB_LIST"] = parse_knowledgebases(cfg["CTIBUTLER_KNOWLEDGEBASES"])

    if not cfg["KB_LIST"]:
        raise ValueError("CTIBUTLER_KNOWLEDGEBASES cannot be empty")

    if cfg["CTIBUTLER_INTERVAL_DAYS"] <= 0:
        raise ValueError("CTIBUTLER_INTERVAL_DAYS must be > 0")

    return cfg


def load_state(path: Path) -> dict:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"versions": {}}


def save_state(path: Path, state: dict):
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def retrieve(session: requests.Session, base_url: str, path: str, list_key: str, params: dict | None = None) -> list[dict]:
    params = params or {}
    params.update(page=1, page_size=200)
    objects: list[dict] = []
    total_results_count = 1

    while total_results_count > len(objects):
        resp = session.get(urljoin(base_url, path), params=params, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        total_results_count = data["total_results_count"]
        objects.extend(data[list_key])
        params["page"] += 1

    return objects


def get_installed_versions(session: requests.Session, base_url: str, kb: str) -> list[str]:
    resp = session.get(urljoin(base_url, f"v1/{kb}/versions/installed/"), timeout=60)
    resp.raise_for_status()
    return resp.json().get("versions", [])


def get_knowledge_base_objects(session: requests.Session, base_url: str, kb: str, ingested_versions: list[str]) -> tuple[str, list[dict]]:
    versions = get_installed_versions(session, base_url, kb)
    if not versions:
        raise ValueError(f"knowledge base for {kb} appears to be empty")

    latest = versions[0]
    if latest in ingested_versions:
        raise RuntimeError(f"version {latest} of {kb} has already been ingested")

    objects = retrieve(
        session,
        base_url,
        f"v1/{kb}/objects/",
        list_key="objects",
        params={"version": latest},
    )
    return latest, objects


def get_object_name(base: str, obj: dict) -> str:
    name = None
    refs = obj.get("external_references")
    if refs:
        name = refs[0].get("external_id")
    name = name or obj.get("id", "unknown-id")
    return f"{base} => {name}"


def summarize_and_fetch_bundles(session: requests.Session, base_url: str, kb: str, objects: list[dict]) -> list[dict]:
    rows = []

    for obj in objects:
        readable_name = get_object_name(kb, obj)
        obj_id = obj.get("id")

        bundle_objects = []
        bundle_error = ""
        try:
            bundle_objects = retrieve(
                session,
                base_url,
                f"v1/{kb}/objects/{obj_id}/bundle/",
                list_key="objects",
                params=None,
            )
        except Exception as e:
            bundle_error = str(e)

        rows.append(
            {
                "knowledge_base": kb,
                "object_id": obj_id,
                "object_name": readable_name,
                "bundle_object_count": len(bundle_objects),
                "bundle_error": bundle_error,
            }
        )

    return rows


def write_outputs(output_dir: Path, all_rows: list[dict], run_payload: dict):
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"ctibutler_{ts}.json"
    csv_path = output_dir / f"ctibutler_{ts}.csv"

    with json_path.open("w", encoding="utf-8") as jf:
        json.dump(run_payload, jf, ensure_ascii=False, indent=2)

    if all_rows:
        with csv_path.open("w", newline="", encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=list(all_rows[0].keys()))
            writer.writeheader()
            writer.writerows(all_rows)
    else:
        with csv_path.open("w", newline="", encoding="utf-8") as cf:
            cf.write("knowledge_base,object_id,object_name,bundle_object_count,bundle_error\n")

    return json_path, csv_path


def main():
    parser = argparse.ArgumentParser(description="CTI Butler standalone runner")
    parser.add_argument("-c", "--config", default="config_ctibutler.yaml", help="Config YAML path")
    parser.add_argument("--validate-only", action="store_true", help="Validate config only")
    parser.add_argument("--dry-run", action="store_true", help="No API call; write empty output")
    args = parser.parse_args()

    try:
        raw = load_yaml(args.config)
        cfg = validate_config(raw)

        if args.validate_only:
            print("Config validation successful.")
            return 0

        if args.dry_run:
            jp, cp = write_outputs(Path(cfg["OUTPUT_DIR"]), [], {"knowledge_bases": {}, "rows": []})
            print(f"[DRY-RUN] JSON: {jp}")
            print(f"[DRY-RUN] CSV : {cp}")
            return 0

        session = requests.Session()
        session.headers.update({"API-KEY": cfg["CTIBUTLER_API_KEY"]})

        state_file = Path(cfg["STATE_FILE"])
        state = load_state(state_file)
        state.setdefault("versions", {})

        all_rows: list[dict] = []
        payload = {"knowledge_bases": {}, "updated": datetime.now(UTC).isoformat()}

        for kb in cfg["KB_LIST"]:
            ingested_versions = state["versions"].setdefault(kb, [])
            kb_result = {"version": None, "objects_count": 0, "status": "unknown", "error": ""}

            try:
                version, objects = get_knowledge_base_objects(
                    session, cfg["CTIBUTLER_BASE_URL"], kb, ingested_versions
                )
                rows = summarize_and_fetch_bundles(session, cfg["CTIBUTLER_BASE_URL"], kb, objects)

                all_rows.extend(rows)
                kb_result["version"] = version
                kb_result["objects_count"] = len(objects)
                kb_result["status"] = "imported"

                # same behavior as connector: append processed version to state
                ingested_versions.append(version)

            except RuntimeError as e:
                kb_result["status"] = "already_ingested"
                kb_result["error"] = str(e)
            except Exception as e:
                kb_result["status"] = "failed"
                kb_result["error"] = str(e)

            payload["knowledge_bases"][kb] = kb_result

        state["updated"] = datetime.now(UTC).isoformat()
        save_state(state_file, state)

        jp, cp = write_outputs(Path(cfg["OUTPUT_DIR"]), all_rows, payload)

        print(f"Processed knowledge bases: {len(cfg['KB_LIST'])}")
        print(f"Rows: {len(all_rows)}")
        print(f"JSON: {jp}")
        print(f"CSV : {cp}")
        print(f"State: {state_file}")
        return 0

    except Exception as e:
        print(f"Execution failed: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
