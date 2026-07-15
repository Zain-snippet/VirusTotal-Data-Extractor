#!/usr/bin/env python3
"""
main.py
VirusTotal IOC Enrichment Pipeline

Queries VirusTotal for file hashes (MD5 / SHA-1 / SHA-256), IP addresses,
and SSL-certificate hashes, and writes results as a STIX 2.1 bundle to
output/session_<timestamp>.json.

Uses up to 4 VT API keys concurrently (~16 req/min aggregate) and writes
every completed result incrementally to a JSONL file for crash resilience.

Input source selection: comment/uncomment ONE line in main() below.
"""

import dataclasses
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

# Ensure imports resolve from this directory regardless of cwd.
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from config import MissingAPIKeyError
from connectors import virustotal as vt_connector
from connectors.exceptions import ConnectorError
from input_handlers import (
    extract_iocs_from_file,
    get_hashes_from_user_input,
)
from normalizers.schema import IOCResult
from normalizers.vt_normalizer import normalize as vt_normalize
from stix.stix_converter import to_stix_bundle

# IOCs of these types are queryable via the VirusTotal API.
_QUERYABLE_TYPES = ("hash", "ip", "cert_hash")
# JA3 is explicitly NOT queryable — see extract_iocs_from_file docs.


# ── Per-IOC enrichment (worker thread) ────────────────────────────────

def _enrich(worker: vt_connector.VTKeyWorker, ioc: str, ioc_type: str) -> IOCResult:
    """Query VirusTotal via *worker* and return a normalized IOCResult.

    Never raises — errors are captured into the returned IOCResult so the
    caller can continue processing the remaining IOCs.
    """
    try:
        if ioc_type == "ip":
            raw = worker.query_ip(ioc)
        else:
            raw = worker.query(ioc)
        return vt_normalize(raw, ioc, ioc_type)
    except (MissingAPIKeyError, ConnectorError) as e:
        return IOCResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            query_success=False,
            error=str(e),
        )
    except Exception as e:  # noqa: BLE001
        return IOCResult(
            source="virustotal",
            ioc=ioc,
            ioc_type=ioc_type,
            query_success=False,
            error=f"Unexpected error: {e}",
        )


def _enrich_category(
    category: str,
    iocs: list[str],
    workers: list,
    executor: ThreadPoolExecutor,
    jsonl_file,
) -> list[IOCResult]:
    """Submit all IOCs of one category to the thread pool and collect results."""
    num_workers = len(workers)
    futures = [
        executor.submit(_enrich, workers[i % num_workers], ioc, category)
        for i, ioc in enumerate(iocs)
    ]

    processed: set = set()
    results: list[IOCResult] = []
    total = len(iocs)

    try:
        for future in as_completed(futures):
            processed.add(future)
            result = future.result()
            results.append(result)

            record = dataclasses.asdict(result)
            jsonl_file.write(json.dumps(record) + "\n")
            jsonl_file.flush()

            n = len(results)
            display = result.ioc if len(result.ioc) <= 16 else result.ioc[:16] + "..."
            print(f"  [{n}/{total}] {display}")
            if result.query_success:
                verdict = "malicious" if result.malicious else "benign"
                pct = (
                    f"{result.raw_score:.1%}"
                    if result.raw_score is not None
                    else "N/A"
                )
                print(f"           → {verdict} ({pct} detection ratio)")
            else:
                print(f"           → error: {result.error}")

    except KeyboardInterrupt:
        print("\n\nInterrupted. Cancelling pending requests...")
        for f in futures:
            f.cancel()
        executor.shutdown(wait=True)
        for f in futures:
            if f not in processed and f.done() and not f.cancelled():
                result = f.result()
                results.append(result)
                record = dataclasses.asdict(result)
                jsonl_file.write(json.dumps(record) + "\n")
                jsonl_file.flush()

    return results


# ── Main ──────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("       VirusTotal IOC Enrichment Pipeline")
    print("=" * 60)

    # ----------------------------------------------------------------
    # FOLDER INPUT — uncomment exactly ONE of the two blocks below.
    # ----------------------------------------------------------------

    # --- Option A: hardcoded paths ---
    #folder_paths = [
    #    r"C:\Users\jahan\Desktop\ioc-enrichment\feeds",
    #    r"C:\Users\jahan\Desktop\New folder (2)",
    #]

    # --- Option B: user input via CLI (comma-separated) ---
    raw_input = input("Enter folder path(s) (comma-separated): ").strip()
    folder_paths = [p.strip() for p in raw_input.split(",") if p.strip()]
    # ----------------------------------------------------------------

    if not folder_paths:
        print("[error] No folder path provided.", file=sys.stderr)
        return

    # ── Discover input files across all folders ──────────────────────
    files: list[Path] = []
    for folder_path in folder_paths:
        folder = Path(folder_path)
        if not folder.exists() or not folder.is_dir():
            print(f"[error] Invalid folder path, skipping: {folder_path}", file=sys.stderr)
            continue

        folder_files = sorted(
            set(folder.rglob("*.json")) | set(folder.rglob("*.jsonl"))
        )
        folder_files = [f for f in folder_files if "output" not in f.parts]
        files.extend(folder_files)

    files = sorted(set(files))

    if not files:
        print("\nNo .json or .jsonl files found across the given folders (excluding output/). Exiting.")
        return

    print(f"\nFound {len(files)} file(s) to process across {len(folder_paths)} folder(s).\n")
    
    # ── Session state ─────────────────────────────────────────────────
    ioc_cache: dict[tuple[str, str], IOCResult] = {}
    session_results: list[IOCResult] = []
    files_processed = 0
    files_skipped = 0
    cache_hits = 0
    vt_queries = 0
    ja3_total = 0

    workers = vt_connector.create_workers()
    num_workers = len(workers)

    output_dir = os.path.join(_script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    jsonl_path = os.path.join(output_dir, f"session_{timestamp}.jsonl")
    out_path = os.path.join(output_dir, f"session_{timestamp}.json")

    jsonl_file: Optional[object] = None

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        jsonl_file = open(jsonl_path, "w", encoding="utf-8")

        for file in files:
            try:
                print(f"\n--- Processing: {file} ---")
                iocs = extract_iocs_from_file(str(file))
                total_found = sum(len(v) for v in iocs.values())

                if total_found == 0:
                    print(f"  No IOCs found, skipping.")
                    files_skipped += 1
                    continue

                # JA3 — count-only, never queried
                ja3_count = len(iocs.get("ja3", []))
                ja3_total += ja3_count
                if ja3_count > 0:
                    print(f"  {ja3_count} JA3 fingerprint(s) found — "
                          "not queryable on VirusTotal, skipped")

                for category in _QUERYABLE_TYPES:
                    items = iocs.get(category, [])
                    if not items:
                        continue

                    hit_list: list[str] = []
                    miss_list: list[str] = []
                    for ioc_val in items:
                        key = (category, ioc_val.lower())
                        if key in ioc_cache:
                            hit_list.append(ioc_val)
                        else:
                            miss_list.append(ioc_val)

                    if hit_list:
                        for ioc_val in hit_list:
                            cached = ioc_cache[(category, ioc_val.lower())]
                            result = dataclasses.replace(
                                cached, source_file=str(file)
                            )
                            session_results.append(result)
                            record = dataclasses.asdict(result)
                            jsonl_file.write(json.dumps(record) + "\n")
                            jsonl_file.flush()
                            cache_hits += 1
                            display = ioc_val if len(ioc_val) <= 16 else ioc_val[:16] + "..."
                            print(f"  [cache] {display} → reused from earlier file")

                    if miss_list:
                        cat_results = _enrich_category(
                            category, miss_list, workers, executor, jsonl_file
                        )
                        for result in cat_results:
                            if result.query_success:
                                ioc_cache[
                                    (result.ioc_type, result.ioc.lower())
                                ] = result
                            result.source_file = str(file)
                            session_results.append(result)
                            vt_queries += 1

                files_processed += 1

            except Exception as e:
                print(f"[error] Skipping {file}: {e}", file=sys.stderr)
                files_skipped += 1

    # ── Build and save STIX bundle ─────────────────────────────────────
    if jsonl_file is not None:
        jsonl_file.close()

    if not session_results:
        print("\nNo results collected.")
        return

    bundle = to_stix_bundle(session_results)
    stix_json = bundle.serialize(pretty=True)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(stix_json)

    parsed = json.loads(stix_json)
    n_indicators = sum(1 for o in parsed["objects"] if o["type"] == "indicator")

    print("\n" + "=" * 60)
    print("  Session Summary")
    print(f"  Files scanned:        {files_processed}")
    print(f"  Files skipped:        {files_skipped}")
    print(f"  VT queries made:      {vt_queries}")
    print(f"  Cache hits:           {cache_hits}")
    print(f"  Total results:        {len(session_results)}")
    print(f"  STIX indicators:      {n_indicators}")
    print(f"  Output:               {out_path}")
    print(f"  Incremental log:      {jsonl_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
