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
    # INPUT — uncomment exactly ONE of the two blocks below.
    # ----------------------------------------------------------------

    # --- Option A: interactive hash entry (unchanged) ---
    #raw_hashes = get_hashes_from_user_input()
    #iocs = {
    #    "hash": raw_hashes,
    #    "ip": [],
    #    "cert_hash": [],
    #    "ja3": [],
    #}

    # --- Option B: multi-IOC JSON file (STIX bundle or flat JSON) ---
    iocs = extract_iocs_from_file("C:\\Users\\jahan\\Desktop\\ioc-enrichment\\30-entries.json")
    # ----------------------------------------------------------------

    total_found = sum(len(v) for v in iocs.values())
    if total_found == 0:
        print("\nNo IOCs found. Exiting.")
        return

    # ── Per-category counts ────────────────────────────────────────────
    print(f"\nIOCs found:  {iocs['hash']!s} hash(es), "
          f"{iocs['ip']!s} IP(s), "
          f"{iocs['cert_hash']!s} cert_hash(es), "
          f"{iocs['ja3']!s} JA3 fingerprint(s) "
          f"(of which {len(iocs['ja3'])} will be skipped — "
          "VirusTotal does not support JA3 lookups).")

    # ── Create one VT key worker per configured API key ────────────────
    workers = vt_connector.create_workers()
    num_workers = len(workers)

    output_dir = os.path.join(_script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    jsonl_path = os.path.join(output_dir, f"session_{timestamp}.jsonl")
    out_path = os.path.join(output_dir, f"session_{timestamp}.json")

    results: list[IOCResult] = []
    jsonl_file: Optional[object] = None

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        jsonl_file = open(jsonl_path, "w", encoding="utf-8")

        for category in _QUERYABLE_TYPES:
            items = iocs.get(category, [])
            if not items:
                print(f"\n--- {category}: 0 IOCs, skipping ---")
                continue

            print(f"\n--- Enriching {len(items)} {category}(s) "
                  f"using {num_workers} API key(s) ---")
            cat_results = _enrich_category(
                category, items, workers, executor, jsonl_file
            )
            results.extend(cat_results)

        # JA3 — count-only, never queried
        ja3_count = len(iocs.get("ja3", []))
        if ja3_count > 0:
            print(f"\n--- ja3: {ja3_count} fingerprint(s) found — "
                  "not queryable on VirusTotal, skipped ---")

    # ── Build and save STIX bundle ─────────────────────────────────────
    if jsonl_file is not None:
        jsonl_file.close()

    if results:
        bundle = to_stix_bundle(results)
        stix_json = bundle.serialize(pretty=True)

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(stix_json)

        parsed = json.loads(stix_json)
        n_indicators = sum(1 for o in parsed["objects"] if o["type"] == "indicator")

        print("\n" + "=" * 60)
        print("  Enrichment Summary by Category:")
        print(f"    hash:      found={len(iocs['hash'])}, "
              f"queried={sum(1 for r in results if r.ioc_type=='hash')}")

        ip_queried = sum(1 for r in results if r.ioc_type == "ip")
        print(f"    ip:        found={len(iocs['ip'])}, "
              f"queried={ip_queried}")

        cert_queried = sum(1 for r in results if r.ioc_type == "cert_hash")
        print(f"    cert_hash: found={len(iocs['cert_hash'])}, "
              f"queried={cert_queried}")
        print(f"    ja3:       found={len(iocs.get('ja3', []))}, "
              "skipped (not queryable)")

        print(f"\n  Total results: {len(results)}")
        print(f"  STIX indicators: {n_indicators}")
        print(f"  Saved to  {out_path}")
        print(f"  Incremental log:  {jsonl_path}")
        print("=" * 60)
    else:
        print("\nNo results collected.")


if __name__ == "__main__":
    main()
