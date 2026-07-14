#!/usr/bin/env python3
"""
main.py
VirusTotal Hash Enrichment Pipeline

Queries VirusTotal for file hashes (MD5 / SHA-1 / SHA-256) and writes
results as a STIX 2.1 bundle to output/session_<timestamp>.json.

Uses up to 4 VT API keys concurrently (~16 req/min aggregate) and writes
every completed result incrementally to a JSONL file for crash resilience.

Switching input method: comment/uncomment ONE line in main() below.
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
from input_handlers import get_hashes_from_file, get_hashes_from_user_input
from normalizers.schema import IOCResult
from normalizers.vt_normalizer import normalize as vt_normalize
from stix.stix_converter import to_stix_bundle


# ── Per-hash enrichment (worker thread) ───────────────────────────────

def _enrich(worker: vt_connector.VTKeyWorker, hash_value: str) -> IOCResult:
    """Query VirusTotal via *worker* and return a normalized IOCResult.

    Never raises — errors are captured into the returned IOCResult so the
    caller can continue processing the remaining hashes.
    """
    try:
        raw = worker.query(hash_value)
        return vt_normalize(raw, hash_value, "hash")
    except (MissingAPIKeyError, ConnectorError) as e:
        return IOCResult(
            source="virustotal",
            ioc=hash_value,
            ioc_type="hash",
            query_success=False,
            error=str(e),
        )
    except Exception as e:  # noqa: BLE001
        return IOCResult(
            source="virustotal",
            ioc=hash_value,
            ioc_type="hash",
            query_success=False,
            error=f"Unexpected error: {e}",
        )


# ── Main ──────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("       VirusTotal Hash Enrichment Pipeline")
    print("=" * 60)

    # ----------------------------------------------------------------
    # INPUT — uncomment exactly ONE of the two lines below.
    # Both return list[str]; everything below is identical either way.
    # ----------------------------------------------------------------
    #hashes = get_hashes_from_user_input()
    hashes = get_hashes_from_file("C:\\Users\\jahan\\Desktop\\ioc-enrichment\\30-entries.json")
    # ----------------------------------------------------------------

    if not hashes:
        print("\nNo hashes provided. Exiting.")
        return

    # ── Create one VT key worker per configured API key ────────────────
    workers = vt_connector.create_workers()
    num_workers = len(workers)
    print(f"\nQuerying VirusTotal for {len(hashes)} hash(es) "
          f"using {num_workers} API key(s)...")
    print("-" * 60)

    output_dir = os.path.join(_script_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    jsonl_path = os.path.join(output_dir, f"session_{timestamp}.jsonl")
    out_path = os.path.join(output_dir, f"session_{timestamp}.json")

    results: list[IOCResult] = []
    jsonl_file: Optional[object] = None

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Round-robin hashes across workers so each key gets ~equal work
        futures = [
            executor.submit(_enrich, workers[i % num_workers], h)
            for i, h in enumerate(hashes)
        ]

        processed: set = set()
        jsonl_file = open(jsonl_path, "w", encoding="utf-8")
        total = len(hashes)

        try:
            for future in as_completed(futures):
                processed.add(future)
                result = future.result()
                results.append(result)

                # Write incrementally — flush after every result
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
            # Give running threads a moment to finish the current request
            executor.shutdown(wait=True)
            # Collect any futures that completed during shutdown
            for f in futures:
                if f not in processed and f.done() and not f.cancelled():
                    result = f.result()
                    results.append(result)
                    record = dataclasses.asdict(result)
                    jsonl_file.write(json.dumps(record) + "\n")
                    jsonl_file.flush()

    # ── Build and save STIX bundle (partial on interrupt, full otherwise)
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
        print(f"  Processed {len(results)} hash(es).")
        print(f"  Produced  {n_indicators} STIX indicator(s).")
        print(f"  Saved to  {out_path}")
        print(f"  Incremental log:  {jsonl_path}")
        print("=" * 60)
    else:
        print("\nNo results collected.")


if __name__ == "__main__":
    main()
