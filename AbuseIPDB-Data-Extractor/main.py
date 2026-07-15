import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone

from config import (
    CHECKPOINT_DIR,
    DEFAULT_CONFIDENCE_MINIMUM,
    DEFAULT_LIMIT,
    OUTPUT_DIR,
    load_config,
)
from fetcher import AbuseIPDBFetcher
from shutdown import register_signal_handlers, stop_event
from stix_converter import convert_checkpoint_to_stix
from writer import CheckpointWriter


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pull AbuseIPDB blacklist and export as STIX 2.1 bundle"
    )
    parser.add_argument(
        "--confidence-minimum",
        type=int,
        default=DEFAULT_CONFIDENCE_MINIMUM,
        help=f"Minimum abuse confidence score (default: {DEFAULT_CONFIDENCE_MINIMUM})",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Max number of records to pull (default: {DEFAULT_LIMIT})",
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    parser.add_argument(
        "--checkpoint-file",
        default=os.path.join(CHECKPOINT_DIR, f"pull_{timestamp}.jsonl"),
        help="Path for the JSONL checkpoint file",
    )
    parser.add_argument(
        "--output-file",
        default=os.path.join(OUTPUT_DIR, f"stix_bundle_{timestamp}.json"),
        help="Path for the output STIX bundle JSON file",
    )
    args = parser.parse_args()

    _ensure_dir(CHECKPOINT_DIR)
    _ensure_dir(OUTPUT_DIR)

    log_path = args.checkpoint_file + ".log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logger = logging.getLogger(__name__)

    register_signal_handlers()

    start_time = time.time()

    try:
        api_key = load_config()
    except RuntimeError as e:
        logger.error(e)
        sys.exit(1)

    fetcher = AbuseIPDBFetcher(
        api_key=api_key,
        confidence_minimum=args.confidence_minimum,
        limit=args.limit,
    )

    try:
        records = fetcher.fetch_blacklist()
    except Exception as e:
        logger.error("Failed to fetch blacklist: %s", e)
        sys.exit(1)

    records_pulled = 0

    try:
        with CheckpointWriter(args.checkpoint_file) as cw:
            for record in records:
                if stop_event.is_set():
                    logger.info("Graceful stop requested, ending pull early")
                    break
                cw.write_record(record)
                records_pulled += 1
    except Exception as e:
        logger.error("Error during checkpoint writing: %s", e)
        raise

    try:
        records_converted = convert_checkpoint_to_stix(
            args.checkpoint_file, args.output_file
        )
    except Exception as e:
        logger.error("STIX conversion failed: %s", e)
        records_converted = 0

    elapsed = time.time() - start_time
    logger.info(
        "SUMMARY: pulled=%d converted=%d checkpoint=%s output=%s runtime=%.2fs",
        records_pulled,
        records_converted,
        args.checkpoint_file,
        args.output_file,
        elapsed,
    )


if __name__ == "__main__":
    main()
