import json
import logging
import os

logger = logging.getLogger(__name__)


class CheckpointWriter:
    """Writes records to a JSONL checkpoint file with immediate fsync."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.fp = open(filepath, "a", buffering=1, encoding="utf-8")
        logger.info("Checkpoint file opened: %s", filepath)

    def write_record(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False) + "\n"
        self.fp.write(line)
        self.fp.flush()
        os.fsync(self.fp.fileno())

    def close(self) -> None:
        if not self.fp.closed:
            self.fp.close()
            logger.info("Checkpoint file closed: %s", self.filepath)

    def __enter__(self) -> "CheckpointWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
