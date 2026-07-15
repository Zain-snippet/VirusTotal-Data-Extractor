import csv
import logging

logger = logging.getLogger("sslbl_pipeline")


def parse_feed_csv(raw_path: str) -> list[dict]:
    """Parse an SSLBL CSV file into a list of row dicts.

    Skips comment/metadata lines beginning with ``#``, then identifies the
    real header line (also ``#``-prefixed but containing commas), strips the
    leading ``#``, and uses ``csv.DictReader`` for all subsequent data rows.

    Args:
        raw_path: Path to the raw CSV file on disk.

    Returns:
        List of dicts keyed by column name.
    """
    with open(raw_path, encoding="utf-8") as f:
        lines = f.readlines()

    header_line = None
    data_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#") and "," in stripped:
            header_line = stripped
            data_start = i + 1
            break

    if header_line is None:
        logger.error("Could not find header line in %s", raw_path)
        return []

    fieldnames = header_line.lstrip("#").strip().split(",")

    data_lines = [
        line for line in lines[data_start:]
        if line.strip() and not line.strip().startswith("#")
    ]
    reader = csv.DictReader(data_lines, fieldnames=fieldnames)
    rows = list(reader)
    logger.info("Parsed %d rows from %s", len(rows), raw_path)
    return rows
