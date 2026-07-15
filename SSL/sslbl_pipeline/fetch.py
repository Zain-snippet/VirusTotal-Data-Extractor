import logging

import requests

from config import Feed, REQUEST_TIMEOUT_SECONDS

logger = logging.getLogger("sslbl_pipeline")


def fetch_feed(feed: Feed) -> bool:
    """Download a single feed and save to disk.

    Args:
        feed: Feed configuration with url and raw_path.

    Returns:
        True on success, False on any failure (logged, not raised).
    """
    try:
        response = requests.get(
            feed.url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            stream=True,
        )
        response.raise_for_status()
        with open(feed.raw_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        logger.info("Downloaded %s -> %s", feed.name, feed.raw_path)
        return True
    except Exception as exc:
        logger.error("Failed to download feed '%s': %s", feed.name, exc)
        return False


def fetch_all(feeds: list[Feed]) -> dict[str, bool]:
    """Download every feed, one at a time.

    Each raw file is fully written to disk before the next download begins
    (crash-safety checkpoint).

    Args:
        feeds: List of Feed configurations.

    Returns:
        Dict mapping feed name -> success boolean.
    """
    results: dict[str, bool] = {}
    for feed in feeds:
        results[feed.name] = fetch_feed(feed)
    return results
