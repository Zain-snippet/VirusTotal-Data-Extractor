import logging
import time
import requests

logger = logging.getLogger(__name__)


class AbuseIPDBFetcher:
    """Fetches the AbuseIPDB blacklist for reported malicious IPs."""

    def __init__(
        self, api_key: str, confidence_minimum: int, limit: int
    ) -> None:
        self.api_key = api_key
        self.confidence_minimum = confidence_minimum
        self.limit = limit

    def fetch_blacklist(self) -> list[dict]:
        url = "https://api.abuseipdb.com/api/v2/blacklist"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "confidenceMinimum": self.confidence_minimum,
            "limit": self.limit,
        }

        logger.info(
            "Fetching blacklist from AbuseIPDB (confidence>=%d, limit=%d)",
            self.confidence_minimum,
            self.limit,
        )

        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            logger.error("Network error during API request: %s", e)
            raise

        if resp.status_code == 401 or resp.status_code == 403:
            logger.error(
                "API key is invalid or unauthorized (HTTP %d)", resp.status_code
            )
            resp.raise_for_status()

        if resp.status_code == 429:
            logger.warning("Rate limited (HTTP 429), retrying once after 5s...")
            time.sleep(5)
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)
            except requests.exceptions.RequestException as e:
                logger.error("Network error on retry: %s", e)
                raise

            if resp.status_code == 429:
                logger.error("Rate limited again on retry, giving up.")
                resp.raise_for_status()

        if resp.status_code != 200:
            logger.error(
                "API request failed with status %d: %s",
                resp.status_code,
                resp.text,
            )
            resp.raise_for_status()

        data = resp.json()
        records = data.get("data", [])
        logger.info("Fetched %d blacklist records", len(records))
        return records
