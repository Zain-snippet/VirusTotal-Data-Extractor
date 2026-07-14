"""
virustotal.py
VirusTotal v3 connector — file hash and IP-address lookups.

Each API key gets its own VTKeyWorker with an independent RateLimiter.
Create workers via create_workers() to get one worker per configured key.
"""

import requests

from config import require_vt_keys
from connectors._rate_limit import RateLimiter
from connectors.exceptions import (
    ConnectorError,
    InvalidAPIKeyError,
    IOCNotFoundError,
    NetworkError,
    RateLimitExceededError,
)

_FILES_ENDPOINT = "https://www.virustotal.com/api/v3/files/"
_IP_ENDPOINT = "https://www.virustotal.com/api/v3/ip_addresses/"
_MIN_INTERVAL = 15.0


class VTKeyWorker:
    """A worker permanently bound to one VT API key + its own rate limiter."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._rate_limiter = RateLimiter(_MIN_INTERVAL)

    def _request(self, url: str, label: str) -> dict:
        """Perform a rate-limited GET and translate HTTP status codes to exceptions.

        Args:
            url: Fully-qualified VT API v3 URL.
            label: Human-readable label for the queried IOC (used in error messages).

        Returns:
            The parsed JSON response dict on success.

        Raises:
            ConnectorError subclass on any failure.
        """
        self._rate_limiter.wait()

        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        try:
            resp = requests.get(url, headers=headers, timeout=30)
        except requests.exceptions.Timeout:
            raise NetworkError("VirusTotal request timed out.")
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(f"VirusTotal connection failed: {e}")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"VirusTotal request error: {e}")

        if resp.status_code == 401:
            raise InvalidAPIKeyError("VirusTotal rejected the API key.")
        if resp.status_code == 429:
            raise RateLimitExceededError(
                "VirusTotal rate limit exceeded (4 req/min on free tier)."
            )
        if resp.status_code == 404:
            raise IOCNotFoundError(
                f"'{label}' not found in VirusTotal."
            )
        if resp.status_code != 200:
            raise ConnectorError(
                f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        return resp.json()

    def query(self, hash_value: str) -> dict:
        """Query the VirusTotal /files endpoint for a single hash value.

        Accepts MD5 (32 hex chars), SHA-1 (40), or SHA-256 (64).
        Returns the raw VT v3 JSON response dict on success.
        Raises a ConnectorError subclass on any failure.
        """
        url = f"{_FILES_ENDPOINT}{hash_value}"
        return self._request(url, hash_value)

    def query_ip(self, ip_value: str) -> dict:
        """Query the VirusTotal /ip_addresses endpoint for a single IP address.

        Returns the raw VT v3 JSON response dict on success.
        Raises a ConnectorError subclass on any failure.
        """
        url = f"{_IP_ENDPOINT}{ip_value}"
        return self._request(url, ip_value)


def create_workers() -> list[VTKeyWorker]:
    """Create one VTKeyWorker per configured API key."""
    return [VTKeyWorker(key) for key in require_vt_keys()]
