import os
from dotenv import load_dotenv

load_dotenv()


class MissingAPIKeyError(Exception):
    pass


def require_vt_keys() -> list[str]:
    """Load all 4 VT API keys (VT_API_KEY_1 … VT_API_KEY_4) as a list.

    Raises MissingAPIKeyError if fewer than 1 key is set.
    """
    keys = []
    for i in range(1, 5):
        value = os.getenv(f"VT_API_KEY_{i}")
        if value:
            keys.append(value)
    if not keys:
        raise MissingAPIKeyError(
            "No VirusTotal API keys found. Set at least VT_API_KEY_1 "
            "in your environment or .env file."
        )
    return keys
