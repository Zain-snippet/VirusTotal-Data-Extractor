import os
from dotenv import load_dotenv

ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
DEFAULT_CONFIDENCE_MINIMUM = 90
DEFAULT_LIMIT = 10000
CHECKPOINT_DIR = "checkpoints"
OUTPUT_DIR = "output"


def load_config() -> str:
    load_dotenv()
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ABUSEIPDB_API_KEY is not set. Please check your .env file."
        )
    return api_key
