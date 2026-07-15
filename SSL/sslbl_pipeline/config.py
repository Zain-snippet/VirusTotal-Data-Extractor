import os


RAW_DIR = "data/raw"
OUTPUT_DIR = "data/output"
OUTPUT_STIX_FILE = os.path.join(OUTPUT_DIR, "sslbl_bundle.json")
REQUEST_TIMEOUT_SECONDS = 30


class Feed:
    def __init__(self, name: str, url: str, raw_filename: str):
        self.name = name
        self.url = url
        self.raw_filename = raw_filename

    @property
    def raw_path(self) -> str:
        return os.path.join(RAW_DIR, self.raw_filename)


FEEDS = [
    Feed(
        name="ssl_cert",
        url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        raw_filename="ssl_cert.csv",
    ),
    Feed(
        name="botnet_ip",
        url="https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        raw_filename="botnet_ip.csv",
    ),
    Feed(
        name="ja3",
        url="https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        raw_filename="ja3.csv",
    ),
]
