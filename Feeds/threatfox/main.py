import csv
import io
import json
import os
import ssl
import sys
import traceback
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Union

import yaml

from stix_mapper.connectors import ThreatFoxMapper


@dataclass(init=False)
class FeedRow:
    first_seen: datetime
    id: str
    value: str
    type: str
    threat_type: str
    fk_malware: str
    malware_aliases: List[str]
    malware_printable: str
    last_seen: Union[datetime, None]
    confidence_level: int
    reference: str
    tags: List[str]
    anonymous: bool
    reporter: str

    def __init__(self, row: Tuple) -> None:
        self.first_seen = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
        self.id = row[1]
        self.value = row[2]
        self.type = row[3]
        self.threat_type = row[4]
        self.fk_malware = "" if row[5] == "unknown" else row[5]
        self.malware_aliases = list(filter(None, row[6].split(",")))
        self.malware_printable = "" if row[7] == "Unknown malware" else row[7]
        if self.malware_aliases == ["None"]:
            self.malware_aliases = []
        if self.malware_printable:
            self.malware_aliases.insert(0, self.malware_printable)
        self.last_seen = datetime.strptime(row[8], "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC) if row[8] else None
        self.confidence_level = int(row[9])
        self.is_compromised = str(row[10]).lower() == "true"
        self.reference = "" if row[11] == "None" else row[11]
        self.tags = list(filter(None, row[12].split(",")))
        if self.threat_type:
            self.tags.insert(0, self.threat_type)
        self.anonymous = bool(int(row[13]))
        self.reporter = row[14]


class ThreatFoxConnector:
    def __init__(self, config_file: str = "config.yaml"):
        self.config = self._load_config(config_file)
        self.output_dir = Path(self.config.get("output_directory", "output"))
        self.output_dir.mkdir(exist_ok=True)
        self.csv_url = self.config.get("threatfox_csv_url", "https://threatfox.abuse.ch/export/csv/recent/")
        self.import_offline = self.config.get("import_offline", True)
        self.create_indicators = self.config.get("create_indicators", True)
        self.default_score = self.config.get("default_score", 50)
        self.interval_days = self.config.get("interval_days", 3)
        self.log(f"Connector initialized. Output directory: {self.output_dir}")

    def _load_config(self, config_file: str) -> dict:
        if os.path.exists(config_file):
            with open(config_file, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def log(self, message: str, level: str = "info"):
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{level.upper()}] {message}")

    def download_csv(self) -> Iterable[str]:
        self.log(f"Fetching ThreatFox dataset from {self.csv_url}")
        with urllib.request.urlopen(self.csv_url, context=ssl.create_default_context()) as response:
            data = response.read()
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zip_ref:
                with zip_ref.open("full.csv") as full_file:
                    csv_data = full_file.read()
        except zipfile.BadZipFile:
            csv_data = data
        for line in csv_data.decode("utf-8").splitlines():
            if not line.startswith("#"):
                yield line

    def process_ioc(self, ioc: FeedRow) -> Dict:
        return {"id": ioc.id, "value": ioc.value, "type": ioc.type, "threat_type": ioc.threat_type, "malware": ioc.fk_malware, "malware_aliases": ioc.malware_aliases, "first_seen": ioc.first_seen.isoformat(), "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None, "confidence_level": ioc.confidence_level, "reporter": ioc.reporter, "tags": ioc.tags, "reference": ioc.reference, "anonymous": ioc.anonymous}

    def import_data(self):
        self.log("Starting ThreatFox import process")
        now = datetime.now(UTC)
        csv.register_dialect("custom", delimiter=",", quotechar='"', skipinitialspace=True)
        ioc_count = 0
        processed_iocs = []
        skipped_count = 0
        for i, row in enumerate(csv.reader(self.download_csv(), dialect="custom")):
            if i % 5000 == 0 and i > 0:
                self.log(f"Processed {i} entries...")
            if len(row) < 15:
                skipped_count += 1
                continue
            try:
                ioc = FeedRow(row)
                if not self.import_offline and ioc.last_seen and ioc.last_seen < now:
                    skipped_count += 1
                    continue
                processed_iocs.append(self.process_ioc(ioc))
                ioc_count += 1
            except Exception as exc:
                self.log(f"Error processing row {i}: {exc}", "warning")
                skipped_count += 1
        self.log(f"Processed {ioc_count} IOCs successfully, skipped {skipped_count}")
        self._save_results(processed_iocs)
        self.log("Import completed successfully")

    def _save_results(self, iocs: List[Dict]):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = self.output_dir / f"threatfox_{timestamp}.json"
        csv_file = self.output_dir / f"threatfox_{timestamp}.csv"
        stix_file = self.output_dir / f"threatfox_{timestamp}_stix.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2, ensure_ascii=False)
        self.log(f"Saved JSON output: {json_file}")
        if iocs:
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=iocs[0].keys())
                writer.writeheader()
                writer.writerows(iocs)
            self.log(f"Saved CSV output: {csv_file}")
        with open(stix_file, "w", encoding="utf-8") as f:
            json.dump(ThreatFoxMapper().create_stix_bundle_from_rows(iocs), f, indent=2, ensure_ascii=False)
        self.log(f"Saved STIX output: {stix_file}")


def main():
    try:
        ThreatFoxConnector("config.yaml").import_data()
        return 0
    except KeyboardInterrupt:
        print("\nConnector stopped by user")
        return 1
    except Exception as exc:
        print(f"Fatal error: {exc}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
