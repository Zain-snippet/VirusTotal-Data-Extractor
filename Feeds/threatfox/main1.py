import csv
import io
import os
import ssl
import sys
import time
import traceback
import urllib.request
import zipfile
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Dict, Iterable, List, Optional, Tuple, Union
from pathlib import Path

import yaml


@dataclass(init=False)
class FeedRow:
    """ThreatFox CSV row"""

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
        """Initializer"""

        first_seen = row[0]
        self.first_seen = datetime.strptime(first_seen, "%Y-%m-%d %H:%M:%S")
        self.first_seen = self.first_seen.replace(tzinfo=UTC)

        self.id = row[1]
        self.value = row[2]
        self.type = row[3]
        self.threat_type = row[4]
        self.fk_malware = row[5]
        self.malware_aliases = list(filter(None, row[6].split(",")))
        self.malware_printable = row[7]

        if self.malware_aliases == ["None"]:
            self.malware_aliases = []

        if self.fk_malware == "unknown":
            self.fk_malware = ""

        if self.malware_printable == "Unknown malware":
            self.malware_printable = ""
        else:
            self.malware_aliases.insert(0, self.malware_printable)

        last_seen = row[8]
        if last_seen:
            self.last_seen = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
            self.last_seen = self.last_seen.replace(tzinfo=UTC)
        else:
            self.last_seen = None

        self.confidence_level = int(row[9])
        self.is_compromised = str(row[10]).lower() == "true"
        self.reference = row[11]

        if self.reference == "None":
            self.reference = ""

        self.tags = list(filter(None, row[12].split(",")))

        if self.threat_type:
            self.tags.insert(0, self.threat_type)

        self.anonymous = bool(int(row[13]))
        self.reporter = row[14]


class ThreatFoxConnector:
    """ThreatFox Connector - Imports IOCs from ThreatFox"""

    def __init__(self, config_file: str = "config.yaml"):
        """Initialize connector with configuration"""
        
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
        """Load configuration from YAML file"""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return yaml.safe_load(f) or {}
        return {}

    def log(self, message: str, level: str = "info"):
        """Log messages"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level.upper()}] {message}")

    def download_csv(self) -> Iterable[str]:
        """Download CSV from ThreatFox"""
        self.log(f"Fetching ThreatFox dataset from {self.csv_url}")
        
        try:
            with urllib.request.urlopen(
                self.csv_url,
                context=ssl.create_default_context(),
            ) as response:
                data = response.read()

            try:
                zipped_file = io.BytesIO(data)
                with zipfile.ZipFile(zipped_file, "r") as zip_ref:
                    with zip_ref.open("full.csv") as full_file:
                        csv_data = full_file.read()
            except zipfile.BadZipFile:
                csv_data = data

            for line in csv_data.decode("utf-8").splitlines():
                if line.startswith("#"):
                    continue
                yield line
                
        except Exception as e:
            self.log(f"Error downloading CSV: {str(e)}", "error")
            raise

    def process_ioc(self, ioc: FeedRow) -> Dict:
        """Process IOC and return structured data"""
        
        processed = {
            "id": ioc.id,
            "value": ioc.value,
            "type": ioc.type,
            "threat_type": ioc.threat_type,
            "malware": ioc.fk_malware,
            "malware_aliases": ioc.malware_aliases,
            "first_seen": ioc.first_seen.isoformat(),
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            "confidence_level": ioc.confidence_level,
            "reporter": ioc.reporter,
            "tags": ioc.tags,
            "reference": ioc.reference,
            "anonymous": ioc.anonymous,
        }
        
        return processed

    def import_data(self):
        """Main data import function"""
        
        self.log("Starting ThreatFox import process")
        now = datetime.now(UTC)
        
        try:
            csv.register_dialect(
                "custom",
                delimiter=",",
                quotechar='"',
                skipinitialspace=True,
            )

            ioc_count = 0
            processed_iocs = []
            skipped_count = 0

            lines = self.download_csv()
            csv_reader = csv.reader(lines, dialect="custom")

            for i, row in enumerate(csv_reader):
                if i % 5000 == 0 and i > 0:
                    self.log(f"Processed {i} entries...")

                if len(row) < 15:
                    self.log(f"Skipping malformed row: {i}", "warning")
                    continue

                try:
                    ioc = FeedRow(row)
                    
                    if not self.import_offline and ioc.last_seen and ioc.last_seen < now:
                        skipped_count += 1
                        continue
                    
                    processed = self.process_ioc(ioc)
                    processed_iocs.append(processed)
                    ioc_count += 1
                    
                except Exception as e:
                    self.log(f"Error processing row {i}: {str(e)}", "warning")
                    skipped_count += 1
                    continue

            self.log(f"Processed {ioc_count} IOCs successfully, skipped {skipped_count}")
            
            self._save_results(processed_iocs)
            self.log("Import completed successfully")
            
        except Exception as e:
            self.log(f"Fatal error during import: {str(e)}", "error")
            raise

    def _save_results(self, iocs: List[Dict]):
        """Save results to JSON and CSV"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_file = self.output_dir / f"threatfox_{timestamp}.json"
        csv_file = self.output_dir / f"threatfox_{timestamp}.csv"
        
        try:
            with open(json_file, 'w') as f:
                json.dump(iocs, f, indent=2)
            self.log(f"Saved JSON output: {json_file}")
            
            if iocs:
                with open(csv_file, 'w', newline='') as f:
                    fieldnames = iocs[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(iocs)
                self.log(f"Saved CSV output: {csv_file}")
                
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "error")
            raise


def main():
    """Main entry point"""
    try:
        connector = ThreatFoxConnector("config.yaml")
        connector.import_data()
        return 0
    except KeyboardInterrupt:
        print("\nConnector stopped by user")
        return 1
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
