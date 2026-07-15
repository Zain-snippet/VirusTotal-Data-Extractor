# AbuseIPDB Blacklist → STIX 2.1 Exporter

A fail-safe CLI tool that pulls malicious IPs from the AbuseIPDB blacklist and exports them as a STIX 2.1 bundle.

## Installation

```bash
pip install -r requirements.txt
```

## Setup

Copy `.env.example` to `.env` and set your API key:

```bash
cp .env.example .env
```

Edit `.env` and insert your AbuseIPDB API key.

## Usage

### Run with defaults (confidence >= 90, limit 10000)

```bash
python main.py
```

### Custom parameters

```bash
python main.py --confidence-minimum 75 --limit 5000
```

### Custom file paths

```bash
python main.py --checkpoint-file checkpoints/my_pull.jsonl --output-file output/my_bundle.json
```

### Standalone STIX re-conversion

If a run was killed forcefully (SIGKILL) and STIX conversion never completed, re-run the converter against the existing checkpoint file:

```bash
python stix_converter.py checkpoints/pull_20250101_120000.jsonl output/stix_bundle_20250101_120000.json
```
