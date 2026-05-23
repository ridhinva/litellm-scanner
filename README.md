# LiteLLM SQL Injection Scanner

> CVE-2026-42208 — SQL injection in LiteLLM Proxy

Detects and validates CVE-2026-42208: SQL injection vulnerability in LiteLLM Proxy's database layer.
For authorized security testing only.

## Features

- CVE-2026-42208 SQL injection detection
- LiteLLM Proxy version fingerprinting
- PoC validation payloads
- Structured JSON / text output

## Requirements

- Python 3.8+

## Usage

```bash
python litellm_scanner.py --url http://target:4000      # Scan a target
python litellm_scanner.py --url http://target:4000 --poc # Run PoC validation
python litellm_scanner.py --help                         # Help
```

## Legal

**For authorized testing only.** Only scan systems you own or have explicit written permission to test.

## Author

ridhinva — https://github.com/ridhinva
