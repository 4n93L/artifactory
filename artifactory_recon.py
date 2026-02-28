#!/usr/bin/env python3
"""
Artifactory Recon Script - Step 1: Inventory & suspicious file detection
Produces a JSON report to analyze offline.
"""

import json
import sys
import getpass
import urllib.request
import urllib.error
import urllib.parse
import ssl
import base64
import time
from datetime import datetime

BASE_URL = "http://10.26.1.75:8081/artifactory"
REPORT_FILE = "artifactory_recon_report.json"

# --- Suspicious file patterns for AQL ---
SUSPICIOUS_NAMES = [
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "*.crt", "*.cer", "*.der",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "id_dsa*",
    "*.env", "*.env.*", ".env",
    "*password*", "*secret*", "*credential*", "*token*",
    "*.properties", "*.yml", "*.yaml", "*.xml", "*.json", "*.toml", "*.ini", "*.cfg", "*.conf",
    "settings.xml", "application.yml", "application.yaml",
    "application-*.yml", "application-*.yaml",
    "docker-compose*", "Dockerfile*",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    ".htpasswd", ".htaccess",
    "known_hosts", "authorized_keys",
    "wp-config.php", "config.php", "database.yml",
    "credentials", "credentials.*",
    "kubeconfig", "kube.config", "*.kubeconfig",
    "terraform.tfvars", "*.tfvars",
    "vault.json", "vault.yml",
]

# High-priority patterns (most likely to contain raw secrets)
HIGH_PRIORITY_NAMES = [
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
    "id_rsa*", "id_ed25519*", "id_ecdsa*",
    "*.env", ".env",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials",
    ".htpasswd",
    "*password*", "*secret*", "*credential*",
    "terraform.tfvars",
    "kubeconfig",
]


def make_request(endpoint, method="GET", data=None, auth_header=None):
    """Make HTTP request to Artifactory API."""
    url = f"{BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    if data and isinstance(data, str):
        headers["Content-Type"] = "text/plain"
        req = urllib.request.Request(url, data=data.encode("utf-8"), headers=headers, method=method)
    elif data:
        req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), headers=headers, method=method)
    else:
        req = urllib.request.Request(url, headers=headers, method=method)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return {"_error": True, "status": e.code, "detail": body, "url": url}
    except Exception as e:
        return {"_error": True, "detail": str(e), "url": url}


def aql_search(query, auth_header):
    """Run an AQL query."""
    url = f"{BASE_URL}/api/search/aql"
    headers = {
        "Content-Type": "text/plain",
        "Authorization": auth_header,
    }
    req = urllib.request.Request(url, data=query.encode("utf-8"), headers=headers, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return {"_error": True, "status": e.code, "detail": body}
    except Exception as e:
        return {"_error": True, "detail": str(e)}


def main():
    print("=" * 60)
    print("  ARTIFACTORY RECON - Post-Incident Secret Scanner")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")
    print()

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    auth_header = f"Basic {creds}"

    report = {
        "scan_date": datetime.now().isoformat(),
        "target": BASE_URL,
        "repos": [],
        "suspicious_files": [],
        "high_priority_files": [],
        "errors": [],
        "stats": {},
    }

    # ---- Step 1: Test connection ----
    print("\n[1/4] Testing connection...")
    ping = make_request("/api/system/ping", auth_header=auth_header)
    if isinstance(ping, dict) and ping.get("_error"):
        # ping returns plain text "OK", try raw
        url = f"{BASE_URL}/api/system/ping"
        headers = {"Authorization": auth_header}
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                text = resp.read().decode()
                if "OK" in text.upper():
                    print("  -> Connection OK")
                else:
                    print(f"  -> Unexpected response: {text}")
        except Exception as e:
            print(f"  -> Connection FAILED: {e}")
            print("  Check URL, credentials, and VPN.")
            sys.exit(1)
    else:
        print("  -> Connection OK")

    # ---- Step 2: List all repos ----
    print("\n[2/4] Listing repositories...")
    repos = make_request("/api/repositories", auth_header=auth_header)
    if isinstance(repos, dict) and repos.get("_error"):
        print(f"  -> ERROR listing repos: {repos}")
        report["errors"].append({"step": "list_repos", "error": repos})
    else:
        print(f"  -> Found {len(repos)} repositories")
        for r in repos:
            print(f"     - {r.get('key', '?'):40s}  type={r.get('type', '?'):10s}  pkg={r.get('packageType', '?')}")
        report["repos"] = repos

    # ---- Step 3: Get storage info ----
    print("\n[3/4] Getting storage info (may take a moment)...")
    storage = make_request("/api/storageinfo", auth_header=auth_header)
    if isinstance(storage, dict) and not storage.get("_error"):
        repo_summaries = storage.get("repositoriesSummaryList", [])
        total_size = storage.get("binariesSummary", {}).get("binariesSize", "unknown")
        print(f"  -> Total binaries size: {total_size}")
        report["storage_summary"] = {
            "total_size": total_size,
            "repos": []
        }
        for rs in repo_summaries:
            key = rs.get("repoKey", "?")
            used = rs.get("usedSpace", "?")
            files = rs.get("filesCount", 0)
            report["storage_summary"]["repos"].append({
                "key": key, "usedSpace": used, "filesCount": files
            })
            if key != "TOTAL":
                print(f"     - {key:40s}  size={used:>12s}  files={files}")
    else:
        print(f"  -> Could not get storage info: {storage}")
        report["errors"].append({"step": "storage_info", "error": str(storage)})

    # ---- Step 4: AQL search for suspicious files ----
    print("\n[4/4] Searching for suspicious files via AQL...")

    # Build AQL OR conditions for all suspicious patterns
    or_clauses = []
    for pattern in SUSPICIOUS_NAMES:
        or_clauses.append(f'{{"name": {{"$match": "{pattern}"}}}}')

    aql_query = f'items.find({{"$or": [{",".join(or_clauses)}]}}).include("repo","path","name","size","created","modified","actual_sha1")'

    print(f"  -> Running AQL query ({len(SUSPICIOUS_NAMES)} patterns)...")
    result = aql_search(aql_query, auth_header)

    if isinstance(result, dict) and result.get("_error"):
        print(f"  -> AQL ERROR: {result}")
        report["errors"].append({"step": "aql_search", "error": result})

        # Fallback: try smaller batches
        print("  -> Trying smaller batch queries...")
        all_results = []
        batch_size = 10
        for i in range(0, len(SUSPICIOUS_NAMES), batch_size):
            batch = SUSPICIOUS_NAMES[i:i+batch_size]
            batch_clauses = [f'{{"name": {{"$match": "{p}"}}}}' for p in batch]
            batch_query = f'items.find({{"$or": [{",".join(batch_clauses)}]}}).include("repo","path","name","size","created","modified","actual_sha1")'
            batch_result = aql_search(batch_query, auth_header)
            if isinstance(batch_result, dict) and not batch_result.get("_error"):
                items = batch_result.get("results", [])
                all_results.extend(items)
                print(f"     Batch {i//batch_size + 1}: {len(items)} matches")
            else:
                print(f"     Batch {i//batch_size + 1}: ERROR - {batch_result}")
            time.sleep(0.5)
        result = {"results": all_results}

    if isinstance(result, dict) and not result.get("_error"):
        items = result.get("results", [])
        print(f"  -> Found {len(items)} suspicious files total")

        for item in items:
            item["full_path"] = f"{item.get('repo','')}/{item.get('path','.')}/{item.get('name','')}"
            item["size_kb"] = round(item.get("size", 0) / 1024, 2)

        report["suspicious_files"] = items

        # Tag high-priority
        hp_set = set()
        for item in items:
            name = item.get("name", "").lower()
            for hp in HIGH_PRIORITY_NAMES:
                hp_clean = hp.replace("*", "").lower()
                if hp_clean in name or name.endswith(hp_clean):
                    hp_set.add(item["full_path"])
                    break

        high_priority = [f for f in items if f["full_path"] in hp_set]
        report["high_priority_files"] = high_priority
        print(f"  -> {len(high_priority)} HIGH PRIORITY files (likely secrets)")

        # Print top findings
        if high_priority:
            print("\n  HIGH PRIORITY FILES:")
            for f in sorted(high_priority, key=lambda x: x.get("name", ""))[:50]:
                print(f"     [!] {f['full_path']}  ({f['size_kb']} KB)")

    # ---- Stats summary ----
    report["stats"] = {
        "total_repos": len(report["repos"]),
        "total_suspicious_files": len(report["suspicious_files"]),
        "high_priority_files": len(report["high_priority_files"]),
        "errors_count": len(report["errors"]),
    }

    # ---- Write report ----
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print("\n" + "=" * 60)
    print(f"  DONE - Report saved to: {REPORT_FILE}")
    print(f"  Repos:            {report['stats']['total_repos']}")
    print(f"  Suspicious files: {report['stats']['total_suspicious_files']}")
    print(f"  High priority:    {report['stats']['high_priority_files']}")
    print(f"  Errors:           {report['stats']['errors_count']}")
    print("=" * 60)
    print(f"\n>> Copy {REPORT_FILE} back and send it to Claude for analysis <<")


if __name__ == "__main__":
    main()
