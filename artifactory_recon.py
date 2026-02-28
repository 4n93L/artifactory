#!/usr/bin/env python3
"""
Artifactory Post-Incident Secret Scanner
All-in-one: find suspicious files -> download small ones -> scan content -> print only confirmed secrets.
Zero external dependencies (stdlib only).
"""

import json
import sys
import os
import re
import getpass
import urllib.request
import urllib.error
import ssl
import base64
import time
from datetime import datetime

BASE_URL = "http://10.26.1.75:8081/artifactory"

# Only download & scan files smaller than this (avoid big binaries)
MAX_SCAN_SIZE = 512 * 1024  # 512 KB

# ============================================================
# AQL file name patterns - what to search for
# ============================================================
SUSPICIOUS_NAME_PATTERNS = [
    # Keys & certs
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa", "id_rsa.*", "id_ed25519", "id_ed25519.*", "id_ecdsa", "id_ecdsa.*",
    # Env / dotfiles with secrets
    "*.env", ".env", ".env.*",
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".htpasswd",
    ".dockercfg", "*.dockerconfigjson",
    # Config files likely to hold creds
    "settings.xml",
    "application.yml", "application.yaml", "application.properties",
    "application-*.yml", "application-*.yaml", "application-*.properties",
    "bootstrap.yml", "bootstrap.yaml",
    "docker-compose*.yml", "docker-compose*.yaml",
    "wp-config.php", "config.php", "database.yml",
    "kubeconfig", "*.kubeconfig", "kube.config",
    "terraform.tfvars", "*.tfvars", "*.auto.tfvars",
    "vault.json", "vault.yml", "vault.yaml",
    # Explicit names
    "credentials", "credentials.*", "credential", "credential.*",
    "*password*", "*secret*", "*credential*", "*credentials*", "*token*",
    # CI/CD
    ".gitlab-ci.yml", "Jenkinsfile",
]

# ============================================================
# Content regex patterns - what counts as a real secret
# ============================================================
SECRET_REGEXES = [
    ("Private Key",             r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    ("AWS Access Key",          r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Key",          r'(?i)aws.?secret.?access.?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{30,}'),
    ("GitHub Token",            r'gh[ps]_[A-Za-z0-9_]{36,}'),
    ("GitLab Token",            r'glpat-[A-Za-z0-9\-]{20,}'),
    ("Slack Token",             r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ("NPM Auth Token",         r'//[^\s]*:_authToken=[^\s]+'),
    ("Docker Auth",             r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
    ("Connection String /w pwd",r'(?i)(mongodb|postgres|mysql|redis|amqp|mssql)://[^\s"\']*:[^\s"\']*@'),
    ("JDBC w/ password",        r'(?i)jdbc:[a-z]+://[^\s"]*password=[^\s"&]+'),
    ("Bearer Token",            r'(?i)(authorization|bearer)\s*[=:]\s*["\']?bearer\s+[a-zA-Z0-9\-_.~+/]{20,}'),
    ("Basic Auth (b64)",        r'(?i)(authorization)\s*[=:]\s*["\']?basic\s+[A-Za-z0-9+/=]{10,}'),
    ("Password assignment",     r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    ("Secret/Token assignment", r'(?i)(secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("Password (unquoted)",     r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s"\'#]{6,})'),
    ("Secret (unquoted)",       r'(?i)(secret_key|api_key|apikey|access_key|token|auth_token)\s*[=:]\s*([^\s"\'#]{10,})'),
    ("SSH key in variable",     r'(?i)ssh[_-]?(private[_-]?key|key|rsa)\s*[=:]\s*["\'].+'),
    ("Hex secret (32+)",        r'(?i)(secret|key|token|password|salt)\s*[=:]\s*["\']?[0-9a-f]{32,}'),
]

# Lines matching these are almost certainly NOT real secrets (false positive filters)
FALSE_POSITIVE_PATTERNS = [
    r'^\s*#',                          # commented out
    r'^\s*//',                         # commented out
    r'\$\{',                           # ${variable} placeholder
    r'\{\{',                           # {{template}} placeholder
    r'%\w+%',                          # %VARIABLE% placeholder
    r'(?i)(example|changeme|replace|your[_-]?|xxx|dummy|fake|test|placeholder|TODO)',
    r'(?i)^\s*(public|private|protected)\s',  # Java/C# access modifiers
    r'^\s*\*',                         # Javadoc/comment block
]

# ============================================================
# HTTP
# ============================================================

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def http_get(endpoint, auth, raw=False):
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=60) as resp:
            data = resp.read()
            return data if raw else json.loads(data.decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": True, "status": e.code, "url": url}
    except Exception as e:
        return {"_error": True, "detail": str(e), "url": url}


def aql_search(query, auth):
    url = f"{BASE_URL}/api/search/aql"
    req = urllib.request.Request(url, data=query.encode("utf-8"), headers={
        "Content-Type": "text/plain", "Authorization": auth,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": True, "status": e.code}
    except Exception as e:
        return {"_error": True, "detail": str(e)}


# ============================================================
# Content scanning
# ============================================================

def is_false_positive(line):
    for fp in FALSE_POSITIVE_PATTERNS:
        if re.search(fp, line):
            return True
    return False


def mask(value):
    """Show just enough to identify the secret without fully exposing it."""
    v = value.strip().strip("\"'")
    if len(v) > 20:
        return v[:6] + "..." + v[-4:]
    elif len(v) > 10:
        return v[:4] + "..." + v[-3:]
    else:
        return v[:3] + "***"


def scan_text(text, filepath):
    findings = []
    for line_num, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if is_false_positive(stripped):
            continue
        for label, pattern in SECRET_REGEXES:
            for m in re.finditer(pattern, line):
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "type": label,
                    "match": mask(m.group(0)),
                    "context": stripped[:150],
                })
    return findings


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    print("=" * W)
    print("  ARTIFACTORY POST-INCIDENT SECRET SCANNER")
    print(f"  Target: {BASE_URL}")
    print(f"  Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * W)

    username = input("\nUsername: ").strip()
    password = getpass.getpass("Password: ")
    auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    # ---- 1. Connectivity ----
    print("\n[1/5] Testing connection...", end=" ", flush=True)
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/system/ping", headers={"Authorization": auth})
        with urllib.request.urlopen(req, context=_ctx, timeout=10) as r:
            print("OK")
    except Exception as e:
        print(f"FAILED ({e})")
        sys.exit(1)

    # ---- 2. List repos ----
    print("[2/5] Listing repos...", end=" ", flush=True)
    repos = http_get("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        print(f"ERROR {repos}")
        sys.exit(1)
    print(f"{len(repos)} repos found")

    # ---- 3. Storage info ----
    print("[3/5] Storage info...", end=" ", flush=True)
    storage = http_get("/api/storageinfo", auth)
    if isinstance(storage, dict) and not storage.get("_error"):
        total = storage.get("binariesSummary", {}).get("binariesSize", "?")
        print(f"total = {total}")
    else:
        print("(skipped)")

    # ---- 4. AQL search for suspicious files ----
    print(f"[4/5] AQL search ({len(SUSPICIOUS_NAME_PATTERNS)} patterns)...")

    all_items = []
    batch_size = 10
    for i in range(0, len(SUSPICIOUS_NAME_PATTERNS), batch_size):
        batch = SUSPICIOUS_NAME_PATTERNS[i:i + batch_size]
        clauses = ",".join(f'{{"name":{{"$match":"{p}"}}}}' for p in batch)
        q = f'items.find({{"$or":[{clauses}]}}).include("repo","path","name","size","created","modified","actual_sha1")'
        result = aql_search(q, auth)
        if isinstance(result, dict) and not result.get("_error"):
            hits = result.get("results", [])
            all_items.extend(hits)
            print(f"  batch {i // batch_size + 1}: {len(hits)} hits")
        else:
            print(f"  batch {i // batch_size + 1}: ERROR {result}")
        time.sleep(0.3)

    # Dedupe
    seen = set()
    items = []
    for it in all_items:
        p = it.get("path", ".")
        fp = f"{it['repo']}/{p}/{it['name']}" if p != "." else f"{it['repo']}/{it['name']}"
        it["_fp"] = fp
        if fp not in seen:
            seen.add(fp)
            items.append(it)

    print(f"  -> {len(items)} unique suspicious files")

    # ---- 5. Download & scan ----
    scannable = [f for f in items if 0 < f.get("size", 0) < MAX_SCAN_SIZE]
    too_big = [f for f in items if f.get("size", 0) >= MAX_SCAN_SIZE]

    print(f"[5/5] Downloading & scanning {len(scannable)} files (< {MAX_SCAN_SIZE//1024} KB)...")

    all_findings = []
    scanned = 0
    dl_errors = 0

    for idx, item in enumerate(scannable):
        fp = item["_fp"]
        if (idx + 1) % 50 == 0:
            print(f"  progress: {idx+1}/{len(scannable)}...")

        raw = http_get(f"/{fp}", auth, raw=True)
        if isinstance(raw, dict):
            dl_errors += 1
            continue

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        findings = scan_text(text, fp)
        all_findings.extend(findings)
        scanned += 1

    # Also flag private key files (even without content scan the file itself IS the secret)
    key_extensions = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
    key_names = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
    always_critical = []
    for item in items:
        name = item.get("name", "")
        _, ext = os.path.splitext(name)
        base = name.split(".")[0]
        if ext.lower() in key_extensions or base.lower() in key_names:
            always_critical.append(item)

    # ============================================================
    # OUTPUT: only the interesting stuff
    # ============================================================
    print("\n" + "=" * W)
    print("  RESULTS")
    print("=" * W)

    # -- A) Confirmed secrets in file content --
    if all_findings:
        # Group by type
        by_type = {}
        for f in all_findings:
            by_type.setdefault(f["type"], []).append(f)

        print(f"\n  CONFIRMED SECRETS FOUND: {len(all_findings)}")
        print(f"  {'Type':<35} {'Count':>5}")
        print(f"  {'-'*35} {'-'*5}")
        for t, fs in sorted(by_type.items(), key=lambda x: -len(x[1])):
            print(f"  {t:<35} {len(fs):>5}")

        print(f"\n  {'─' * (W-4)}")
        print("  DETAILS (grouped by file):")
        print(f"  {'─' * (W-4)}")

        by_file = {}
        for f in all_findings:
            by_file.setdefault(f["file"], []).append(f)

        for fpath in sorted(by_file):
            print(f"\n  >> {fpath}")
            for f in by_file[fpath]:
                print(f"     L{f['line']:<5}  [{f['type']}]")
                print(f"            {f['match']}")
                print(f"            {f['context'][:120]}")
    else:
        print("\n  No confirmed secrets found in file contents.")

    # -- B) Critical files by extension (keys, certs) --
    if always_critical:
        print(f"\n  {'─' * (W-4)}")
        print(f"  KEY/CERT FILES ({len(always_critical)} files - these ARE secrets):")
        print(f"  {'─' * (W-4)}")
        for item in sorted(always_critical, key=lambda x: x["_fp"]):
            sz = round(item.get("size", 0) / 1024, 1)
            print(f"  {item['_fp']:<60} {sz:>8} KB")

    # -- C) Files too large to scan --
    if too_big:
        print(f"\n  {'─' * (W-4)}")
        print(f"  SUSPICIOUS BUT TOO LARGE TO SCAN ({len(too_big)} files):")
        print(f"  {'─' * (W-4)}")
        for item in sorted(too_big, key=lambda x: -x.get("size", 0)):
            sz = round(item.get("size", 0) / (1024 * 1024), 2)
            print(f"  {item['_fp']:<60} {sz:>8} MB")

    # -- Summary --
    print(f"\n{'=' * W}")
    print(f"  SUMMARY")
    print(f"  Repos:                  {len(repos)}")
    print(f"  Suspicious files found: {len(items)}")
    print(f"  Files scanned:          {scanned}")
    print(f"  Download errors:        {dl_errors}")
    print(f"  Confirmed secrets:      {len(all_findings)}")
    print(f"  Key/cert files:         {len(always_critical)}")
    print(f"  Too large to scan:      {len(too_big)}")
    print(f"{'=' * W}")


if __name__ == "__main__":
    main()
