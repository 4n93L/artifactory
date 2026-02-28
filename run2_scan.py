#!/usr/bin/env python3
"""
Run 2: Full content scan.
- Downloads & scans all text files directly.
- Opens archives (.jar/.war/.zip) one by one, scans config files inside.
- Prints ONLY confirmed secrets.
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
import zipfile
import gzip
import tarfile
import tempfile
import io
from datetime import datetime

BASE_URL = "http://10.26.1.75:8081/artifactory"

# Max archive size to download (skip huge ones)
MAX_ARCHIVE_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_TEXT_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Extensions considered text (download and scan directly)
TEXT_EXTS = {
    ".pom", ".xml", ".md", ".sql", ".js", ".ts", ".py", ".sh", ".bash",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".txt", ".csv", ".html", ".htm", ".css", ".php", ".rb", ".go",
    ".java", ".kt", ".gradle", ".groovy", ".tf", ".hcl",
    ".bat", ".cmd", ".ps1", ".psm1",
    "", # no extension
}

# Archive extensions (download, open, scan inside)
ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".gz", ".tgz"}

# Inside archives, only extract files matching these patterns
INTERESTING_INSIDE_ARCHIVE = [
    r'(?i)application[\w\-]*\.(yml|yaml|properties|xml)$',
    r'(?i)bootstrap[\w\-]*\.(yml|yaml|properties)$',
    r'(?i)settings\.xml$',
    r'(?i)\.env$',
    r'(?i)\.env\.\w+$',
    r'(?i)config[\w\-]*\.(yml|yaml|properties|xml|json|toml|ini|cfg)$',
    r'(?i)database\.(yml|yaml|properties)$',
    r'(?i)datasource[\w\-]*\.(yml|yaml|properties|xml)$',
    r'(?i)persistence[\w\-]*\.xml$',
    r'(?i)context[\w\-]*\.xml$',
    r'(?i)web\.xml$',
    r'(?i)standalone[\w\-]*\.xml$',
    r'(?i)docker-compose[\w\-]*\.(yml|yaml)$',
    r'(?i)Dockerfile',
    r'(?i)\.npmrc$',
    r'(?i)\.pypirc$',
    r'(?i)\.netrc$',
    r'(?i)\.git-credentials$',
    r'(?i)\.htpasswd$',
    r'(?i)\.dockercfg$',
    r'(?i)kubeconfig',
    r'(?i)terraform\.tfvars$',
    r'(?i)vault\.(json|yml|yaml)$',
    r'(?i)credentials(\.\w+)?$',
    r'(?i)secret(\.\w+)?$',
    r'(?i)(id_rsa|id_ed25519|id_ecdsa)',
    r'(?i)\.(pem|key|p12|pfx|jks|keystore)$',
    r'(?i)logback[\w\-]*\.xml$',
    r'(?i)log4j[\w\-]*\.(xml|properties)$',
]

# ============================================================
# Secret detection regexes
# ============================================================
SECRET_REGEXES = [
    ("Private Key",              r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    ("AWS Access Key",           r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret",               r'(?i)aws.?secret.?access.?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{30,}'),
    ("GitHub Token",             r'gh[ps]_[A-Za-z0-9_]{36,}'),
    ("GitLab Token",             r'glpat-[A-Za-z0-9\-]{20,}'),
    ("Slack Token",              r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ("NPM Auth",                 r'//[^\s]*:_authToken=[^\s]+'),
    ("Docker Auth",              r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
    ("Connection String w/ pwd", r'(?i)(mongodb|postgres|mysql|redis|amqp|mssql|oracle|sqlserver)://[^\s"\']*:[^\s"\']*@'),
    ("JDBC password",            r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+'),
    ("Password (quoted)",        r'(?i)(password|passwd|pwd|pass|mot_de_passe)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    ("Password (unquoted)",      r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s"\'<>#\{]{4,})'),
    ("Secret/Key (quoted)",      r'(?i)(secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|client[_-]?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("Secret/Key (unquoted)",    r'(?i)(secret_key|api_key|apikey|access_key|client_secret|auth_token)\s*[=:]\s*([^\s"\'<>#\{]{10,})'),
    ("Bearer Token",             r'(?i)bearer\s+[a-zA-Z0-9\-_.~+/]{20,}'),
    ("Basic Auth b64",           r'(?i)authorization\s*[=:]\s*["\']?basic\s+[A-Za-z0-9+/=]{10,}'),
    ("SSH key ref",              r'(?i)ssh[_-]?(private[_-]?key|key|rsa)\s*[=:]\s*["\'].+'),
    ("Hex secret 32+",          r'(?i)(secret|key|token|password|salt|pepper)\s*[=:]\s*["\']?[0-9a-f]{32,}'),
    ("XML password tag",         r'(?i)<(password|secret|token|apiKey|apikey|accessKey|secretKey)[^>]*>[^<]{4,}</'),
    ("Spring datasource pwd",    r'(?i)spring\.datasource\.password\s*=\s*\S+'),
    ("Maven server password",    r'(?i)<password>[^<$\{]{3,}</password>'),
    ("Encrypted Spring",         r'(?i)ENC\([A-Za-z0-9+/=]{10,}\)'),
]

# False positive filters
FP_PATTERNS = [
    r'^\s*[#;]',                          # comment
    r'^\s*//',                             # comment
    r'^\s*\*',                             # block comment
    r'^\s*<!--',                           # XML comment
    r'\$\{',                               # ${placeholder}
    r'\{\{',                               # {{template}}
    r'%\{',                                # %{placeholder}
    r'@\w+@',                              # @placeholder@
    r'(?i)(example|changeme|your[_-]?password|xxx+|dummy|fake|test|placeholder|TODO|FIXME|CHANGE.?ME|replace.?me|N/A)',
    r'(?i)^.*(\.class|\.java|\.jar|\.xsd|\.dtd)\s*$',  # just a path
]

# ============================================================
# HTTP
# ============================================================

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def http_json(endpoint, auth):
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=60) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_error": True, "detail": str(e)}


def http_download(path, auth):
    """Download file content as bytes. Returns bytes or None."""
    url = f"{BASE_URL}/{path}"
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=120) as r:
            return r.read()
    except Exception:
        return None


def aql(query, auth):
    url = f"{BASE_URL}/api/search/aql"
    req = urllib.request.Request(url, data=query.encode("utf-8"), headers={
        "Content-Type": "text/plain", "Authorization": auth,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_error": True, "detail": str(e)}


# ============================================================
# Scanning
# ============================================================

def is_fp(line):
    for p in FP_PATTERNS:
        if re.search(p, line):
            return True
    return False


def mask(val):
    v = val.strip().strip("\"'")
    if len(v) > 20:
        return v[:6] + "..." + v[-4:]
    elif len(v) > 10:
        return v[:4] + "..." + v[-3:]
    return v[:3] + "***"


def scan_text(text, filepath):
    findings = []
    for num, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s or is_fp(s):
            continue
        for label, pat in SECRET_REGEXES:
            for m in re.finditer(pat, line):
                findings.append({
                    "file": filepath,
                    "line": num,
                    "type": label,
                    "match": mask(m.group(0)),
                    "context": s[:150],
                })
    return findings


def is_interesting_inside(entry_name):
    basename = entry_name.rsplit("/", 1)[-1] if "/" in entry_name else entry_name
    for pat in INTERESTING_INSIDE_ARCHIVE:
        if re.search(pat, basename):
            return True
    return False


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    print("=" * W)
    print("  RUN 2 - FULL CONTENT SCAN")
    print(f"  Target: {BASE_URL}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * W)

    username = input("\nUsername: ").strip()
    password = getpass.getpass("Password: ")
    auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    # Test
    print("\nConnecting...", end=" ", flush=True)
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/system/ping", headers={"Authorization": auth})
        with urllib.request.urlopen(req, context=_ctx, timeout=10):
            print("OK")
    except Exception as e:
        print(f"FAILED ({e})")
        sys.exit(1)

    # List non-virtual, non-empty repos
    repos = http_json("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        print(f"ERROR: {repos}")
        sys.exit(1)

    local_repos = [r["key"] for r in repos if r.get("type") != "VIRTUAL"]
    print(f"Repos to scan: {len(local_repos)}\n")

    all_findings = []
    stats = {"text_scanned": 0, "archives_scanned": 0, "archives_skipped_size": 0,
             "entries_scanned": 0, "errors": 0}

    for repo in local_repos:
        # Get all files in this repo
        result = aql(f'items.find({{"repo":"{repo}"}}).include("name","size","path")', auth)
        if isinstance(result, dict) and result.get("_error"):
            print(f"  [{repo}] AQL error, skipping")
            stats["errors"] += 1
            continue

        items = result.get("results", [])
        if not items:
            continue

        text_files = []
        archive_files = []

        for it in items:
            name = it.get("name", "")
            size = it.get("size", 0)
            path = it.get("path", ".")
            fp = f"{repo}/{path}/{name}" if path != "." else f"{repo}/{name}"
            _, ext = os.path.splitext(name)
            ext = ext.lower()

            if ext in ARCHIVE_EXTS:
                archive_files.append((fp, size, ext))
            elif ext in TEXT_EXTS or ext == "":
                if size > 0 and size < MAX_TEXT_FILE_SIZE:
                    text_files.append((fp, size))

        if not text_files and not archive_files:
            continue

        print(f"  [{repo}] {len(text_files)} text, {len(archive_files)} archives")

        # --- Scan text files ---
        for fp, size in text_files:
            raw = http_download(fp, auth)
            if raw is None:
                stats["errors"] += 1
                continue
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                continue
            findings = scan_text(text, fp)
            all_findings.extend(findings)
            stats["text_scanned"] += 1

        # --- Scan archives ---
        for fp, size, ext in archive_files:
            if size > MAX_ARCHIVE_SIZE:
                stats["archives_skipped_size"] += 1
                continue

            raw = http_download(fp, auth)
            if raw is None:
                stats["errors"] += 1
                continue

            entries_found = 0
            try:
                if ext in (".jar", ".war", ".ear", ".zip"):
                    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                        for entry in zf.namelist():
                            if not is_interesting_inside(entry):
                                continue
                            try:
                                info = zf.getinfo(entry)
                                if info.file_size > MAX_TEXT_FILE_SIZE or info.file_size == 0:
                                    continue
                                data = zf.read(entry)
                                text = data.decode("utf-8", errors="replace")
                                findings = scan_text(text, f"{fp}!/{entry}")
                                all_findings.extend(findings)
                                entries_found += 1
                            except Exception:
                                continue

                elif ext == ".gz":
                    try:
                        decompressed = gzip.decompress(raw)
                        # Could be a .tar.gz
                        try:
                            with tarfile.open(fileobj=io.BytesIO(decompressed)) as tf:
                                for member in tf.getmembers():
                                    if not member.isfile():
                                        continue
                                    if not is_interesting_inside(member.name):
                                        continue
                                    if member.size > MAX_TEXT_FILE_SIZE or member.size == 0:
                                        continue
                                    try:
                                        f = tf.extractfile(member)
                                        if f:
                                            data = f.read()
                                            text = data.decode("utf-8", errors="replace")
                                            findings = scan_text(text, f"{fp}!/{member.name}")
                                            all_findings.extend(findings)
                                            entries_found += 1
                                    except Exception:
                                        continue
                        except tarfile.TarError:
                            # Plain .gz, not tar
                            text = decompressed.decode("utf-8", errors="replace")
                            findings = scan_text(text, fp)
                            all_findings.extend(findings)
                            entries_found += 1
                    except Exception:
                        pass

                elif ext == ".tgz":
                    try:
                        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
                            for member in tf.getmembers():
                                if not member.isfile():
                                    continue
                                if not is_interesting_inside(member.name):
                                    continue
                                if member.size > MAX_TEXT_FILE_SIZE or member.size == 0:
                                    continue
                                try:
                                    f = tf.extractfile(member)
                                    if f:
                                        data = f.read()
                                        text = data.decode("utf-8", errors="replace")
                                        findings = scan_text(text, f"{fp}!/{member.name}")
                                        all_findings.extend(findings)
                                        entries_found += 1
                                except Exception:
                                    continue
                    except Exception:
                        pass

            except Exception:
                stats["errors"] += 1
                continue

            stats["archives_scanned"] += 1
            stats["entries_scanned"] += entries_found

            if entries_found > 0:
                print(f"    -> {fp}: {entries_found} config files inside")

        time.sleep(0.1)  # Be gentle

    # ============================================================
    # OUTPUT
    # ============================================================
    print(f"\n{'=' * W}")
    print(f"  SCAN COMPLETE")
    print(f"{'=' * W}")
    print(f"  Text files scanned:      {stats['text_scanned']}")
    print(f"  Archives opened:         {stats['archives_scanned']}")
    print(f"  Archives too large:      {stats['archives_skipped_size']}")
    print(f"  Config entries scanned:  {stats['entries_scanned']}")
    print(f"  Errors:                  {stats['errors']}")
    print(f"  SECRETS FOUND:           {len(all_findings)}")

    if not all_findings:
        print(f"\n  No secrets detected.")
        print(f"{'=' * W}")
        return

    # Group by type
    by_type = {}
    for f in all_findings:
        by_type.setdefault(f["type"], []).append(f)

    print(f"\n  {'SECRET TYPE':<35} {'COUNT':>6}")
    print(f"  {'-'*35} {'-'*6}")
    for t, fs in sorted(by_type.items(), key=lambda x: -len(x[1])):
        print(f"  {t:<35} {len(fs):>6}")

    # Group by file
    by_file = {}
    for f in all_findings:
        by_file.setdefault(f["file"], []).append(f)

    print(f"\n{'─' * W}")
    print(f"  DETAILED FINDINGS ({len(by_file)} files)")
    print(f"{'─' * W}")

    for fpath in sorted(by_file):
        print(f"\n  >> {fpath}")
        for f in by_file[fpath]:
            print(f"     L{f['line']:<5}  [{f['type']}]")
            print(f"            {f['match']}")
            print(f"            {f['context'][:120]}")

    print(f"\n{'=' * W}")
    print(f"  TOTAL: {len(all_findings)} secrets in {len(by_file)} files")
    print(f"{'=' * W}")


if __name__ == "__main__":
    main()
