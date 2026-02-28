#!/usr/bin/env python3
"""
Run 2: EXHAUSTIVE content scan.
- Scans ALL files (not just known config names).
- Inside archives: scans ALL entries that decode as text.
- Nested archives: .war -> .jar -> .properties (2 levels deep).
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
import io
from datetime import datetime


# ============================================================
# Tee: print to terminal AND write to file simultaneously
# ============================================================
class Tee:
    def __init__(self, filepath):
        self.terminal = sys.stdout
        self.file = open(filepath, "w", encoding="utf-8")

    def write(self, msg):
        self.terminal.write(msg)
        self.file.write(msg)

    def flush(self):
        self.terminal.flush()
        self.file.flush()

    def close(self):
        self.file.close()


OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tobesent")
sys.stdout = Tee(OUTPUT_FILE)

BASE_URL = "http://10.26.1.75:8081/artifactory"

# Max archive size to download
MAX_ARCHIVE_SIZE = 200 * 1024 * 1024   # 200 MB
# Max single file/entry to scan
MAX_ENTRY_SIZE = 10 * 1024 * 1024      # 10 MB

# Extensions that are DEFINITELY binary (skip entirely)
BINARY_EXTS = {
    # compiled / bytecode
    ".class", ".pyc", ".pyo", ".o", ".a", ".lib", ".obj",
    ".exe", ".dll", ".so", ".dylib",
    # images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".tiff", ".tif",
    # media
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg",
    # fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # office docs (binary)
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    # hashes / sigs (not secrets, just checksums)
    ".sha1", ".sha256", ".sha512", ".md5", ".sig", ".asc",
    # native packages
    ".deb", ".rpm", ".msi", ".dmg", ".apk", ".ipa",
    # other binary
    ".pdf", ".swf", ".dat", ".bin", ".iso",
}

# Archive extensions we can open
ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".gz", ".tgz", ".tar"}

# Nested archive extensions (inside a .war/.zip we also open these)
NESTED_ARCHIVE_EXTS = {".jar", ".zip", ".war", ".ear"}

# ============================================================
# Secret detection regexes - EXHAUSTIVE
# ============================================================
SECRET_REGEXES = [
    # --- Cryptographic material ---
    ("PRIVATE KEY",              r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----'),
    ("CERTIFICATE",              r'-----BEGIN CERTIFICATE-----'),

    # --- Cloud provider keys ---
    ("AWS Access Key",           r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret",               r'(?i)aws.?secret.?access.?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{30,}'),
    ("AWS Session Token",        r'(?i)aws.?session.?token\s*[=:]\s*["\']?[A-Za-z0-9/+=]{30,}'),
    ("Azure Client Secret",      r'(?i)(azure|client).?secret\s*[=:]\s*["\']?[A-Za-z0-9\-_.~]{20,}'),
    ("GCP Service Account",      r'"type"\s*:\s*"service_account"'),

    # --- Platform tokens ---
    ("GitHub Token",             r'gh[ps]_[A-Za-z0-9_]{36,}'),
    ("GitHub OAuth",             r'gho_[A-Za-z0-9_]{36,}'),
    ("GitLab Token",             r'glpat-[A-Za-z0-9\-]{20,}'),
    ("Slack Token",              r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
    ("Slack Webhook",            r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    ("NPM Auth",                 r'//[^\s]*:_authToken=[^\s]+'),
    ("Docker Auth",              r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
    ("Artifactory Token",        r'(?i)(artifactory|jfrog).?(token|password|key)\s*[=:]\s*["\']?[^\s"\']{8,}'),
    ("SonarQube Token",          r'(?i)sonar\.login\s*=\s*[^\s]{8,}'),

    # --- Connection strings ---
    ("DB Connection String",     r'(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql|oracle|sqlserver|ldap|ldaps)://[^\s"\']*:[^\s"\']*@'),
    ("JDBC w/ password",         r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+'),
    ("JDBC full string",         r'(?i)jdbc:[a-z:]+//[^\s"\']+'),
    ("LDAP Bind password",       r'(?i)(ldap|bind).?(password|pwd|credential)\s*[=:]\s*["\']?[^\s"\'<>#\{]{4,}'),
    ("JNDI datasource pwd",     r'(?i)jndi[.\w]*password\s*[=:]\s*["\']?[^\s"\']{4,}'),

    # --- Auth headers ---
    ("Bearer Token",             r'(?i)(authorization|bearer)\s*[=:]\s*["\']?bearer\s+[a-zA-Z0-9\-_.~+/]{20,}'),
    ("Basic Auth b64",           r'(?i)authorization\s*[=:]\s*["\']?basic\s+[A-Za-z0-9+/=]{10,}'),

    # --- Password fields (all formats) ---
    ("Password (quoted)",        r'(?i)(password|passwd|pwd|pass|mot_de_passe|passwort|contraseña|motdepasse)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    ("Password (unquoted)",      r'(?i)(password|passwd|pwd)\s*[=:]\s*([^\s"\'<>#\{\}]{4,})'),

    # --- Secret/key/token fields ---
    ("Secret/Key (quoted)",      r'(?i)(secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth[_-]?token|client[_-]?secret|encryption[_-]?key|signing[_-]?key|master[_-]?key)\s*[=:]\s*["\']([^"\']{8,})["\']'),
    ("Secret/Key (unquoted)",    r'(?i)(secret_key|api_key|apikey|access_key|client_secret|auth_token|encryption_key|signing_key|master_key)\s*[=:]\s*([^\s"\'<>#\{\}]{10,})'),
    ("Credential field",         r'(?i)(credential|credentials|cred)\s*[=:]\s*["\']?[^\s"\'<>#\{\}]{6,}'),

    # --- SSH ---
    ("SSH key ref",              r'(?i)ssh[_-]?(private[_-]?key|key|rsa|ed25519)\s*[=:]\s*["\'].+'),
    ("SSH passphrase",           r'(?i)ssh.?(passphrase|password)\s*[=:]\s*["\']?[^\s"\']{4,}'),

    # --- XML-specific ---
    ("XML password tag",         r'(?i)<(password|secret|token|apiKey|apikey|accessKey|secretKey|passphrase|credential|credentials)[^>]*>[^<\$\{]{4,}</'),
    ("Spring datasource pwd",    r'(?i)spring[\w.]*password\s*[=:]\s*[^\s\$\{]{3,}'),
    ("Maven server password",    r'(?i)<password>[^<\$\{]{3,}</password>'),
    ("Maven server username",    r'(?i)<username>[^<\$\{]{2,}</username>'),
    ("JNDI resource pwd",        r'(?i)password="[^"\$\{]{3,}"'),

    # --- Encoded secrets ---
    ("Encrypted (ENC)",          r'ENC\([A-Za-z0-9+/=]{10,}\)'),
    ("Hex secret 32+",          r'(?i)(secret|key|token|password|salt|pepper|hmac)\s*[=:]\s*["\']?[0-9a-f]{32,}'),
    ("Base64 long secret",       r'(?i)(secret|key|password|token)\s*[=:]\s*["\']?[A-Za-z0-9+/]{40,}={0,2}["\']?'),

    # --- Misc ---
    ("Keystore password",        r'(?i)(keystore|truststore|storepass|keypass)[.\w]*\s*[=:]\s*["\']?[^\s"\'<>#\{\}]{4,}'),
    ("Encryption IV/Salt",       r'(?i)(iv|salt|nonce)\s*[=:]\s*["\']?[0-9a-fA-F]{16,}'),
    ("Private URL w/ token",     r'https?://[^\s"]*[?&](token|key|api_key|access_token|secret)=[^\s"&]{8,}'),
    ("Webhook URL w/ secret",    r'https?://[^\s"]*webhook[^\s"]*'),
]

# False positive filters
FP_PATTERNS = [
    r'^\s*[#;!]',                         # comment
    r'^\s*//',                             # comment
    r'^\s*\*\s',                           # block comment
    r'^\s*<!--',                           # XML comment
    r'^\s*\*/',                            # end block comment
    r'\$\{[^}]+\}',                        # ${placeholder}
    r'\{\{[^}]+\}\}',                      # {{template}}
    r'%\{[^}]+\}',                         # %{placeholder}
    r'@[A-Za-z]+@',                        # @placeholder@
    r'(?i)(example\.com|example\.org|localhost)',
    r'(?i)(changeme|your[_-]?password|xxx+|dummy|fake|placeholder|TODO|FIXME|CHANGE.?ME|replace.?me|N/A|none|null|empty|undefined)',
    r'(?i)^.*(\.class|\.java|\.jar|\.xsd|\.dtd|\.wsdl)\s*$',
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


def artif_url(filepath):
    """Build the direct Artifactory download URL for a file.
    For entries inside archives: returns URL of the archive itself."""
    base_file = filepath.split("!/")[0]  # strip nested path inside archive
    return f"{BASE_URL}/{base_file}"


def print_finding(f):
    """Print a finding immediately so it shows up in terminal + file in real time."""
    print(f"  !! SECRET >> [{f['type']}] in {f['file']}:{f['line']}")
    print(f"              value:   {f['value']}")
    print(f"              context: {f['context'][:160]}")
    print(f"              fetch:   {artif_url(f['file'])}")
    sys.stdout.flush()


def scan_text(text, filepath):
    findings = []
    seen_lines = set()
    for num, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s or is_fp(s):
            continue
        for label, pat in SECRET_REGEXES:
            for m in re.finditer(pat, line):
                key = (filepath, num, label)
                if key not in seen_lines:
                    seen_lines.add(key)
                    finding = {
                        "file": filepath,
                        "line": num,
                        "type": label,
                        "value": m.group(0).strip(),
                        "context": s[:300],
                    }
                    findings.append(finding)
                    print_finding(finding)
    return findings


def is_text(data, sample_size=8192):
    """Heuristic: try to decode as utf-8, check ratio of printable chars."""
    try:
        sample = data[:sample_size]
        text = sample.decode("utf-8")
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return (printable / len(text)) > 0.85
    except (UnicodeDecodeError, ZeroDivisionError):
        return False


def ext_of(name):
    _, ext = os.path.splitext(name)
    return ext.lower()


def scan_archive_entries(archive_bytes, archive_path, ext, depth, stats, all_findings):
    """Scan all entries inside an archive. Recurse into nested archives up to depth."""
    try:
        if ext in (".jar", ".war", ".ear", ".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(archive_bytes))
            except zipfile.BadZipFile:
                return
            with zf:
                for entry in zf.namelist():
                    if entry.endswith("/"):
                        continue
                    try:
                        info = zf.getinfo(entry)
                    except KeyError:
                        continue
                    if info.file_size == 0 or info.file_size > MAX_ENTRY_SIZE:
                        continue

                    entry_ext = ext_of(entry)

                    # Nested archive?
                    if depth > 0 and entry_ext in NESTED_ARCHIVE_EXTS and info.file_size < MAX_ARCHIVE_SIZE:
                        try:
                            nested_data = zf.read(entry)
                            scan_archive_entries(nested_data, f"{archive_path}!/{entry}",
                                                 entry_ext, depth - 1, stats, all_findings)
                        except Exception:
                            pass
                        continue

                    # Skip known binary
                    if entry_ext in BINARY_EXTS:
                        continue

                    try:
                        data = zf.read(entry)
                    except Exception:
                        continue

                    if not is_text(data):
                        continue

                    text = data.decode("utf-8", errors="replace")
                    findings = scan_text(text, f"{archive_path}!/{entry}")
                    all_findings.extend(findings)
                    stats["entries_scanned"] += 1

        elif ext in (".gz", ".tgz"):
            try:
                if ext == ".gz":
                    decompressed = gzip.decompress(archive_bytes)
                    # Try as tar first
                    try:
                        tf = tarfile.open(fileobj=io.BytesIO(decompressed))
                    except tarfile.TarError:
                        # Plain gzipped file
                        if is_text(decompressed):
                            text = decompressed.decode("utf-8", errors="replace")
                            findings = scan_text(text, archive_path)
                            all_findings.extend(findings)
                            stats["entries_scanned"] += 1
                        return
                else:
                    tf = tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz")

                with tf:
                    for member in tf.getmembers():
                        if not member.isfile() or member.size == 0 or member.size > MAX_ENTRY_SIZE:
                            continue

                        member_ext = ext_of(member.name)

                        if member_ext in BINARY_EXTS:
                            continue

                        try:
                            f = tf.extractfile(member)
                            if not f:
                                continue
                            data = f.read()
                        except Exception:
                            continue

                        # Nested archive?
                        if depth > 0 and member_ext in NESTED_ARCHIVE_EXTS and len(data) < MAX_ARCHIVE_SIZE:
                            scan_archive_entries(data, f"{archive_path}!/{member.name}",
                                                 member_ext, depth - 1, stats, all_findings)
                            continue

                        if not is_text(data):
                            continue

                        text = data.decode("utf-8", errors="replace")
                        findings = scan_text(text, f"{archive_path}!/{member.name}")
                        all_findings.extend(findings)
                        stats["entries_scanned"] += 1

            except Exception:
                pass

        elif ext == ".tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as tf:
                    for member in tf.getmembers():
                        if not member.isfile() or member.size == 0 or member.size > MAX_ENTRY_SIZE:
                            continue
                        member_ext = ext_of(member.name)
                        if member_ext in BINARY_EXTS:
                            continue
                        try:
                            f = tf.extractfile(member)
                            if not f:
                                continue
                            data = f.read()
                        except Exception:
                            continue
                        if not is_text(data):
                            continue
                        text = data.decode("utf-8", errors="replace")
                        findings = scan_text(text, f"{archive_path}!/{member.name}")
                        all_findings.extend(findings)
                        stats["entries_scanned"] += 1
            except Exception:
                pass

    except Exception:
        stats["errors"] += 1


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    print("=" * W)
    print("  RUN 2 - EXHAUSTIVE CONTENT SCAN")
    print(f"  Target: {BASE_URL}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Strategy: scan ALL text in ALL files + ALL archive entries")
    print(f"  Nested archives: 2 levels deep (war->jar->properties)")
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

    # List repos
    repos = http_json("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        print(f"ERROR: {repos}")
        sys.exit(1)

    # Include REMOTE repos too (caches may contain tampered/leaked files)
    scan_repos = [r["key"] for r in repos if r.get("type") != "VIRTUAL"]
    print(f"Repos to scan: {len(scan_repos)} (LOCAL + REMOTE, excl VIRTUAL)\n")

    all_findings = []
    stats = {
        "text_scanned": 0, "archives_scanned": 0, "archives_skipped_size": 0,
        "entries_scanned": 0, "files_not_text": 0, "errors": 0,
    }
    total_repos = len(scan_repos)
    scan_start = time.time()

    for repo_idx, repo in enumerate(scan_repos, 1):
        elapsed = time.time() - scan_start
        elapsed_str = time.strftime("%H:%M:%S", time.gmtime(elapsed))

        print(f"\n{'─' * W}")
        print(f"  REPO {repo_idx}/{total_repos}: {repo}")
        print(f"  Elapsed: {elapsed_str} | Findings so far: {len(all_findings)} | Errors: {stats['errors']}")
        print(f"{'─' * W}")
        sys.stdout.flush()

        result = aql(f'items.find({{"repo":"{repo}"}}).include("name","size","path")', auth)
        if isinstance(result, dict) and result.get("_error"):
            print(f"  AQL error, skipping")
            stats["errors"] += 1
            continue

        items = result.get("results", [])
        if not items:
            print(f"  (empty)")
            continue

        # Classify all files
        text_files = []
        archive_files = []
        skipped = 0

        for it in items:
            name = it.get("name", "")
            size = it.get("size", 0)
            path = it.get("path", ".")
            fp = f"{repo}/{path}/{name}" if path != "." else f"{repo}/{name}"
            ext = ext_of(name)

            if size == 0:
                continue

            if ext in ARCHIVE_EXTS:
                archive_files.append((fp, size, ext))
            elif ext in BINARY_EXTS:
                skipped += 1
            elif size <= MAX_ENTRY_SIZE:
                text_files.append((fp, size))
            else:
                skipped += 1

        if not text_files and not archive_files:
            print(f"  {len(items)} files, all binary -> skipped")
            continue

        total_in_repo = len(text_files) + len(archive_files)
        print(f"  {len(text_files)} text + {len(archive_files)} archives + {skipped} binary-skipped = {len(items)} total")

        # --- Scan direct text files ---
        for i, (fp, size) in enumerate(text_files, 1):
            if i % 20 == 0 or i == 1:
                print(f"    text [{i}/{len(text_files)}] ...", flush=True)

            raw = http_download(fp, auth)
            if raw is None:
                stats["errors"] += 1
                continue

            if not is_text(raw):
                stats["files_not_text"] += 1
                continue

            text = raw.decode("utf-8", errors="replace")
            findings = scan_text(text, fp)
            all_findings.extend(findings)
            stats["text_scanned"] += 1

        # --- Scan archives (with nesting) ---
        for i, (fp, size, ext) in enumerate(archive_files, 1):
            size_mb = round(size / 1024 / 1024, 1)

            if size > MAX_ARCHIVE_SIZE:
                stats["archives_skipped_size"] += 1
                print(f"    archive [{i}/{len(archive_files)}] SKIP {fp} ({size_mb} MB > limit)")
                sys.stdout.flush()
                continue

            if i % 10 == 0 or i == 1:
                print(f"    archive [{i}/{len(archive_files)}] {fp} ({size_mb} MB)...", flush=True)

            raw = http_download(fp, auth)
            if raw is None:
                stats["errors"] += 1
                continue

            before = stats["entries_scanned"]
            scan_archive_entries(raw, fp, ext, depth=2, stats=stats, all_findings=all_findings)
            scanned_inside = stats["entries_scanned"] - before
            stats["archives_scanned"] += 1

            if scanned_inside > 0:
                print(f"      -> {scanned_inside} text entries scanned inside")

        time.sleep(0.05)

    # ============================================================
    # OUTPUT
    # ============================================================
    print(f"\n{'=' * W}")
    print(f"  SCAN COMPLETE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * W}")
    print(f"  Direct text files scanned:   {stats['text_scanned']}")
    print(f"  Files rejected (binary):     {stats['files_not_text']}")
    print(f"  Archives opened:             {stats['archives_scanned']}")
    print(f"  Archives skipped (too big):  {stats['archives_skipped_size']}")
    print(f"  Entries scanned in archives: {stats['entries_scanned']}")
    print(f"  Errors:                      {stats['errors']}")
    print(f"  === SECRETS FOUND:           {len(all_findings)} ===")

    if not all_findings:
        print(f"\n  No secrets detected.")
        print(f"{'=' * W}")
        return

    # Deduplicate (same value in multiple locations)
    unique = {}
    for f in all_findings:
        key = (f["type"], f["value"])
        if key not in unique:
            unique[key] = {**f, "locations": [f["file"]]}
        else:
            unique[key]["locations"].append(f["file"])

    deduped = list(unique.values())

    # ── Categorize for actionable output ──

    cat_credentials = []  # password/username pairs
    cat_tokens = []       # API tokens, bearer, etc.
    cat_keys = []         # private keys, certs
    cat_connstrings = []  # connection strings with embedded creds
    cat_other = []        # everything else

    cred_types = {"Password (quoted)", "Password (unquoted)", "Spring datasource pwd",
                  "Maven server password", "Maven server username", "JNDI datasource pwd",
                  "LDAP Bind password", "Credential field", "XML password tag",
                  "JNDI resource pwd", "Keystore password", "SSH passphrase",
                  "Secret/Key (quoted)", "Secret/Key (unquoted)", "Hex secret 32+",
                  "Base64 long secret", "Encrypted (ENC)"}
    token_types = {"GitHub Token", "GitHub OAuth", "GitLab Token", "Slack Token",
                   "Slack Webhook", "NPM Auth", "Docker Auth", "Artifactory Token",
                   "SonarQube Token", "Bearer Token", "Basic Auth b64",
                   "AWS Access Key", "AWS Secret", "AWS Session Token",
                   "Azure Client Secret", "GCP Service Account",
                   "Private URL w/ token", "Webhook URL w/ secret"}
    key_types = {"PRIVATE KEY", "CERTIFICATE", "SSH key ref", "Encryption IV/Salt"}
    conn_types = {"DB Connection String", "JDBC w/ password", "JDBC full string",
                  "Connection String w/ pwd"}

    for f in deduped:
        t = f["type"]
        if t in key_types:
            cat_keys.append(f)
        elif t in conn_types:
            cat_connstrings.append(f)
        elif t in token_types:
            cat_tokens.append(f)
        elif t in cred_types:
            cat_credentials.append(f)
        else:
            cat_other.append(f)

    def print_category(title, items):
        if not items:
            return
        print(f"\n{'━' * W}")
        print(f"  {title} ({len(items)})")
        print(f"{'━' * W}")
        for i, f in enumerate(items, 1):
            locs = f["locations"]
            loc_str = locs[0]
            print(f"\n  [{i}] {f['type']}")
            print(f"      VALUE:    {f['value']}")
            print(f"      CONTEXT:  {f['context'][:180]}")
            print(f"      FILE:     {loc_str}")
            print(f"      FETCH:    {artif_url(loc_str)}")
            if len(locs) > 1:
                print(f"      ALSO IN:  {len(locs)-1} other location(s):")
                for other in locs[1:5]:
                    print(f"                {other}")
                if len(locs) > 5:
                    print(f"                ... and {len(locs)-5} more")

    print_category("CREDENTIALS (passwords, secrets, keys in config)", cat_credentials)
    print_category("TOKENS (API keys, OAuth, platform tokens)", cat_tokens)
    print_category("PRIVATE KEYS & CERTIFICATES", cat_keys)
    print_category("CONNECTION STRINGS (DB, LDAP, AMQP...)", cat_connstrings)
    print_category("OTHER FINDINGS", cat_other)

    # ── Quick copy-paste summary ──
    print(f"\n{'━' * W}")
    print(f"  QUICK SUMMARY - unique secrets to rotate/revoke")
    print(f"{'━' * W}")
    print(f"\n  Credentials:        {len(cat_credentials)}")
    print(f"  Tokens:             {len(cat_tokens)}")
    print(f"  Private keys/certs: {len(cat_keys)}")
    print(f"  Connection strings: {len(cat_connstrings)}")
    print(f"  Other:              {len(cat_other)}")
    print(f"  ─────────────────────────")
    print(f"  TOTAL unique:       {len(deduped)}")
    print(f"  TOTAL raw:          {len(all_findings)}")

    print(f"\n{'=' * W}")
    print(f"  SCAN DONE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * W}")


if __name__ == "__main__":
    main()
