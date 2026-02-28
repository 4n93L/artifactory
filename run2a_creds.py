#!/usr/bin/env python3
"""
Run 2a: Find ONLY real credentials (user/pass pairs, connection strings, private keys).
Ignores all Java/Spring library files inside JARs.
Output: tobesent file with only actionable findings.
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
import threading
from datetime import datetime

# ============================================================
# Skip: press 's' to skip current repo
# ============================================================
_skip_flag = False
_skip_lock = threading.Lock()


def _key_listener():
    global _skip_flag
    try:
        import msvcrt
        while True:
            if msvcrt.kbhit():
                if msvcrt.getch().lower() == b's':
                    with _skip_lock:
                        _skip_flag = True
                    print("\n  >>> SKIP >>>", flush=True)
            time.sleep(0.1)
    except ImportError:
        pass  # Linux: won't have interactive skip


def should_skip():
    with _skip_lock:
        return _skip_flag


def reset_skip():
    global _skip_flag
    with _skip_lock:
        _skip_flag = False


# ============================================================
# Output
# ============================================================
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tobesent")
_ff = open(OUTPUT_FILE, "w", encoding="utf-8")


def log(msg):
    print(msg, flush=True)


def found(msg):
    print(msg, flush=True)
    _ff.write(msg + "\n")
    _ff.flush()


BASE_URL = "http://10.26.1.75:8081/artifactory"
MAX_ARCHIVE_SIZE = 200 * 1024 * 1024
MAX_ENTRY_SIZE = 10 * 1024 * 1024

# ============================================================
# SKIP these paths inside archives (library code = noise)
# ============================================================
SKIP_INSIDE = [
    r'/org/apache/',
    r'/org/springframework/',
    r'/org/hibernate/',
    r'/org/eclipse/',
    r'/org/jboss/',
    r'/org/wildfly/',
    r'/com/sun/',
    r'/com/oracle/',
    r'/com/google/',
    r'/com/fasterxml/',
    r'/com/amazonaws/',
    r'/javax/',
    r'/jakarta/',
    r'/META-INF/maven/',
    r'/META-INF/MANIFEST',
    r'/messages_\w+\.properties',
    r'/LocalStrings\.properties',
    r'/ValidationMessages',
    r'\.class$',
    r'\.MF$',
    r'\.SF$',
    r'\.RSA$',
    r'\.DSA$',
    r'\.EC$',
    r'/license',
    r'/LICENSE',
    r'/NOTICE',
    r'/changelog',
    r'/CHANGELOG',
]

BINARY_EXTS = {
    ".class", ".pyc", ".o", ".a", ".lib", ".obj", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".sha1", ".sha256", ".sha512", ".md5", ".sig", ".asc",
    ".deb", ".rpm", ".msi", ".apk",
    ".pdf", ".swf", ".dat", ".bin", ".iso",
}

ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".gz", ".tgz", ".tar"}
NESTED_ARCHIVE_EXTS = {".jar", ".zip", ".war", ".ear"}

# ============================================================
# ONLY these regexes - high signal, low noise
# ============================================================
SECRET_REGEXES = [
    # Connection strings with embedded creds (user:pass@host)
    ("CONN_STRING",  r'(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql|oracle|sqlserver|ldap|ldaps|ftp|ftps|smb|ssh)://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+'),

    # JDBC with password param
    ("JDBC_PWD",     r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+'),

    # spring.datasource.password = actualvalue (not placeholder)
    ("SPRING_PWD",   r'(?i)spring[\w.]*\.(password|secret)\s*[=:]\s*[^\s\$\{#]+'),

    # password/pwd in .properties or .yml with real value
    ("PWD_FIELD",    r'(?i)^[\w.\-]*(password|passwd|pwd|pass|secret|token|apikey|api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*\S+'),

    # XML tags: <password>realvalue</password>
    ("XML_PWD",      r'(?i)<(password|secret|token|apiKey|secretKey|accessKey|passphrase)[^>]*>[^<\$\{\}]{3,}</'),

    # XML attributes: password="realvalue"
    ("XML_ATTR_PWD", r'(?i)(password|secret|token|apiKey|secretKey|passwd|pwd)\s*=\s*"[^"\$\{]{3,}"'),

    # Private keys
    ("PRIVATE_KEY",  r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----'),

    # AWS
    ("AWS_KEY",      r'AKIA[0-9A-Z]{16}'),

    # Platform tokens (high-confidence patterns)
    ("GITHUB_TOKEN", r'gh[ps]_[A-Za-z0-9_]{36,}'),
    ("GITLAB_TOKEN", r'glpat-[A-Za-z0-9\-]{20,}'),
    ("SLACK_TOKEN",  r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
]

# Values that are NOT real passwords
JUNK_VALUES = {
    "password", "passwd", "pwd", "pass", "secret", "token", "key", "apikey",
    "api_key", "property", "value", "string", "text", "name", "type", "field",
    "null", "none", "nil", "empty", "blank", "undefined", "default",
    "true", "false", "yes", "no", "on", "off", "enabled", "disabled",
    "required", "optional", "encrypted", "encoded", "hashed",
    "username", "user", "login", "admin", "root", "test",
    "description", "label", "placeholder", "prompt", "hint", "message",
    "config", "configuration", "setting", "classpath", "filepath",
    "java.lang.string", "change_me", "changeme", "fixme", "todo",
}

JUNK_PATTERNS = [
    r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$',   # CamelCase: PasswordEncoder
    r'^[a-z]+\.[a-z]+\.',                 # package: com.foo.bar
    r'^\$[\{\(]',                          # ${} or $()
    r'^\{\{',                              # {{template}}
    r'^@',                                 # @annotation
    r'^System\.',
    r'^org\.',
    r'^com\.',
    r'^net\.',
    r'^javax?\.',
    r'^class\s',
    r'^\w+\.class$',
]

FP_LINE_PATTERNS = [
    r'^\s*[#;!]',
    r'^\s*//',
    r'^\s*\*',
    r'^\s*<!--',
    r'(?i)(example\.com|example\.org|localhost)',
    r'(?i)(changeme|your.?password|xxx+|dummy|fake|placeholder|CHANGE.?ME|replace.?me)',
    r'\$\{[^}]+\}',
    r'\{\{[^}]+\}\}',
]


def is_fp_line(line):
    for p in FP_LINE_PATTERNS:
        if re.search(p, line):
            return True
    return False


def is_junk(matched):
    # For patterns that have key=value, check the value part
    parts = re.split(r'[=:]\s*', matched, maxsplit=1)
    if len(parts) >= 2:
        val = parts[1].strip().strip("\"'<>/")
        if not val or len(val) <= 2:
            return True
        if val.lower() in JUNK_VALUES:
            return True
        for p in JUNK_PATTERNS:
            if re.match(p, val):
                return True
        if len(set(val)) <= 2:  # "****", "xxxx"
            return True
    return False


def should_skip_entry(entry_path):
    """Skip known library/framework files inside archives."""
    for p in SKIP_INSIDE:
        if re.search(p, entry_path):
            return True
    return False


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

def artif_url(fp):
    return f"{BASE_URL}/{fp.split('!/')[0]}"


def is_text(data):
    try:
        t = data[:8192].decode("utf-8")
        return (sum(1 for c in t if c.isprintable() or c in '\n\r\t') / len(t)) > 0.85 if t else False
    except (UnicodeDecodeError, ZeroDivisionError):
        return False


def ext_of(name):
    _, ext = os.path.splitext(name)
    return ext.lower()


def scan_text(text, filepath):
    results = []
    lines = text.split("\n")
    seen = set()
    for num, line in enumerate(lines, 1):
        s = line.strip()
        if not s or is_fp_line(s):
            continue
        for label, pat in SECRET_REGEXES:
            for m in re.finditer(pat, line):
                matched = m.group(0).strip()

                # High-confidence patterns skip junk check
                if label not in ("PRIVATE_KEY", "AWS_KEY", "GITHUB_TOKEN",
                                 "GITLAB_TOKEN", "SLACK_TOKEN", "CONN_STRING"):
                    if is_junk(matched):
                        continue

                key = (filepath, num, label)
                if key in seen:
                    continue
                seen.add(key)

                # Context: 3 lines before
                before = []
                for off in range(3, 0, -1):
                    idx = num - 1 - off
                    if 0 <= idx < len(lines) and lines[idx].strip():
                        before.append(lines[idx].strip()[:160])

                found(f"─── [{label}] {filepath}:{num}")
                for b in before:
                    found(f"  {b}")
                found(f">>  {s[:200]}")
                found(f"  FETCH: {artif_url(filepath)}")
                found("")

                results.append({"file": filepath, "line": num, "type": label, "value": matched})
    return results


def scan_archive(data, path, ext, depth, stats, findings):
    try:
        if ext in (".jar", ".war", ".ear", ".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                return
            with zf:
                for entry in zf.namelist():
                    if entry.endswith("/"):
                        continue
                    if should_skip_entry(entry):
                        continue
                    try:
                        info = zf.getinfo(entry)
                    except KeyError:
                        continue
                    if info.file_size == 0 or info.file_size > MAX_ENTRY_SIZE:
                        continue

                    eext = ext_of(entry)
                    if depth > 0 and eext in NESTED_ARCHIVE_EXTS and info.file_size < MAX_ARCHIVE_SIZE:
                        try:
                            scan_archive(zf.read(entry), f"{path}!/{entry}", eext, depth - 1, stats, findings)
                        except Exception:
                            pass
                        continue
                    if eext in BINARY_EXTS:
                        continue
                    try:
                        raw = zf.read(entry)
                    except Exception:
                        continue
                    if not is_text(raw):
                        continue
                    text = raw.decode("utf-8", errors="replace")
                    findings.extend(scan_text(text, f"{path}!/{entry}"))
                    stats["entries"] += 1

        elif ext in (".gz", ".tgz"):
            try:
                if ext == ".gz":
                    dec = gzip.decompress(data)
                    try:
                        tf = tarfile.open(fileobj=io.BytesIO(dec))
                    except tarfile.TarError:
                        if is_text(dec):
                            findings.extend(scan_text(dec.decode("utf-8", errors="replace"), path))
                            stats["entries"] += 1
                        return
                else:
                    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
                with tf:
                    for m in tf.getmembers():
                        if not m.isfile() or m.size == 0 or m.size > MAX_ENTRY_SIZE:
                            continue
                        if should_skip_entry(m.name):
                            continue
                        mext = ext_of(m.name)
                        if mext in BINARY_EXTS:
                            continue
                        try:
                            f = tf.extractfile(m)
                            if not f:
                                continue
                            raw = f.read()
                        except Exception:
                            continue
                        if depth > 0 and mext in NESTED_ARCHIVE_EXTS and len(raw) < MAX_ARCHIVE_SIZE:
                            scan_archive(raw, f"{path}!/{m.name}", mext, depth - 1, stats, findings)
                            continue
                        if not is_text(raw):
                            continue
                        findings.extend(scan_text(raw.decode("utf-8", errors="replace"), f"{path}!/{m.name}"))
                        stats["entries"] += 1
            except Exception:
                pass

        elif ext == ".tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    for m in tf.getmembers():
                        if not m.isfile() or m.size == 0 or m.size > MAX_ENTRY_SIZE:
                            continue
                        if should_skip_entry(m.name):
                            continue
                        if ext_of(m.name) in BINARY_EXTS:
                            continue
                        try:
                            f = tf.extractfile(m)
                            if not f:
                                continue
                            raw = f.read()
                        except Exception:
                            continue
                        if not is_text(raw):
                            continue
                        findings.extend(scan_text(raw.decode("utf-8", errors="replace"), f"{path}!/{m.name}"))
                        stats["entries"] += 1
            except Exception:
                pass
    except Exception:
        stats["errors"] += 1


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    log("=" * W)
    log("  RUN 2a - CREDENTIALS ONLY (user/pass, conn strings, keys)")
    log(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"  Press 's' to skip current repo")
    log("=" * W)

    found("=" * W)
    found(f"  CREDENTIALS SCAN - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    found("=" * W)
    found("")

    username = input("\nUsername: ").strip()
    password = getpass.getpass("Password: ")
    auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()

    threading.Thread(target=_key_listener, daemon=True).start()

    log("\nConnecting...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/system/ping", headers={"Authorization": auth})
        with urllib.request.urlopen(req, context=_ctx, timeout=10):
            log("  OK")
    except Exception as e:
        log(f"  FAILED ({e})")
        sys.exit(1)

    repos = http_json("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        log(f"ERROR: {repos}")
        sys.exit(1)

    scan_repos = [r["key"] for r in repos if r.get("type") != "VIRTUAL"]
    log(f"Repos: {len(scan_repos)}\n")

    all_findings = []
    stats = {"text": 0, "archives": 0, "entries": 0, "errors": 0}
    t0 = time.time()

    for ri, repo in enumerate(scan_repos, 1):
        reset_skip()
        el = time.strftime("%H:%M:%S", time.gmtime(time.time() - t0))
        log(f"[{ri}/{len(scan_repos)}] {repo}  ({el}, {len(all_findings)} creds found)  [s=skip]")

        result = aql(f'items.find({{"repo":"{repo}"}}).include("name","size","path")', auth)
        if isinstance(result, dict) and result.get("_error"):
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
            ext = ext_of(name)

            if size == 0:
                continue
            if ext in ARCHIVE_EXTS:
                archive_files.append((fp, size, ext))
            elif ext not in BINARY_EXTS and size <= MAX_ENTRY_SIZE:
                text_files.append((fp, size))

        if not text_files and not archive_files:
            continue

        log(f"  {len(text_files)} text + {len(archive_files)} archives")

        # Text files
        for i, (fp, sz) in enumerate(text_files, 1):
            if should_skip():
                break
            raw = http_download(fp, auth)
            if raw is None:
                continue
            if not is_text(raw):
                continue
            all_findings.extend(scan_text(raw.decode("utf-8", errors="replace"), fp))
            stats["text"] += 1

        if should_skip():
            log("  >>> SKIPPED")
            continue

        # Archives
        for i, (fp, sz, ext) in enumerate(archive_files, 1):
            if should_skip():
                break
            if sz > MAX_ARCHIVE_SIZE:
                continue
            if i % 20 == 0 or i == 1:
                log(f"    archive {i}/{len(archive_files)}...")
            raw = http_download(fp, auth)
            if raw is None:
                continue
            scan_archive(raw, fp, ext, depth=2, stats=stats, findings=all_findings)
            stats["archives"] += 1

        if should_skip():
            log("  >>> SKIPPED")

    # Summary
    found("")
    found("=" * W)
    found(f"  DONE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    found(f"  Scanned: {stats['text']} text, {stats['archives']} archives, {stats['entries']} entries")
    found(f"  CREDENTIALS FOUND: {len(all_findings)}")
    found("=" * W)

    _ff.close()
    log(f"\nResults in: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
