#!/usr/bin/env python3
"""
Run 2a: Find ONLY real credentials (user/pass pairs, connection strings, private keys).
Ignores all Java/Spring library files inside JARs.
MULTI-THREADED: parallel downloads + parallel archive scanning.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from queue import Queue

# ============================================================
# Config - TUNE THIS
# ============================================================
WORKERS_DOWNLOAD = 12      # parallel HTTP downloads
WORKERS_SCAN = 6           # parallel archive scanners
WORKERS_REPO = 4           # repos scanned in parallel

# ============================================================
# Skip: press 's' to skip current repo
# ============================================================
_skip_repos = set()
_skip_lock = threading.Lock()
_current_repo = None
_current_repo_lock = threading.Lock()


def _key_listener():
    try:
        import msvcrt
        while True:
            if msvcrt.kbhit():
                if msvcrt.getch().lower() == b's':
                    with _current_repo_lock:
                        r = _current_repo
                    if r:
                        with _skip_lock:
                            _skip_repos.add(r)
                        print(f"\n  >>> SKIP {r} >>>", flush=True)
            time.sleep(0.1)
    except ImportError:
        pass


def should_skip(repo):
    with _skip_lock:
        return repo in _skip_repos


# ============================================================
# Thread-safe output
# ============================================================
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tobesent")
_ff = open(OUTPUT_FILE, "w", encoding="utf-8")
_out_lock = threading.Lock()
_findings_lock = threading.Lock()


def log(msg):
    print(msg, flush=True)


def found(msg):
    with _out_lock:
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

# Pre-compile for speed
_SKIP_INSIDE_RE = [re.compile(p) for p in SKIP_INSIDE]

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
    ("CONN_STRING",  re.compile(r'(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql|oracle|sqlserver|ldap|ldaps|ftp|ftps|smb|ssh)://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+')),
    ("JDBC_PWD",     re.compile(r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+')),
    ("SPRING_PWD",   re.compile(r'(?i)spring[\w.]*\.(password|secret)\s*[=:]\s*[^\s\$\{#]+')),
    ("PWD_FIELD",    re.compile(r'(?i)^[\w.\-]*(password|passwd|pwd|pass|secret|token|apikey|api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*\S+')),
    ("XML_PWD",      re.compile(r'(?i)<(password|secret|token|apiKey|secretKey|accessKey|passphrase)[^>]*>[^<\$\{\}]{3,}</')),
    ("XML_ATTR_PWD", re.compile(r'(?i)(password|secret|token|apiKey|secretKey|passwd|pwd)\s*=\s*"[^"\$\{]{3,}"')),
    ("PRIVATE_KEY",  re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----')),
    ("AWS_KEY",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("GITHUB_TOKEN", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("GITLAB_TOKEN", re.compile(r'glpat-[A-Za-z0-9\-]{20,}')),
    ("SLACK_TOKEN",  re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),
]

HIGH_CONFIDENCE = {"PRIVATE_KEY", "AWS_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN", "CONN_STRING"}

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

_JUNK_PATTERNS_RE = [
    re.compile(r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$'),
    re.compile(r'^[a-z]+\.[a-z]+\.'),
    re.compile(r'^\$[\{\(]'),
    re.compile(r'^\{\{'),
    re.compile(r'^@'),
    re.compile(r'^System\.'),
    re.compile(r'^org\.'),
    re.compile(r'^com\.'),
    re.compile(r'^net\.'),
    re.compile(r'^javax?\.'),
    re.compile(r'^class\s'),
    re.compile(r'^\w+\.class$'),
]

_FP_LINE_RE = [
    re.compile(r'^\s*[#;!]'),
    re.compile(r'^\s*//'),
    re.compile(r'^\s*\*'),
    re.compile(r'^\s*<!--'),
    re.compile(r'(?i)(example\.com|example\.org|localhost)'),
    re.compile(r'(?i)(changeme|your.?password|xxx+|dummy|fake|placeholder|CHANGE.?ME|replace.?me)'),
    re.compile(r'\$\{[^}]+\}'),
    re.compile(r'\{\{[^}]+\}\}'),
]


def is_fp_line(line):
    for p in _FP_LINE_RE:
        if p.search(line):
            return True
    return False


def is_junk(matched):
    parts = re.split(r'[=:]\s*', matched, maxsplit=1)
    if len(parts) >= 2:
        val = parts[1].strip().strip("\"'<>/")
        if not val or len(val) <= 2:
            return True
        if val.lower() in JUNK_VALUES:
            return True
        for p in _JUNK_PATTERNS_RE:
            if p.match(val):
                return True
        if len(set(val)) <= 2:
            return True
    return False


def should_skip_entry(entry_path):
    for p in _SKIP_INSIDE_RE:
        if p.search(entry_path):
            return True
    return False


# ============================================================
# HTTP - connection pool via multiple openers
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
            for m in pat.finditer(line):
                matched = m.group(0).strip()

                if label not in HIGH_CONFIDENCE:
                    if is_junk(matched):
                        continue

                key = (filepath, num, label)
                if key in seen:
                    continue
                seen.add(key)

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


def scan_archive(data, path, ext, depth, repo):
    """Scan archive, returns (entries_scanned, findings_list)."""
    findings = []
    entries = 0

    if should_skip(repo):
        return entries, findings

    try:
        if ext in (".jar", ".war", ".ear", ".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                return entries, findings
            with zf:
                for entry in zf.namelist():
                    if should_skip(repo):
                        break
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
                            ne, nf = scan_archive(zf.read(entry), f"{path}!/{entry}", eext, depth - 1, repo)
                            entries += ne
                            findings.extend(nf)
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
                    findings.extend(scan_text(raw.decode("utf-8", errors="replace"), f"{path}!/{entry}"))
                    entries += 1

        elif ext in (".gz", ".tgz"):
            try:
                if ext == ".gz":
                    dec = gzip.decompress(data)
                    try:
                        tf = tarfile.open(fileobj=io.BytesIO(dec))
                    except tarfile.TarError:
                        if is_text(dec):
                            findings.extend(scan_text(dec.decode("utf-8", errors="replace"), path))
                            entries += 1
                        return entries, findings
                else:
                    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
                with tf:
                    for m in tf.getmembers():
                        if should_skip(repo):
                            break
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
                            ne, nf = scan_archive(raw, f"{path}!/{m.name}", mext, depth - 1, repo)
                            entries += ne
                            findings.extend(nf)
                            continue
                        if not is_text(raw):
                            continue
                        findings.extend(scan_text(raw.decode("utf-8", errors="replace"), f"{path}!/{m.name}"))
                        entries += 1
            except Exception:
                pass

        elif ext == ".tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    for m in tf.getmembers():
                        if should_skip(repo):
                            break
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
                        entries += 1
            except Exception:
                pass
    except Exception:
        pass

    return entries, findings


# ============================================================
# Per-file worker: download + scan (runs in thread pool)
# ============================================================

def _process_text_file(fp, auth, repo):
    """Download and scan a single text file. Returns findings list."""
    if should_skip(repo):
        return [], 0
    raw = http_download(fp, auth)
    if raw is None:
        return [], 0
    if not is_text(raw):
        return [], 0
    return scan_text(raw.decode("utf-8", errors="replace"), fp), 1


def _process_archive(fp, sz, ext, auth, repo):
    """Download and scan a single archive. Returns (entries, findings)."""
    if should_skip(repo):
        return 0, []
    if sz > MAX_ARCHIVE_SIZE:
        return 0, []
    raw = http_download(fp, auth)
    if raw is None:
        return 0, []
    entries, findings = scan_archive(raw, fp, ext, depth=2, repo=repo)
    return entries, findings


# ============================================================
# Scan one repo (called from main thread pool)
# ============================================================

def scan_repo(repo, ri, total_repos, auth, t0, global_findings_count):
    """Scan a single repo. Returns (findings_list, stats_dict)."""
    global _current_repo

    if should_skip(repo):
        return [], {"text": 0, "archives": 0, "entries": 0, "errors": 0}

    with _current_repo_lock:
        _current_repo = repo

    stats = {"text": 0, "archives": 0, "entries": 0, "errors": 0}
    findings = []

    el = time.strftime("%H:%M:%S", time.gmtime(time.time() - t0))
    with _findings_lock:
        fc = global_findings_count[0]
    log(f"[{ri}/{total_repos}] {repo}  ({el}, {fc} creds)  [s=skip]")

    result = aql(f'items.find({{"repo":"{repo}"}}).include("name","size","path")', auth)
    if isinstance(result, dict) and result.get("_error"):
        stats["errors"] += 1
        return findings, stats

    items = result.get("results", [])
    if not items:
        return findings, stats

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
        return findings, stats

    log(f"  {len(text_files)} text + {len(archive_files)} archives")

    # --- Parallel text file scanning ---
    with ThreadPoolExecutor(max_workers=WORKERS_DOWNLOAD) as pool:
        futs = {pool.submit(_process_text_file, fp, auth, repo): fp for fp, sz in text_files}
        for fut in as_completed(futs):
            if should_skip(repo):
                break
            try:
                f, count = fut.result()
                findings.extend(f)
                stats["text"] += count
            except Exception:
                pass

    if should_skip(repo):
        log(f"  >>> SKIPPED {repo}")
        return findings, stats

    # --- Parallel archive scanning ---
    done_archives = 0
    with ThreadPoolExecutor(max_workers=WORKERS_SCAN) as pool:
        futs = {pool.submit(_process_archive, fp, sz, ext, auth, repo): fp
                for fp, sz, ext in archive_files}
        for fut in as_completed(futs):
            if should_skip(repo):
                break
            try:
                entries, f = fut.result()
                findings.extend(f)
                stats["archives"] += 1
                stats["entries"] += entries
            except Exception:
                pass
            done_archives += 1
            if done_archives % 30 == 0:
                log(f"    archives {done_archives}/{len(archive_files)}...")

    if should_skip(repo):
        log(f"  >>> SKIPPED {repo}")

    # Update global count for display
    with _findings_lock:
        global_findings_count[0] += len(findings)

    return findings, stats


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    log("=" * W)
    log("  RUN 2a - CREDENTIALS ONLY (MULTI-THREADED)")
    log(f"  {WORKERS_DOWNLOAD} download threads / {WORKERS_SCAN} scan threads / {WORKERS_REPO} repo threads")
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
    total_stats = {"text": 0, "archives": 0, "entries": 0, "errors": 0}
    t0 = time.time()
    global_findings_count = [0]  # mutable for thread sharing

    # Process repos in parallel batches
    with ThreadPoolExecutor(max_workers=WORKERS_REPO) as repo_pool:
        futs = {}
        for ri, repo in enumerate(scan_repos, 1):
            fut = repo_pool.submit(scan_repo, repo, ri, len(scan_repos), auth, t0, global_findings_count)
            futs[fut] = repo

        for fut in as_completed(futs):
            repo = futs[fut]
            try:
                findings, stats = fut.result()
                all_findings.extend(findings)
                for k in total_stats:
                    total_stats[k] += stats[k]
            except Exception as e:
                log(f"  ERROR on {repo}: {e}")

    elapsed = time.strftime("%H:%M:%S", time.gmtime(time.time() - t0))

    found("")
    found("=" * W)
    found(f"  DONE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({elapsed})")
    found(f"  Scanned: {total_stats['text']} text, {total_stats['archives']} archives, {total_stats['entries']} entries")
    found(f"  CREDENTIALS FOUND: {len(all_findings)}")
    found("=" * W)

    _ff.close()
    log(f"\nResults in: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
