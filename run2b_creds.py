#!/usr/bin/env python3
"""
Run 2b: Zero-noise credential scanner.
Only scans CONFIG files (properties, yml, json, xml configs, shell scripts, env, docker).
Skips ALL code, CSS, JS, i18n, HTML, Java.
Multi-threaded.
"""

import json, sys, os, re, getpass, urllib.request, urllib.error, ssl, base64
import time, zipfile, gzip, tarfile, io, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ============================================================
# Tuning
# ============================================================
WORKERS_DL = 12
WORKERS_SCAN = 6
WORKERS_REPO = 4

BASE_URL = "http://10.26.1.75:8081/artifactory"
MAX_ARCHIVE = 200 * 1024 * 1024
MAX_ENTRY = 10 * 1024 * 1024

# Repos already covered - scan LAST
ALREADY_DONE = {
    "ads-release-local", "ads-snapshot-local", "atlas-release-local",
    "elogcard-release-local", "hyperion-search", "kneo-local-dependencies",
    "kneo-release-local", "kneo-snapshot-local", "ncm-release-local",
    "pbh-release-local", "pcf-release-local",
}

# ============================================================
# FILE WHITELIST - only scan these file types
# ============================================================

# Config file extensions we always scan
_CONFIG_EXTS = {
    ".properties", ".yml", ".yaml", ".env", ".conf", ".cfg", ".ini",
    ".sh", ".bat", ".ps1", ".cmd",
}

# Config file NAME patterns (matched against basename)
_CONFIG_NAMES = [re.compile(p, re.I) for p in [
    r'^portal-ext\.properties$',
    r'^application[\w\-]*\.(properties|yml|yaml)$',
    r'^bootstrap[\w\-]*\.(yml|yaml)$',
    r'^docker-compose[\w\-]*\.(yml|yaml)$',
    r'^Dockerfile',
    r'^\.env',
    r'^\.npmrc$', r'^\.pypirc$', r'^\.netrc$', r'^\.git-credentials$',
    r'^\.htpasswd$', r'^\.dockercfg$',
    r'^settings\.xml$',
    r'^(app|config|appsettings|credentials|secrets)[\w\-]*\.(json|xml|properties|yml|yaml|conf)$',
    r'^(context|datasource|server|proxy|standalone|domain)[\w\-]*\.xml$',
    r'^terraform\.tfvars$', r'\.auto\.tfvars$',
    r'^kubeconfig$', r'.*\.kubeconfig$',
    r'^vault\.(json|yml|yaml)$',
    r'^(keycloak|realm)[\w\-]*\.json$',
    r'^Jenkinsfile$', r'^\.gitlab-ci\.yml$',
    r'.*secret.*', r'.*credential.*',
    r'^delete_company\.sh$',  # known finding
]]

# Files to NEVER scan even if extension matches
_SKIP_NAMES = [re.compile(p, re.I) for p in [
    r'^Language[\w_]*\.properties$',
    r'^messages[\w_]*\.properties$',
    r'^LocalStrings[\w_]*\.properties$',
    r'^ValidationMessages',
    r'^LocalizedErrorMessages',
    r'[\w]*Error[\w]*\.properties$',
    r'^pingfederate-messages',
]]

# Inside archives: library paths to always skip
_SKIP_LIB = [re.compile(p) for p in [
    r'/org/apache/', r'/org/springframework/', r'/org/hibernate/',
    r'/org/eclipse/', r'/org/jboss/', r'/org/wildfly/',
    r'/com/sun/', r'/com/oracle/', r'/com/google/', r'/com/fasterxml/',
    r'/com/amazonaws/', r'/com/liferay/', r'/com/mysql/',
    r'/javax/', r'/jakarta/',
    r'/META-INF/maven/', r'/META-INF/MANIFEST',
    r'/node_modules/', r'/vendor/', r'/bower_components/',
]]

BINARY_EXTS = {
    ".class", ".pyc", ".o", ".a", ".lib", ".obj", ".exe", ".dll", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".sha1", ".sha256", ".sha512", ".md5", ".sig", ".asc",
    ".deb", ".rpm", ".msi", ".apk",
    ".pdf", ".swf", ".dat", ".bin", ".iso",
    ".css", ".less", ".scss", ".sass",
    ".java", ".kt", ".scala", ".groovy",
    ".js", ".ts", ".jsx", ".tsx", ".mjs",
    ".html", ".htm", ".xhtml", ".jsp", ".ftl", ".vm",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".go", ".rs",
    ".png", ".gif", ".ico",
    ".MF", ".SF", ".RSA", ".DSA", ".EC",
    ".md", ".txt", ".adoc", ".rst",
    ".sql",
}

ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".gz", ".tgz", ".tar"}
NESTED_ARCHIVE_EXTS = {".jar", ".zip", ".war", ".ear"}


def is_config_file(filepath):
    """Return True only if this file is a config we should scan."""
    basename = os.path.basename(filepath)
    _, ext = os.path.splitext(basename)
    ext = ext.lower()

    # Skip blacklisted names first
    for p in _SKIP_NAMES:
        if p.search(basename):
            return False

    # Check whitelisted extensions
    if ext in _CONFIG_EXTS:
        return True

    # Check whitelisted name patterns
    for p in _CONFIG_NAMES:
        if p.search(basename):
            return True

    # JSON: only config-like JSON
    if ext == ".json":
        for p in _CONFIG_NAMES:
            if p.search(basename):
                return True
        return False

    # XML: only config-like XML
    if ext == ".xml":
        for p in _CONFIG_NAMES:
            if p.search(basename):
                return True
        # Also scan if name suggests config
        bl = basename.lower()
        if any(w in bl for w in ["config", "context", "datasource", "server",
                                  "proxy", "setting", "standalone", "domain",
                                  "pom", "persistence", "web"]):
            return True
        return False

    return False


def in_library_path(path):
    """Skip known library/framework paths inside archives."""
    for p in _SKIP_LIB:
        if p.search(path):
            return True
    return False


# ============================================================
# CREDENTIAL DETECTION
# ============================================================

# High-confidence patterns (always report, no value check needed)
_ALWAYS_PATTERNS = [
    ("CONN_STRING",  re.compile(r'(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql|oracle|sqlserver|ldap|ldaps|ftp|ftps|smb|ssh)://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+')),
    ("JDBC_PWD",     re.compile(r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+')),
    ("PRIVATE_KEY",  re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----')),
    ("AWS_KEY",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("GITHUB_TOKEN", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("GITLAB_TOKEN", re.compile(r'glpat-[A-Za-z0-9\-]{20,}')),
    ("SLACK_TOKEN",  re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),
]

# Key-value patterns: key must contain sensitive word, value is validated
_KV_KEYS = re.compile(r'(?i)(password|passwd|pwd|secret|token|apikey|api[_-]?key|client[_-]?secret|auth[_-]?token|storepass|keypass|trustpass)')

# For XML attributes: password="value"
_XML_ATTR = re.compile(r'(?i)(password|secret|token|storepass|keypass|trustpass)\s*=\s*"([^"]*)"')

# For JSON: "key": "value"
_JSON_KV = re.compile(r'(?i)"(password|passwd|secret|token|client[_-]?secret|api[_-]?key|apikey|auth[_-]?token|credentials?)"\s*:\s*"([^"]*)"')

# For properties/env/shell: key=value or key: value
_PROP_KV = re.compile(r'(?i)^[\w.\-]*(password|passwd|pwd|secret|token|apikey|api[_-]?key|client[_-]?secret|auth[_-]?token|storepass)\s*[=:]\s*(.+)$')


def is_real_value(val):
    """Is this value a real credential (not a placeholder, label, or code)?"""
    val = val.strip().strip("\"'<>/")

    if not val or len(val) <= 2:
        return False

    # Placeholders
    if '${' in val or '{{' in val or '%' in val and '%' in val[1:]:
        return False

    # Spaces = human text / label
    if ' ' in val:
        return False

    # Known non-values
    _junk = {
        "password", "passwd", "pwd", "pass", "secret", "token", "key", "apikey",
        "null", "none", "nil", "empty", "blank", "undefined", "default",
        "true", "false", "yes", "no", "on", "off",
        "encrypted", "encoded", "hashed",
        "property", "value", "string", "text", "name", "type", "field",
        "changeme", "change_me", "fixme", "todo", "xxx", "yyy",
        "description", "label", "placeholder", "prompt",
        "classpath", "filepath",
    }
    if val.lower() in _junk:
        return False

    # Pure single alphabetic word = not a password (Passwort, Codigo, etc.)
    if re.match(r'^[A-Za-z]+$', val):
        return False

    # CamelCase class name (PasswordEncoder, SecretKeyFactory, etc.)
    if re.match(r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$', val):
        return False

    # Java package (com.foo.bar)
    if re.match(r'^[a-z]+\.[a-z]+\.', val):
        return False

    # Starts with $ @ { = code/variable reference
    if val[0] in '$@{':
        return False

    # All same char (*****, ===, ...)
    if len(set(val.replace('*', ''))) <= 1:
        return False

    # Looks like: {TO_BE_DEFINED} or similar
    if val.startswith('{') and val.endswith('}'):
        return False

    return True


# ============================================================
# HTTP
# ============================================================
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def http_json(ep, auth):
    url = ep if ep.startswith("http") else f"{BASE_URL}{ep}"
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=60) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_error": True, "detail": str(e)}


def http_dl(path, auth):
    req = urllib.request.Request(f"{BASE_URL}/{path}", headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=120) as r:
            return r.read()
    except Exception:
        return None


def aql(q, auth):
    req = urllib.request.Request(f"{BASE_URL}/api/search/aql",
        data=q.encode("utf-8"),
        headers={"Content-Type": "text/plain", "Authorization": auth},
        method="POST")
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_error": True, "detail": str(e)}


# ============================================================
# Skip repo (press 's')
# ============================================================
_skip = set()
_skip_lock = threading.Lock()
_cur = [None]


def _keys():
    try:
        import msvcrt
        while True:
            if msvcrt.kbhit() and msvcrt.getch().lower() == b's':
                r = _cur[0]
                if r:
                    with _skip_lock:
                        _skip.add(r)
                    print(f"\n  >>> SKIP {r} >>>", flush=True)
            time.sleep(0.1)
    except ImportError:
        pass


def skipped(repo):
    with _skip_lock:
        return repo in _skip


# ============================================================
# Output
# ============================================================
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tobesent")
_ff = open(OUT, "w", encoding="utf-8")
_ol = threading.Lock()


def log(msg):
    print(msg, flush=True)


def found(msg):
    with _ol:
        print(msg, flush=True)
        _ff.write(msg + "\n")
        _ff.flush()


# ============================================================
# Scanning a config file
# ============================================================

def ext_of(n):
    _, e = os.path.splitext(n)
    return e.lower()


def is_text(data):
    try:
        t = data[:8192].decode("utf-8")
        return (sum(1 for c in t if c.isprintable() or c in '\n\r\t') / len(t)) > 0.85 if t else False
    except (UnicodeDecodeError, ZeroDivisionError):
        return False


def scan_config(text, filepath):
    """Scan a config file for credentials. Returns list of findings."""
    results = []
    lines = text.split("\n")
    seen = set()

    for num, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith('#') or s.startswith('//') or s.startswith('*') or s.startswith('<!--'):
            continue

        # --- Always-report patterns (connection strings, keys, tokens) ---
        for label, pat in _ALWAYS_PATTERNS:
            for m in pat.finditer(line):
                key = (filepath, num, label)
                if key in seen:
                    continue
                seen.add(key)
                _emit(filepath, num, label, s, lines)
                results.append(1)

        # --- Key=value in properties/env/shell ---
        m = _PROP_KV.search(line)
        if m:
            val = m.group(2).strip()
            if is_real_value(val):
                key = (filepath, num, "CRED")
                if key not in seen:
                    seen.add(key)
                    _emit(filepath, num, "CRED", s, lines)
                    results.append(1)

        # --- XML attributes: password="xxx" ---
        for m in _XML_ATTR.finditer(line):
            val = m.group(2)
            if is_real_value(val):
                key = (filepath, num, "XML_CRED")
                if key not in seen:
                    seen.add(key)
                    _emit(filepath, num, "XML_CRED", s, lines)
                    results.append(1)

        # --- JSON "key": "value" ---
        for m in _JSON_KV.finditer(line):
            val = m.group(2)
            if is_real_value(val):
                key = (filepath, num, "JSON_CRED")
                if key not in seen:
                    seen.add(key)
                    _emit(filepath, num, "JSON_CRED", s, lines)
                    results.append(1)

    return results


def _emit(filepath, num, label, line, lines):
    """Output a finding with context."""
    ctx = []
    for off in range(3, 0, -1):
        idx = num - 1 - off
        if 0 <= idx < len(lines) and lines[idx].strip():
            ctx.append(lines[idx].strip()[:160])

    found(f"[{label}] {filepath}:{num}")
    for c in ctx:
        found(f"  {c}")
    found(f">>  {line[:200]}")
    found(f"  FETCH: {BASE_URL}/{filepath.split('!/')[0]}")
    found("")


# ============================================================
# Archive scanning - only extract config files
# ============================================================

def scan_archive(data, path, ext, depth, repo):
    findings = []
    entries = 0
    if skipped(repo):
        return 0, []
    try:
        if ext in (".jar", ".war", ".ear", ".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                return 0, []
            with zf:
                for entry in zf.namelist():
                    if skipped(repo) or entry.endswith("/"):
                        continue
                    if in_library_path(entry):
                        continue
                    try:
                        info = zf.getinfo(entry)
                    except KeyError:
                        continue
                    if info.file_size == 0 or info.file_size > MAX_ENTRY:
                        continue
                    eext = ext_of(entry)
                    # Recurse into nested archives
                    if depth > 0 and eext in NESTED_ARCHIVE_EXTS and info.file_size < MAX_ARCHIVE:
                        try:
                            ne, nf = scan_archive(zf.read(entry), f"{path}!/{entry}", eext, depth - 1, repo)
                            entries += ne; findings.extend(nf)
                        except Exception:
                            pass
                        continue
                    # Only scan config files
                    if not is_config_file(entry):
                        continue
                    try:
                        raw = zf.read(entry)
                    except Exception:
                        continue
                    if not is_text(raw):
                        continue
                    findings.extend(scan_config(raw.decode("utf-8", errors="replace"), f"{path}!/{entry}"))
                    entries += 1

        elif ext in (".gz", ".tgz"):
            try:
                if ext == ".gz":
                    dec = gzip.decompress(data)
                    try:
                        tf = tarfile.open(fileobj=io.BytesIO(dec))
                    except tarfile.TarError:
                        # Plain gzip file
                        if is_text(dec) and is_config_file(path):
                            findings.extend(scan_config(dec.decode("utf-8", errors="replace"), path))
                            entries += 1
                        return entries, findings
                else:
                    tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
                with tf:
                    for m in tf.getmembers():
                        if skipped(repo) or not m.isfile() or m.size == 0 or m.size > MAX_ENTRY:
                            continue
                        if in_library_path(m.name):
                            continue
                        mext = ext_of(m.name)
                        if mext in BINARY_EXTS:
                            continue
                        try:
                            f = tf.extractfile(m)
                            if not f: continue
                            raw = f.read()
                        except Exception:
                            continue
                        if depth > 0 and mext in NESTED_ARCHIVE_EXTS and len(raw) < MAX_ARCHIVE:
                            ne, nf = scan_archive(raw, f"{path}!/{m.name}", mext, depth - 1, repo)
                            entries += ne; findings.extend(nf)
                            continue
                        if not is_config_file(m.name):
                            continue
                        if not is_text(raw):
                            continue
                        findings.extend(scan_config(raw.decode("utf-8", errors="replace"), f"{path}!/{m.name}"))
                        entries += 1
            except Exception:
                pass

        elif ext == ".tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    for m in tf.getmembers():
                        if skipped(repo) or not m.isfile() or m.size == 0 or m.size > MAX_ENTRY:
                            continue
                        if in_library_path(m.name):
                            continue
                        if not is_config_file(m.name):
                            continue
                        try:
                            f = tf.extractfile(m)
                            if not f: continue
                            raw = f.read()
                        except Exception:
                            continue
                        if not is_text(raw):
                            continue
                        findings.extend(scan_config(raw.decode("utf-8", errors="replace"), f"{path}!/{m.name}"))
                        entries += 1
            except Exception:
                pass
    except Exception:
        pass
    return entries, findings


# ============================================================
# Workers
# ============================================================

def _do_text(fp, auth, repo):
    if skipped(repo): return [], 0
    if not is_config_file(fp): return [], 0
    raw = http_dl(fp, auth)
    if not raw or not is_text(raw): return [], 0
    return scan_config(raw.decode("utf-8", errors="replace"), fp), 1


def _do_archive(fp, sz, ext, auth, repo):
    if skipped(repo) or sz > MAX_ARCHIVE: return 0, []
    raw = http_dl(fp, auth)
    if not raw: return 0, []
    return scan_archive(raw, fp, ext, 2, repo)


# ============================================================
# Scan one repo
# ============================================================
_gcnt = [0]
_gl = threading.Lock()


def scan_repo(repo, ri, total, auth, t0):
    if skipped(repo):
        return [], {"t": 0, "a": 0, "e": 0}

    _cur[0] = repo
    el = time.strftime("%H:%M:%S", time.gmtime(time.time() - t0))
    with _gl:
        c = _gcnt[0]
    tag = " (REDO)" if repo in ALREADY_DONE else ""
    log(f"[{ri}/{total}] {repo}{tag}  ({el}, {c} creds)  [s=skip]")

    st = {"t": 0, "a": 0, "e": 0}
    findings = []

    r = aql(f'items.find({{"repo":"{repo}"}}).include("name","size","path")', auth)
    if isinstance(r, dict) and r.get("_error"):
        return [], st

    items = r.get("results", [])
    if not items:
        return [], st

    texts, archives = [], []
    for it in items:
        name = it.get("name", "")
        size = it.get("size", 0)
        path = it.get("path", ".")
        fp = f"{repo}/{path}/{name}" if path != "." else f"{repo}/{name}"
        ext = ext_of(name)
        if size == 0:
            continue
        if ext in ARCHIVE_EXTS:
            archives.append((fp, size, ext))
        elif ext not in BINARY_EXTS and size <= MAX_ENTRY:
            texts.append((fp, size))

    if not texts and not archives:
        return [], st

    log(f"  {len(texts)} text + {len(archives)} archives")

    # Parallel text
    with ThreadPoolExecutor(max_workers=WORKERS_DL) as pool:
        for fut in as_completed({pool.submit(_do_text, fp, auth, repo): fp for fp, _ in texts}):
            if skipped(repo): break
            try:
                f, c = fut.result()
                findings.extend(f); st["t"] += c
            except Exception:
                pass

    if not skipped(repo):
        done = 0
        with ThreadPoolExecutor(max_workers=WORKERS_SCAN) as pool:
            for fut in as_completed({pool.submit(_do_archive, fp, sz, ext, auth, repo): fp for fp, sz, ext in archives}):
                if skipped(repo): break
                try:
                    e, f = fut.result()
                    findings.extend(f); st["a"] += 1; st["e"] += e
                except Exception:
                    pass
                done += 1
                if done % 30 == 0:
                    log(f"    archives {done}/{len(archives)}...")

    if skipped(repo):
        log(f"  >>> SKIPPED")

    with _gl:
        _gcnt[0] += len(findings)

    return findings, st


# ============================================================
# Main
# ============================================================

def main():
    W = 70
    log("=" * W)
    log("  RUN 2b - ZERO NOISE (config files only)")
    log(f"  {WORKERS_DL}dl / {WORKERS_SCAN}scan / {WORKERS_REPO}repo threads")
    log(f"  {datetime.now():%Y-%m-%d %H:%M:%S}  [s=skip repo]")
    log("=" * W)

    found(f"CREDENTIALS SCAN - {datetime.now():%Y-%m-%d %H:%M:%S}")
    found("")

    user = input("\nUsername: ").strip()
    pw = getpass.getpass("Password: ")
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    threading.Thread(target=_keys, daemon=True).start()

    log("\nPing...")
    try:
        req = urllib.request.Request(f"{BASE_URL}/api/system/ping", headers={"Authorization": auth})
        with urllib.request.urlopen(req, context=_ctx, timeout=10):
            log("  OK")
    except Exception as e:
        log(f"  FAILED ({e})"); sys.exit(1)

    repos = http_json("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        log(f"ERROR: {repos}"); sys.exit(1)

    all_repos = [r["key"] for r in repos if r.get("type") != "VIRTUAL"]
    new_repos = [r for r in all_repos if r not in ALREADY_DONE]
    old_repos = [r for r in all_repos if r in ALREADY_DONE]
    ordered = new_repos + old_repos

    log(f"\nRepos: {len(ordered)} ({len(new_repos)} new, {len(old_repos)} redo)\n")

    all_findings = []
    ts = {"t": 0, "a": 0, "e": 0}
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=WORKERS_REPO) as pool:
        futs = {pool.submit(scan_repo, repo, i, len(ordered), auth, t0): repo
                for i, repo in enumerate(ordered, 1)}
        for fut in as_completed(futs):
            try:
                f, s = fut.result()
                all_findings.extend(f)
                for k in ts: ts[k] += s[k]
            except Exception as e:
                log(f"  ERR: {e}")

    el = time.strftime("%H:%M:%S", time.gmtime(time.time() - t0))
    found("")
    found(f"DONE - {datetime.now():%Y-%m-%d %H:%M:%S} ({el})")
    found(f"Scanned: {ts['t']} text, {ts['a']} archives, {ts['e']} config entries")
    found(f"CREDENTIALS FOUND: {len(all_findings)}")

    _ff.close()
    log(f"\nResults in: {OUT}")


if __name__ == "__main__":
    main()
