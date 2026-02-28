#!/usr/bin/env python3
"""
Run 2b: Clean credentials scan. Zero noise.
- Starts with repos NOT yet covered, then does the rest.
- Skips CSS, i18n, Liferay, localization, javadoc, library jars.
- Multi-threaded.
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

# Repos already scanned in previous run - do these LAST
ALREADY_DONE = {
    "ads-release-local", "ads-snapshot-local", "atlas-release-local",
    "elogcard-release-local", "hyperion-search", "kneo-local-dependencies",
    "kneo-release-local", "kneo-snapshot-local", "ncm-release-local",
    "pbh-release-local", "pcf-release-local",
}

# ============================================================
# Skip logic - AGGRESSIVE noise filtering
# ============================================================

# Skip these PATHS inside archives
_SKIP_PATH = [re.compile(p) for p in [
    r'/org/apache/', r'/org/springframework/', r'/org/hibernate/',
    r'/org/eclipse/', r'/org/jboss/', r'/org/wildfly/',
    r'/com/sun/', r'/com/oracle/', r'/com/google/', r'/com/fasterxml/',
    r'/com/amazonaws/', r'/com/liferay/', r'/com/mysql/jdbc/LocalizedError',
    r'/javax/', r'/jakarta/',
    r'/META-INF/maven/', r'/META-INF/MANIFEST',
    r'/messages_\w+\.properties', r'/LocalStrings\.properties',
    r'/ValidationMessages', r'/Language\.properties', r'/Language_\w+\.properties',
    r'\.class$', r'\.MF$', r'\.SF$', r'\.RSA$', r'\.DSA$', r'\.EC$',
    r'/license', r'/LICENSE', r'/NOTICE', r'/changelog', r'/CHANGELOG',
    # CSS/font files = compass/token noise
    r'\.css$', r'\.less$', r'\.scss$', r'\.svg$', r'\.woff', r'\.ttf$', r'\.eot$',
    # JS libraries
    r'/node_modules/', r'\.min\.js$', r'/jquery', r'/bootstrap',
    # Liferay / portal i18n
    r'/html/form/', r'/local\.identity/', r'/forgot-password',
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
    # Also skip CSS/JS font noise at top level
    ".css", ".less", ".scss",
}

ARCHIVE_EXTS = {".jar", ".war", ".ear", ".zip", ".gz", ".tgz", ".tar"}
NESTED_ARCHIVE_EXTS = {".jar", ".zip", ".war", ".ear"}

# ============================================================
# Regexes - ONLY high-signal
# ============================================================
SECRET_REGEXES = [
    # Connection strings user:pass@host
    ("CONN_STRING",  re.compile(r'(?i)(mongodb|postgres|postgresql|mysql|redis|amqp|mssql|oracle|sqlserver|ldap|ldaps|ftp|ftps|smb|ssh)://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+')),
    # JDBC with password
    ("JDBC_PWD",     re.compile(r'(?i)jdbc:[a-z:]+//[^\s"]*password=[^\s"&]+')),
    # spring.*.password = realvalue
    ("SPRING_PWD",   re.compile(r'(?i)spring[\w.]*\.(password|secret)\s*[=:]\s*[^\s\$\{#]+')),
    # key=value where key contains password/secret/token AND value is real
    ("PWD_FIELD",    re.compile(r'(?i)^[\w.\-]*(password|passwd|pwd|secret|token|apikey|api[_-]?key|client[_-]?secret|auth[_-]?token)\s*[=:]\s*\S+')),
    # XML <password>real</password>
    ("XML_PWD",      re.compile(r'(?i)<(password|secret|token|apiKey|secretKey|accessKey|passphrase)[^>]*>[^<\$\{\}]{3,}</')),
    # XML password="real"
    ("XML_ATTR_PWD", re.compile(r'(?i)(password|secret|token|apiKey|secretKey|passwd|pwd)\s*=\s*"[^"\$\{]{3,}"')),
    # Private keys
    ("PRIVATE_KEY",  re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----')),
    # AWS
    ("AWS_KEY",      re.compile(r'AKIA[0-9A-Z]{16}')),
    # Tokens
    ("GITHUB_TOKEN", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ("GITLAB_TOKEN", re.compile(r'glpat-[A-Za-z0-9\-]{20,}')),
    ("SLACK_TOKEN",  re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),
    # Keycloak / OAuth client secret (JSON)
    ("OAUTH_SECRET", re.compile(r'(?i)"(client[_-]?secret|secret)"\s*:\s*"[^"\$\{]{4,}"')),
]

HIGH_CONFIDENCE = {"PRIVATE_KEY", "AWS_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN", "CONN_STRING", "OAUTH_SECRET"}

# ============================================================
# Junk value filtering
# ============================================================
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
    "openidm-admin",  # already found
}

_JUNK_PAT = [re.compile(p) for p in [
    r'^[A-Z][a-z]+(?:[A-Z][a-z]+)+$',   # CamelCase
    r'^[a-z]+\.[a-z]+\.',                 # package
    r'^\$[\{\(]', r'^\{\{', r'^@',
    r'^System\.', r'^org\.', r'^com\.', r'^net\.', r'^javax?\.',
    r'^class\s', r'^\w+\.class$',
]]

# Lines that are NEVER real secrets
_FP_LINE = [re.compile(p) for p in [
    r'^\s*[#;!]', r'^\s*//', r'^\s*\*', r'^\s*<!--',
    r'(?i)(example\.com|example\.org|localhost)',
    r'(?i)(changeme|your.?password|xxx+|dummy|fake|placeholder|CHANGE.?ME|replace.?me)',
    r'\$\{[^}]+\}', r'\{\{[^}]+\}\}',
    # CSS noise
    r'^\s*\.[\w-]+\s*[:{]',       # .icon-compass:before {
    r'::?before\s*\{',            # ::before {
    r'content:\s*"\\',             # content: "\f29e"
    # i18n / UI label noise
    r'(?i)^(forgot|html\.form|local\.identity|bad\.user\.password)',
    r'(?i)(enter.*password|new\s+password|confirm.*password|reset.*password|change\s+password)',
    r'(?i)^(action\.|label\.|message\.|error\.|info\.|warning\.)',
    # Code noise
    r'(?i)^.*target\.password\s*=\s*password',
    r'(?i)ConnectionProperties\.',
    r'(?i)<password>password</password>',
    # Exports / JS module
    r'^exports\.',
    r'(?i)SQL_TOKEN',
]]


def is_fp(line):
    for p in _FP_LINE:
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
        for p in _JUNK_PAT:
            if p.match(val):
                return True
        if len(set(val)) <= 2:
            return True
    return False


def skip_entry(path):
    for p in _SKIP_PATH:
        if p.search(path):
            return True
    return False


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
# Scanning
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


def scan_text(text, filepath):
    results = []
    lines = text.split("\n")
    seen = set()
    for num, line in enumerate(lines, 1):
        s = line.strip()
        if not s or is_fp(s):
            continue
        for label, pat in SECRET_REGEXES:
            for m in pat.finditer(line):
                matched = m.group(0).strip()
                if label not in HIGH_CONFIDENCE and is_junk(matched):
                    continue
                key = (filepath, num, label)
                if key in seen:
                    continue
                seen.add(key)

                ctx = []
                for off in range(3, 0, -1):
                    idx = num - 1 - off
                    if 0 <= idx < len(lines) and lines[idx].strip():
                        ctx.append(lines[idx].strip()[:160])

                found(f"[{label}] {filepath}:{num}")
                for c in ctx:
                    found(f"  {c}")
                found(f">>  {s[:200]}")
                found(f"  FETCH: {BASE_URL}/{filepath.split('!/')[0]}")
                found("")
                results.append(1)
    return results


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
                    if skip_entry(entry):
                        continue
                    try:
                        info = zf.getinfo(entry)
                    except KeyError:
                        continue
                    if info.file_size == 0 or info.file_size > MAX_ENTRY:
                        continue
                    eext = ext_of(entry)
                    if depth > 0 and eext in NESTED_ARCHIVE_EXTS and info.file_size < MAX_ARCHIVE:
                        try:
                            ne, nf = scan_archive(zf.read(entry), f"{path}!/{entry}", eext, depth - 1, repo)
                            entries += ne; findings.extend(nf)
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
                        if skipped(repo) or not m.isfile() or m.size == 0 or m.size > MAX_ENTRY:
                            continue
                        if skip_entry(m.name):
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
                        if skipped(repo) or not m.isfile() or m.size == 0 or m.size > MAX_ENTRY:
                            continue
                        if skip_entry(m.name) or ext_of(m.name) in BINARY_EXTS:
                            continue
                        try:
                            f = tf.extractfile(m)
                            if not f: continue
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
# Per-file workers
# ============================================================

def _do_text(fp, auth, repo):
    if skipped(repo): return [], 0
    raw = http_dl(fp, auth)
    if not raw or not is_text(raw): return [], 0
    return scan_text(raw.decode("utf-8", errors="replace"), fp), 1


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
    log("  RUN 2b - CLEAN CREDS (new repos first)")
    log(f"  {WORKERS_DL}dl / {WORKERS_SCAN}scan / {WORKERS_REPO}repo threads")
    log(f"  {datetime.now():%Y-%m-%d %H:%M:%S}  [s=skip repo]")
    log("=" * W)

    found(f"CREDENTIALS SCAN - {datetime.now():%Y-%m-%d %H:%M:%S}")
    found("")

    user = input("\nUsername: ").strip()
    pw = getpass.getpass("Password: ")
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()

    threading.Thread(target=_keys, daemon=True).start()

    log("\nPing...", )
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

    # New repos first, already-done repos last
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
    found(f"Scanned: {ts['t']} text, {ts['a']} archives, {ts['e']} entries")
    found(f"CREDENTIALS FOUND: {len(all_findings)}")

    _ff.close()
    log(f"\nResults in: {OUT}")


if __name__ == "__main__":
    main()
