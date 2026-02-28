#!/usr/bin/env python3
"""
Run 1: Full inventory of ALL files in ALL repos.
Outputs structured info so we know what to scan next.
"""

import json
import sys
import getpass
import urllib.request
import urllib.error
import ssl
import base64
from datetime import datetime
from collections import defaultdict

BASE_URL = "http://10.26.1.75:8081/artifactory"

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def http_get(endpoint, auth):
    url = endpoint if endpoint.startswith("http") else f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"Authorization": auth})
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": True, "status": e.code}
    except Exception as e:
        return {"_error": True, "detail": str(e)}


def aql(query, auth):
    url = f"{BASE_URL}/api/search/aql"
    req = urllib.request.Request(url, data=query.encode("utf-8"), headers={
        "Content-Type": "text/plain", "Authorization": auth,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": True, "status": e.code,
                "detail": e.read().decode("utf-8", errors="replace")[:500]}
    except Exception as e:
        return {"_error": True, "detail": str(e)}


def main():
    print("=" * 70)
    print("  RUN 1 - FULL INVENTORY")
    print("=" * 70)

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
    print("Listing repos...", end=" ", flush=True)
    repos = http_get("/api/repositories", auth)
    if isinstance(repos, dict) and repos.get("_error"):
        print(f"ERROR {repos}")
        sys.exit(1)
    print(f"{len(repos)} repos\n")

    for r in repos:
        print(f"  {r.get('key',''):<45} type={r.get('type',''):<10} pkg={r.get('packageType','')}")

    # AQL: get ALL files, but only metadata (name, size, repo)
    # We do it per repo to avoid timeout on huge instances
    print(f"\nEnumerating ALL files per repo...")

    grand_total_files = 0
    grand_total_size = 0
    ext_stats = defaultdict(lambda: {"count": 0, "size": 0})
    repo_stats = []

    for r in repos:
        rkey = r.get("key", "")
        rtype = r.get("type", "")

        # Skip virtual repos (they're just aggregators, would double-count)
        if rtype == "VIRTUAL":
            print(f"  {rkey:<45} [VIRTUAL - skipped]")
            continue

        q = f'items.find({{"repo":"{rkey}"}}).include("name","size","repo","path")'
        result = aql(q, auth)

        if isinstance(result, dict) and result.get("_error"):
            print(f"  {rkey:<45} ERROR {result.get('status','')}")
            repo_stats.append({"repo": rkey, "files": 0, "size_mb": 0, "error": True})
            continue

        items = result.get("results", [])
        total_size = sum(it.get("size", 0) for it in items)
        grand_total_files += len(items)
        grand_total_size += total_size

        # Extension breakdown for this repo
        for it in items:
            name = it.get("name", "")
            parts = name.rsplit(".", 1)
            ext = ("." + parts[1].lower()) if len(parts) > 1 else "(no ext)"
            ext_stats[ext]["count"] += 1
            ext_stats[ext]["size"] += it.get("size", 0)

        size_mb = round(total_size / (1024 * 1024), 1)
        print(f"  {rkey:<45} {len(items):>7} files  {size_mb:>10} MB")
        repo_stats.append({"repo": rkey, "files": len(items), "size_mb": size_mb})

    # Summary
    print(f"\n{'=' * 70}")
    print(f"  TOTALS: {grand_total_files} files, {round(grand_total_size/(1024*1024),1)} MB")
    print(f"{'=' * 70}")

    # Extension breakdown (sorted by count)
    print(f"\n  FILE EXTENSIONS (top 50):")
    print(f"  {'EXT':<20} {'COUNT':>8} {'SIZE MB':>10}")
    print(f"  {'-'*20} {'-'*8} {'-'*10}")

    sorted_exts = sorted(ext_stats.items(), key=lambda x: -x[1]["count"])
    for ext, stats in sorted_exts[:50]:
        sz = round(stats["size"] / (1024 * 1024), 1)
        print(f"  {ext:<20} {stats['count']:>8} {sz:>10}")

    # Identify which extensions are "text-scannable"
    binary_exts = {
        ".jar", ".war", ".ear", ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z",
        ".rar", ".whl", ".egg", ".deb", ".rpm", ".msi", ".exe", ".dll", ".so",
        ".dylib", ".class", ".pyc", ".pyo", ".o", ".a", ".lib",
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tiff",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac",
        ".ttf", ".otf", ".woff", ".woff2", ".eot",
        ".nupkg", ".gem", ".aar", ".apk",
        ".sha1", ".sha256", ".sha512", ".md5",
        ".sig", ".asc",
    }

    text_count = 0
    text_size = 0
    for ext, stats in sorted_exts:
        if ext not in binary_exts:
            text_count += stats["count"]
            text_size += stats["size"]

    print(f"\n  SCANNABLE (text) files: {text_count} ({round(text_size/(1024*1024),1)} MB)")
    print(f"  Binary (skipped):      {grand_total_files - text_count}")

    # List text extensions
    print(f"\n  TEXT EXTENSIONS THAT WILL BE SCANNED:")
    text_exts = [(ext, s) for ext, s in sorted_exts if ext not in binary_exts]
    for ext, stats in text_exts[:40]:
        sz = round(stats["size"] / (1024 * 1024), 1)
        print(f"    {ext:<20} {stats['count']:>8} files  {sz:>8} MB")

    print(f"\n  BINARY EXTENSIONS THAT WILL BE SKIPPED:")
    bin_exts = [(ext, s) for ext, s in sorted_exts if ext in binary_exts]
    for ext, stats in bin_exts[:30]:
        sz = round(stats["size"] / (1024 * 1024), 1)
        print(f"    {ext:<20} {stats['count']:>8} files  {sz:>8} MB")

    print(f"\n{'=' * 70}")
    print(f"  Copy this output and send it back.")
    print(f"  Next: run2 will scan all {text_count} text files for secrets.")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
