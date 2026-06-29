#!/usr/bin/env python3
"""
预填充漏洞缓存脚本 (Pre-populate Vulnerability Cache)

从 OSV.dev API 批量拉取常见 Python 包的漏洞数据，
生成 cache/vuln_cache.json 供离线使用。

任务书要求：①调用API查询 + ④支持离线漏洞库（本地JSON缓存）
本脚本在本机运行（有网络访问），拉取真实API数据，部署时一起带走。
"""
import json
import os
import time
import requests

OSV_URL = "https://api.osv.dev/v1/query"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "vuln_cache.json")
RATE_LIMIT = 0.5  # seconds between requests

# 100+ 常见 Python 包及其已知有漏洞的版本
PACKAGES = [
    # === Web 框架 ===
    ("flask", "2.0.1"),
    ("flask", "1.1.0"),
    ("flask", "0.12.0"),
    ("django", "3.2.0"),
    ("django", "2.2.0"),
    ("django", "1.11.0"),
    ("django", "4.0.0"),
    ("fastapi", "0.63.0"),
    ("tornado", "6.1.0"),
    ("aiohttp", "3.7.4"),
    ("aiohttp", "3.8.0"),
    ("starlette", "0.14.0"),
    ("bottle", "0.12.19"),
    ("werkzeug", "2.0.0"),
    ("werkzeug", "1.0.0"),
    ("uvicorn", "0.15.0"),

    # === HTTP 库 ===
    ("requests", "2.25.1"),
    ("requests", "2.19.0"),
    ("requests", "2.27.0"),
    ("urllib3", "1.26.4"),
    ("urllib3", "1.25.0"),
    ("urllib3", "1.21.0"),
    ("httpx", "0.21.0"),
    ("httplib2", "0.19.0"),
    ("gunicorn", "20.0.0"),

    # === 模板引擎 ===
    ("jinja2", "2.11.3"),
    ("jinja2", "2.10.0"),
    ("jinja2", "3.0.0"),
    ("mako", "1.1.0"),
    ("markupsafe", "2.0.0"),

    # === 数据科学 ===
    ("numpy", "1.21.0"),
    ("numpy", "1.22.0"),
    ("numpy", "1.19.0"),
    ("pandas", "1.3.0"),
    ("pandas", "1.1.0"),
    ("scipy", "1.7.0"),
    ("scipy", "1.5.0"),
    ("pillow", "8.3.0"),
    ("pillow", "8.0.0"),
    ("pillow", "7.0.0"),
    ("matplotlib", "3.4.0"),

    # === 加密/安全 ===
    ("cryptography", "3.4.7"),
    ("cryptography", "3.0.0"),
    ("cryptography", "2.0.0"),
    ("pyopenssl", "20.0.0"),
    ("pyopenssl", "19.0.0"),
    ("pyjwt", "2.0.0"),
    ("pyjwt", "1.7.0"),
    ("passlib", "1.7.0"),
    ("bcrypt", "3.0.0"),
    ("paramiko", "2.7.0"),
    ("paramiko", "2.0.0"),

    # === 数据库 ===
    ("sqlalchemy", "1.4.0"),
    ("sqlalchemy", "1.3.0"),
    ("psycopg2", "2.8.0"),
    ("pymongo", "3.11.0"),
    ("redis", "3.5.0"),
    ("celery", "5.0.0"),
    ("elasticsearch", "7.0.0"),

    # === 构建/打包 ===
    ("setuptools", "65.5.0"),
    ("setuptools", "57.0.0"),
    ("pip", "21.0.0"),
    ("pip", "20.0.0"),
    ("poetry", "1.1.0"),

    # === YAML/JSON/配置 ===
    ("pyyaml", "5.4.1"),
    ("pyyaml", "5.3.0"),
    ("pyyaml", "3.13"),
    ("toml", "0.10.0"),
    ("configparser", "3.5.0"),

    # === 认证/OAuth ===
    ("oauthlib", "3.1.0"),
    ("authlib", "0.15.0"),
    ("python-jose", "3.2.0"),
    ("python-keycloak", "0.0.1"),

    # === 文件处理 ===
    ("certifi", "2022.12.07"),
    ("certifi", "2021.10.08"),
    ("certifi", "2020.0.0"),
    ("lxml", "4.6.0"),
    ("lxml", "4.5.0"),
    ("beautifulsoup4", "4.9.0"),

    # === 异步/网络 ===
    ("twisted", "21.2.0"),
    ("twisted", "20.0.0"),
    ("pyzmq", "22.0.0"),
    ("websockets", "9.0"),
    ("grpcio", "1.38.0"),

    # === 日志/工具 ===
    ("click", "8.0.0"),
    ("click", "7.0.0"),
    ("itsdangerous", "2.0.0"),
    ("itsdangerous", "1.1.0"),
    ("markupsafe", "0.23"),
    ("six", "1.15.0"),
    ("python-dateutil", "2.8.0"),

    # === 安全相关 ===
    ("bleach", "3.3.0"),
    ("bleach", "3.0.0"),
    ("html5lib", "1.1"),
    ("sqlparse", "0.4.0"),

    # === 其他常见包 ===
    ("asgiref", "3.4.0"),
    ("chardet", "4.0.0"),
    ("chardet", "3.0.0"),
    ("idna", "2.10"),
    ("charset-normalizer", "2.0.0"),
    ("pytz", "2021.1"),
    ("sentry-sdk", "1.5.0"),
    ("protobuf", "3.18.0"),
    ("google-api-core", "2.0.0"),
    ("boto3", "1.20.0"),
    ("botocore", "1.23.0"),
    ("requests-toolbelt", "0.9.0"),
    ("uritemplate", "3.0.0"),
    ("djangorestframework", "3.12.0"),
    ("djangorestframework", "3.11.0"),
    ("django-cors-headers", "3.7.0"),
]


def query_osv(package_name, version):
    """Query OSV.dev API for a single package version."""
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": "PyPI"}
    }
    try:
        resp = requests.post(OSV_URL, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"  [ERROR] {package_name}=={version}: {e}")
        return None


def parse_vuln(vuln_data):
    """Parse a single vulnerability entry from OSV.dev response."""
    vuln_id = vuln_data.get("id", "UNKNOWN")
    summary = vuln_data.get("summary", "No summary available")
    details = vuln_data.get("details", "")
    aliases = vuln_data.get("aliases", [])

    # Extract CVSS score
    cvss_score = None
    for sev in vuln_data.get("severity", []):
        if isinstance(sev, dict):
            try:
                s = float(sev.get("score", 0))
                if cvss_score is None or s > cvss_score:
                    cvss_score = s
            except (ValueError, TypeError):
                pass

    # Classify severity
    if cvss_score is not None:
        if cvss_score >= 9.0:
            severity = "critical"
        elif cvss_score >= 7.0:
            severity = "high"
        elif cvss_score >= 4.0:
            severity = "medium"
        else:
            severity = "low"
    else:
        db_spec = vuln_data.get("database_specific", {})
        sev_label = str(db_spec.get("severity", "")).lower()
        if sev_label in ("critical", "high", "medium", "low"):
            severity = sev_label
        elif vuln_id != "UNKNOWN":
            severity = "medium"
        else:
            severity = "unknown"

    # Extract affected info
    affected = {"ranges": [], "fix_versions": [], "ecosystem": "PyPI"}
    for aff in vuln_data.get("affected", []):
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges", []):
            if not isinstance(rng, dict):
                continue
            range_info = {"type": rng.get("type", ""), "introduced": "", "fixed": ""}
            for event in rng.get("events", []):
                if not isinstance(event, dict):
                    continue
                if "introduced" in event:
                    range_info["introduced"] = str(event["introduced"])
                if "fixed" in event:
                    fix_ver = str(event["fixed"])
                    range_info["fixed"] = fix_ver
                    if fix_ver not in affected["fix_versions"]:
                        affected["fix_versions"].append(fix_ver)
            affected["ranges"].append(range_info)

    # Check if actively exploited
    actively_exploited_ids = {
        "CVE-2021-44228", "CVE-2021-45046", "CVE-2020-10199",
        "CVE-2019-1003030", "CVE-2017-5638", "CVE-2014-0160",
        "CVE-2014-6271", "CVE-2023-44487", "CVE-2024-3094",
        "CVE-2021-33503", "CVE-2022-40897", "CVE-2024-22195",
        "GHSA-cph5-m8f7-6h5x", "GHSA-xg73-94fp-g449",
    }
    all_ids = {vuln_id} | set(aliases)
    is_exploited = bool(all_ids & actively_exploited_ids)
    if not is_exploited:
        if any(kw in summary.lower() for kw in ["actively exploited", "in the wild"]):
            is_exploited = True

    # Extract references
    references = []
    for ref in vuln_data.get("references", [])[:5]:
        if isinstance(ref, dict):
            references.append({"type": ref.get("type", "WEB"), "url": ref.get("url", "")})

    # Extract CWEs
    cwes = []
    db_spec = vuln_data.get("database_specific", {})
    if isinstance(db_spec, dict):
        cwe_ids = db_spec.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            cwes = [str(c) for c in cwe_ids]

    return {
        "id": vuln_id,
        "aliases": aliases,
        "summary": summary,
        "details": details[:500] if details else "",
        "cvss_score": cvss_score,
        "severity": severity,
        "cwes": cwes,
        "affected_versions": affected,
        "is_actively_exploited": is_exploited,
        "references": references,
        "published": vuln_data.get("published", ""),
        "modified": vuln_data.get("modified", ""),
    }


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)

    # Load existing cache
    cache = {}
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
        except (json.JSONDecodeError, IOError):
            cache = {}

    total = len(PACKAGES)
    found_vulns = 0
    total_vulns = 0

    print(f"=== Pre-populating vulnerability cache ===")
    print(f"Total packages to query: {total}")
    print(f"Existing cache entries: {len(cache)}")
    print()

    for idx, (pkg, ver) in enumerate(PACKAGES, 1):
        cache_key = f"{pkg.lower()}@{ver}"

        # Skip if already cached with results
        if cache_key in cache and cache[cache_key].get("vulns"):
            print(f"  [{idx}/{total}] {pkg}=={ver} (cached: {len(cache[cache_key]['vulns'])} vulns)")
            found_vulns += 1
            total_vulns += len(cache[cache_key]["vulns"])
            continue

        print(f"  [{idx}/{total}] Querying OSV.dev: {pkg}=={ver}...", end=" ", flush=True)
        data = query_osv(pkg, ver)

        if data is None:
            print("FAILED")
            time.sleep(RATE_LIMIT)
            continue

        vulns = []
        for v in data.get("vulns", []):
            try:
                parsed = parse_vuln(v)
                vulns.append(parsed)
            except Exception as e:
                print(f"parse error: {e}")

        cache[cache_key] = {
            "timestamp": time.time(),
            "vulns": vulns,
            "source": "osv_api",
        }

        if vulns:
            found_vulns += 1
            total_vulns += len(vulns)
            print(f"FOUND {len(vulns)} vulns")
        else:
            print("no vulns")

        # Save cache periodically
        if idx % 10 == 0:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2, ensure_ascii=False)

        time.sleep(RATE_LIMIT)

    # Final save
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

    print()
    print(f"=== Done! ===")
    print(f"Total packages queried: {total}")
    print(f"Packages with vulns: {found_vulns}")
    print(f"Total vulnerabilities cached: {total_vulns}")
    print(f"Cache file: {CACHE_FILE} ({os.path.getsize(CACHE_FILE)} bytes)")


if __name__ == "__main__":
    main()
