"""Configuration for SCS Checker - Supply Chain Security Detection Tool"""
import os

# --- API Configuration ---
OSV_API_BASE = "https://api.osv.dev/v1"
OSV_QUERY_ENDPOINT = f"{OSV_API_BASE}/query"
OSV_VULN_ENDPOINT = f"{OSV_API_BASE}/vulns"
API_RATE_LIMIT_DELAY = 0.35  # seconds between API calls (~3 req/s)
API_TIMEOUT = 30  # HTTP timeout in seconds
MAX_RETRIES = 3  # max retries on API failure

# --- Severity Thresholds (CVSS v3) ---
SEVERITY_HIGH_MIN = 7.0
SEVERITY_MEDIUM_MIN = 4.0

# --- Paths ---
CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cache")

# --- Tool Info ---
TOOL_NAME = "SCS Checker"
TOOL_VERSION = "1.0.0"
TOOL_DESCRIPTION = "开源软件供应链安全检测工具"
