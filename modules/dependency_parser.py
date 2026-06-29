"""
依赖解析模块 - Dependency Parser Module (v2 - Optimized)

解析 requirements.txt 文件，使用 PyPI API 解析版本约束，
构建完整的依赖树（含间接依赖）。

性能优化：
- 内存缓存避免重复 API 调用
- requests.Session 连接复用
- 传递依赖发现时收集 deps+info，构建依赖树时直接复用
- 支持进度回调 (progress_callback)
"""
import re
import time
import requests
import json
from typing import Dict, List, Optional, Tuple, Callable


PYPI_API = "https://pypi.org/pypi"


def parse_requirements_txt(filepath: str) -> List[Dict[str, str]]:
    """Parse requirements.txt file and return list of direct dependencies."""
    packages = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(
                r"([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])"
                r"(?:\[.*?\])?"
                r"\s*((?:[><=!~]=?\s*[\d.]+\s*(?:,\s*[><=!~]=?\s*[\d.]+\s*)*)?)",
                line,
            )
            if match:
                name = match.group(1).strip()
                version_spec = match.group(2).strip() if match.group(2) else ""
                packages.append({"name": name, "version_spec": version_spec, "line": line})
    return packages


def _parse_version_tuple(v: str) -> Tuple:
    """Parse a version string into a comparable tuple."""
    parts = []
    for part in v.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _version_matches_spec(version: str, spec: str) -> bool:
    """Check if a version matches a version specifier string."""
    if not spec:
        return True
    ver = _parse_version_tuple(version)
    for constraint in spec.split(","):
        constraint = constraint.strip()
        if not constraint:
            continue
        match = re.match(r"([><=!~]+)\s*([\d][\d.]*)", constraint)
        if not match:
            continue
        op = match.group(1)
        target = _parse_version_tuple(match.group(2))
        if op == "==" and ver != target:
            return False
        elif op == "!=" and ver == target:
            return False
        elif op == ">=" and ver < target:
            return False
        elif op == "<=" and ver > target:
            return False
        elif op == ">" and ver <= target:
            return False
        elif op == "<" and ver >= target:
            return False
        elif op == "~=":
            if ver < target:
                return False
            if len(target) >= 2:
                upper = list(target[:-1])
                upper[-1] += 1
                if ver >= tuple(upper):
                    return False
    return True


# --- Cached PyPI API layer ---

_pypi_cache = {}  # key: (name, version) -> full JSON data
_session = requests.Session()
_session.headers.update({"Accept": "application/json"})
_adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10)
_session.mount("https://", _adapter)


def _fetch_pypi(name: str, version: str = "") -> Optional[Dict]:
    """Fetch package data from PyPI with in-memory caching."""
    cache_key = (name.lower(), version or "__latest__")
    if cache_key in _pypi_cache:
        return _pypi_cache[cache_key]
    try:
        if version:
            url = f"{PYPI_API}/{name}/{version}/json"
        else:
            url = f"{PYPI_API}/{name}/json"
        resp = _session.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        _pypi_cache[cache_key] = data
        return data
    except Exception:
        return None


def resolve_package_version(name: str, version_spec: str) -> Optional[str]:
    """Resolve the best version for a package using PyPI API."""
    pin_match = re.match(r"^==\s*([\d][\d.]*)$", version_spec.strip())
    if pin_match:
        return pin_match.group(1)

    data = _fetch_pypi(name)
    if not data:
        return None

    if not version_spec:
        info_version = data.get("info", {}).get("version", "")
        return info_version if info_version else None

    releases = data.get("releases", {})
    matching = []
    for ver_str, files in releases.items():
        if any(c in ver_str for c in ("a", "b", "rc", "dev", "post")):
            continue
        if not files:
            continue
        if _version_matches_spec(ver_str, version_spec):
            matching.append(ver_str)

    if matching:
        matching.sort(key=_parse_version_tuple, reverse=True)
        return matching[0]

    return data.get("info", {}).get("version", "")


def _extract_deps_from_data(data: Dict) -> List[str]:
    """Extract dependency names from PyPI API response data."""
    requires_dist = data.get("info", {}).get("requires_dist", []) or []
    deps = []
    for req in requires_dist:
        if "; extra ==" in req:
            continue
        dep_match = re.match(r"([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])", req)
        if dep_match:
            dep_name = dep_match.group(1).lower()
            if dep_name not in deps:
                deps.append(dep_name)
    return deps


def _extract_info_from_data(data: Dict, name: str, version: str) -> Dict[str, str]:
    """Extract package info from PyPI API response data."""
    info = data.get("info", {})
    return {
        "name": info.get("name", name),
        "version": info.get("version", version),
        "summary": info.get("summary", ""),
        "license": info.get("license", "Unknown") or "Unknown",
        "homepage": info.get("home_page", "") or info.get("project_url", ""),
    }


def parse_and_resolve(
    requirements_path: str,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> Tuple[Dict, List[Dict], Dict[str, str]]:
    """Main entry: parse requirements.txt and resolve full dependency tree.

    progress_callback(percent, message) is called with progress updates.

    Returns: (dependency_tree, direct_packages, resolved_packages_dict)
    """
    def _report(pct, msg):
        if progress_callback:
            progress_callback(pct, msg)

    _pypi_cache.clear()  # fresh cache per scan

    # Step 1: Parse requirements.txt
    _report(5, "Parsing requirements.txt...")
    direct_packages = parse_requirements_txt(requirements_path)
    print(f"      Found {len(direct_packages)} direct dependencies")

    # Step 2: Resolve versions for direct packages
    _report(8, "Resolving package versions...")
    resolved: Dict[str, str] = {}
    pkg_deps: Dict[str, List[str]] = {}   # name_lower -> [dep_names]
    pkg_info: Dict[str, Dict[str, str]] = {}  # name_lower -> info dict

    total_direct = len(direct_packages)
    for i, pkg in enumerate(direct_packages, 1):
        name = pkg["name"]
        spec = pkg["version_spec"]
        version = resolve_package_version(name, spec)
        if version:
            resolved[name.lower()] = version
        _report(8 + int(12 * i / total_direct), f"Resolving {name}...")

    # Step 3: Discover transitive dependencies (BFS)
    _report(20, "Discovering transitive dependencies...")
    to_resolve = list(resolved.items())
    seen = set(resolved.keys())
    bfs_done = 0

    while to_resolve:
        name, version = to_resolve.pop(0)
        data = _fetch_pypi(name, version)
        if data:
            deps = _extract_deps_from_data(data)
            pkg_deps[name] = deps
            pkg_info[name] = _extract_info_from_data(data, name, version)
        else:
            pkg_deps[name] = []
            pkg_info[name] = {"name": name, "version": version, "summary": "", "license": "Unknown", "homepage": ""}

        for dep in pkg_deps.get(name, []):
            dep_lower = dep.lower()
            if dep_lower not in seen:
                seen.add(dep_lower)
                dep_version = resolve_package_version(dep, "")
                if dep_version:
                    resolved[dep_lower] = dep_version
                    to_resolve.append((dep_lower, dep_version))

        bfs_done += 1
        total_est = max(bfs_done, len(seen))
        pct = min(55, 20 + int(35 * bfs_done / total_est))
        _report(pct, f"Resolving dependencies ({bfs_done} packages processed, {len(resolved)} total)...")

    print(f"      Total resolved: {len(resolved)} packages")
    _report(55, f"Resolved {len(resolved)} packages. Building dependency tree...")

    # Step 4: Build dependency tree (no API calls - uses cached data)
    tree = _build_tree_from_cache(direct_packages, resolved, pkg_deps, pkg_info)
    _report(60, "Dependency tree built.")

    return tree, direct_packages, resolved


def _build_tree_from_cache(
    direct_packages: List[Dict[str, str]],
    resolved_packages: Dict[str, str],
    pkg_deps: Dict[str, List[str]],
    pkg_info: Dict[str, Dict[str, str]],
) -> Dict:
    """Build dependency tree from pre-collected data (no API calls)."""
    def make_node(pkg_name: str, visited: set) -> Dict:
        version = resolved_packages.get(pkg_name, "unknown")
        info = pkg_info.get(pkg_name, {})
        node = {
            "name": pkg_name,
            "version": version,
            "requires": pkg_deps.get(pkg_name, []),
            "license": info.get("license", "Unknown"),
            "homepage": info.get("homepage", ""),
            "summary": info.get("summary", ""),
            "children": [],
        }
        if pkg_name not in visited:
            visited_copy = visited | {pkg_name}
            for dep in pkg_deps.get(pkg_name, []):
                dep_lower = dep.lower()
                if dep_lower in resolved_packages:
                    child = make_node(dep_lower, visited_copy)
                    node["children"].append(child)
        return node

    root_children = []
    for pkg in direct_packages:
        name_lower = pkg["name"].lower()
        if name_lower in resolved_packages:
            child = make_node(name_lower, set())
            root_children.append(child)

    return {
        "name": "requirements.txt",
        "version": "",
        "children": root_children,
        "total_packages": len(resolved_packages),
        "direct_count": len(direct_packages),
    }


def format_tree_text(node: Dict, prefix: str = "", is_last: bool = True, is_root: bool = True) -> str:
    """Format dependency tree as readable text."""
    lines = []
    if is_root:
        lines.append(f"{node['name']} ({node.get('total_packages', '?')} packages total)")
    else:
        connector = "└── " if is_last else "├── "
        version = f"=={node['version']}" if node.get("version") else ""
        lines.append(f"{prefix}{connector}{node['name']}{version}")

    child_prefix = prefix
    if not is_root:
        child_prefix += "    " if is_last else "│   "

    children = node.get("children", [])
    for i, child in enumerate(children):
        is_child_last = (i == len(children) - 1)
        lines.append(format_tree_text(child, child_prefix, is_child_last, is_root=False))

    return "\n".join(lines)
