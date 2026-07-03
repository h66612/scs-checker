"""
Universal Package Parser Framework
Supports 20+ package/dependency file formats across multiple ecosystems.
"""
import os
import re
import json
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple


def _clean_version(ver_str):
    """Extract a clean semantic version from a version constraint string.

    Preserves pre-release (-alpha) and build metadata (+build) per SemVer spec.
    Strips constraint operators (>=, <=, ==, ~=, ^, >, <) and whitespace.
    """
    if not ver_str:
        return ''
    # Strip constraint operators and whitespace
    ver_str = ver_str.strip().lstrip('>=<~^=! ')
    # Match semver pattern: X.Y.Z[-prerelease][+build]
    m = re.match(r'(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)', ver_str)
    if m:
        return m.group(1)
    # Fallback: just digits and dots
    m = re.match(r'(\d+\.\d+(?:\.\d+)?)', ver_str)
    return m.group(1) if m else ''


# =============================================================================
# Registry
# =============================================================================

_PARSERS = {}


def register_parser(name, extensions, parser_func, ecosystem):
    """Register a parser. parser_func(content: str, filename: str) -> list of {package, version, ecosystem}"""
    _PARSERS[name] = {
        'extensions': extensions,
        'parser': parser_func,
        'ecosystem': ecosystem,
    }


def detect_format(filename, content=''):
    """Auto-detect file format from filename and content."""
    base = os.path.basename(filename).lower()

    # Exact filename matches
    exact = {
        'requirements.txt': 'requirements_txt',
        'requirements.in': 'requirements_txt',
        'pipfile': 'pipfile',
        'pipfile.lock': 'pipfile_lock',
        'pyproject.toml': 'pyproject_toml',
        'setup.py': 'setup_py',
        'setup.cfg': 'setup_cfg',
        'environment.yml': 'conda_env',
        'environment.yaml': 'conda_env',
        'package.json': 'package_json',
        'package-lock.json': 'package_lock',
        'yarn.lock': 'yarn_lock',
        'pnpm-lock.yaml': 'pnpm_lock',
        'pom.xml': 'pom_xml',
        'build.gradle': 'gradle',
        'build.gradle.kts': 'gradle',
        'composer.json': 'composer_json',
        'composer.lock': 'composer_lock',
        'gemfile': 'gemfile',
        'gemfile.lock': 'gemfile_lock',
        'go.mod': 'go_mod',
        'cargo.toml': 'cargo_toml',
        'cargo.lock': 'cargo_lock',
        'pubspec.yaml': 'pubspec_yaml',
        'pubspec.yml': 'pubspec_yaml',
        'package.swift': 'package_swift',
        'dockerfile': 'dockerfile',
        'docker-compose.yml': 'docker_compose',
        'docker-compose.yaml': 'docker_compose',
        'mix.exs': 'mix_exs',
    }

    if base in exact:
        fmt = exact[base]
        if fmt in _PARSERS:
            return fmt

    # Extension-based detection (with content disambiguation for ambiguous extensions)
    _, ext = os.path.splitext(base)
    
    # For ambiguous extensions, check content first
    if ext == '.toml' and content:
        if '[package]' in content and ('[dependencies]' in content or '[dev-dependencies]' in content):
            return 'cargo_toml'
        if '[project]' in content or '[tool.poetry]' in content or '[build-system]' in content:
            return 'pyproject_toml'
        return 'pyproject_toml'  # default for .toml
    elif ext == '.json' and content:
        try:
            d = json.loads(content)
            if 'require' in d and ('require-dev' in d or 'autoload' in d):
                return 'composer_json'
            if 'packages' in d and 'metadata' in d:
                return 'composer_lock'
            if 'bomFormat' in d:
                return 'cyclonedx_json'
            if 'spdxVersion' in d:
                return 'spdx_json'
            if '_meta' in d and 'default' in d:
                return 'pipfile_lock'
            if 'dependencies' in d or 'devDependencies' in d:
                return 'package_json'
            return 'package_json'  # default for .json
        except:
            return 'package_json'
    elif ext == '.lock' and content:
        if '_meta' in content and 'default' in content:
            return 'pipfile_lock'
        if 'packages' in content and 'metadata' in content:
            return 'composer_lock'
        if 'GEM' in content and 'remote:' in content:
            return 'gemfile_lock'
        if '# yarn' in content or content.strip().startswith('#'):
            return 'yarn_lock'
        if '[[package]]' in content and ('name = "' in content or "name = '" in content):
            return 'cargo_lock'
        return 'pipfile_lock'  # default for .lock
    elif ext == '.yaml' or ext == '.yml':
        if content and 'services:' in content and ('image:' in content or 'build:' in content):
            return 'docker_compose'
        if content and 'name:' in content and ('dependencies:' in content or 'dev_dependencies:' in content):
            return 'pubspec_yaml'
        return 'conda_env'  # default for .yml/.yaml
    else:
        # Non-ambiguous extensions
        ext_map = {
            '.txt': 'requirements_txt',
            '.in': 'requirements_txt',
            '.cfg': 'setup_cfg',
            '.xml': 'pom_xml',
            '.gradle': 'gradle',
            '.gradle.kts': 'gradle',
            '.csproj': 'csproj',
            '.swift': 'package_swift',
            '.cabal': 'cabal',
            '.apk': 'apk',
            '.jar': 'jar',
            '.war': 'jar',
            '.whl': 'whl',
        }
        if ext in ext_map:
            fmt = ext_map[ext]
            if fmt in _PARSERS:
                return fmt

    # Content-based heuristics (when filename doesn't match)
    if content:
        first_line = content[:200].strip()
        # JSON-based formats
        if first_line.startswith('{'):
            try:
                d = json.loads(content)
                if 'bomFormat' in d:
                    if d.get('bomFormat') == 'CycloneDX':
                        return 'cyclonedx_json'
                    if d.get('spdxVersion'):
                        return 'spdx_json'
                if 'dependencies' in d and 'devDependencies' in d:
                    return 'package_json'
                if 'name' in d and 'version' in d and 'dependencies' in d:
                    return 'package_json'
                if '_meta' in d and 'default' in d:
                    return 'pipfile_lock'
                if 'packages' in d and 'metadata' in d:
                    return 'composer_lock'
                if 'require' in d and ('require-dev' in d or 'autoload' in d):
                    return 'composer_json'
            except:
                pass
        # Python formats
        # Requirements.txt - detect by package==version pattern
        lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
        req_eq = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*(\[[\w,-]+\])?\s*==\s*[\d]')
        req_any = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*(\[[\w,-]+\])?\s*(==|>=|<=|~=|>|<|===)\s*[\d]')
        eq_count = sum(1 for l in lines if req_eq.match(l))
        any_count = sum(1 for l in lines if req_any.match(l))
        if eq_count >= 1 or any_count >= 2:
            return 'requirements_txt'
        if 'from setuptools import' in content or ('install_requires' in content and 'setup(' in content):
            return 'setup_py'
        if '[packages]' in content or ('[dev-packages]' in content):
            return 'pipfile'
        if '[project]' in content or '[tool.poetry]' in content:
            return 'pyproject_toml'
        # Java formats
        if '<project' in content and ('xmlns="http://maven' in content or '<dependencies>' in content or '<dependency>' in content):
            return 'pom_xml'
        if 'plugins {' in content or 'apply plugin' in content or 'implementation' in content and 'group:' in content:
            return 'gradle'
        # Ruby formats
        if 'source "https://rubygems.org"' in content or (first_line.startswith('source') and 'gem' in content):
            return 'gemfile'
        if 'GEM' in content and 'remote:' in content:
            return 'gemfile_lock'
        # Go formats
        if content.strip().startswith('module '):
            return 'go_mod'
        # Rust formats
        if '[package]' in content and '[dependencies]' in content:
            return 'cargo_toml'
        # Elixir formats
        if 'defmodule' in content and 'Mix.Project' in content:
            return 'mix_exs'
        # Docker formats
        if 'FROM ' in content and ('RUN ' in content or 'COPY ' in content or 'WORKDIR' in content):
            return 'dockerfile'
        if 'services:' in content and ('image:' in content or 'build:' in content):
            return 'docker_compose'
        # Other formats
        if 'name:' in content and 'dependencies:' in content and 'environment:' in content:
            return 'conda_env'
        if 'name:' in content and ('dependencies:' in content or 'dev_dependencies:' in content):
            return 'pubspec_yaml'

    return None


def parse_file(filename, content, fmt=None):
    """Parse a dependency file. Returns list of {package, version, ecosystem}."""
    if not fmt:
        fmt = detect_format(filename, content)
    if not fmt or fmt not in _PARSERS:
        return []
    try:
        return _PARSERS[fmt]['parser'](content, filename)
    except Exception as e:
        print(f"  [!] Parser error ({fmt}): {e}")
        return []


def get_supported_formats():
    """Return list of supported formats with descriptions."""
    return {
        name: {
            'extensions': info['extensions'],
            'ecosystem': info['ecosystem'],
        }
        for name, info in _PARSERS.items()
    }


# =============================================================================
# Python Ecosystem
# =============================================================================

def _parse_requirements_txt(content, filename=''):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        m = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])(?:\[.*?\])?\s*((?:[><=!~]=?\s*[\d.]+\s*(?:,\s*[><=!~]=?\s*[\d.]+\s*)*)?)', line)
        if m:
            name = m.group(1).strip()
            spec = m.group(2).strip() if m.group(2) else ''
            version = ''
            pin = re.match(r'^==\s*([\d][\d.]*)$', spec)
            if pin:
                version = pin.group(1)
            packages.append({'package': name, 'version': version, 'ecosystem': 'PyPI'})
    return packages

register_parser('requirements_txt', ['.txt', '.in'], _parse_requirements_txt, 'PyPI')


def _parse_pyproject_toml(content, filename=''):
    packages = []
    # Extract dependencies from [project] dependencies list
    dep_section = False
    for line in content.splitlines():
        line = line.strip()
        # Simple TOML parsing for dependencies
        if re.match(r'dependencies\s*=\s*\[', line):
            dep_section = True
        if dep_section:
            for m in re.finditer(r'"([^"]+)"', line):
                pkg_str = m.group(1)
                pm = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*(?:[><=!~]+\s*([\d.]+))?', pkg_str)
                if pm:
                    packages.append({'package': pm.group(1), 'version': pm.group(2) or '', 'ecosystem': 'PyPI'})
            if ']' in line:
                dep_section = False

    # Also check [tool.poetry.dependencies]
    poetry_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if '[tool.poetry.dependencies]' in stripped:
            poetry_deps = True
            continue
        if stripped.startswith('[') and poetry_deps:
            poetry_deps = False
            continue
        if poetry_deps and '=' in stripped and not stripped.startswith('#'):
            m = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*=\s*(.+)', stripped)
            if m:
                name = m.group(1).strip()
                if name.lower() == 'python':
                    continue
                ver_str = m.group(2).strip().strip('"').strip("'")
                version = ''
                pm = re.search(r'(\d+\.[\d.]+)', ver_str)
                if pm:
                    version = pm.group(1)
                packages.append({'package': name, 'version': version, 'ecosystem': 'PyPI'})

    return packages

register_parser('pyproject_toml', ['.toml'], _parse_pyproject_toml, 'PyPI')


def _parse_pipfile(content, filename=''):
    packages = []
    in_section = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ('[packages]', '[dev-packages]'):
            in_section = True
            continue
        if stripped.startswith('['):
            in_section = False
            continue
        if in_section and '=' in stripped:
            m = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*=\s*(.+)', stripped)
            if m:
                name = m.group(1).strip()
                ver = m.group(2).strip().strip('"').strip("'")
                version = ''
                if ver == '*':
                    version = ''
                else:
                    pm = re.search(r'(\d+\.[\d.]+)', ver)
                    if pm:
                        version = pm.group(1)
                packages.append({'package': name, 'version': version, 'ecosystem': 'PyPI'})
    return packages

register_parser('pipfile', [], _parse_pipfile, 'PyPI')


def _parse_pipfile_lock(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for section in ('default', 'develop'):
            for name, info in data.get(section, {}).items():
                ver = info.get('version', '')
                if ver.startswith('=='):
                    ver = ver[2:]
                packages.append({'package': name, 'version': ver, 'ecosystem': 'PyPI'})
    except:
        pass
    return packages

register_parser('pipfile_lock', ['.lock'], _parse_pipfile_lock, 'PyPI')


def _parse_setup_py(content, filename=''):
    packages = []
    # Look for install_requires list
    m = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
    if m:
        for pkg_str in re.finditer(r'["\']([^"\']+)["\']', m.group(1)):
            pm = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*(?:[><=!~]+\s*([\d.]+))?', pkg_str.group(1))
            if pm:
                packages.append({'package': pm.group(1), 'version': pm.group(2) or '', 'ecosystem': 'PyPI'})
    return packages

register_parser('setup_py', ['.py'], _parse_setup_py, 'PyPI')


def _parse_setup_cfg(content, filename=''):
    packages = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.lower() in ('install_requires', 'install_requires:'):
            in_deps = True
            continue
        if stripped.startswith('['):
            in_deps = False
            continue
        if in_deps and stripped:
            pm = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]|[a-zA-Z0-9])\s*(?:[><=!~]+\s*([\d.]+))?', stripped)
            if pm:
                packages.append({'package': pm.group(1), 'version': pm.group(2) or '', 'ecosystem': 'PyPI'})
    return packages

register_parser('setup_cfg', ['.cfg'], _parse_setup_cfg, 'PyPI')


def _parse_conda_env(content, filename=''):
    packages = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == 'dependencies:':
            in_deps = True
            continue
        if stripped and not stripped.startswith('-') and not stripped.startswith(' '):
            in_deps = False
            continue
        if in_deps and stripped.startswith('- '):
            pkg_str = stripped[2:].strip()
            if '=' in pkg_str and not pkg_str.startswith('pip'):
                parts = re.split(r'[=<>]+', pkg_str)
                name = parts[0].strip()
                version = parts[1].strip() if len(parts) > 1 else ''
                packages.append({'package': name, 'version': version, 'ecosystem': 'PyPI'})
    return packages

register_parser('conda_env', ['.yml', '.yaml'], _parse_conda_env, 'PyPI')


# =============================================================================
# Node.js Ecosystem
# =============================================================================

def _parse_package_json(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            for name, ver in data.get(section, {}).items():
                clean_ver = _clean_version(ver)
                packages.append({'package': name, 'version': clean_ver, 'ecosystem': 'npm'})
    except:
        pass
    return packages

register_parser('package_json', ['.json'], _parse_package_json, 'npm')


def _parse_package_lock(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        # npm v2/v3 lockfile format
        pkgs = data.get('packages', {})
        for path, info in pkgs.items():
            if not path or path == '':
                continue
            name = info.get('name', '') or (path.split('node_modules/')[-1] if 'node_modules/' in path else path)
            version = info.get('version', '')
            if name:
                packages.append({'package': name, 'version': version, 'ecosystem': 'npm'})
        # Fallback to v1 format
        if not pkgs:
            deps = data.get('dependencies', {})
            for name, info in deps.items():
                version = info.get('version', '')
                packages.append({'package': name, 'version': version, 'ecosystem': 'npm'})
    except:
        pass
    return packages

register_parser('package_lock', ['.json'], _parse_package_lock, 'npm')


def _parse_yarn_lock(content, filename=''):
    packages = []
    current_pkg = ''
    for line in content.splitlines():
        m = re.match(r'^"?([^"@][^"]*)@', line)
        if m:
            current_pkg = m.group(1).strip()
        if line.strip().startswith('version'):
            ver_m = re.match(r'\s*version\s+"([^"]+)"', line)
            if ver_m and current_pkg:
                packages.append({'package': current_pkg, 'version': ver_m.group(1), 'ecosystem': 'npm'})
                current_pkg = ''
    return packages

register_parser('yarn_lock', ['.lock'], _parse_yarn_lock, 'npm')


def _parse_pnpm_lock(content, filename=''):
    packages = []
    in_packages = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('packages:'):
            in_packages = True
            continue
        if in_packages and line.startswith('  ') and '/' in stripped:
            m = re.match(r'\s*/?([^/:\s]+)[@/]([^:\s]+):', line)
            if not m:
                m = re.match(r'\s+/?([^/]+)[@/]([^:]+):', line)
            if m:
                name = m.group(1).strip("'\"")
                version = m.group(2).strip("'\"")
                packages.append({'package': name, 'version': version, 'ecosystem': 'npm'})
        if in_packages and not line.startswith(' ') and stripped and not stripped.startswith('#'):
            in_packages = False
    return packages

register_parser('pnpm_lock', ['.yaml'], _parse_pnpm_lock, 'npm')


# =============================================================================
# Java/Kotlin Ecosystem
# =============================================================================

def _parse_pom_xml(content, filename=''):
    packages = []
    try:
        # Remove XML declaration and ALL namespace-related attributes to avoid "unbound prefix" errors
        # Remove <?xml ...?> declaration
        content_clean = re.sub(r'<\?xml[^>]*\?>', '', content)
        # Remove xmlns, xmlns:xsi, xsi:schemaLocation and any other namespace attrs
        content_clean = re.sub(r'\s+xmlns(?::\w+)?\s*=\s*"[^"]*"', '', content_clean)
        content_clean = re.sub(r'\s+\w+:\w+\s*=\s*"[^"]*"', '', content_clean)
        # Remove any remaining namespace prefixes from tags
        content_clean = re.sub(r'<(/?)[\w]+:', r'<\1', content_clean)

        root = ET.fromstring(content_clean)
        for dep in root.iter('dependency'):
            group_id = (dep.findtext('groupId') or '').strip()
            artifact_id = (dep.findtext('artifactId') or '').strip()
            version = (dep.findtext('version') or '').strip()
            if artifact_id:
                name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                # Skip variable references like ${project.version}
                if version.startswith('$'):
                    version = ''
                packages.append({'package': name, 'version': version, 'ecosystem': 'Maven'})
    except Exception as e:
        print(f"  [!] POM XML parse error: {e}")
    return packages

register_parser('pom_xml', ['.xml'], _parse_pom_xml, 'Maven')


def _parse_gradle(content, filename=''):
    packages = []
    # Match implementation/api/compile/testImplementation dependencies
    patterns = [
        r"(?:implementation|api|compile|testImplementation|runtimeOnly)\s+['\"]([^'\"]+)['\"]",
        r"(?:implementation|api|compile|testImplementation|runtimeOnly)\s*\(\s*['\"]([^'\"]+)['\"]",
    ]
    for pat in patterns:
        for m in re.finditer(pat, content):
            dep = m.group(1).strip()
            parts = dep.split(':')
            if len(parts) >= 2:
                name = f"{parts[0]}:{parts[1]}"
                version = parts[2] if len(parts) > 2 else ''
                packages.append({'package': name, 'version': version, 'ecosystem': 'Maven'})
    return packages

register_parser('gradle', ['.gradle', '.kts'], _parse_gradle, 'Maven')


# =============================================================================
# PHP Ecosystem
# =============================================================================

def _parse_composer_json(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for section in ('require', 'require-dev'):
            for name, ver in data.get(section, {}).items():
                if name == 'php' or name.startswith('ext-'):
                    continue
                clean_ver = _clean_version(ver)
                packages.append({'package': name, 'version': clean_ver, 'ecosystem': 'Packagist'})
    except:
        pass
    return packages

register_parser('composer_json', ['.json'], _parse_composer_json, 'Packagist')


def _parse_composer_lock(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for pkg in data.get('packages', []) + data.get('packages-dev', []):
            name = pkg.get('name', '')
            version = pkg.get('version', '')
            if version.startswith('v'):
                version = version[1:]
            if name:
                packages.append({'package': name, 'version': version, 'ecosystem': 'Packagist'})
    except:
        pass
    return packages

register_parser('composer_lock', ['.lock'], _parse_composer_lock, 'Packagist')


# =============================================================================
# Ruby Ecosystem
# =============================================================================

def _parse_gemfile(content, filename=''):
    packages = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        m = re.match(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]*)['\"])?", stripped)
        if m:
            name = m.group(1)
            version = m.group(2) or ''
            clean_ver = _clean_version(version)
            packages.append({'package': name, 'version': clean_ver, 'ecosystem': 'RubyGems'})
    return packages

register_parser('gemfile', [], _parse_gemfile, 'RubyGems')


def _parse_gemfile_lock(content, filename=''):
    packages = []
    in_specs = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == 'specs:':
            in_specs = True
            continue
        if stripped and not stripped.startswith(' ') and not stripped.startswith('\t'):
            in_specs = False
            continue
        if in_specs:
            m = re.match(r'\s+(\S+)\s+\(([^)]+)\)', line)
            if m:
                packages.append({'package': m.group(1), 'version': m.group(2), 'ecosystem': 'RubyGems'})
    return packages

register_parser('gemfile_lock', ['.lock'], _parse_gemfile_lock, 'RubyGems')


# =============================================================================
# Go Ecosystem
# =============================================================================

def _parse_go_mod(content, filename=''):
    packages = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('require ('):
            in_require = True
            continue
        if stripped == ')' and in_require:
            in_require = False
            continue
        if in_require or stripped.startswith('require '):
            parts = stripped.replace('require ', '').strip().split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1]
                if version.startswith('v'):
                    version = version[1:]
                packages.append({'package': name, 'version': version, 'ecosystem': 'Go'})
    return packages

register_parser('go_mod', ['.mod'], _parse_go_mod, 'Go')


# =============================================================================
# Rust Ecosystem
# =============================================================================

def _parse_cargo_toml(content, filename=''):
    packages = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ('[dependencies]', '[dev-dependencies]', '[build-dependencies]'):
            in_deps = True
            continue
        if stripped.startswith('['):
            in_deps = False
            continue
        if in_deps and '=' in stripped and not stripped.startswith('#'):
            m = re.match(r'([a-zA-Z0-9_-]+)\s*=\s*(.+)', stripped)
            if m:
                name = m.group(1).strip()
                ver_part = m.group(2).strip()
                version = ''
                # Handle "version = "X.Y"" or just "X.Y"
                vm = re.search(r'version\s*=\s*"([^"]+)"', ver_part)
                if vm:
                    version = vm.group(1)
                else:
                    version = ver_part.strip('"').strip("'")
                version = _clean_version(version)
                packages.append({'package': name, 'version': version, 'ecosystem': 'crates.io'})
    return packages

register_parser('cargo_toml', ['.toml'], _parse_cargo_toml, 'crates.io')


def _parse_cargo_lock(content, filename=''):
    packages = []
    current_name = ''
    current_version = ''
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == '[[package]]':
            if current_name and current_version:
                packages.append({'package': current_name, 'version': current_version, 'ecosystem': 'crates.io'})
            current_name = ''
            current_version = ''
        m = re.match(r'name\s*=\s*"([^"]+)"', stripped)
        if m:
            current_name = m.group(1)
        m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
        if m:
            current_version = m.group(1)
    if current_name and current_version:
        packages.append({'package': current_name, 'version': current_version, 'ecosystem': 'crates.io'})
    return packages

register_parser('cargo_lock', ['.lock'], _parse_cargo_lock, 'crates.io')


# =============================================================================
# C# / .NET Ecosystem
# =============================================================================

def _parse_csproj(content, filename=''):
    packages = []
    try:
        content_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', '', content)
        root = ET.fromstring(content_clean)
        for ref in root.iter('PackageReference'):
            name = ref.get('Include', '') or ref.get('include', '')
            version = ref.get('Version', '') or ref.get('version', '')
            if not version:
                ver_el = ref.find('Version')
                if ver_el is not None:
                    version = ver_el.text or ''
            if name:
                packages.append({'package': name, 'version': version, 'ecosystem': 'NuGet'})
    except:
        pass
    return packages

register_parser('csproj', ['.csproj'], _parse_csproj, 'NuGet')


def _parse_packages_config(content, filename=''):
    packages = []
    try:
        root = ET.fromstring(content)
        for pkg in root.iter('package'):
            name = pkg.get('id', '')
            version = pkg.get('version', '')
            if name:
                packages.append({'package': name, 'version': version, 'ecosystem': 'NuGet'})
    except:
        pass
    return packages

register_parser('packages_config', [], _parse_packages_config, 'NuGet')


# =============================================================================
# Dart/Flutter Ecosystem
# =============================================================================

def _parse_pubspec_yaml(content, filename=''):
    packages = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ('dependencies:', 'dev_dependencies:', 'dependency_overrides:'):
            in_deps = True
            continue
        if stripped and not stripped.startswith(' ') and not stripped.startswith('-') and ':' in stripped and not in_deps:
            continue
        if stripped and not stripped.startswith(' ') and stripped.endswith(':') and in_deps:
            in_deps = False
            continue
        if in_deps and ':' in stripped and not stripped.startswith('#'):
            m = re.match(r'\s+([a-zA-Z0-9_]+):\s*(.*)', line)
            if m:
                name = m.group(1).strip()
                ver_part = m.group(2).strip()
                version = ''
                if ver_part and ver_part != '^' and not ver_part.startswith('{'):
                    version = _clean_version(ver_part)
                packages.append({'package': name, 'version': version, 'ecosystem': 'Pub'})
    return packages

register_parser('pubspec_yaml', ['.yaml', '.yml'], _parse_pubspec_yaml, 'Pub')


# =============================================================================
# Swift Ecosystem
# =============================================================================

def _parse_package_swift(content, filename=''):
    packages = []
    # Match .package(url: "...", from: "X.Y.Z")
    for m in re.finditer(r'\.package\s*\(\s*(?:url|name)\s*:\s*"([^"]+)"\s*,\s*(?:from|\.exact|\.upToNextMajor)\s*:\s*"([^"]+)"', content):
        url = m.group(1)
        version = m.group(2)
        # Extract package name from URL
        name = url.rstrip('/').split('/')[-1].replace('.git', '')
        packages.append({'package': name, 'version': version, 'ecosystem': 'Swift'})
    return packages

register_parser('package_swift', ['.swift'], _parse_package_swift, 'Swift')


# =============================================================================
# Haskell Ecosystem
# =============================================================================

def _parse_cabal(content, filename=''):
    packages = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith('build-depends:'):
            in_deps = True
            deps_str = stripped.split(':', 1)[1].strip()
        elif in_deps and (stripped.startswith(',') or (stripped and stripped[0].isalpha() and not stripped.endswith(':'))):
            deps_str = stripped
        else:
            in_deps = False
            continue
        if in_deps or 'build-depends' in stripped.lower():
            if 'build-depends' in stripped.lower():
                deps_str = stripped.split(':', 1)[1] if ':' in stripped else ''
            for part in re.split(r'[,&&]', deps_str):
                part = part.strip()
                m = re.match(r'([a-zA-Z0-9-]+)\s*(?:[><=!]+\s*([\d.]+))?', part)
                if m:
                    name = m.group(1).strip()
                    version = m.group(2) or ''
                    if name and name.lower() != 'base':
                        packages.append({'package': name, 'version': version, 'ecosystem': 'Hackage'})
    return packages

register_parser('cabal', ['.cabal'], _parse_cabal, 'Hackage')


# =============================================================================
# Docker / Container Analysis
# =============================================================================

def _parse_dockerfile(content, filename=''):
    packages = []
    # Join line continuations (backslash at end of line)
    lines = content.replace('\\\n', ' ').splitlines()
    for line in lines:
        stripped = line.strip()
        # Skip comment lines and empty lines
        if not stripped or stripped.startswith('#'):
            continue
        # pip install
        for m in re.finditer(r'pip[3]?\s+install\s+(.+?)(?:\s*&&|\s*$)', stripped):
            for pkg in re.finditer(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9])(?:==([\d.]+))?', m.group(1)):
                if pkg.group(1) not in ('--no-cache-dir', '--upgrade', '-r', '-U', '--no-cache', '-q', '--quiet'):
                    packages.append({'package': pkg.group(1), 'version': pkg.group(2) or '', 'ecosystem': 'PyPI'})
        # npm install
        for m in re.finditer(r'npm\s+install\s+(.+?)(?:\s*&&|\s*$)', stripped):
            for pkg in re.finditer(r'([@a-zA-Z0-9][-a-zA-Z0-9_./]*)(?:@([\d.]+))?', m.group(1)):
                name = pkg.group(1)
                if name not in ('--save', '--save-dev', '-g', '-D', '--production', '--no-save'):
                    packages.append({'package': name, 'version': pkg.group(2) or '', 'ecosystem': 'npm'})
        # apt-get install (just note the packages)
        for m in re.finditer(r'apt-get\s+install\s+(?:-y\s+)?(.+?)(?:\s*&&|\s*$)', stripped):
            for pkg in m.group(1).split():
                if not pkg.startswith('-') and pkg not in ('&&', '|'):
                    packages.append({'package': pkg, 'version': '', 'ecosystem': 'Debian'})
        # apk add
        for m in re.finditer(r'apk\s+add\s+(?:--no-cache\s+)?(.+?)(?:\s*&&|\s*$)', stripped):
            for pkg in m.group(1).split():
                if not pkg.startswith('-'):
                    packages.append({'package': pkg, 'version': '', 'ecosystem': 'Alpine'})
    return packages

register_parser('dockerfile', [], _parse_dockerfile, 'Docker')


def _parse_docker_compose(content, filename=''):
    packages = []
    # Extract images for container scanning reference
    for m in re.finditer(r'image:\s*([^\s#]+)', content):
        image = m.group(1).strip().strip('"').strip("'")
        parts = image.split(':')
        name = parts[0]
        version = parts[1] if len(parts) > 1 else 'latest'
        packages.append({'package': name, 'version': version, 'ecosystem': 'Docker'})
    return packages

register_parser('docker_compose', ['.yml', '.yaml'], _parse_docker_compose, 'Docker')


# =============================================================================
# Elixir (Hex) Ecosystem
# =============================================================================

def _parse_mix_exs(content, filename=''):
    """Parse Elixir mix.exs dependency file.
    Extracts {:package_name, "version"} and {:package_name, "~> version"} tuples.
    """
    packages = []
    # Match patterns like {:phoenix, "~> 1.4.0"} or {:plug, ">= 1.0.0"}
    # Also match {:package_name, github: ...} (skip these, no version)
    for m in re.finditer(r'\{:(\w[\w.]*)\s*,\s*"([^"]+)"', content):
        name = m.group(1).strip()
        version = _clean_version(m.group(2).strip())
        if name and version:
            packages.append({'package': name, 'version': version, 'ecosystem': 'Hex'})
    # Also match {:package_name, ~r"version"} pattern
    for m in re.finditer(r'\{:(\w[\w.]*)\s*,\s*~r"([^"]+)"', content):
        name = m.group(1).strip()
        version = _clean_version(m.group(2).strip())
        if name and version:
            packages.append({'package': name, 'version': version, 'ecosystem': 'Hex'})
    return packages

register_parser('mix_exs', [], _parse_mix_exs, 'Hex')


# =============================================================================
# SBOM Import (CycloneDX / SPDX)
# =============================================================================

def _parse_cyclonedx_json(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for comp in data.get('components', []):
            name = comp.get('name', '')
            version = comp.get('version', '')
            purl = comp.get('purl', '')
            ecosystem = 'Unknown'
            if purl:
                if 'pkg:pypi' in purl:
                    ecosystem = 'PyPI'
                elif 'pkg:npm' in purl:
                    ecosystem = 'npm'
                elif 'pkg:maven' in purl:
                    ecosystem = 'Maven'
                elif 'pkg:gem' in purl:
                    ecosystem = 'RubyGems'
                elif 'pkg:golang' in purl:
                    ecosystem = 'Go'
                elif 'pkg:cargo' in purl:
                    ecosystem = 'crates.io'
                elif 'pkg:nuget' in purl:
                    ecosystem = 'NuGet'
            packages.append({'package': name, 'version': version, 'ecosystem': ecosystem})
    except:
        pass
    return packages

register_parser('cyclonedx_json', ['.json'], _parse_cyclonedx_json, 'SBOM')


def _parse_spdx_json(content, filename=''):
    packages = []
    try:
        data = json.loads(content)
        for pkg in data.get('packages', []):
            name = pkg.get('name', '')
            version = pkg.get('versionInfo', '')
            packages.append({'package': name, 'version': version, 'ecosystem': 'SPDX'})
    except:
        pass
    return packages

register_parser('spdx_json', ['.json'], _parse_spdx_json, 'SBOM')


# =============================================================================
# Binary Analysis (APK, JAR, WHL)
# =============================================================================

def _parse_apk(content, filename=''):
    """Parse APK file to extract Java/Kotlin libraries."""
    packages = []
    try:
        import zipfile
        # content is the raw bytes/path for binary files
        # For APK, we need the actual file path
        apk_path = filename
        if not os.path.exists(apk_path):
            return packages
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # Check classes.dex for library references
            dex_files = [f for f in zf.namelist() if f.endswith('.dex')]
            # Check for known library patterns in resources
            for name in zf.namelist():
                # Android support library
                if 'android/support/' in name or 'androidx/' in name:
                    parts = name.split('/')
                    if len(parts) >= 3:
                        lib = '/'.join(parts[:3])
                        packages.append({'package': lib, 'version': '', 'ecosystem': 'Maven'})
                # OkHttp, Retrofit, Gson etc.
                for lib_name in ('okhttp', 'retrofit', 'gson', 'glide', 'picasso', 'rxjava', 'dagger'):
                    if f'/{lib_name}/' in name.lower():
                        packages.append({'package': lib_name, 'version': '', 'ecosystem': 'Maven'})
            # Try to read AndroidManifest.xml for package info
            if 'AndroidManifest.xml' in zf.namelist():
                pass  # Binary XML, needs special parsing
            # Try to read META-INF for library metadata
            for name in zf.namelist():
                if name.startswith('META-INF/') and name.endswith('.pom'):
                    pom_content = zf.read(name).decode('utf-8', errors='ignore')
                    packages.extend(_parse_pom_xml(pom_content, name))
        # Deduplicate
        seen = set()
        unique = []
        for p in packages:
            key = (p['package'], p['version'])
            if key not in seen:
                seen.add(key)
                unique.append(p)
        packages = unique
    except Exception as e:
        print(f"  [!] APK parse error: {e}")
    return packages

register_parser('apk', ['.apk'], _parse_apk, 'Maven')


def _parse_jar(content, filename=''):
    """Parse JAR/WAR file to extract Maven dependencies."""
    packages = []
    try:
        jar_path = filename
        if not os.path.exists(jar_path):
            return packages
        with zipfile.ZipFile(jar_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith('META-INF/maven/') and name.endswith('/pom.xml'):
                    pom_content = zf.read(name).decode('utf-8', errors='ignore')
                    packages.extend(_parse_pom_xml(pom_content, name))
                # Also check for pom.properties
                if name.endswith('/pom.properties'):
                    props = zf.read(name).decode('utf-8', errors='ignore')
                    group = ''
                    artifact = ''
                    version = ''
                    for line in props.splitlines():
                        if line.startswith('groupId='):
                            group = line.split('=', 1)[1].strip()
                        elif line.startswith('artifactId='):
                            artifact = line.split('=', 1)[1].strip()
                        elif line.startswith('version='):
                            version = line.split('=', 1)[1].strip()
                    if artifact:
                        name_str = f"{group}:{artifact}" if group else artifact
                        packages.append({'package': name_str, 'version': version, 'ecosystem': 'Maven'})
    except Exception as e:
        print(f"  [!] JAR parse error: {e}")
    return packages

register_parser('jar', ['.jar', '.war'], _parse_jar, 'Maven')


def _parse_whl(content, filename=''):
    """Parse Python wheel (.whl) file."""
    packages = []
    try:
        whl_path = filename
        if not os.path.exists(whl_path):
            return packages
        with zipfile.ZipFile(whl_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.dist-info/METADATA'):
                    metadata = zf.read(name).decode('utf-8', errors='ignore')
                    pkg_name = ''
                    pkg_version = ''
                    requires = []
                    for line in metadata.splitlines():
                        if line.startswith('Name: '):
                            pkg_name = line[6:].strip()
                        elif line.startswith('Version: '):
                            pkg_version = line[9:].strip()
                        elif line.startswith('Requires-Dist: '):
                            req = line[15:].strip()
                            rm = re.match(r'([a-zA-Z0-9][-a-zA-Z0-9_.]*)', req)
                            if rm and '; extra ==' not in req:
                                requires.append(rm.group(1).lower())
                    if pkg_name:
                        packages.append({'package': pkg_name, 'version': pkg_version, 'ecosystem': 'PyPI'})
                    for r in requires:
                        packages.append({'package': r, 'version': '', 'ecosystem': 'PyPI'})
                    break
    except Exception as e:
        print(f"  [!] WHL parse error: {e}")
    return packages

register_parser('whl', ['.whl'], _parse_whl, 'PyPI')


# =============================================================================
# Summary
# =============================================================================
"""
Supported formats (25+):
  Python:    requirements.txt, pyproject.toml, Pipfile, Pipfile.lock, setup.py, setup.cfg, environment.yml
  Node.js:   package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
  Java:      pom.xml, build.gradle
  PHP:       composer.json, composer.lock
  Ruby:      Gemfile, Gemfile.lock
  Go:        go.mod
  Rust:      Cargo.toml, Cargo.lock
  C#/.NET:   *.csproj, packages.config
  Dart:      pubspec.yaml
  Swift:     Package.swift
  Haskell:   *.cabal
  Docker:    Dockerfile, docker-compose.yml
  SBOM:      CycloneDX JSON, SPDX JSON
  Binary:    APK, JAR/WAR, WHL
"""
