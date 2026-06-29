#!/usr/bin/env python3
"""
SCS Checker - Vulnerability Remediation Module
Provides fix suggestions, whitelist management, and batch fix script generation.
"""
import json
import os
from datetime import datetime


def get_fix_suggestions(scan_data):
    """Extract fix suggestions from scan data.
    Returns list of {package, current_version, suggested_version, vuln_ids, severity}.
    """
    suggestions = []
    packages = scan_data.get('packages', [])

    for pkg in packages:
        if pkg.get('vuln_count', 0) == 0:
            continue

        fix_version = None
        vuln_ids = []
        max_severity = 'low'

        for vuln in pkg.get('vulnerabilities', []):
            vuln_ids.append(vuln.get('id', ''))
            sev = vuln.get('severity', 'low')
            if sev == 'critical':
                max_severity = 'critical'
            elif sev == 'high' and max_severity != 'critical':
                max_severity = 'high'
            elif sev == 'medium' and max_severity not in ('critical', 'high'):
                max_severity = 'medium'

            # Extract fix version from affected versions
            affected = vuln.get('affected_versions', {})
            fixes = affected.get('fix_versions', []) if affected else []
            if fixes:
                fix_version = fixes[0]

        if fix_version and fix_version != pkg.get('version', ''):
            suggestions.append({
                'package': pkg['package'],
                'current_version': pkg.get('version', 'unknown'),
                'suggested_version': fix_version,
                'vuln_ids': vuln_ids,
                'vuln_count': len(vuln_ids),
                'severity': max_severity,
            })

    # Sort by severity (critical first)
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    suggestions.sort(key=lambda x: sev_order.get(x['severity'], 4))
    return suggestions


def generate_fix_script(suggestions, ecosystem='PyPI'):
    """Generate a batch fix script (shell script for pip upgrade)."""
    lines = [
        '#!/bin/bash',
        '# SCS Checker - Auto-Generated Vulnerability Fix Script',
        f'# Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'# Ecosystem: {ecosystem}',
        f'# Total packages to fix: {len(suggestions)}',
        '',
        'set -e',
        'echo "========================================"',
        'echo "  SCS Checker - Vulnerability Fix Script"',
        'echo "========================================"',
        '',
    ]

    for s in suggestions:
        if ecosystem == 'PyPI':
            lines.append(f'# {s["package"]}: {s["vuln_count"]} vulnerabilities ({s["severity"]})')
            lines.append(f'pip install --upgrade {s["package"]}=={s["suggested_version"]}')
            lines.append('')
        elif ecosystem == 'npm':
            lines.append(f'npm install {s["package"]}@{s["suggested_version"]}')
            lines.append('')

    lines.append('echo "========================================"')
    lines.append('echo "  Fix script completed. Re-run scan to verify."')
    lines.append('echo "========================================"')

    return '\n'.join(lines)


def generate_requirements_fixed(suggestions, original_content):
    """Generate a fixed requirements.txt with updated versions."""
    lines = original_content.strip().split('\n')
    fix_map = {s['package'].lower(): s['suggested_version'] for s in suggestions}

    fixed_lines = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            fixed_lines.append(line)
            continue
        # Parse package name
        for sep in ['>=', '<=', '==', '~=', '!=', '>', '<', '=']:
            if sep in line:
                parts = line.split(sep, 1)
                pkg_name = parts[0].strip().lower()
                if pkg_name in fix_map:
                    fixed_lines.append(f'{parts[0].strip()}=={fix_map[pkg_name]}  # Fixed: was {line}')
                else:
                    fixed_lines.append(line)
                break
        else:
            # No version specifier
            if line.lower() in fix_map:
                fixed_lines.append(f'{line}=={fix_map[line.lower()]}  # Fixed: added version')
            else:
                fixed_lines.append(line)

    return '\n'.join(fixed_lines)


def init_remediation_tables(conn):
    """Create remediation-related tables."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            package_name TEXT NOT NULL,
            vuln_id TEXT NOT NULL,
            reason TEXT DEFAULT '',
            status TEXT DEFAULT 'ignored',
            created_at TEXT NOT NULL,
            UNIQUE(scan_id, package_name, vuln_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS remediation_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            package_name TEXT NOT NULL,
            action_type TEXT DEFAULT 'upgrade',
            old_version TEXT,
            new_version TEXT,
            vuln_ids TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT NOT NULL
        )
    ''')
