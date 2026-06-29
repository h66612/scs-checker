#!/usr/bin/env python3
"""
SCS Checker - Web Application
Interactive Supply Chain Security Detection Platform

A Flask-based web application that provides:
- Interactive requirements.txt input and scanning
- Real-time scan progress tracking
- Visual vulnerability dashboard with charts
- Detection history with timestamps and severity records
- Export functionality (HTML, JSON, SBOM)
"""
import sys
import os
import json
import time
import threading
import sqlite3
import tempfile
import re
from datetime import datetime, timedelta

# Add project root to path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

# 北京时间 (UTC+8) - PythonAnywhere 服务器默认 UTC
def now_beijing():
    """Return current time in Beijing timezone (UTC+8)."""
    return datetime.utcnow() + timedelta(hours=8)

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session

app = Flask(__name__,
            template_folder=os.path.join(PROJECT_DIR, 'templates'),
            static_folder=os.path.join(PROJECT_DIR, 'static'))
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'scs-checker-secret-2026')

# Import extension modules
from modules.auth import (
    hash_password, verify_password, login_required, admin_required,
    get_current_user, log_audit, init_auth_tables
)
from modules.remediation import (
    get_fix_suggestions, generate_fix_script, generate_requirements_fixed,
    init_remediation_tables
)
from modules.exports import export_excel, export_word, export_pdf_html
from modules.knowledge import (
    init_kb_tables, search_kb, CVE_KNOWLEDGE_BASE,
    COMPLIANCE_STANDARDS, run_compliance_check, check_alert_rules
)

# Database setup - use data/ subdirectory for persistent disk support on Render
DATA_DIR = os.path.join(PROJECT_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, 'scans.db')

# Progress tracking for active scans
scan_progress = {}  # task_id -> {status, phase, progress, message, error, scan_id}


def get_db():
    """Get a SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the database with required tables."""
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_name TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            total_packages INTEGER DEFAULT 0,
            vulnerable_packages INTEGER DEFAULT 0,
            total_vulnerabilities INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            requirements_content TEXT,
            scan_data TEXT,
            status TEXT DEFAULT 'completed'
        )
    ''')
    # Initialize extension tables
    init_auth_tables(conn)
    init_remediation_tables(conn)
    init_kb_tables(conn)
    conn.commit()
    conn.close()


# Ensure DB tables exist on module import (needed for WSGI deployment)
init_db()


def run_scan_task(task_id, file_content, project_name, filename='requirements.txt', file_format=None):
    """Run the actual scan in a background thread.
    Uses the universal parser framework to support 25+ file formats.
    """
    progress = scan_progress[task_id]
    try:
        # Phase 0: Parse the input file using the universal parser
        from parsers import parse_file, detect_format
        from modules.dependency_parser import (
            parse_and_resolve, format_tree_text,
            resolve_package_version, _fetch_pypi,
            _extract_deps_from_data, _extract_info_from_data,
            _build_tree_from_cache
        )

        progress['message'] = f'Detecting format: {filename}...'
        progress['progress'] = 3

        # Detect and parse
        fmt = file_format or detect_format(filename, file_content)
        if fmt:
            progress['message'] = f'Parsing {fmt} file...'
            parsed_packages = parse_file(filename, file_content, fmt)
        else:
            # Fallback to requirements.txt parser
            parsed_packages = parse_file(filename, file_content, 'requirements_txt')

        progress['progress'] = 5
        progress['message'] = f'Found {len(parsed_packages)} packages in file'

        if not parsed_packages:
            progress['status'] = 'error'
            progress['error'] = f'No packages found in file. Format detected: {fmt}'
            return

        # Phase 1: Resolve dependencies (for PyPI ecosystem packages)
        pypi_packages = [p for p in parsed_packages if p.get('ecosystem', 'PyPI') == 'PyPI']
        non_pypi_packages = [p for p in parsed_packages if p.get('ecosystem', 'PyPI') != 'PyPI']

        # Build requirements.txt-like content for PyPI resolution
        req_lines = []
        for p in pypi_packages:
            name = p['package']
            ver = p.get('version', '')
            req_lines.append(f"{name}=={ver}" if ver else name)

        resolved_packages = {}

        # Only run parse_and_resolve if there are PyPI packages
        if req_lines:
            # Write temp file for parse_and_resolve
            tmp_file = os.path.join(tempfile.gettempdir(), f'scs_scan_{task_id}.txt')
            with open(tmp_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(req_lines))

            def _dep_progress(pct, msg):
                progress['progress'] = pct
                progress['message'] = msg
                progress['phase'] = 1

            dep_tree, direct_packages, resolved_packages = parse_and_resolve(
                tmp_file, progress_callback=_dep_progress
            )

            # Clean up temp file
            try:
                os.remove(tmp_file)
            except:
                pass
        else:
            # No PyPI packages - create minimal dep_tree
            dep_tree = {'name': filename, 'version': '', 'children': [], 'total_packages': 0, 'direct_count': 0}
            direct_packages = []
            progress['progress'] = 55
            progress['message'] = f'No PyPI packages to resolve. {len(non_pypi_packages)} non-PyPI packages found.'

        if not resolved_packages and not non_pypi_packages:
            progress['status'] = 'error'
            progress['error'] = 'No packages resolved. Check your input file.'
            return

        # For non-PyPI packages, add them to resolved with their ecosystem info
        non_pypi_info = {}  # name -> {version, ecosystem}
        for p in non_pypi_packages:
            name = p['package'].lower()
            ver = p.get('version', '')
            eco = p.get('ecosystem', 'Unknown')
            if name not in resolved_packages:
                if ver:
                    resolved_packages[name] = ver
                non_pypi_info[name] = {'version': ver, 'ecosystem': eco}

        progress['progress'] = 60
        progress['message'] = f'Resolved {len(resolved_packages)} packages. Scanning for vulnerabilities...'

        # Phase 2: Scan for vulnerabilities (ALL ecosystems via OSV.dev)
        progress['phase'] = 2
        from modules.vulnerability_checker import VulnerabilityChecker
        cache_dir = os.path.join(PROJECT_DIR, 'cache')
        os.makedirs(cache_dir, exist_ok=True)
        checker = VulnerabilityChecker(cache_dir=cache_dir, rate_limit_delay=0.35)

        # Build unified package list with ecosystem info for multi-ecosystem scanning
        all_packages_for_check = []

        # Add PyPI packages (from resolved packages, excluding non-PyPI ones)
        pypi_resolved = {k: v for k, v in resolved_packages.items()
                        if k not in non_pypi_info}
        for name, version in pypi_resolved.items():
            all_packages_for_check.append({
                'package': name,
                'version': version,
                'ecosystem': 'PyPI',
            })

        # Add non-PyPI packages with their ecosystem
        for name, info in non_pypi_info.items():
            all_packages_for_check.append({
                'package': name,
                'version': info['version'],
                'ecosystem': info['ecosystem'],
            })

        progress['message'] = f'Scanning {len(all_packages_for_check)} packages across multiple ecosystems...'

        # Run multi-ecosystem vulnerability check
        scan_result = checker.check_multi_ecosystem(all_packages_for_check, project_name=project_name)

        progress['progress'] = 80
        progress['message'] = 'Generating reports...'

        # Phase 3: Generate reports
        progress['phase'] = 3
        output_dir = os.path.join(PROJECT_DIR, 'web_reports', task_id)
        os.makedirs(output_dir, exist_ok=True)

        from modules.report_generator import generate_html_report, generate_json_report, generate_dependency_graph
        from modules.sbom_generator import generate_sbom
        from modules.graph_renderer import render_dependency_tree_svg

        # Generate SVG dependency graph
        svg_path = os.path.join(output_dir, 'dependency_graph.svg')
        render_dependency_tree_svg(dep_tree, scan_result, svg_path)

        # Generate HTML report
        generate_html_report(scan_result, dep_tree, output_dir, project_name)

        # Generate JSON report
        generate_json_report(scan_result, output_dir, project_name)

        # Generate SBOM
        generate_sbom(resolved_packages, scan_result, output_dir, project_name)

        # Store dependency tree text
        tree_text = format_tree_text(dep_tree)
        scan_result['dependency_tree'] = tree_text
        scan_result['dep_tree_structure'] = dep_tree

        # Calculate risk score
        sev = scan_result['severity_counts']
        risk_score = min(100, sev.get('critical', 0) * 25 + sev.get('high', 0) * 15 +
                         sev.get('medium', 0) * 5 + sev.get('low', 0) * 1)

        # Save to database
        conn = get_db()
        cursor = conn.execute(
            '''INSERT INTO scans 
               (project_name, scan_time, total_packages, vulnerable_packages, total_vulnerabilities,
                critical_count, high_count, medium_count, low_count, risk_score,
                requirements_content, scan_data, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (project_name, now_beijing().strftime('%Y-%m-%d %H:%M:%S'),
             scan_result['total_packages'], scan_result['vulnerable_packages'],
             scan_result['total_vulnerabilities'],
             sev.get('critical', 0), sev.get('high', 0),
             sev.get('medium', 0), sev.get('low', 0),
             risk_score,
             file_content,
             json.dumps(scan_result, ensure_ascii=False),
             'completed')
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Check alert rules and create notifications if thresholds exceeded
        try:
            conn2 = get_db()
            check_alert_rules(scan_result, scan_id, conn2)
            conn2.close()
        except Exception as alert_err:
            print(f"Alert check error: {alert_err}")

        # Clean up temp file
        try:
            os.remove(tmp_file)
        except:
            pass

        progress['status'] = 'completed'
        progress['progress'] = 100
        progress['message'] = 'Scan completed successfully!'
        progress['scan_id'] = scan_id

    except Exception as e:
        progress['status'] = 'error'
        progress['error'] = str(e)
        import traceback
        traceback.print_exc()


# --- Routes ---

@app.route('/')
def index():
    """Home page with requirements.txt input."""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new scan. Accepts JSON or multipart form data.

    Input types:
    - text: requirements.txt / config file content (original behavior)
    - upload: file upload via multipart form
    - manual: direct package name + version list
    - url: GitHub repository URL (future)
    """
    project_name = ''
    file_content = ''
    file_format = None
    filename = 'requirements.txt'

    if request.content_type and 'multipart' in request.content_type:
        # File upload
        uploaded = request.files.get('file')
        if uploaded:
            file_content = uploaded.read().decode('utf-8', errors='ignore')
            filename = uploaded.filename or 'unknown'
        project_name = request.form.get('project_name', '')
        file_format = request.form.get('format')
    else:
        # JSON body
        data = request.get_json(silent=True) or {}
        project_name = data.get('project_name', '')
        file_format = data.get('format')

        if data.get('input_type') == 'manual':
            # Manual package list: [{"package": "flask", "version": "2.0.1"}, ...]
            manual_pkgs = data.get('packages', [])
            if not manual_pkgs:
                return jsonify({'error': 'No packages provided'}), 400
            # Convert to a pseudo-requirements.txt for compatibility
            lines = []
            for p in manual_pkgs:
                name = p.get('package', '').strip()
                ver = p.get('version', '').strip()
                if name:
                    lines.append(f"{name}=={ver}" if ver else name)
            file_content = '\n'.join(lines)
            filename = 'manual_input.txt'
        elif data.get('input_type') == 'url':
            # GitHub URL scanning (placeholder)
            url = data.get('url', '').strip()
            if not url:
                return jsonify({'error': 'No URL provided'}), 400
            return jsonify({'error': 'GitHub URL scanning is coming soon'}), 501
        else:
            file_content = data.get('requirements', '') or data.get('content', '')
            filename = data.get('filename', 'requirements.txt')

    if not file_content or not file_content.strip():
        return jsonify({'error': 'No file content provided'}), 400

    project_name = project_name.strip() or 'Unnamed Project'

    # Validate: must have at least some content
    if not file_content.strip():
        return jsonify({'error': 'File is empty'}), 400

    task_id = f'scan_{int(time.time() * 1000)}'
    scan_progress[task_id] = {
        'status': 'running',
        'phase': 0,
        'progress': 0,
        'message': 'Initializing scan...',
        'error': None,
        'scan_id': None,
        'project_name': project_name,
        'start_time': now_beijing().strftime('%Y-%m-%d %H:%M:%S'),
    }

    thread = threading.Thread(
        target=run_scan_task,
        args=(task_id, file_content, project_name, filename, file_format),
        daemon=True
    )
    thread.start()

    return jsonify({'task_id': task_id})


@app.route('/api/scan/<task_id>/status')
def scan_status(task_id):
    """Check scan progress."""
    if task_id not in scan_progress:
        return jsonify({'error': 'Task not found'}), 404
    return jsonify(scan_progress[task_id])


@app.route('/result/<int:scan_id>')
def result_page(scan_id):
    """Render the scan result page."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return render_template('error.html', message='Scan not found'), 404
    return render_template('result.html', scan_id=scan_id, project_name=row['project_name'])


@app.route('/api/result/<int:scan_id>')
def result_data(scan_id):
    """Get scan result data as JSON."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    # Add metadata
    scan_data['db_id'] = row['id']
    scan_data['db_project_name'] = row['project_name']
    scan_data['db_scan_time'] = row['scan_time']
    scan_data['db_risk_score'] = row['risk_score']
    return jsonify(scan_data)


@app.route('/history')
def history_page():
    """Render the detection history page."""
    return render_template('history.html')


@app.route('/api/history')
def history_data():
    """Get scan history as JSON."""
    conn = get_db()
    rows = conn.execute(
        '''SELECT id, project_name, scan_time, total_packages, vulnerable_packages,
                  total_vulnerabilities, critical_count, high_count, medium_count, low_count,
                  risk_score, status
           FROM scans ORDER BY id DESC'''
    ).fetchall()
    conn.close()

    history = []
    for row in rows:
        history.append({
            'id': row['id'],
            'project_name': row['project_name'],
            'scan_time': row['scan_time'],
            'total_packages': row['total_packages'],
            'vulnerable_packages': row['vulnerable_packages'],
            'total_vulnerabilities': row['total_vulnerabilities'],
            'critical': row['critical_count'],
            'high': row['high_count'],
            'medium': row['medium_count'],
            'low': row['low_count'],
            'risk_score': row['risk_score'],
            'status': row['status'],
        })
    return jsonify(history)


@app.route('/api/scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan record."""
    conn = get_db()
    conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/stats')
def stats():
    """Get overall statistics across all scans."""
    conn = get_db()
    row = conn.execute('''
        SELECT COUNT(*) as total_scans,
               SUM(total_packages) as total_packages,
               SUM(vulnerable_packages) as total_vulnerable,
               SUM(total_vulnerabilities) as total_vulns,
               SUM(critical_count) as total_critical,
               SUM(high_count) as total_high,
               SUM(medium_count) as total_medium,
               SUM(low_count) as total_low
        FROM scans
    ''').fetchone()
    conn.close()

    return jsonify({
        'total_scans': row['total_scans'] or 0,
        'total_packages': row['total_packages'] or 0,
        'total_vulnerable': row['total_vulnerable'] or 0,
        'total_vulns': row['total_vulns'] or 0,
        'total_critical': row['total_critical'] or 0,
        'total_high': row['total_high'] or 0,
        'total_medium': row['total_medium'] or 0,
        'total_low': row['total_low'] or 0,
    })


@app.route('/api/dependency-graph/<int:scan_id>')
def dependency_graph(scan_id):
    """Serve the SVG dependency graph for a scan."""
    conn = get_db()
    row = conn.execute('SELECT project_name FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    # Try to find the SVG in web_reports directories
    web_reports_dir = os.path.join(PROJECT_DIR, 'web_reports')
    if os.path.exists(web_reports_dir):
        for dir_name in os.listdir(web_reports_dir):
            svg_path = os.path.join(web_reports_dir, dir_name, 'dependency_graph.svg')
            if os.path.exists(svg_path):
                # Verify this is the right scan by checking the JSON metadata
                json_path = os.path.join(web_reports_dir, dir_name, 'scan_results.json')
                if os.path.exists(json_path):
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if data.get('project_name') == row['project_name']:
                        return send_file(svg_path, mimetype='image/svg+xml')

    # Fallback: check main reports directory
    main_svg = os.path.join(PROJECT_DIR, 'reports', 'dependency_graph.svg')
    if os.path.exists(main_svg):
        return send_file(main_svg, mimetype='image/svg+xml')

    return jsonify({'error': 'Graph not found'}), 404


@app.route('/api/sample/<sample_type>')
def sample_project(sample_type):
    """Get sample requirements.txt content."""
    if sample_type == 'vulnerable':
        return jsonify({
            'name': 'Vulnerable Test Project',
            'content': """flask==2.0.1
requests==2.25.1
urllib3==1.26.4
jinja2==2.11.3
numpy==1.21.0
cryptography==3.4.7
django==3.2.0
certifi==2022.12.7
setuptools==65.5.0
pyyaml==5.4.1"""
        })
    elif sample_type == 'safe':
        return jsonify({
            'name': 'Safe Test Project',
            'content': """flask>=3.0.0
requests>=2.31.0
numpy>=1.26.0
django>=5.0.0"""
        })
    return jsonify({'error': 'Unknown sample type'}), 400


# ============================================================================
# Dashboard - Security Posture Overview
# ============================================================================

@app.route('/dashboard')
def dashboard_page():
    """Security posture dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/dashboard')
def dashboard_data():
    """Aggregated dashboard data: stats, recent scans, top vulns, trend, CWE."""
    conn = get_db()

    # Overall stats
    stats_row = conn.execute('''
        SELECT COUNT(*) as total_scans,
               SUM(total_packages) as total_packages,
               SUM(vulnerable_packages) as total_vulnerable,
               SUM(total_vulnerabilities) as total_vulns,
               SUM(critical_count) as total_critical,
               SUM(high_count) as total_high,
               SUM(medium_count) as total_medium,
               SUM(low_count) as total_low,
               AVG(risk_score) as avg_risk
        FROM scans WHERE status='completed'
    ''').fetchone()

    # Recent 5 scans
    recent = conn.execute('''
        SELECT id, project_name, scan_time, total_packages, vulnerable_packages,
               total_vulnerabilities, critical_count, high_count, medium_count,
               low_count, risk_score
        FROM scans WHERE status='completed' ORDER BY id DESC LIMIT 5
    ''').fetchall()

    # Risk trend (all scans chronologically)
    trend = conn.execute('''
        SELECT id, project_name, scan_time, risk_score, total_vulnerabilities,
               critical_count, high_count, medium_count, low_count
        FROM scans WHERE status='completed' ORDER BY id ASC
    ''').fetchall()

    # Top vulnerable packages across all scans
    pkg_vuln_map = {}  # pkg_name -> {total_vulns, scans, worst_sev}
    rows = conn.execute('SELECT scan_data FROM scans WHERE status=\"completed\"').fetchall()
    cwe_counter = {}
    for row in rows:
        try:
            data = json.loads(row['scan_data'])
            for pkg in data.get('packages', []):
                if pkg.get('vuln_count', 0) > 0:
                    name = pkg['package']
                    if name not in pkg_vuln_map:
                        pkg_vuln_map[name] = {'name': name, 'total_vulns': 0, 'scans': 0, 'versions': set()}
                    pkg_vuln_map[name]['total_vulns'] += pkg['vuln_count']
                    pkg_vuln_map[name]['scans'] += 1
                    pkg_vuln_map[name]['versions'].add(pkg.get('version', ''))
                # Count CWEs
                for vuln in pkg.get('vulnerabilities', []):
                    for cwe in vuln.get('cwes', []):
                        cwe_counter[cwe] = cwe_counter.get(cwe, 0) + 1
        except:
            pass

    top_pkgs = sorted(pkg_vuln_map.values(), key=lambda x: x['total_vulns'], reverse=True)[:10]
    for p in top_pkgs:
        p['versions'] = list(p['versions'])

    top_cwes = sorted(cwe_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    conn.close()

    return jsonify({
        'stats': {
            'total_scans': stats_row['total_scans'] or 0,
            'total_packages': stats_row['total_packages'] or 0,
            'total_vulnerable': stats_row['total_vulnerable'] or 0,
            'total_vulns': stats_row['total_vulns'] or 0,
            'total_critical': stats_row['total_critical'] or 0,
            'total_high': stats_row['total_high'] or 0,
            'total_medium': stats_row['total_medium'] or 0,
            'total_low': stats_row['total_low'] or 0,
            'avg_risk': round(stats_row['avg_risk'] or 0, 1),
        },
        'recent_scans': [{
            'id': r['id'], 'project_name': r['project_name'], 'scan_time': r['scan_time'],
            'total_packages': r['total_packages'], 'vulnerable_packages': r['vulnerable_packages'],
            'total_vulnerabilities': r['total_vulnerabilities'],
            'critical': r['critical_count'], 'high': r['high_count'],
            'medium': r['medium_count'], 'low': r['low_count'],
            'risk_score': r['risk_score'],
        } for r in recent],
        'risk_trend': [{
            'id': r['id'], 'name': r['project_name'], 'time': r['scan_time'],
            'risk': r['risk_score'], 'vulns': r['total_vulnerabilities'],
            'critical': r['critical_count'], 'high': r['high_count'],
            'medium': r['medium_count'], 'low': r['low_count'],
        } for r in trend],
        'top_packages': top_pkgs,
        'top_cwes': [{'name': c, 'count': n} for c, n in top_cwes],
    })


# ============================================================================
# Scan Comparison
# ============================================================================

@app.route('/compare')
def compare_page():
    """Scan comparison page."""
    scan1 = request.args.get('scan1', type=int)
    scan2 = request.args.get('scan2', type=int)
    conn = get_db()
    scans_list = conn.execute(
        'SELECT id, project_name, scan_time FROM scans WHERE status=\"completed\" ORDER BY id DESC'
    ).fetchall()
    conn.close()
    return render_template('compare.html',
                           scan1_id=scan1, scan2_id=scan2,
                           scans_list=[{'id': r['id'], 'name': r['project_name'], 'time': r['scan_time']} for r in scans_list])


@app.route('/api/compare')
def compare_data():
    """Compare two scans: show new, fixed, and unchanged vulnerabilities."""
    scan1_id = request.args.get('scan1', type=int)
    scan2_id = request.args.get('scan2', type=int)

    if not scan1_id or not scan2_id:
        return jsonify({'error': 'Both scan1 and scan2 parameters are required'}), 400

    conn = get_db()
    row1 = conn.execute('SELECT * FROM scans WHERE id = ?', (scan1_id,)).fetchone()
    row2 = conn.execute('SELECT * FROM scans WHERE id = ?', (scan2_id,)).fetchone()
    conn.close()

    if not row1 or not row2:
        return jsonify({'error': 'Scan not found'}), 404

    data1 = json.loads(row1['scan_data']) if row1['scan_data'] else {}
    data2 = json.loads(row2['scan_data']) if row2['scan_data'] else {}

    # Build vulnerability ID sets per package
    def build_vuln_map(data):
        result = {}  # pkg_name -> {version, vuln_ids: set, vulns: list}
        for pkg in data.get('packages', []):
            name = pkg['package']
            vuln_ids = set()
            for v in pkg.get('vulnerabilities', []):
                vid = v.get('id', '')
                if vid:
                    vuln_ids.add(vid)
                for alias in v.get('aliases', []):
                    vuln_ids.add(alias)
            result[name] = {
                'version': pkg.get('version', ''),
                'vuln_ids': vuln_ids,
                'vuln_count': pkg.get('vuln_count', 0),
                'vulnerabilities': pkg.get('vulnerabilities', []),
            }
        return result

    map1 = build_vuln_map(data1)
    map2 = build_vuln_map(data2)

    all_pkgs = set(map1.keys()) | set(map2.keys())

    new_vulns = []      # In scan2 but not scan1
    fixed_vulns = []     # In scan1 but not scan2
    unchanged = []       # Same in both
    new_packages = []    # Packages only in scan2
    removed_packages = [] # Packages only in scan1

    for pkg_name in sorted(all_pkgs):
        p1 = map1.get(pkg_name)
        p2 = map2.get(pkg_name)

        if p1 and not p2:
            removed_packages.append({'name': pkg_name, 'version': p1['version'],
                                     'vuln_count': p1['vuln_count']})
        elif p2 and not p1:
            new_packages.append({'name': pkg_name, 'version': p2['version'],
                                'vuln_count': p2['vuln_count']})
        elif p1 and p2:
            only_in_1 = p1['vuln_ids'] - p2['vuln_ids']
            only_in_2 = p2['vuln_ids'] - p1['vuln_ids']
            common = p1['vuln_ids'] & p2['vuln_ids']

            if only_in_1:
                fixed_vulns.append({
                    'name': pkg_name, 'v1': p1['version'], 'v2': p2['version'],
                    'fixed': list(only_in_1), 'count': len(only_in_1)
                })
            if only_in_2:
                new_vulns.append({
                    'name': pkg_name, 'v1': p1['version'], 'v2': p2['version'],
                    'new': list(only_in_2), 'count': len(only_in_2)
                })
            if common and not only_in_1 and not only_in_2:
                unchanged.append({
                    'name': pkg_name, 'v1': p1['version'], 'v2': p2['version'],
                    'count': len(common)
                })

    sev1 = data1.get('severity_counts', {})
    sev2 = data2.get('severity_counts', {})

    return jsonify({
        'scan1': {
            'id': row1['id'], 'name': row1['project_name'], 'time': row1['scan_time'],
            'total_packages': row1['total_packages'], 'total_vulns': row1['total_vulnerabilities'],
            'risk_score': row1['risk_score'],
            'severity': {'critical': sev1.get('critical',0), 'high': sev1.get('high',0),
                         'medium': sev1.get('medium',0), 'low': sev1.get('low',0)},
        },
        'scan2': {
            'id': row2['id'], 'name': row2['project_name'], 'time': row2['scan_time'],
            'total_packages': row2['total_packages'], 'total_vulns': row2['total_vulnerabilities'],
            'risk_score': row2['risk_score'],
            'severity': {'critical': sev2.get('critical',0), 'high': sev2.get('high',0),
                         'medium': sev2.get('medium',0), 'low': sev2.get('low',0)},
        },
        'new_vulns': new_vulns,
        'fixed_vulns': fixed_vulns,
        'unchanged': unchanged,
        'new_packages': new_packages,
        'removed_packages': removed_packages,
        'summary': {
            'new_count': sum(v['count'] for v in new_vulns),
            'fixed_count': sum(v['count'] for v in fixed_vulns),
            'unchanged_count': sum(v['count'] for v in unchanged),
            'new_packages_count': len(new_packages),
            'removed_packages_count': len(removed_packages),
        }
    })


# ============================================================================
# Package Detail
# ============================================================================

@app.route('/api/package/<path:name>')
def package_detail(name):
    """Get package details across all scans."""
    conn = get_db()
    rows = conn.execute('SELECT * FROM scans WHERE status=\"completed\" ORDER BY id DESC').fetchall()
    conn.close()

    history = []
    all_vulns = []

    for row in rows:
        try:
            data = json.loads(row['scan_data'])
            for pkg in data.get('packages', []):
                if pkg['package'].lower() == name.lower():
                    history.append({
                        'scan_id': row['id'],
                        'project_name': row['project_name'],
                        'scan_time': row['scan_time'],
                        'version': pkg.get('version', ''),
                        'vuln_count': pkg.get('vuln_count', 0),
                        'is_direct': pkg.get('is_direct', False),
                    })
                    for v in pkg.get('vulnerabilities', []):
                        all_vulns.append({
                            'id': v.get('id', ''),
                            'severity': v.get('severity', ''),
                            'cvss': v.get('cvss_score', 0),
                            'summary': v.get('summary', ''),
                            'scan_id': row['id'],
                            'scan_time': row['scan_time'],
                            'version': pkg.get('version', ''),
                        })
        except:
            pass

    return jsonify({
        'name': name,
        'history': history,
        'vulnerabilities': all_vulns,
        'total_scans': len(history),
        'total_vulns': len(all_vulns),
    })


# ============================================================================
# Export
# ============================================================================

@app.route('/api/export/<int:scan_id>/<fmt>')
def export_scan(scan_id, fmt):
    """Export scan data in the requested format."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    project_name = row['project_name'] or 'scan'
    safe_name = re.sub(r'[^\w\-]', '_', project_name)

    if fmt == 'json':
        return jsonify(scan_data)

    elif fmt == 'sbom':
        sbom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.4',
            'metadata': {
                'component': {'name': project_name, 'type': 'application'},
                'timestamp': row['scan_time'],
            },
            'components': [
                {
                    'type': 'library',
                    'name': pkg.get('package', ''),
                    'version': pkg.get('version', ''),
                    'purl': 'pkg:pypi/' + pkg.get('package', '').lower(),
                }
                for pkg in scan_data.get('packages', [])
            ],
        }
        response = jsonify(sbom)
        response.headers['Content-Disposition'] = f'attachment; filename={safe_name}_sbom.json'
        return response

    elif fmt == 'svg':
        # Try to find the SVG file
        web_reports_dir = os.path.join(PROJECT_DIR, 'web_reports')
        if os.path.exists(web_reports_dir):
            for dir_name in os.listdir(web_reports_dir):
                svg_path = os.path.join(web_reports_dir, dir_name, 'dependency_graph.svg')
                if os.path.exists(svg_path):
                    json_path = os.path.join(web_reports_dir, dir_name, 'scan_results.json')
                    if os.path.exists(json_path):
                        with open(json_path, 'r', encoding='utf-8') as f:
                            d = json.load(f)
                        if d.get('project_name') == project_name:
                            return send_file(svg_path, mimetype='image/svg+xml',
                                             as_attachment=True,
                                             download_name=f'{safe_name}_dep_graph.svg')
        # Fallback: generate a simple text-based SVG from dep tree
        tree_text = scan_data.get('dependency_tree', 'No tree data')
        svg_content = '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="800" height="600">'
        svg_content += f'<text x="20" y="30" font-size="14" fill="#333">{safe_name} dependency tree</text>'
        svg_content += '</svg>'
        from io import BytesIO
        buf = BytesIO(svg_content.encode('utf-8'))
        return send_file(buf, mimetype='image/svg+xml', as_attachment=True,
                         download_name=f'{safe_name}_dep_graph.svg')

    elif fmt == 'requirements':
        lines = scan_data.get('requirements_content', '')
        if not lines:
            for pkg in scan_data.get('packages', []):
                if pkg.get('is_direct'):
                    lines += f"{pkg['package']}=={pkg['version']}\n"
        from io import BytesIO
        buf = BytesIO(lines.encode('utf-8'))
        return send_file(buf, mimetype='text/plain', as_attachment=True,
                         download_name=f'{safe_name}_requirements.txt')

    return jsonify({'error': f'Unknown format: {fmt}'}), 400


# ============================================================================
# Supported Formats
# ============================================================================

@app.route('/api/formats')
def list_formats():
    """List all supported file formats."""
    from parsers import get_supported_formats
    formats = get_supported_formats()
    # Group by ecosystem
    grouped = {}
    for name, info in formats.items():
        eco = info['ecosystem']
        if eco not in grouped:
            grouped[eco] = []
        grouped[eco].append({
            'id': name,
            'extensions': info['extensions'],
        })
    return jsonify({'formats': grouped, 'total': len(formats)})


# ============================================================================
# Quick Package Check
# ============================================================================

@app.route('/api/quick-check/<package>')
def quick_check(package):
    """Quick vulnerability check for a single package."""
    version = request.args.get('version', '')
    ecosystem = request.args.get('ecosystem', 'PyPI')

    from modules.vulnerability_checker import VulnerabilityChecker, OSV_ECOSYSTEM_MAP
    cache_dir = os.path.join(PROJECT_DIR, 'cache')
    os.makedirs(cache_dir, exist_ok=True)
    checker = VulnerabilityChecker(cache_dir=cache_dir, rate_limit_delay=0.1)

    # Check if ecosystem is supported
    osv_eco = OSV_ECOSYSTEM_MAP.get(ecosystem, ecosystem)
    if osv_eco is None:
        return jsonify({'error': f'Ecosystem {ecosystem} not supported by OSV.dev'}), 400

    result = checker.check_multi_ecosystem(
        [{'package': package, 'version': version, 'ecosystem': ecosystem}],
        project_name='quick-check'
    )

    pkg_data = result.get('packages', [{}])[0] if result.get('packages') else {}
    return jsonify({
        'package': package,
        'version': version,
        'ecosystem': ecosystem,
        'vulnerabilities': pkg_data.get('vulnerabilities', []),
        'vuln_count': pkg_data.get('vuln_count', 0),
    })


# ============================================================================
# File Parse Preview
# ============================================================================

@app.route('/api/parse', methods=['POST'])
def parse_preview():
    """Parse a file and return detected packages without vulnerability scanning."""
    from parsers import parse_file, detect_format

    if request.content_type and 'multipart' in request.content_type:
        uploaded = request.files.get('file')
        if not uploaded:
            return jsonify({'error': 'No file uploaded'}), 400
        content = uploaded.read().decode('utf-8', errors='ignore')
        filename = uploaded.filename or 'unknown'
        fmt = request.form.get('format')
    else:
        data = request.get_json(silent=True) or {}
        content = data.get('content', '')
        filename = data.get('filename', 'requirements.txt')
        fmt = data.get('format')

    if not content.strip():
        return jsonify({'error': 'Empty content'}), 400

    detected_fmt = fmt or detect_format(filename, content)
    if not detected_fmt:
        return jsonify({'error': 'Could not detect file format', 'supported': list(get_supported_formats().keys())}), 400

    packages = parse_file(filename, content, detected_fmt)

    return jsonify({
        'format': detected_fmt,
        'packages': packages,
        'count': len(packages),
    })


# ============================================================================
# MODULE 1: Authentication & User Management
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """User login page."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')

        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
        if row and verify_password(password, row['password_hash']):
            session['user_id'] = row['id']
            session['username'] = row['username']
            session['role'] = row['role']
            session['email'] = row['email']
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                         (now_beijing().strftime('%Y-%m-%d %H:%M:%S'), row['id']))
            conn.commit()
            log_audit(conn, row['id'], row['username'], 'LOGIN', 'Web Platform', '成功登录')
            conn.close()
            return jsonify({'success': True, 'role': row['role']})
        conn.close()
        return jsonify({'error': '用户名或密码错误'}), 401

    return render_template('login.html', mode='login')


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    """User registration page."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()

        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
        if len(password) < 6:
            return jsonify({'error': '密码至少6位'}), 400

        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'error': '用户名已存在'}), 409

        pw_hash = hash_password(password)
        conn.execute(
            '''INSERT INTO users (username, password_hash, email, role, created_at)
               VALUES (?, ?, ?, 'user', ?)''',
            (username, pw_hash, email, now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        log_audit(conn, 0, username, 'REGISTER', 'Web Platform', f'新用户注册: {username}')
        conn.close()
        return jsonify({'success': True, 'message': '注册成功，请登录'})

    return render_template('login.html', mode='register')


@app.route('/logout')
def logout():
    """User logout."""
    conn = get_db()
    user = get_current_user()
    if user:
        log_audit(conn, user['id'], user['username'], 'LOGOUT', 'Web Platform', '用户退出')
    conn.close()
    session.clear()
    return redirect(url_for('index'))


@app.route('/admin')
@admin_required
def admin_page():
    """Admin panel for user management and audit logs."""
    return render_template('admin.html')


@app.route('/api/users')
@admin_required
def list_users():
    """List all users (admin only)."""
    conn = get_db()
    rows = conn.execute(
        'SELECT id, username, email, role, created_at, last_login, is_active FROM users ORDER BY id'
    ).fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'username': r['username'], 'email': r['email'],
        'role': r['role'], 'created_at': r['created_at'],
        'last_login': r['last_login'], 'is_active': r['is_active']
    } for r in rows])


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    """Delete/deactivate a user (admin only)."""
    conn = get_db()
    if user_id == session.get('user_id'):
        conn.close()
        return jsonify({'error': '不能删除当前登录用户'}), 400
    conn.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    user = get_current_user()
    log_audit(conn, user['id'], user['username'], 'DELETE_USER', f'用户ID:{user_id}', '停用用户')
    conn.close()
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>/role', methods=['POST'])
@admin_required
def update_user_role(user_id):
    """Update user role (admin only)."""
    data = request.get_json(silent=True) or {}
    new_role = data.get('role', 'user')
    if new_role not in ('admin', 'user'):
        return jsonify({'error': '无效角色'}), 400
    conn = get_db()
    conn.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    user = get_current_user()
    log_audit(conn, user['id'], user['username'], 'UPDATE_ROLE', f'用户ID:{user_id}', f'角色变更为{new_role}')
    conn.close()
    return jsonify({'success': True})


@app.route('/api/audit-logs')
@admin_required
def audit_logs():
    """Get audit logs (admin only)."""
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200'
    ).fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'user_id': r['user_id'], 'username': r['username'],
        'action': r['action'], 'target': r['target'], 'details': r['details'],
        'ip': r['ip_address'], 'timestamp': r['timestamp']
    } for r in rows])


@app.route('/api/current-user')
def current_user():
    """Get current user info."""
    user = get_current_user()
    if user:
        return jsonify(user)
    return jsonify({'logged_in': False})


# ============================================================================
# MODULE 2: Vulnerability Remediation
# ============================================================================

@app.route('/remediation/<int:scan_id>')
def remediation_page(scan_id):
    """Vulnerability remediation page."""
    conn = get_db()
    row = conn.execute('SELECT project_name FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return render_template('error.html', message='Scan not found'), 404
    return render_template('remediation.html', scan_id=scan_id, project_name=row['project_name'])


@app.route('/api/remediation/<int:scan_id>')
def remediation_data(scan_id):
    """Get fix suggestions for a scan."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    whitelist = conn.execute(
        'SELECT package_name, vuln_id FROM whitelist WHERE scan_id = ? AND status = "ignored"', (scan_id,)
    ).fetchall()
    conn.close()

    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    suggestions = get_fix_suggestions(scan_data)

    # Mark whitelisted items
    wl_set = {(w['package_name'], w['vuln_id']) for w in whitelist}
    for s in suggestions:
        s['whitelisted_vulns'] = [vid for vid in s['vuln_ids'] if (s['package'], vid) in wl_set]
        s['active_vuln_count'] = len(s['vuln_ids']) - len(s['whitelisted_vulns'])

    return jsonify({
        'scan_id': scan_id,
        'project_name': row['project_name'],
        'risk_score': row['risk_score'],
        'suggestions': suggestions,
        'whitelist_count': len(wl_set),
        'requirements_content': row['requirements_content'] or '',
    })


@app.route('/api/remediation/<int:scan_id>/whitelist', methods=['POST'])
def add_whitelist(scan_id):
    """Add a vulnerability to whitelist (ignore)."""
    data = request.get_json(silent=True) or {}
    pkg = data.get('package', '')
    vuln_id = data.get('vuln_id', '')
    reason = data.get('reason', 'Manual override')

    if not pkg or not vuln_id:
        return jsonify({'error': 'Package and vuln_id required'}), 400

    conn = get_db()
    try:
        conn.execute(
            '''INSERT OR REPLACE INTO whitelist (scan_id, package_name, vuln_id, reason, status, created_at)
               VALUES (?, ?, ?, ?, 'ignored', ?)''',
            (scan_id, pkg, vuln_id, reason, now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        user = get_current_user()
        if user:
            log_audit(conn, user['id'], user['username'], 'WHITELIST', f'{pkg}/{vuln_id}', f'扫描{scan_id}白名单')
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/remediation/<int:scan_id>/whitelist/<vuln_id>', methods=['DELETE'])
def remove_whitelist(scan_id, vuln_id):
    """Remove a vulnerability from whitelist."""
    conn = get_db()
    conn.execute('DELETE FROM whitelist WHERE scan_id = ? AND vuln_id = ?', (scan_id, vuln_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/remediation/<int:scan_id>/fix-script')
def download_fix_script(scan_id):
    """Download batch fix script for a scan."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    suggestions = get_fix_suggestions(scan_data)
    script = generate_fix_script(suggestions)

    from io import BytesIO
    buf = BytesIO(script.encode('utf-8'))
    safe_name = re.sub(r'[^\w\-]', '_', row['project_name'])
    return send_file(buf, mimetype='text/x-shellscript', as_attachment=True,
                     download_name=f'{safe_name}_fix_script.sh')


@app.route('/api/remediation/<int:scan_id>/fixed-requirements')
def download_fixed_requirements(scan_id):
    """Download fixed requirements.txt."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    suggestions = get_fix_suggestions(scan_data)
    fixed = generate_requirements_fixed(suggestions, row['requirements_content'] or '')

    from io import BytesIO
    buf = BytesIO(fixed.encode('utf-8'))
    safe_name = re.sub(r'[^\w\-]', '_', row['project_name'])
    return send_file(buf, mimetype='text/plain', as_attachment=True,
                     download_name=f'{safe_name}_requirements_fixed.txt')


# ============================================================================
# MODULE 3: Risk Alerts & Notifications
# ============================================================================

@app.route('/alerts')
def alerts_page():
    """Risk alerts and notifications page."""
    return render_template('alerts.html')


@app.route('/api/alert-rules', methods=['GET', 'POST'])
def alert_rules():
    """Get or create alert rules."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        name = data.get('name', '')
        if not name:
            return jsonify({'error': 'Rule name required'}), 400

        conn = get_db()
        conn.execute(
            '''INSERT INTO alert_rules (name, severity_threshold, vuln_count_threshold,
               risk_score_threshold, email_notify, active, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (name, data.get('severity_threshold', 'high'),
             data.get('vuln_count_threshold', 0),
             data.get('risk_score_threshold', 0),
             1 if data.get('email_notify') else 0,
             1, now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    conn = get_db()
    rows = conn.execute('SELECT * FROM alert_rules ORDER BY id DESC').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'name': r['name'], 'severity_threshold': r['severity_threshold'],
        'vuln_count_threshold': r['vuln_count_threshold'],
        'risk_score_threshold': r['risk_score_threshold'],
        'email_notify': r['email_notify'], 'active': r['active'],
        'created_at': r['created_at']
    } for r in rows])


@app.route('/api/alert-rules/<int:rule_id>', methods=['DELETE'])
def delete_alert_rule(rule_id):
    """Delete an alert rule."""
    conn = get_db()
    conn.execute('DELETE FROM alert_rules WHERE id = ?', (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications')
def notifications():
    """Get all notifications."""
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM notifications ORDER BY id DESC LIMIT 100'
    ).fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'type': r['type'], 'title': r['title'],
        'message': r['message'], 'scan_id': r['scan_id'],
        'severity': r['severity'], 'is_read': r['is_read'],
        'created_at': r['created_at']
    } for r in rows])


@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
def mark_notification_read(notif_id):
    """Mark notification as read."""
    conn = get_db()
    conn.execute('UPDATE notifications SET is_read = 1 WHERE id = ?', (notif_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/read-all', methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications as read."""
    conn = get_db()
    conn.execute('UPDATE notifications SET is_read = 1')
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/notifications/unread-count')
def unread_notification_count():
    """Get count of unread notifications."""
    conn = get_db()
    row = conn.execute('SELECT COUNT(*) as cnt FROM notifications WHERE is_read = 0').fetchone()
    conn.close()
    return jsonify({'count': row['cnt']})


# ============================================================================
# MODULE 4: Advanced Analytics & Compliance
# ============================================================================

@app.route('/analytics')
def analytics_page():
    """Advanced analytics page."""
    return render_template('analytics.html')


@app.route('/api/compliance/<int:scan_id>')
def compliance_check(scan_id):
    """Run compliance check for a scan."""
    standard = request.args.get('standard', 'OWASP Top 10')
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    result = run_compliance_check(scan_data, standard)

    if result:
        # Save compliance result
        conn = get_db()
        conn.execute(
            '''INSERT INTO compliance_results (scan_id, standard, total_checks, passed, failed, warnings, details, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_id, standard, result['total_checks'], result['passed'],
             result['failed'], result['warnings'],
             json.dumps(result['details'], ensure_ascii=False),
             now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()

    return jsonify(result)


@app.route('/api/compliance/standards')
def compliance_standards():
    """List available compliance standards."""
    return jsonify({
        'standards': [
            {'name': name, 'description': info['description'],
             'checks_count': len(info['checks'])}
            for name, info in COMPLIANCE_STANDARDS.items()
        ]
    })


@app.route('/api/analytics/dependency-trace/<int:scan_id>')
def dependency_trace(scan_id):
    """Get dependency traceability data for a scan."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    packages = scan_data.get('packages', [])

    # Build traceability data
    trace = {
        'scan_id': scan_id,
        'project_name': row['project_name'],
        'total_packages': len(packages),
        'direct_deps': sum(1 for p in packages if p.get('is_direct')),
        'transitive_deps': sum(1 for p in packages if not p.get('is_direct')),
        'vulnerable_direct': sum(1 for p in packages if p.get('is_direct') and p.get('vuln_count', 0) > 0),
        'vulnerable_transitive': sum(1 for p in packages if not p.get('is_direct') and p.get('vuln_count', 0) > 0),
        'dependency_tree': scan_data.get('dependency_tree', ''),
        'dep_tree_structure': scan_data.get('dep_tree_structure', {}),
        'packages': packages,
    }
    return jsonify(trace)


@app.route('/api/analytics/trends')
def vulnerability_trends():
    """Get vulnerability trends across all scans."""
    conn = get_db()
    rows = conn.execute('''
        SELECT id, project_name, scan_time, total_vulnerabilities,
               critical_count, high_count, medium_count, low_count, risk_score
        FROM scans WHERE status = 'completed' ORDER BY id ASC
    ''').fetchall()
    conn.close()

    trends = []
    cumulative_vulns = 0
    for r in rows:
        cumulative_vulns += r['total_vulnerabilities']
        trends.append({
            'id': r['id'], 'name': r['project_name'], 'time': r['scan_time'],
            'vulns': r['total_vulnerabilities'], 'cumulative': cumulative_vulns,
            'critical': r['critical_count'], 'high': r['high_count'],
            'medium': r['medium_count'], 'low': r['low_count'],
            'risk': r['risk_score'],
        })

    # Severity distribution over time
    total_sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for t in trends:
        for k in total_sev:
            total_sev[k] += t[k]

    return jsonify({
        'trends': trends,
        'total_severity': total_sev,
        'total_scans': len(trends),
        'avg_risk': round(sum(t['risk'] for t in trends) / len(trends), 1) if trends else 0,
    })


# ============================================================================
# MODULE 5: Enhanced Report Export
# ============================================================================

@app.route('/api/export/<int:scan_id>/excel')
def export_excel_route(scan_id):
    """Export scan results to Excel."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    safe_name = re.sub(r'[^\w\-]', '_', row['project_name'])

    buf = export_excel(scan_data, row['project_name'], row['scan_time'])
    return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name=f'{safe_name}_report.xlsx')


@app.route('/api/export/<int:scan_id>/word')
def export_word_route(scan_id):
    """Export scan results to Word document."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    safe_name = re.sub(r'[^\w\-]', '_', row['project_name'])

    buf = export_word(scan_data, row['project_name'], row['scan_time'], row['risk_score'])
    if buf is None:
        return jsonify({'error': 'python-docx not installed on server'}), 500

    return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                     as_attachment=True, download_name=f'{safe_name}_report.docx')


@app.route('/api/export/<int:scan_id>/pdf')
def export_pdf_route(scan_id):
    """Export scan results as print-friendly PDF HTML."""
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404

    scan_data = json.loads(row['scan_data']) if row['scan_data'] else {}
    html = export_pdf_html(scan_data, row['project_name'], row['scan_time'], row['risk_score'])
    return html


# ============================================================================
# MODULE 6: CVE Knowledge Base, Favorites & Snapshots
# ============================================================================

@app.route('/kb')
def knowledge_base_page():
    """CVE knowledge base page."""
    return render_template('kb.html')


@app.route('/api/kb/search')
def kb_search():
    """Search CVE knowledge base."""
    query = request.args.get('q', '')
    results = search_kb(query)
    return jsonify({
        'results': results,
        'total': len(results),
        'query': query,
    })


@app.route('/api/favorites', methods=['GET', 'POST'])
def favorites():
    """Get or add favorites."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        cve_id = data.get('cve_id', '')
        if not cve_id:
            return jsonify({'error': 'CVE ID required'}), 400

        conn = get_db()
        try:
            conn.execute(
                '''INSERT OR REPLACE INTO favorites (cve_id, package_name, severity, summary, created_at)
                   VALUES (?, ?, ?, ?, ?)''',
                (cve_id, data.get('package_name', ''), data.get('severity', ''),
                 data.get('summary', '')[:500], now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 500

    conn = get_db()
    rows = conn.execute('SELECT * FROM favorites ORDER BY id DESC').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'cve_id': r['cve_id'], 'package_name': r['package_name'],
        'severity': r['severity'], 'summary': r['summary'], 'created_at': r['created_at']
    } for r in rows])


@app.route('/api/favorites/<cve_id>', methods=['DELETE'])
def remove_favorite(cve_id):
    """Remove a favorite."""
    conn = get_db()
    conn.execute('DELETE FROM favorites WHERE cve_id = ?', (cve_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/snapshots', methods=['GET', 'POST'])
def snapshots():
    """Get or create snapshots."""
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        scan_id = data.get('scan_id')
        name = data.get('name', '')
        description = data.get('description', '')

        if not scan_id or not name:
            return jsonify({'error': 'Scan ID and name required'}), 400

        conn = get_db()
        row = conn.execute('SELECT scan_data, project_name, risk_score FROM scans WHERE id = ?', (scan_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({'error': 'Scan not found'}), 404

        conn.execute(
            '''INSERT INTO snapshots (scan_id, name, description, snapshot_data, created_at)
               VALUES (?, ?, ?, ?, ?)''',
            (scan_id, name, description,
             json.dumps({'scan_data': row['scan_data'], 'risk_score': row['risk_score'],
                         'project_name': row['project_name']}),
             now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True})

    conn = get_db()
    rows = conn.execute('''
        SELECT s.*, sc.project_name, sc.risk_score
        FROM snapshots s LEFT JOIN scans sc ON s.scan_id = sc.id
        ORDER BY s.id DESC
    ''').fetchall()
    conn.close()
    return jsonify([{
        'id': r['id'], 'scan_id': r['scan_id'], 'name': r['name'],
        'description': r['description'], 'created_at': r['created_at'],
        'project_name': r['project_name'] if 'project_name' in r.keys() else '',
        'risk_score': r['risk_score'] if 'risk_score' in r.keys() else 0,
    } for r in rows])


@app.route('/api/snapshots/<int:snapshot_id>', methods=['DELETE'])
def delete_snapshot(snapshot_id):
    """Delete a snapshot."""
    conn = get_db()
    conn.execute('DELETE FROM snapshots WHERE id = ?', (snapshot_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/snapshots/compare')
def compare_snapshots():
    """Compare two snapshots or a snapshot with current scan."""
    snap1 = request.args.get('snap1', type=int)
    snap2 = request.args.get('snap2', type=int)
    scan_id = request.args.get('scan', type=int)

    conn = get_db()
    results = {}

    if snap1:
        row = conn.execute('SELECT * FROM snapshots WHERE id = ?', (snap1,)).fetchone()
        if row:
            data = json.loads(row['snapshot_data'])
            results['snapshot1'] = {
                'id': row['id'], 'name': row['name'], 'created_at': row['created_at'],
                'risk_score': data.get('risk_score', 0),
                'project_name': data.get('project_name', ''),
            }

    if snap2:
        row = conn.execute('SELECT * FROM snapshots WHERE id = ?', (snap2,)).fetchone()
        if row:
            data = json.loads(row['snapshot_data'])
            results['snapshot2'] = {
                'id': row['id'], 'name': row['name'], 'created_at': row['created_at'],
                'risk_score': data.get('risk_score', 0),
                'project_name': data.get('project_name', ''),
            }

    conn.close()
    return jsonify(results)


if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    print("=" * 55)
    print("  SCS Checker - Interactive Web Platform v2.0")
    print("=" * 55)
    print()
    print(f"  Database: {DB_PATH}")
    print(f"  Project:  {PROJECT_DIR}")
    print()
    print(f"  Starting server at http://{host}:{port}")
    print()
    app.run(host=host, port=port, debug=os.environ.get('FLASK_DEBUG', 'true').lower() == 'true')
