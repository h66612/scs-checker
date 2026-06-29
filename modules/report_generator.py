"""
报告生成模块 - Report Generator Module

生成 HTML 供应链安全报告（含依赖图可视化）、JSON 数据导出，
以及 Graphviz DOT 格式的依赖关系图。
"""
import json
import os
import html
from datetime import datetime
from typing import Dict, List, Optional


def generate_html_report(
    scan_result: Dict,
    dep_tree: Dict,
    output_dir: str,
    project_name: str = "Project",
) -> str:
    """Generate a comprehensive HTML supply chain security report.

    Args:
        scan_result: vulnerability scan results
        dep_tree: dependency tree data
        output_dir: directory to save the report
        project_name: project name for the report title

    Returns:
        Path to the generated HTML report.
    """
    os.makedirs(output_dir, exist_ok=True)

    dep_graph_png = os.path.join(output_dir, "dependency_graph.png")
    dep_graph_svg = os.path.join(output_dir, "dependency_graph.svg")
    dep_graph_dot = os.path.join(output_dir, "dependency_graph.dot")
    has_graph_png = os.path.exists(dep_graph_png)
    has_graph_svg = os.path.exists(dep_graph_svg)
    has_graph_dot = os.path.exists(dep_graph_dot)

    tree_text = _format_tree_text(dep_tree)
    severity = scan_result.get("severity_counts", {})

    # Build vulnerability details HTML
    vuln_details_html = _build_vuln_details_html(scan_result.get("packages", []))

    # Build recommendations table
    recommendations_html = _build_recommendations_html(scan_result.get("packages", []))

    # Build dependency list table
    dep_list_html = _build_dependency_list_html(scan_result.get("packages", []))

    timestamp = scan_result.get("scan_time", datetime.now().isoformat())
    scan_date = timestamp.split("T")[0] if "T" in timestamp else timestamp

    # Risk score calculation
    total_vulns = scan_result.get("total_vulnerabilities", 0)
    high_count = severity.get("high", 0) + severity.get("critical", 0)
    risk_score = min(100, high_count * 25 + severity.get("medium", 0) * 10 + severity.get("low", 0) * 3)
    risk_level = "Critical" if risk_score >= 75 else "High" if risk_score >= 50 else "Medium" if risk_score >= 25 else "Low"
    risk_color = "#dc3545" if risk_score >= 75 else "#fd7e14" if risk_score >= 50 else "#ffc107" if risk_score >= 25 else "#28a745"

    # Graph section
    graph_section = ""
    if has_graph_png:
        graph_section = f'<img src="dependency_graph.png" alt="Dependency Graph" class="dep-graph">'
    elif has_graph_svg:
        graph_section = f'<img src="dependency_graph.svg" alt="Dependency Graph" class="dep-graph">'
    elif has_graph_dot:
        with open(dep_graph_dot, "r", encoding="utf-8") as f:
            dot_content = html.escape(f.read())
        graph_section = f'<pre class="dot-source">{dot_content}</pre>'

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>供应链安全报告 - {_esc(project_name)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; color: #333; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: white; padding: 40px 20px; text-align: center; }}
        .header h1 {{ font-size: 2em; margin-bottom: 8px; }}
        .header .subtitle {{ opacity: 0.85; font-size: 1em; }}
        .header .risk-badge {{ display: inline-block; margin-top: 15px; padding: 8px 24px; border-radius: 20px; font-weight: bold; font-size: 1.1em; background: {risk_color}; color: white; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .section {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .section h2 {{ color: #1a1a2e; margin-bottom: 16px; font-size: 1.4em; border-bottom: 2px solid #e9ecef; padding-bottom: 8px; }}
        .section h3 {{ color: #16213e; margin: 12px 0 8px; font-size: 1.1em; }}
        .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }}
        .card {{ background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        .card .number {{ font-size: 2.5em; font-weight: bold; }}
        .card .label {{ color: #666; font-size: 0.9em; margin-top: 4px; }}
        .card.total .number {{ color: #0f3460; }}
        .card.vulnerable .number {{ color: #fd7e14; }}
        .card.high .number {{ color: #dc3545; }}
        .card.medium .number {{ color: #ffc107; }}
        .card.low .number {{ color: #28a745; }}
        .card.critical .number {{ color: #6f42c1; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th {{ background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; color: white; }}
        .badge-critical {{ background: #6f42c1; }}
        .badge-high {{ background: #dc3545; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; }}
        .badge-none {{ background: #6c757d; }}
        .badge-unknown {{ background: #adb5bd; color: #333; }}
        .badge-exploit {{ background: #ff0000; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.7; }} }}
        .dep-graph {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px; margin-top: 10px; }}
        .tree-text {{ background: #1a1a2e; color: #a8d8a8; padding: 16px; border-radius: 8px; font-family: 'Consolas', 'Courier New', monospace; font-size: 0.85em; white-space: pre; overflow-x: auto; margin-top: 10px; }}
        .dot-source {{ background: #1a1a2e; color: #e0e0e0; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 0.8em; white-space: pre-wrap; max-height: 400px; overflow: auto; }}
        .vuln-card {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; margin-bottom: 12px; border-left: 4px solid #ccc; }}
        .vuln-card.sev-critical {{ border-left-color: #6f42c1; background: #faf5ff; }}
        .vuln-card.sev-high {{ border-left-color: #dc3545; background: #fff5f5; }}
        .vuln-card.sev-medium {{ border-left-color: #ffc107; background: #fffdf5; }}
        .vuln-card.sev-low {{ border-left-color: #28a745; background: #f5fff5; }}
        .vuln-card h4 {{ margin-bottom: 8px; }}
        .vuln-card .meta {{ color: #666; font-size: 0.85em; margin-top: 8px; }}
        .vuln-card .suggestion {{ background: #e8f4fd; padding: 8px 12px; border-radius: 6px; margin-top: 10px; font-size: 0.9em; }}
        .recommendation {{ padding: 12px; margin: 8px 0; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #0f3460; }}
        .recommendation.sev-high {{ border-left-color: #dc3545; }}
        .recommendation.sev-critical {{ border-left-color: #6f42c1; }}
        .footer {{ text-align: center; color: #888; padding: 20px; font-size: 0.85em; }}
        .collapsible {{ cursor: pointer; user-select: none; }}
        .collapsible::after {{ content: " ▼"; font-size: 0.7em; }}
        .collapsible.collapsed::after {{ content: " ▶"; }}
        .collapse-content {{ overflow: hidden; transition: max-height 0.3s; }}
        .collapse-content.hidden {{ max-height: 0 !important; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Supply Chain Security Report</h1>
        <div class="subtitle">{_esc(project_name)} | Scan Date: {scan_date}</div>
        <div class="risk-badge">Risk Score: {risk_score}/100 ({risk_level})</div>
    </div>

    <div class="container">
        <div class="dashboard">
            <div class="card total">
                <div class="number">{scan_result.get('total_packages', 0)}</div>
                <div class="label">Total Dependencies</div>
            </div>
            <div class="card vulnerable">
                <div class="number">{scan_result.get('vulnerable_packages', 0)}</div>
                <div class="label">Vulnerable Packages</div>
            </div>
            <div class="card high">
                <div class="number">{severity.get('high', 0) + severity.get('critical', 0)}</div>
                <div class="label">High/Critical Vulns</div>
            </div>
            <div class="card medium">
                <div class="number">{severity.get('medium', 0)}</div>
                <div class="label">Medium Vulns</div>
            </div>
            <div class="card low">
                <div class="number">{severity.get('low', 0)}</div>
                <div class="label">Low Vulns</div>
            </div>
        </div>

        <!-- Dependency Graph -->
        <div class="section">
            <h2>Dependency Graph</h2>
            {graph_section if graph_section else '<p style="color:#888;">No dependency graph generated.</p>'}
            <h3 style="margin-top:16px;">Dependency Tree (Text)</h3>
            <div class="tree-text">{html.escape(tree_text)}</div>
        </div>

        <!-- All Dependencies -->
        <div class="section">
            <h2 class="collapsible" onclick="toggleCollapse(this)">All Dependencies ({scan_result.get('total_packages', 0)})</h2>
            <div class="collapse-content">
                {dep_list_html}
            </div>
        </div>

        <!-- Vulnerability Details -->
        <div class="section">
            <h2 class="collapsible" onclick="toggleCollapse(this)">Vulnerability Details ({scan_result.get('total_vulnerabilities', 0)})</h2>
            <div class="collapse-content">
                {vuln_details_html}
            </div>
        </div>

        <!-- Recommendations -->
        <div class="section">
            <h2>Upgrade Recommendations</h2>
            {recommendations_html}
        </div>
    </div>

    <div class="footer">
        Generated by SCS Checker v1.0.0 | {scan_date}
    </div>

    <script>
    function toggleCollapse(el) {{
        el.classList.toggle('collapsed');
        var content = el.nextElementSibling;
        content.classList.toggle('hidden');
    }}
    </script>
</body>
</html>"""

    report_path = os.path.join(output_dir, "supply_chain_report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return report_path


def _esc(text: str) -> str:
    """Escape HTML entities."""
    return html.escape(str(text)) if text else ""


def _build_vuln_details_html(packages: List[Dict]) -> str:
    """Build HTML for vulnerability detail cards."""
    parts = []
    has_any = False

    for pkg in packages:
        vulns = pkg.get("vulnerabilities", [])
        if not vulns:
            continue
        has_any = True

        for vuln in vulns:
            sev = vuln.get("severity", "unknown")
            badge_class = f"badge-{sev}"
            sev_label = sev.upper()

            exploit_badge = ""
            if vuln.get("is_actively_exploited"):
                exploit_badge = '<span class="badge badge-exploit">ACTIVELY EXPLOITED</span> '

            cvss_str = f"{vuln['cvss_score']:.1f}" if vuln.get("cvss_score") is not None else "N/A"

            refs_html = ""
            refs = vuln.get("references", [])
            if refs:
                ref_links = " | ".join(
                    f'<a href="{_esc(r["url"])}" target="_blank">{_esc(r.get("type", "Link"))}</a>'
                    for r in refs[:3] if r.get("url")
                )
                refs_html = f'<div class="meta">References: {ref_links}</div>'

            cwes = vuln.get("cwes", [])
            cwe_str = ", ".join(cwes) if cwes else "N/A"

            fix_versions = vuln.get("affected_versions", {}).get("fix_versions", [])
            fix_str = ", ".join(fix_versions) if fix_versions else "No fix available"

            suggestion = _get_suggestion(vuln)

            parts.append(f"""
            <div class="vuln-card sev-{sev}">
                <h4>{exploit_badge}<span class="badge {badge_class}">{sev_label}</span>
                    {_esc(vuln.get('id', 'UNKNOWN'))} - {_esc(vuln.get('summary', 'No summary')[:120])}
                </h4>
                <div>
                    <strong>Package:</strong> {_esc(pkg['package'])}=={_esc(pkg['version'])} |
                    <strong>CVSS:</strong> {cvss_str} |
                    <strong>CWE:</strong> {_esc(cwe_str)} |
                    <strong>Fix:</strong> {_esc(fix_str)}
                </div>
                {refs_html}
                <div class="suggestion"><strong>Suggestion:</strong> {_esc(suggestion)}</div>
            </div>""")

    if not has_any:
        return '<p style="color: #28a745; font-size: 1.1em;">No vulnerabilities detected. All dependencies appear to be clean.</p>'

    return "\n".join(parts)


def _build_recommendations_html(packages: List[Dict]) -> str:
    """Build HTML for upgrade recommendations."""
    parts = []
    has_any = False

    for pkg in packages:
        vulns = pkg.get("vulnerabilities", [])
        if not vulns:
            continue
        has_any = True

        for vuln in vulns:
            sev = vuln.get("severity", "unknown")
            suggestion = _get_suggestion(vuln)
            fix_versions = vuln.get("affected_versions", {}).get("fix_versions", [])

            action = ""
            if fix_versions:
                latest = fix_versions[-1]
                action = f'<strong>Action:</strong> Upgrade {_esc(pkg["package"])} from {_esc(pkg["version"])} to &gt;= {_esc(latest)}'
            else:
                action = f'<strong>Action:</strong> Monitor {_esc(pkg["package"])} for security patches. Consider alternative packages.'

            parts.append(f"""
            <div class="recommendation sev-{sev}">
                <span class="badge badge-{sev}">{sev.upper()}</span>
                <strong> {_esc(vuln.get('id', ''))}</strong>: {_esc(vuln.get('summary', '')[:100])}<br>
                {action}
            </div>""")

    if not has_any:
        return '<p style="color: #28a745;">No recommendations needed - no vulnerabilities found.</p>'

    return "\n".join(parts)


def _build_dependency_list_html(packages: List[Dict]) -> str:
    """Build HTML table of all dependencies."""
    rows = []
    for pkg in sorted(packages, key=lambda p: p.get("package", "")):
        vuln_count = pkg.get("vuln_count", 0)
        count_display = f'{vuln_count}' if vuln_count > 0 else "0"
        count_class = "high" if vuln_count > 0 else ""

        vuln_badges = ""
        for v in pkg.get("vulnerabilities", []):
            sev = v.get("severity", "unknown")
            vuln_badges += f' <span class="badge badge-{sev}">{v.get("id", "")}</span>'

        rows.append(f"""
            <tr>
                <td><strong>{_esc(pkg['package'])}</strong></td>
                <td>{_esc(pkg['version'])}</td>
                <td class="{count_class}">{count_display}{vuln_badges}</td>
            </tr>""")

    return f"""
    <table>
        <thead>
            <tr><th>Package</th><th>Version</th><th>Vulnerabilities</th></tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>"""


def _get_suggestion(vuln: Dict) -> str:
    """Get upgrade suggestion for a vulnerability."""
    fix_versions = vuln.get("affected_versions", {}).get("fix_versions", [])
    if fix_versions:
        return f"Upgrade to version {fix_versions[-1]} or later"
    summary = vuln.get("summary", "").lower()
    if "deprecat" in summary:
        return "Consider replacing with a maintained alternative"
    return "No known fix version. Monitor upstream for updates."


def _format_tree_text(node: Dict, prefix: str = "", is_last: bool = True, is_root: bool = True) -> str:
    """Format dependency tree as readable text."""
    lines = []
    if is_root:
        total = node.get("total_packages", "?")
        lines.append(f"{node['name']} ({total} packages total)")
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
        lines.append(_format_tree_text(child, child_prefix, is_child_last, is_root=False))

    return "\n".join(lines)


def generate_json_report(scan_result: Dict, output_dir: str, project_name: str = "Project") -> str:
    """Generate JSON report with full scan data."""
    os.makedirs(output_dir, exist_ok=True)

    report_data = {
        "tool": "SCS Checker",
        "version": "1.0.0",
        "project_name": project_name,
        "scan_time": scan_result.get("scan_time", datetime.now().isoformat()),
        "summary": {
            "total_packages": scan_result.get("total_packages", 0),
            "vulnerable_packages": scan_result.get("vulnerable_packages", 0),
            "total_vulnerabilities": scan_result.get("total_vulnerabilities", 0),
            "severity_counts": scan_result.get("severity_counts", {}),
        },
        "packages": scan_result.get("packages", []),
    }

    json_path = os.path.join(output_dir, "scan_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    return json_path


def generate_dependency_graph(
    dep_tree: Dict,
    scan_result: Dict,
    output_dir: str,
) -> Optional[str]:
    """Generate a Graphviz DOT dependency graph with vulnerability highlighting.

    Returns path to DOT file (and PNG if graphviz is installed).
    """
    os.makedirs(output_dir, exist_ok=True)

    # Build vulnerability lookup
    vuln_lookup: Dict[str, str] = {}
    for pkg in scan_result.get("packages", []):
        pkg_name = pkg.get("package", "").lower()
        if pkg.get("vuln_count", 0) > 0:
            worst = "low"
            for v in pkg.get("vulnerabilities", []):
                sev = v.get("severity", "none")
                if sev in ("critical", "high") and worst not in ("critical",):
                    worst = sev
                elif sev == "medium" and worst not in ("critical", "high"):
                    worst = sev
            vuln_lookup[pkg_name] = worst

    # Generate DOT
    lines = [
        'digraph "Dependency Graph" {',
        '  rankdir=TB;',
        '  node [shape=box, style=filled, fontname="Arial", fontsize=10];',
        '  edge [color="#666666"];',
        '  "requirements.txt" [shape=ellipse, fillcolor="#1a1a2e", fontcolor=white, fontsize=12];',
    ]

    visited = set()

    def add_nodes(node: Dict, parent_name: str):
        name = node.get("name", "")
        version = node.get("version", "")
        node_id = f"{name}"

        if node_id not in visited:
            visited.add(node_id)
            severity = vuln_lookup.get(name.lower(), "")

            if severity == "critical":
                color = "#6f42c1"
                fontcolor = "white"
            elif severity == "high":
                color = "#dc3545"
                fontcolor = "white"
            elif severity == "medium":
                color = "#ffc107"
                fontcolor = "black"
            elif severity == "low":
                color = "#28a745"
                fontcolor = "white"
            else:
                color = "#e8f4fd"
                fontcolor = "black"

            label = f"{name}\\n{version}" if version else name
            lines.append(f'  "{node_id}" [label="{label}", fillcolor="{color}", fontcolor="{fontcolor}"];')

        edge_label = ""
        lines.append(f'  "{parent_name}" -> "{node_id}"{edge_label};')

        for child in node.get("children", []):
            add_nodes(child, name)

    for child in dep_tree.get("children", []):
        add_nodes(child, "requirements.txt")

    # Legend
    lines.extend([
        '  subgraph cluster_legend {',
        '    label="Legend";',
        '    style=dashed;',
        '    "legend_vuln_high" [label="High/Critical Vuln", fillcolor="#dc3545", fontcolor=white];',
        '    "legend_vuln_med" [label="Medium Vuln", fillcolor="#ffc107", fontcolor=black];',
        '    "legend_vuln_low" [label="Low Vuln", fillcolor="#28a745", fontcolor=white];',
        '    "legend_clean" [label="No Vulns", fillcolor="#e8f4fd", fontcolor=black];',
        '  }',
        '}',
    ])

    dot_content = "\n".join(lines)
    dot_path = os.path.join(output_dir, "dependency_graph.dot")
    with open(dot_path, "w", encoding="utf-8") as f:
        f.write(dot_content)

    # Try to render with graphviz
    png_path = os.path.join(output_dir, "dependency_graph.png")
    try:
        import graphviz
        src = graphviz.Source(dot_content)
        src.render(
            filename=os.path.join(output_dir, "dependency_graph"),
            format="png",
            cleanup=True,
        )
        print(f"    [OK] Dependency graph rendered as PNG")
    except ImportError:
        print(f"    [!] graphviz Python package not installed, DOT file saved only")
    except Exception as e:
        print(f"    [!] Could not render graph: {e}")

    return dot_path
