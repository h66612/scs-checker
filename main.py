#!/usr/bin/env python3
"""
SCS Checker - 开源软件供应链安全检测工具
Open Source Software Supply Chain Security Detection Tool

Usage:
    python main.py -r requirements.txt [-o output_dir] [-n project_name]

Features:
    - Parse requirements.txt and resolve transitive dependencies
    - Query OSV.dev API for known vulnerabilities
    - Generate HTML report with dependency graph visualization
    - Export JSON scan results and CycloneDX SBOM
"""
import sys
import os
import argparse
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.dependency_parser import parse_and_resolve, format_tree_text
from modules.vulnerability_checker import VulnerabilityChecker
from modules.report_generator import (
    generate_html_report,
    generate_json_report,
    generate_dependency_graph,
)
from modules.sbom_generator import generate_sbom
from modules.graph_renderer import render_dependency_tree_svg


def main():
    parser = argparse.ArgumentParser(
        description="SCS Checker - Open Source Supply Chain Security Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -r requirements.txt
  python main.py -r requirements.txt -o ./reports -n "My Project"
  python main.py -r test_project/requirements.txt --sbom --graph
        """,
    )
    parser.add_argument(
        "-r", "--requirements",
        required=True,
        help="Path to requirements.txt file",
    )
    parser.add_argument(
        "-o", "--output",
        default="reports",
        help="Output directory for reports (default: reports/)",
    )
    parser.add_argument(
        "-n", "--name",
        default=None,
        help="Project name (default: derived from requirements file path)",
    )
    parser.add_argument(
        "--no-sbom",
        action="store_true",
        help="Skip SBOM generation",
    )
    parser.add_argument(
        "--no-graph",
        action="store_true",
        help="Skip dependency graph generation",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Scan timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.35,
        help="API rate limit delay in seconds (default: 0.35)",
    )
    parser.add_argument(
        "--cache-dir",
        default="cache",
        help="Cache directory for vulnerability data (default: cache/)",
    )

    args = parser.parse_args()

    # Derive project name if not specified
    project_name = args.name
    if not project_name:
        req_dir = os.path.dirname(os.path.abspath(args.requirements))
        project_name = os.path.basename(req_dir) or "Project"

    # Setup output directory
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    cache_dir = os.path.abspath(args.cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    # Banner
    print("=" * 65)
    print("  SCS Checker - Open Source Supply Chain Security Detection Tool")
    print("  Version 1.0.0")
    print("=" * 65)
    print()
    print(f"  Project:     {project_name}")
    print(f"  Requirements: {os.path.abspath(args.requirements)}")
    print(f"  Output:      {output_dir}")
    print(f"  SBOM:        {'No' if args.no_sbom else 'Yes'}")
    print(f"  Graph:       {'No' if args.no_graph else 'Yes'}")
    print(f"  Cache:       {cache_dir}")
    print()

    # ============================================
    # Phase 1: Parse dependencies
    # ============================================
    print("[Phase 1] Parsing dependencies...")
    print("-" * 45)

    requirements_path = os.path.abspath(args.requirements)
    if not os.path.exists(requirements_path):
        print(f"  [ERROR] File not found: {requirements_path}")
        sys.exit(1)

    dep_tree, direct_packages, resolved_packages = parse_and_resolve(requirements_path)

    if not resolved_packages:
        print("  [ERROR] No packages resolved. Check your requirements file.")
        sys.exit(1)

    print(f"\n  Dependency Tree:")
    print(f"  {'=' * 40}")
    tree_text = format_tree_text(dep_tree)
    for line in tree_text.split("\n"):
        print(f"  {line}")
    print()

    # ============================================
    # Phase 2: Scan for vulnerabilities
    # ============================================
    print("[Phase 2] Scanning for vulnerabilities...")
    print("-" * 45)

    checker = VulnerabilityChecker(
        cache_dir=cache_dir,
        rate_limit_delay=args.rate_limit,
    )
    scan_result = checker.check_all(resolved_packages, project_name=project_name)

    # Print summary
    sev = scan_result["severity_counts"]
    print(f"\n  Scan Results:")
    print(f"  {'=' * 40}")
    print(f"  Total packages scanned: {scan_result['total_packages']}")
    print(f"  Vulnerable packages:    {scan_result['vulnerable_packages']}")
    print(f"  Total vulnerabilities:  {scan_result['total_vulnerabilities']}")
    print(f"    Critical: {sev.get('critical', 0)}")
    print(f"    High:     {sev.get('high', 0)}")
    print(f"    Medium:   {sev.get('medium', 0)}")
    print(f"    Low:      {sev.get('low', 0)}")
    print(f"    None:     {sev.get('none', 0)}")
    print()

    # ============================================
    # Phase 3: Generate reports
    # ============================================
    print("[Phase 3] Generating reports...")
    print("-" * 45)

    # Dependency graph
    if not args.no_graph:
        print("  [*] Generating dependency graph...")
        dot_path = generate_dependency_graph(dep_tree, scan_result, output_dir)
        if dot_path:
            print(f"      DOT file: {dot_path}")
        # Always generate SVG as well (pure Python, no Graphviz binary needed)
        svg_path = os.path.join(output_dir, "dependency_graph.svg")
        render_dependency_tree_svg(dep_tree, scan_result, svg_path)
        print(f"      SVG file: {svg_path}")

    # HTML report
    print("  [*] Generating HTML report...")
    html_path = generate_html_report(scan_result, dep_tree, output_dir, project_name)
    print(f"      HTML report: {html_path}")

    # JSON report
    print("  [*] Generating JSON report...")
    json_path = generate_json_report(scan_result, output_dir, project_name)
    print(f"      JSON report: {json_path}")

    # SBOM
    if not args.no_sbom:
        print("  [*] Generating SBOM (CycloneDX)...")
        sbom_path = generate_sbom(resolved_packages, scan_result, output_dir, project_name)
        print(f"      SBOM: {sbom_path}")

    print()
    print("=" * 65)
    print("  Scan complete!")
    print(f"  Reports saved to: {output_dir}")
    print("=" * 65)

    return 0


if __name__ == "__main__":
    sys.exit(main())
