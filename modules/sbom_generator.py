"""
SBOM 生成模块 - Software Bill of Materials Generator

生成 CycloneDX 格式的 SBOM（软件物料清单）。
"""
import json
import os
import uuid
from datetime import datetime
from typing import Dict, List


def generate_sbom(
    resolved_packages: Dict[str, str],
    scan_result: Dict,
    output_dir: str,
    project_name: str = "Project",
) -> str:
    """Generate a CycloneDX-format SBOM in JSON.

    Args:
        resolved_packages: dict of {package_name: version}
        scan_result: vulnerability scan results
        output_dir: directory to save the SBOM
        project_name: project name

    Returns:
        Path to the generated SBOM file.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Build CycloneDX SBOM structure
    components = []
    for pkg_name, version in sorted(resolved_packages.items()):
        # Find vulnerability info for this package
        vuln_refs = []
        for pkg_result in scan_result.get("packages", []):
            if pkg_result.get("package", "").lower() == pkg_name.lower():
                for vuln in pkg_result.get("vulnerabilities", []):
                    vuln_refs.append({
                        "id": vuln.get("id", "UNKNOWN"),
                        "source": {"name": "OSV", "url": "https://osv.dev"},
                    })
                break

        component = {
            "type": "library",
            "name": pkg_name,
            "version": version,
            "purl": f"pkg:pypi/{pkg_name}@{version}",
            "bom-ref": f"{pkg_name}@{version}",
        }

        if vuln_refs:
            component["vulnerabilities"] = vuln_refs

        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "tools": [
                {
                    "vendor": "SCS Checker",
                    "name": "scs-checker",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "name": project_name,
                "version": "1.0.0",
            },
        },
        "components": components,
    }

    sbom_path = os.path.join(output_dir, "sbom.json")
    with open(sbom_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    return sbom_path
