"""
SVG 依赖关系图渲染器 - 纯 Python 实现，无需 Graphviz 二进制程序。
生成带有漏洞颜色标记的依赖树 SVG 图像。
"""
import html as html_module
from typing import Dict, List, Optional


# Layout parameters
NODE_WIDTH = 180
NODE_HEIGHT = 44
H_GAP = 24
V_GAP = 56
PADDING = 40
FONT_SIZE = 11
VERSION_FONT_SIZE = 9

# Severity colors
COLORS = {
    "critical": {"bg": "#6f42c1", "text": "white", "border": "#5a32a3"},
    "high":     {"bg": "#dc3545", "text": "white", "border": "#b02a37"},
    "medium":   {"bg": "#ffc107", "text": "#333",  "border": "#cc9a06"},
    "low":      {"bg": "#28a745", "text": "white", "border": "#207536"},
    "none":     {"bg": "#e8f4fd", "text": "#333",  "border": "#b0d4f1"},
    "root":     {"bg": "#1a1a2e", "text": "white", "border": "#0f3460"},
}


def render_dependency_tree_svg(
    dep_tree: Dict,
    scan_result: Dict,
    output_path: str,
) -> str:
    """Render dependency tree as an SVG image.

    Args:
        dep_tree: dependency tree dict
        scan_result: scan results with vulnerability info
        output_path: where to save the SVG

    Returns:
        Path to the generated SVG file.
    """
    # Build vulnerability lookup
    vuln_lookup: Dict[str, str] = {}
    for pkg in scan_result.get("packages", []):
        pkg_name = pkg.get("package", "").lower()
        if pkg.get("vuln_count", 0) > 0:
            worst = "low"
            for v in pkg.get("vulnerabilities", []):
                sev = v.get("severity", "none")
                if sev == "critical":
                    worst = "critical"
                elif sev == "high" and worst != "critical":
                    worst = "high"
                elif sev == "medium" and worst not in ("critical", "high"):
                    worst = "medium"
            vuln_lookup[pkg_name] = worst

    # Calculate tree layout
    positions = {}
    x_counter = [0]

    def assign_positions(node: Dict, depth: int):
        children = node.get("children", [])
        if not children:
            x = x_counter[0]
            x_counter[0] += 1
            positions[id(node)] = (x, depth)
            return x

        child_xs = []
        for child in children:
            cx = assign_positions(child, depth + 1)
            child_xs.append(cx)

        x = sum(child_xs) / len(child_xs)
        positions[id(node)] = (x, depth)
        return x

    assign_positions(dep_tree, 0)

    # Calculate SVG dimensions
    max_x = max(pos[0] for pos in positions.values()) if positions else 0
    max_depth = max(pos[1] for pos in positions.values()) if positions else 0

    svg_width = int((max_x + 1) * (NODE_WIDTH + H_GAP) + PADDING * 2)
    svg_height = int((max_depth + 1) * (NODE_HEIGHT + V_GAP) + PADDING * 2 + 60)

    # Generate SVG
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_width}" height="{svg_height}" '
        f'viewBox="0 0 {svg_width} {svg_height}">',
        '<defs>',
        '  <filter id="shadow" x="-5%" y="-5%" width="110%" height="115%">',
        '    <feDropShadow dx="1" dy="2" stdDeviation="2" flood-opacity="0.15"/>',
        '  </filter>',
        '  <style>',
        '    text { font-family: "Segoe UI", Arial, sans-serif; }',
        '    .node-name { font-weight: 600; }',
        '    .node-version { opacity: 0.85; }',
        '    .edge { stroke: #999; stroke-width: 1.5; fill: none; }',
        '  </style>',
        '</defs>',
        f'<rect width="{svg_width}" height="{svg_height}" fill="#f8f9fa"/>',
    ]

    # Title
    svg_parts.append(
        f'<text x="{svg_width // 2}" y="28" text-anchor="middle" '
        f'font-size="16" font-weight="bold" fill="#1a1a2e">Dependency Graph</text>'
    )

    # Draw edges first (so they're behind nodes)
    def draw_edges(node: Dict):
        pos = positions.get(id(node))
        if not pos:
            return
        parent_cx = PADDING + pos[0] * (NODE_WIDTH + H_GAP) + NODE_WIDTH / 2
        parent_cy = PADDING + 50 + pos[1] * (NODE_HEIGHT + V_GAP) + NODE_HEIGHT

        for child in node.get("children", []):
            child_pos = positions.get(id(child))
            if not child_pos:
                continue
            child_cx = PADDING + child_pos[0] * (NODE_WIDTH + H_GAP) + NODE_WIDTH / 2
            child_cy = PADDING + 50 + child_pos[1] * (NODE_HEIGHT + V_GAP)

            # Draw curved edge
            mid_y = (parent_cy + child_cy) / 2
            svg_parts.append(
                f'<path class="edge" d="M{parent_cx},{parent_cy} '
                f'C{parent_cx},{mid_y} {child_cx},{mid_y} {child_cx},{child_cy}"/>'
            )
            draw_edges(child)

    draw_edges(dep_tree)

    # Draw nodes
    def draw_nodes(node: Dict):
        pos = positions.get(id(node))
        if not pos:
            return

        x = PADDING + pos[0] * (NODE_WIDTH + H_GAP)
        y = PADDING + 50 + pos[1] * (NODE_HEIGHT + V_GAP)

        name = node.get("name", "")
        version = node.get("version", "")
        is_root = (pos[1] == 0)

        if is_root:
            color_key = "root"
        else:
            color_key = vuln_lookup.get(name.lower(), "none")

        colors = COLORS.get(color_key, COLORS["none"])

        # Node rectangle with rounded corners
        svg_parts.append(
            f'<rect x="{x}" y="{y}" width="{NODE_WIDTH}" height="{NODE_HEIGHT}" '
            f'rx="8" ry="8" fill="{colors["bg"]}" stroke="{colors["border"]}" '
            f'stroke-width="1.5" filter="url(#shadow)"/>'
        )

        # Package name
        display_name = name[:22] + ".." if len(name) > 24 else name
        svg_parts.append(
            f'<text class="node-name" x="{x + NODE_WIDTH // 2}" y="{y + 18}" '
            f'text-anchor="middle" font-size="{FONT_SIZE}" fill="{colors["text"]}">'
            f'{html_module.escape(display_name)}</text>'
        )

        # Version
        if version:
            display_ver = version[:20] if len(version) <= 20 else version[:18] + ".."
            svg_parts.append(
                f'<text class="node-version" x="{x + NODE_WIDTH // 2}" y="{y + 34}" '
                f'text-anchor="middle" font-size="{VERSION_FONT_SIZE}" fill="{colors["text"]}">'
                f'{html_module.escape(display_ver)}</text>'
            )

        for child in node.get("children", []):
            draw_nodes(child)

    draw_nodes(dep_tree)

    # Legend
    legend_y = svg_height - 35
    legend_items = [
        ("Critical", COLORS["critical"]["bg"]),
        ("High", COLORS["high"]["bg"]),
        ("Medium", COLORS["medium"]["bg"]),
        ("Low", COLORS["low"]["bg"]),
        ("Clean", COLORS["none"]["bg"]),
    ]
    legend_x = PADDING
    for label, color in legend_items:
        svg_parts.append(
            f'<rect x="{legend_x}" y="{legend_y}" width="14" height="14" rx="3" fill="{color}"/>'
        )
        svg_parts.append(
            f'<text x="{legend_x + 20}" y="{legend_y + 12}" font-size="11" fill="#333">{label}</text>'
        )
        legend_x += 85

    svg_parts.append('</svg>')

    svg_content = "\n".join(svg_parts)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    return output_path
