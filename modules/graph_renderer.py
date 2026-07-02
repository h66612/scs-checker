"""
SVG 依赖关系图渲染器 - 纯 Python 实现，无需 Graphviz 二进制程序。
生成带有漏洞颜色标记的依赖树 SVG 图像（从左到右布局）。
"""
import html as html_module
from typing import Dict, List, Optional


# Layout parameters
NODE_WIDTH = 130
NODE_HEIGHT = 36
H_GAP = 50   # horizontal gap between depth levels (left-to-right)
V_GAP = 14   # vertical gap between sibling nodes
PADDING = 30
FONT_SIZE = 10
VERSION_FONT_SIZE = 8

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
    """Render dependency tree as an SVG image (left-to-right layout).

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

    # Calculate tree layout — left-to-right (depth = x, leaf counter = y)
    positions = {}
    y_counter = [0]

    def assign_positions(node: Dict, depth: int):
        children = node.get("children", [])
        if not children:
            y = y_counter[0]
            y_counter[0] += 1
            positions[id(node)] = (depth, y)
            return y

        child_ys = []
        for child in children:
            cy = assign_positions(child, depth + 1)
            child_ys.append(cy)

        y = sum(child_ys) / len(child_ys)
        positions[id(node)] = (depth, y)
        return y

    assign_positions(dep_tree, 0)

    # Calculate SVG dimensions — width based on depth, height based on leaf count
    max_depth = max(pos[0] for pos in positions.values()) if positions else 0
    max_y = max(pos[1] for pos in positions.values()) if positions else 0

    svg_width = int((max_depth + 1) * (NODE_WIDTH + H_GAP) + PADDING * 2)
    svg_height = int((max_y + 1) * (NODE_HEIGHT + V_GAP) + PADDING * 2 + 50)

    # Generate SVG
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_width}" height="{svg_height}" '
        f'viewBox="0 0 {svg_width} {svg_height}" '
        f'style="background: #f8f9fa;">',
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
        f'<text x="{PADDING}" y="24" '
        f'font-size="16" font-weight="bold" fill="#1a1a2e">Dependency Graph</text>'
    )

    # Draw edges first (so they're behind nodes)
    def draw_edges(node: Dict):
        pos = positions.get(id(node))
        if not pos:
            return
        # Parent right edge
        parent_cx = PADDING + pos[0] * (NODE_WIDTH + H_GAP) + NODE_WIDTH
        parent_cy = PADDING + 40 + pos[1] * (NODE_HEIGHT + V_GAP) + NODE_HEIGHT / 2

        for child in node.get("children", []):
            child_pos = positions.get(id(child))
            if not child_pos:
                continue
            # Child left edge
            child_cx = PADDING + child_pos[0] * (NODE_WIDTH + H_GAP)
            child_cy = PADDING + 40 + child_pos[1] * (NODE_HEIGHT + V_GAP) + NODE_HEIGHT / 2

            # Draw curved edge (left to right)
            mid_x = (parent_cx + child_cx) / 2
            svg_parts.append(
                f'<path class="edge" d="M{parent_cx},{parent_cy} '
                f'C{mid_x},{parent_cy} {mid_x},{child_cy} {child_cx},{child_cy}"/>'
            )
            draw_edges(child)

    draw_edges(dep_tree)

    # Draw nodes
    def draw_nodes(node: Dict):
        pos = positions.get(id(node))
        if not pos:
            return

        x = PADDING + pos[0] * (NODE_WIDTH + H_GAP)
        y = PADDING + 40 + pos[1] * (NODE_HEIGHT + V_GAP)

        name = node.get("name", "")
        version = node.get("version", "")
        is_root = (pos[0] == 0)

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
            f'<text class="node-name" x="{x + NODE_WIDTH // 2}" y="{y + 16}" '
            f'text-anchor="middle" font-size="{FONT_SIZE}" fill="{colors["text"]}">'
            f'{html_module.escape(display_name)}</text>'
        )

        # Version
        if version:
            display_ver = version[:20] if len(version) <= 20 else version[:18] + ".."
            svg_parts.append(
                f'<text class="node-version" x="{x + NODE_WIDTH // 2}" y="{y + 30}" '
                f'text-anchor="middle" font-size="{VERSION_FONT_SIZE}" fill="{colors["text"]}">'
                f'{html_module.escape(display_ver)}</text>'
            )

        for child in node.get("children", []):
            draw_nodes(child)

    draw_nodes(dep_tree)

    # Legend
    legend_y = svg_height - 25
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
