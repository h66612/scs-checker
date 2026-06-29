// SCS Checker - Result Page JavaScript (Enhanced v2)
// Handles: risk gauge, charts (severity + package + CWE), table filtering,
// dependency tree, fix suggestions, package detail, export, toasts

let severityChart = null, packageChart = null, cweChart = null;
let allVulns = [], scanData = null;

document.addEventListener('DOMContentLoaded', function() {
    loadResultData();
    document.getElementById('severityFilter').addEventListener('change', filterTable);
    document.getElementById('tableSearch').addEventListener('input', filterTable);
    document.getElementById('treeSearch').addEventListener('input', filterTree);
});

// === Load Result Data ===
function loadResultData() {
    var metaEl = document.getElementById('resultMeta');
    fetch('/api/result/' + SCAN_ID)
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status + ' ' + r.statusText);
            return r.json();
        })
        .then(function(data) {
            if (data.error) {
                metaEl.textContent = '加载失败: ' + data.error;
                metaEl.style.color = '#f85149';
                return;
            }
            console.log('[SCS] Result data loaded:', Object.keys(data));
            scanData = data;
            try {
                renderSummary(data);
                renderSeverityBar(data);
                renderRiskGauge(data);
                renderCharts(data);
                renderTable(data);
                renderDepTree(data);
                renderFixSuggestions(data);
            } catch(renderErr) {
                console.error('[SCS] Render error:', renderErr);
                metaEl.textContent = '渲染错误: ' + renderErr.message;
                metaEl.style.color = '#f85149';
            }
        })
        .catch(function(err) {
            console.error('[SCS] Load error:', err);
            metaEl.textContent = '加载失败: ' + err.message + ' (scan_id=' + SCAN_ID + ')';
            metaEl.style.color = '#f85149';
        });
}

// === Summary Cards ===
function renderSummary(data) {
    const sev = data.severity_counts || {};
    const summary = data.summary || {};
    const total = summary.total_packages || data.total_packages || 0;
    const vulnPkgs = summary.vulnerable_packages || data.vulnerable_packages || 0;

    document.getElementById('totalPackages').textContent = total;
    document.getElementById('vulnPackages').textContent = vulnPkgs;
    document.getElementById('totalVulns').textContent = summary.total_vulnerabilities || data.total_vulnerabilities || 0;
    document.getElementById('safePackages').textContent = total - vulnPkgs;

    document.getElementById('sevCritical').textContent = sev.critical || 0;
    document.getElementById('sevHigh').textContent = sev.high || 0;
    document.getElementById('sevMedium').textContent = sev.medium || 0;
    document.getElementById('sevLow').textContent = sev.low || 0;

    const projName = data.db_project_name || data.project_name || 'Unknown';
    const scanTime = data.db_scan_time || data.scan_time || '';
    document.getElementById('resultMeta').textContent = '项目: ' + projName + ' | 扫描时间: ' + scanTime;
}

// === Risk Gauge ===
function renderRiskGauge(data) {
    const sev = data.severity_counts || {};
    const riskScore = data.db_risk_score || 0;
    const arc = document.getElementById('riskGaugeArc');
    const scoreEl = document.getElementById('riskScore');
    const levelEl = document.getElementById('riskLevel');
    const riskCard = document.getElementById('riskCard');

    // Animate score number
    animateNumber(scoreEl, 0, riskScore, 1000);

    // Arc: circumference = 251 (half circle), offset = 251 * (1 - score/100)
    const circumference = 251;
    const offset = circumference * (1 - riskScore / 100);

    // Determine color and level
    let color, level;
    if (sev.critical > 0) { color = '#ff6b6b'; level = '严重 (Critical)'; riskCard.style.borderColor = '#ff6b6b'; scoreEl.style.color = '#ff6b6b'; }
    else if (sev.high > 0) { color = '#f85149'; level = '高危 (High)'; riskCard.style.borderColor = '#f85149'; scoreEl.style.color = '#f85149'; }
    else if (sev.medium > 0) { color = '#d29922'; level = '中危 (Medium)'; riskCard.style.borderColor = '#d29922'; scoreEl.style.color = '#d29922'; }
    else if (sev.low > 0) { color = '#3fb950'; level = '低危 (Low)'; riskCard.style.borderColor = '#3fb950'; scoreEl.style.color = '#3fb950'; }
    else { color = '#58a6ff'; level = '安全 (Safe)'; riskCard.style.borderColor = '#58a6ff'; scoreEl.style.color = '#58a6ff'; }

    levelEl.textContent = level;

    // Animate arc after a small delay for transition effect
    setTimeout(function() {
        arc.style.stroke = color;
        arc.style.strokeDashoffset = offset;
    }, 200);
}

// === Severity Stacked Bar ===
function renderSeverityBar(data) {
    const sev = data.severity_counts || {};
    const total = (sev.critical||0) + (sev.high||0) + (sev.medium||0) + (sev.low||0);
    const container = document.getElementById('severityBar');

    if (total === 0) {
        container.innerHTML = '<div class="severity-bar-segment" style="width:100%; background:#1a3a5c">无漏洞</div>';
        return;
    }

    const segments = [
        {sev: 'critical', count: sev.critical||0, color: '#7d1a1a'},
        {sev: 'high', count: sev.high||0, color: '#8b2020'},
        {sev: 'medium', count: sev.medium||0, color: '#6b4c10'},
        {sev: 'low', count: sev.low||0, color: '#1a4d1a'},
    ];

    container.innerHTML = segments.map(function(s) {
        if (s.count === 0) return '';
        const pct = (s.count / total * 100).toFixed(1);
        return '<div class="severity-bar-segment" style="width:' + pct + '%; background:' + s.color + '" title="' + s.sev + ': ' + s.count + '">' + s.count + '</div>';
    }).join('');
}

// === Charts ===
function renderCharts(data) {
    const sev = data.severity_counts || {};
    renderSeverityChart(sev);
    renderPackageChart(data.packages || []);
    renderCweChart(data.packages || []);
}

function renderSeverityChart(sev) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['严重', '高危', '中危', '低危'],
            datasets: [{
                data: [sev.critical||0, sev.high||0, sev.medium||0, sev.low||0],
                backgroundColor: ['#7d1a1a', '#8b2020', '#6b4c10', '#1a4d1a'],
                borderColor: ['#ff6b6b', '#f85149', '#d29922', '#3fb950'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#c9d1d9', padding: 8, font: {size: 11} } },
                tooltip: { callbacks: { label: function(c) { return c.label + ': ' + c.parsed + ' 个'; } } }
            }
        }
    });
}

function renderPackageChart(packages) {
    const vulnPkgs = packages.filter(function(p) { return p.vuln_count > 0; })
        .sort(function(a, b) { return b.vuln_count - a.vuln_count; }).slice(0, 10);
    const ctx = document.getElementById('packageChart').getContext('2d');
    if (packageChart) packageChart.destroy();
    packageChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: vulnPkgs.map(function(p) { return p.package; }),
            datasets: [{
                data: vulnPkgs.map(function(p) { return p.vuln_count; }),
                backgroundColor: vulnPkgs.map(function(p) {
                    var w = getWorstSeverity(p);
                    return w === 'critical' ? '#7d1a1a' : w === 'high' ? '#8b2020' : w === 'medium' ? '#6b4c10' : '#1a4d1a';
                }),
                borderColor: vulnPkgs.map(function(p) {
                    var w = getWorstSeverity(p);
                    return w === 'critical' ? '#ff6b6b' : w === 'high' ? '#f85149' : w === 'medium' ? '#d29922' : '#3fb950';
                }),
                borderWidth: 1
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e' }, grid: { color: '#30363d' } },
                y: { ticks: { color: '#c9d1d9', font: {size: 11} }, grid: { display: false } }
            }
        }
    });
}

// === CWE Chart (NEW) ===
function renderCweChart(packages) {
    const cweCounter = {};
    for (const pkg of packages) {
        for (const vuln of (pkg.vulnerabilities || [])) {
            for (const cwe of (vuln.cwes || [])) {
                cweCounter[cwe] = (cweCounter[cwe] || 0) + 1;
            }
        }
    }
    const sorted = Object.entries(cweCounter).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 8);

    const ctx = document.getElementById('cweChart').getContext('2d');
    if (cweChart) cweChart.destroy();
    cweChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(function(e) { return e[0]; }),
            datasets: [{
                data: sorted.map(function(e) { return e[1]; }),
                backgroundColor: '#1a3a5c',
                borderColor: '#58a6ff',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: function(c) { return c.parsed.x + ' 个漏洞'; } } }
            },
            scales: {
                x: { ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: '#30363d' } },
                y: { ticks: { color: '#c9d1d9', font: {size: 10} }, grid: { display: false } }
            }
        }
    });
}

// === Fix Suggestions (NEW) ===
function renderFixSuggestions(data) {
    const packages = data.packages || [];
    const suggestions = [];

    for (const pkg of packages) {
        if (pkg.vuln_count > 0 && pkg.vulnerabilities) {
            // Collect all fixed versions
            const fixedVersions = new Set();
            for (const v of pkg.vulnerabilities) {
                var fixes = getFixVersions(v);
                fixes.forEach(function(f) { if (f && f !== '-') fixedVersions.add(f); });
            }
            if (fixedVersions.size > 0) {
                const worst = getWorstSeverity(pkg);
                suggestions.push({
                    name: pkg.package,
                    version: pkg.version,
                    fixed: Array.from(fixedVersions).sort(),
                    vulnCount: pkg.vuln_count,
                    worst: worst
                });
            }
        }
    }

    if (suggestions.length === 0) {
        document.getElementById('fixSuggestionsCard').style.display = 'none';
        return;
    }

    // Sort by worst severity
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
    suggestions.sort(function(a, b) { return (sevOrder[a.worst]||5) - (sevOrder[b.worst]||5); });

    const body = document.getElementById('fixSuggestionsBody');
    body.innerHTML = suggestions.map(function(s) {
        const targetVer = s.fixed[s.fixed.length - 1] || s.fixed[0];
        const sevClass = 'sev-' + (s.worst || 'none');
        return '<div class="fix-suggestion-item">' +
            '<div class="flex-grow-1">' +
                '<span class="pkg-name">' + escapeHtml(s.name) + '</span> ' +
                '<span class="badge ' + sevClass + ' me-2">' + s.vulnCount + ' vulns</span>' +
                '<div class="version-change mt-1">' +
                    '<span class="text-danger">v' + escapeHtml(s.version) + '</span>' +
                    '<span class="arrow">→</span>' +
                    '<span class="text-success">v' + escapeHtml(targetVer) + '</span>' +
                '</div>' +
            '</div>' +
            '<button class="btn btn-sm btn-outline-info ms-2" onclick="showPackageDetail(\'' + escapeHtml(s.name) + '\')">' +
                '<i class="bi bi-info-circle"></i></button>' +
        '</div>';
    }).join('');

    document.getElementById('fixSuggestionsCard').style.display = '';
}

// === Table ===
function renderTable(data) {
    allVulns = [];
    for (const pkg of data.packages || []) {
        if (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) {
            for (const vuln of pkg.vulnerabilities) {
                allVulns.push({
                    package: pkg.package, version: pkg.version,
                    id: vuln.id || 'N/A', severity: vuln.severity || 'unknown',
                    cvss: vuln.cvss_score || '-', summary: vuln.summary || '',
                    fixed_version: getFixVersions(vuln),
                    aliases: vuln.aliases || [], cwe: vuln.cwes || [],
                    affected: vuln.affected_versions ? JSON.stringify(vuln.affected_versions.ranges || []) : '',
                    references: vuln.references || [],
                    is_exploited: vuln.is_actively_exploited || false,
                    fullVuln: vuln
                });
            }
        }
    }
    filterTable();
}

function filterTable() {
    const sevFilter = document.getElementById('severityFilter').value;
    const searchQuery = document.getElementById('tableSearch').value.toLowerCase();
    let filtered = allVulns.filter(function(v) {
        if (sevFilter !== 'all' && v.severity !== sevFilter) return false;
        if (searchQuery) {
            var text = (v.package + ' ' + v.id + ' ' + v.summary).toLowerCase();
            if (!text.includes(searchQuery)) return false;
        }
        return true;
    });
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, none: 5 };
    filtered.sort(function(a, b) { return (sevOrder[a.severity]||6) - (sevOrder[b.severity]||6); });

    const tbody = document.getElementById('vulnTableBody');
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4"><i class="bi bi-check-circle"></i> 没有匹配的漏洞记录</td></tr>';
        return;
    }
    tbody.innerHTML = filtered.map(function(v) {
        const sevClass = 'sev-' + (v.severity || 'none');
        const sevText = (v.severity || 'unknown').toUpperCase();
        const cvssText = typeof v.cvss === 'number' ? v.cvss.toFixed(1) : v.cvss;
        const summaryShort = v.summary.length > 80 ? v.summary.substring(0, 80) + '...' : v.summary;
        const exploitedBadge = v.is_exploited ? ' <span class="badge bg-danger ms-1">被利用</span>' : '';
        return '<tr class="fade-in">' +
            '<td><a href="javascript:void(0)" onclick="showPackageDetail(\'' + escapeHtml(v.package) + '\')" class="text-info"><strong>' + escapeHtml(v.package) + '</strong></a></td>' +
            '<td>' + escapeHtml(v.version) + '</td>' +
            '<td><code>' + escapeHtml(v.id) + '</code></td>' +
            '<td><span class="badge ' + sevClass + '">' + sevText + '</span>' + exploitedBadge + '</td>' +
            '<td>' + cvssText + '</td>' +
            '<td style="max-width:300px">' + escapeHtml(summaryShort) + '</td>' +
            '<td>' + escapeHtml(Array.isArray(v.fixed_version) ? v.fixed_version.join(', ') : v.fixed_version) + '</td>' +
            '<td><button class="btn btn-sm btn-outline-info" onclick="showVulnDetail(' + allVulns.indexOf(v) + ')"><i class="bi bi-eye"></i></button></td>' +
            '</tr>';
    }).join('');
}

// === Vuln Detail Modal ===
function showVulnDetail(idx) {
    const v = allVulns[idx];
    if (!v) return;
    const sevClass = 'sev-' + (v.severity || 'none');
    let html = '<div class="vuln-detail-row"><div class="vuln-detail-label">漏洞ID</div><div class="vuln-detail-value"><code>' + escapeHtml(v.id) + '</code></div></div>';
    if (v.aliases && v.aliases.length > 0) {
        html += '<div class="vuln-detail-row"><div class="vuln-detail-label">CVE编号</div><div class="vuln-detail-value">' + v.aliases.map(function(a) { return '<code>' + escapeHtml(a) + '</code>'; }).join(' ') + '</div></div>';
    }
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">受影响包</div><div class="vuln-detail-value"><a href="javascript:void(0)" onclick="showPackageDetail(\'' + escapeHtml(v.package) + '\')" class="text-info"><strong>' + escapeHtml(v.package) + '</strong></a> @ ' + escapeHtml(v.version) + '</div></div>';
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">严重性</div><div class="vuln-detail-value"><span class="badge ' + sevClass + '">' + (v.severity||'unknown').toUpperCase() + '</span>';
    if (v.is_exploited) html += ' <span class="badge bg-danger">被积极利用</span>';
    html += '</div></div>';
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">CVSS评分</div><div class="vuln-detail-value">' + (typeof v.cvss === 'number' ? v.cvss.toFixed(1) : v.cvss) + '</div></div>';
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">受影响范围</div><div class="vuln-detail-value">' + escapeHtml(v.affected || '-') + '</div></div>';
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">修复版本</div><div class="vuln-detail-value">' + escapeHtml(Array.isArray(v.fixed_version) ? v.fixed_version.join(', ') : v.fixed_version) + '</div></div>';
    if (v.cwe && v.cwe.length > 0) {
        html += '<div class="vuln-detail-row"><div class="vuln-detail-label">CWE分类</div><div class="vuln-detail-value">' + v.cwe.map(function(c) { return '<code>' + escapeHtml(c) + '</code>'; }).join(' ') + '</div></div>';
    }
    html += '<div class="vuln-detail-row"><div class="vuln-detail-label">漏洞摘要</div><div class="vuln-detail-value">' + escapeHtml(v.summary) + '</div></div>';
    if (v.references && v.references.length > 0) {
        html += '<div class="vuln-detail-row"><div class="vuln-detail-label">参考链接</div><div class="vuln-detail-value">';
        for (const ref of v.references.slice(0, 5)) {
            const url = typeof ref === 'string' ? ref : (ref.url || '');
            if (url) html += '<a href="' + url + '" target="_blank" class="d-block text-info">' + escapeHtml(url) + '</a>';
        }
        html += '</div></div>';
    }
    document.getElementById('vulnDetailTitle').textContent = '漏洞详情: ' + v.id;
    document.getElementById('vulnDetailBody').innerHTML = html;
    new bootstrap.Modal(document.getElementById('vulnDetailModal')).show();
}

// === Package Detail Modal (NEW) ===
function showPackageDetail(name) {
    fetch('/api/package/' + encodeURIComponent(name))
        .then(r => r.json())
        .then(data => {
            let html = '<div class="pkg-detail-section"><h6><i class="bi bi-box-seam"></i> ' + escapeHtml(data.name) + '</h6>';
            html += '<p class="text-muted mb-0">在 ' + data.total_scans + ' 次扫描中出现，共发现 ' + data.total_vulns + ' 个漏洞</p></div>';

            // Version history
            if (data.history && data.history.length > 0) {
                html += '<div class="pkg-detail-section"><h6>版本历史</h6>';
                for (const h of data.history) {
                    const riskColor = h.vuln_count > 0 ? 'text-danger' : 'text-success';
                    html += '<div class="pkg-version-history">' +
                        '<span class="pkg-version-badge">v' + escapeHtml(h.version) + '</span>' +
                        '<span class="' + riskColor + '">' + (h.vuln_count > 0 ? h.vuln_count + ' 个漏洞' : '安全') + '</span>' +
                        '<small class="text-muted">' + escapeHtml(h.scan_time) + '</small>' +
                        ' <a href="/result/' + h.scan_id + '" class="text-info">查看</a>' +
                        '</div>';
                }
                html += '</div>';
            }

            // Vulnerabilities
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                html += '<div class="pkg-detail-section"><h6>已知漏洞 (' + data.vulnerabilities.length + ')</h6>';
                html += '<div class="table-responsive"><table class="table table-sm table-dark"><thead><tr><th>漏洞ID</th><th>严重性</th><th>CVSS</th><th>版本</th><th>摘要</th></tr></thead><tbody>';
                for (const v of data.vulnerabilities.slice(0, 15)) {
                    const sevClass = 'sev-' + (v.severity || 'none');
                    html += '<tr><td><code>' + escapeHtml(v.id) + '</code></td>' +
                        '<td><span class="badge ' + sevClass + '">' + (v.severity||'').toUpperCase() + '</span></td>' +
                        '<td>' + (typeof v.cvss === 'number' ? v.cvss.toFixed(1) : v.cvss) + '</td>' +
                        '<td>' + escapeHtml(v.version) + '</td>' +
                        '<td style="max-width:250px">' + escapeHtml((v.summary||'').substring(0, 60)) + '</td></tr>';
                }
                html += '</tbody></table></div></div>';
            }

            document.getElementById('pkgDetailTitle').textContent = '包详情: ' + name;
            document.getElementById('pkgDetailBody').innerHTML = html;
            new bootstrap.Modal(document.getElementById('pkgDetailModal')).show();
        })
        .catch(err => showToast('error', '加载失败', err.message));
}

// === Dependency Tree ===
function renderDepTree(data) {
    const container = document.getElementById('depTreeContainer');
    const tree = data.dep_tree_structure || data.dep_tree;
    if (!tree) {
        if (data.dependency_tree) {
            container.innerHTML = '<pre style="font-size:12px; white-space:pre-wrap; color:#c9d1d9">' + escapeHtml(data.dependency_tree) + '</pre>';
            return;
        }
        container.innerHTML = '<div class="empty-state"><i class="bi bi-inbox"></i><p>依赖树数据不可用</p></div>';
        return;
    }
    if (typeof tree === 'string') {
        container.innerHTML = '<pre style="font-size:12px; white-space:pre-wrap; color:#c9d1d9">' + escapeHtml(tree) + '</pre>';
        return;
    }
    container.innerHTML = renderTreeNode(tree, 0);
    attachTreeListeners();
}

function renderTreeNode(node, depth) {
    if (!node || !node.name) return '';
    const pkgData = scanData.packages ? scanData.packages.find(function(p) { return p.package === node.name; }) : null;
    const vulnCount = pkgData ? pkgData.vuln_count : (node.vuln_count || 0);
    const sevClass = pkgData ? getWorstSeverity(pkgData) : 'none';
    const colors = { critical: '#ff6b6b', high: '#f85149', medium: '#d29922', low: '#3fb950', none: '#58a6ff' };
    const color = colors[sevClass] || colors.none;

    let html = '<div class="dep-node" style="color:' + color + '" data-expanded="true" data-name="' + escapeHtml(node.name.toLowerCase()) + '">';
    html += '<span class="dep-toggle">' + (node.children && node.children.length > 0 ? '▼' : '•') + '</span> ';
    html += '<a href="javascript:void(0)" onclick="event.stopPropagation(); showPackageDetail(\'' + escapeHtml(node.name) + '\')" style="color:inherit; text-decoration:none"><strong>' + escapeHtml(node.name) + '</strong></a>';
    if (node.version) html += ' <span class="text-muted">v' + escapeHtml(node.version) + '</span>';
    if (vulnCount > 0) html += ' <span class="dep-badge" style="background:' + color + '; color:#fff">' + vulnCount + ' vulns</span>';
    html += '</div>';
    if (node.children && node.children.length > 0) {
        html += '<div class="dep-children">';
        for (const child of node.children) { html += renderTreeNode(child, depth + 1); }
        html += '</div>';
    }
    return html;
}

function attachTreeListeners() {
    document.querySelectorAll('.dep-node').forEach(function(node) {
        node.addEventListener('click', function(e) {
            e.stopPropagation();
            var children = this.nextElementSibling;
            if (children && children.classList.contains('dep-children')) {
                var isExpanded = children.style.display !== 'none';
                children.style.display = isExpanded ? 'none' : '';
                var toggle = this.querySelector('.dep-toggle');
                if (toggle) toggle.textContent = isExpanded ? '▶' : '▼';
            }
        });
    });
}

function filterTree() {
    const query = document.getElementById('treeSearch').value.toLowerCase();
    document.querySelectorAll('.dep-node').forEach(function(node) {
        const name = node.getAttribute('data-name') || '';
        const parent = node.parentElement;
        if (!query || name.includes(query)) {
            node.style.opacity = '1';
            if (parent) parent.style.display = '';
        } else {
            node.style.opacity = '0.3';
        }
    });
}

// === Export ===
function exportData(format) {
    window.location.href = '/api/export/' + SCAN_ID + '/' + format;
    showToast('info', '导出', '正在下载 ' + format.toUpperCase() + ' 文件...');
}

// === Utilities ===
function getFixVersions(vuln) {
    // Try multiple possible field locations
    if (vuln.fixed_versions) return Array.isArray(vuln.fixed_versions) ? vuln.fixed_versions : [vuln.fixed_versions];
    if (vuln.fixed_version) return Array.isArray(vuln.fixed_version) ? vuln.fixed_version : [vuln.fixed_version];
    if (vuln.affected_versions && vuln.affected_versions.fix_versions) return vuln.affected_versions.fix_versions;
    if (vuln.affected_versions && vuln.affected_versions.ranges) {
        var fixes = [];
        for (var r of vuln.affected_versions.ranges) {
            if (r.fixed) fixes.push(r.fixed);
        }
        if (fixes.length > 0) return fixes;
    }
    return ['-'];
}

function getWorstSeverity(pkg) {
    if (!pkg.vulnerabilities || pkg.vulnerabilities.length === 0) return 'none';
    let worst = 'none';
    for (const v of pkg.vulnerabilities) {
        const sev = v.severity || 'unknown';
        if (sev === 'critical') return 'critical';
        if (sev === 'high' && worst !== 'critical') worst = 'high';
        if (sev === 'medium' && worst !== 'critical' && worst !== 'high') worst = 'medium';
        if (sev === 'low' && worst === 'none') worst = 'low';
    }
    return worst;
}

function animateNumber(el, start, end, duration) {
    const startTime = performance.now();
    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (end - start) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function showToast(type, title, message) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: 'bi-check-circle-fill', error: 'bi-x-circle-fill', info: 'bi-info-circle-fill', warning: 'bi-exclamation-triangle-fill' };
    const colors = { success: '#3fb950', error: '#f85149', info: '#58a6ff', warning: '#d29922' };
    const toast = document.createElement('div');
    toast.className = 'toast-msg ' + type;
    toast.innerHTML = '<div style="display:flex; align-items:start; gap:8px">' +
        '<i class="bi ' + (icons[type]||icons.info) + '" style="color:' + (colors[type]||colors.info) + '; font-size:1.2rem"></i>' +
        '<div><strong>' + escapeHtml(title) + '</strong><br><small class="text-muted">' + escapeHtml(message) + '</small></div></div>';
    container.appendChild(toast);
    setTimeout(function() {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(400px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(function() { toast.remove(); }, 300);
    }, 3500);
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
