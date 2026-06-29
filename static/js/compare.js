// SCS Checker - Compare Page JavaScript
// Handles: scan comparison, diff tables, severity chart, toast notifications, URL params

let severityCompareChart = null;   // Chart.js instance for severity comparison
let lastCompareData = null;        // Cached comparison result for search filtering

document.addEventListener('DOMContentLoaded', function() {
    // Compare button
    const btnCompare = document.getElementById('btnCompare');
    if (btnCompare) btnCompare.addEventListener('click', startCompare);

    // Dropdown change validation (prevent same scan in both)
    const s1 = document.getElementById('scan1Select');
    const s2 = document.getElementById('scan2Select');
    if (s1) s1.addEventListener('change', preventSameScan);
    if (s2) s2.addEventListener('change', preventSameScan);

    // Share link button
    const btnShare = document.getElementById('btnShareLink');
    if (btnShare) btnShare.addEventListener('click', shareCompareLink);

    // Search filters for the three diff tables
    const nvSearch = document.getElementById('newVulnsSearch');
    const fvSearch = document.getElementById('fixedVulnsSearch');
    const ucSearch = document.getElementById('unchangedSearch');
    if (nvSearch) nvSearch.addEventListener('input', function() { filterTable('newVulns', this.value); });
    if (fvSearch) fvSearch.addEventListener('input', function() { filterTable('fixedVulns', this.value); });
    if (ucSearch) ucSearch.addEventListener('input', function() { filterTable('unchanged', this.value); });

    // Auto-load from URL params ?scan1=X&scan2=Y
    const params = new URLSearchParams(window.location.search);
    const p1 = params.get('scan1');
    const p2 = params.get('scan2');
    if (p1 && p2 && s1 && s2) {
        s1.value = p1;
        s2.value = p2;
        // Only auto-run if both options actually exist in the dropdowns
        if (s1.value === p1 && s2.value === p2) {
            startCompare();
        } else {
            showToast('URL 中指定的扫描记录不存在，请手动选择', 'warning');
        }
    }
});

// Prevent selecting the same scan in both dropdowns
function preventSameScan() {
    const s1 = document.getElementById('scan1Select');
    const s2 = document.getElementById('scan2Select');
    if (s1.value && s2.value && s1.value === s2.value) {
        showToast('请选择两个不同的扫描记录进行对比', 'warning');
        s2.value = '';
    }
}

// Start comparison: fetch /api/compare?scan1=X&scan2=Y
function startCompare() {
    const s1 = document.getElementById('scan1Select');
    const s2 = document.getElementById('scan2Select');
    const id1 = s1.value;
    const id2 = s2.value;

    if (!id1 || !id2) {
        showToast('请选择两个扫描记录', 'warning');
        return;
    }
    if (id1 === id2) {
        showToast('请选择两个不同的扫描记录', 'warning');
        return;
    }

    const btn = document.getElementById('btnCompare');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 对比中...';

    fetch('/api/compare?scan1=' + encodeURIComponent(id1) + '&scan2=' + encodeURIComponent(id2))
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(data) {
            if (data.error) {
                showToast('对比失败: ' + data.error, 'danger');
                return;
            }
            lastCompareData = data;
            // Reflect the comparison in the URL (no reload) for bookmarking/sharing
            const newUrl = window.location.pathname + '?scan1=' + encodeURIComponent(id1) + '&scan2=' + encodeURIComponent(id2);
            window.history.replaceState({}, '', newUrl);
            renderComparison(data);
            showToast('对比分析完成', 'success');
        })
        .catch(function(err) {
            console.error('Compare error:', err);
            showToast('对比请求失败: ' + err.message, 'danger');
        })
        .finally(function() {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-arrow-left-right"></i> 开始对比';
        });
}

// ---- Rendering ----

// Master render: hide empty state, show all result sections
function renderComparison(data) {
    document.getElementById('emptyState').style.display = 'none';
    document.getElementById('compareResults').style.display = '';

    renderScanInfo(data);
    renderSummary(data);
    renderBadges(data);
    renderOverviewTable(data);
    renderSeverityChart(data);
    renderNewVulnsTable(data.new_vulns || []);
    renderFixedVulnsTable(data.fixed_vulns || []);
    renderUnchangedTable(data.unchanged || []);
    renderNewPackages(data.new_packages || []);
    renderRemovedPackages(data.removed_packages || []);

    // Smooth scroll to the results
    const results = document.getElementById('compareResults');
    if (results) results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Render the scan info banner (names + times)
function renderScanInfo(data) {
    const s1 = data.scan1 || {};
    const s2 = data.scan2 || {};
    document.getElementById('scan1Info').innerHTML =
        '#' + escapeHtml(s1.id) + ' ' + escapeHtml(s1.name) +
        ' <small class="text-muted">' + escapeHtml(s1.time) + '</small>';
    document.getElementById('scan2Info').innerHTML =
        '#' + escapeHtml(s2.id) + ' ' + escapeHtml(s2.name) +
        ' <small class="text-muted">' + escapeHtml(s2.time) + '</small>';
}

// Render the 5 summary cards
function renderSummary(data) {
    const sum = data.summary || {};
    document.getElementById('sumNewVulns').textContent = sum.new_count || 0;
    document.getElementById('sumFixedVulns').textContent = sum.fixed_count || 0;
    document.getElementById('sumUnchanged').textContent = sum.unchanged_count || 0;
    document.getElementById('sumNewPkgs').textContent = sum.new_packages_count || 0;
    document.getElementById('sumRemovedPkgs').textContent = sum.removed_packages_count || 0;
}

// Update the table-header badges with row counts
function renderBadges(data) {
    document.getElementById('newVulnsBadge').textContent = (data.new_vulns || []).length;
    document.getElementById('fixedVulnsBadge').textContent = (data.fixed_vulns || []).length;
    document.getElementById('unchangedBadge').textContent = (data.unchanged || []).length;
    document.getElementById('newPkgsBadge').textContent = (data.new_packages || []).length;
    document.getElementById('removedPkgsBadge').textContent = (data.removed_packages || []).length;
}

// Render the side-by-side overview table (risk, vulns, packages, severity)
function renderOverviewTable(data) {
    const s1 = data.scan1 || {};
    const s2 = data.scan2 || {};
    const sev1 = s1.severity || {};
    const sev2 = s2.severity || {};

    // Security metrics: increase is bad (red), decrease is good (green).
    // Package count is neutral (info) since more deps is not inherently bad.
    setMetric('Risk', s1.risk_score, s2.risk_score, false);
    setMetric('Vulns', s1.total_vulns, s2.total_vulns, false);
    setMetric('Pkgs', s1.total_packages, s2.total_packages, true);
    setMetric('Crit', sev1.critical, sev2.critical, false);
    setMetric('High', sev1.high, sev2.high, false);
    setMetric('Med', sev1.medium, sev2.medium, false);
    setMetric('Low', sev1.low, sev2.low, false);
}

// Write a single metric row (value1, value2, delta)
function setMetric(prefix, v1, v2, neutral) {
    v1 = Number(v1) || 0;
    v2 = Number(v2) || 0;
    const delta = v2 - v1;
    document.getElementById('cmp' + prefix + '1').textContent = v1;
    document.getElementById('cmp' + prefix + '2').textContent = v2;
    document.getElementById('cmp' + prefix + 'Delta').innerHTML = formatDelta(delta, neutral);
}

// Format a delta value with directional color
function formatDelta(delta, neutral) {
    if (delta === 0) return '<span class="text-muted">0</span>';
    if (neutral) {
        return '<span class="text-info">' + (delta > 0 ? '+' : '') + delta + '</span>';
    }
    // Security metric: increase = danger, decrease = success
    return delta > 0
        ? '<span class="text-danger"><i class="bi bi-arrow-up"></i> +' + delta + '</span>'
        : '<span class="text-success"><i class="bi bi-arrow-down"></i> ' + delta + '</span>';
}

// Create a grouped bar chart comparing scan1 vs scan2 severity distributions
function renderSeverityChart(data) {
    const s1 = (data.scan1 || {}).severity || {};
    const s2 = (data.scan2 || {}).severity || {};
    const canvas = document.getElementById('severityCompareChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (severityCompareChart) severityCompareChart.destroy();

    severityCompareChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['严重 Critical', '高危 High', '中危 Medium', '低危 Low'],
            datasets: [
                {
                    label: '扫描一 (基准)',
                    data: [s1.critical || 0, s1.high || 0, s1.medium || 0, s1.low || 0],
                    backgroundColor: 'rgba(88, 166, 255, 0.7)',
                    borderColor: '#58a6ff',
                    borderWidth: 1,
                    borderRadius: 4
                },
                {
                    label: '扫描二 (对比)',
                    data: [s2.critical || 0, s2.high || 0, s2.medium || 0, s2.low || 0],
                    backgroundColor: 'rgba(188, 140, 255, 0.7)',
                    borderColor: '#bc8cff',
                    borderWidth: 1,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#c9d1d9', font: { size: 13 }, padding: 12 }
                },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            return ctx.dataset.label + ': ' + ctx.parsed.y + ' 个';
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e', font: { size: 12 } },
                    grid: { color: '#30363d' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: '#8b949e', precision: 0, font: { size: 12 } },
                    grid: { color: '#30363d' }
                }
            }
        }
    });
}

// ---- Diff tables ----

// New vulnerabilities table (only renders tbody; badge set in renderBadges)
function renderNewVulnsTable(items) {
    const tbody = document.getElementById('newVulnsBody');
    if (!items || !items.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-success py-3">' +
            '<i class="bi bi-check-circle"></i> 无新增漏洞</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(function(row) {
        const ids = (row.new || []).map(function(id) {
            return '<span class="badge sev-high me-1 mb-1">' + escapeHtml(id) + '</span>';
        }).join('');
        return '<tr>' +
            '<td><strong>' + escapeHtml(row.name) + '</strong></td>' +
            '<td><span class="text-muted">' + escapeHtml(row.v1 || '-') + '</span> ' +
            '<i class="bi bi-arrow-right text-muted mx-1"></i> ' +
            '<span>' + escapeHtml(row.v2 || '-') + '</span></td>' +
            '<td>' + (ids || '<span class="text-muted">-</span>') + '</td>' +
            '<td class="text-center"><span class="badge bg-danger">' + (row.count || 0) + '</span></td>' +
            '</tr>';
    }).join('');
}

// Fixed vulnerabilities table
function renderFixedVulnsTable(items) {
    const tbody = document.getElementById('fixedVulnsBody');
    if (!items || !items.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-3">' +
            '<i class="bi bi-dash-circle"></i> 无已修复漏洞</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(function(row) {
        const ids = (row.fixed || []).map(function(id) {
            return '<span class="badge sev-low me-1 mb-1">' + escapeHtml(id) + '</span>';
        }).join('');
        return '<tr>' +
            '<td><strong>' + escapeHtml(row.name) + '</strong></td>' +
            '<td><span class="text-muted">' + escapeHtml(row.v1 || '-') + '</span> ' +
            '<i class="bi bi-arrow-right text-muted mx-1"></i> ' +
            '<span>' + escapeHtml(row.v2 || '-') + '</span></td>' +
            '<td>' + (ids || '<span class="text-muted">-</span>') + '</td>' +
            '<td class="text-center"><span class="badge bg-success">' + (row.count || 0) + '</span></td>' +
            '</tr>';
    }).join('');
}

// Unchanged vulnerabilities table
function renderUnchangedTable(items) {
    const tbody = document.getElementById('unchangedBody');
    if (!items || !items.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-success py-3">' +
            '<i class="bi bi-check-circle"></i> 无未变化项</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(function(row) {
        return '<tr>' +
            '<td><strong>' + escapeHtml(row.name) + '</strong></td>' +
            '<td>' + escapeHtml(row.v1 || '-') + '</td>' +
            '<td>' + escapeHtml(row.v2 || '-') + '</td>' +
            '<td class="text-center"><span class="badge bg-secondary">' + (row.count || 0) + '</span></td>' +
            '</tr>';
    }).join('');
}

// New packages list
function renderNewPackages(items) {
    const tbody = document.getElementById('newPkgsBody');
    if (!items || !items.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">无新增依赖包</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(function(row) {
        const vc = row.vuln_count || 0;
        return '<tr>' +
            '<td><strong>' + escapeHtml(row.name) + '</strong></td>' +
            '<td>' + escapeHtml(row.version || '-') + '</td>' +
            '<td class="text-center">' + (vc > 0
                ? '<span class="text-danger fw-bold">' + vc + '</span>'
                : '<span class="text-muted">0</span>') + '</td>' +
            '</tr>';
    }).join('');
}

// Removed packages list
function renderRemovedPackages(items) {
    const tbody = document.getElementById('removedPkgsBody');
    if (!items || !items.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">无移除依赖包</td></tr>';
        return;
    }
    tbody.innerHTML = items.map(function(row) {
        const vc = row.vuln_count || 0;
        return '<tr>' +
            '<td><strong>' + escapeHtml(row.name) + '</strong></td>' +
            '<td>' + escapeHtml(row.version || '-') + '</td>' +
            '<td class="text-center">' + (vc > 0
                ? '<span class="text-danger fw-bold">' + vc + '</span>'
                : '<span class="text-muted">0</span>') + '</td>' +
            '</tr>';
    }).join('');
}

// ---- Search filtering (uses cached lastCompareData) ----

function filterTable(type, query) {
    if (!lastCompareData) return;
    query = (query || '').toLowerCase().trim();

    let items, renderer;
    if (type === 'newVulns') {
        items = lastCompareData.new_vulns || [];
        renderer = renderNewVulnsTable;
    } else if (type === 'fixedVulns') {
        items = lastCompareData.fixed_vulns || [];
        renderer = renderFixedVulnsTable;
    } else if (type === 'unchanged') {
        items = lastCompareData.unchanged || [];
        renderer = renderUnchangedTable;
    } else {
        return;
    }

    if (!query) {
        renderer(items);
        return;
    }
    const filtered = items.filter(function(row) {
        const name = (row.name || '').toLowerCase();
        // Search across vuln IDs for new/fixed tables
        const idList = row.new || row.fixed || [];
        const ids = idList.join(' ').toLowerCase();
        return name.includes(query) || ids.includes(query);
    });
    renderer(filtered);
}

// ---- Share link ----

function shareCompareLink() {
    const s1 = document.getElementById('scan1Select');
    const s2 = document.getElementById('scan2Select');
    if (!s1.value || !s2.value) {
        showToast('请先选择两次扫描', 'warning');
        return;
    }
    const url = window.location.origin + window.location.pathname +
                '?scan1=' + encodeURIComponent(s1.value) +
                '&scan2=' + encodeURIComponent(s2.value);
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url)
            .then(function() { showToast('对比链接已复制到剪贴板', 'success'); })
            .catch(function() { fallbackCopy(url); });
    } else {
        fallbackCopy(url);
    }
}

function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.top = '-9999px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    try {
        document.execCommand('copy');
        showToast('对比链接已复制', 'success');
    } catch (e) {
        showToast('复制失败，请手动复制链接', 'warning');
    }
    document.body.removeChild(ta);
}

// ---- Toast notifications ----

function showToast(message, type) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const bgClass = 'text-bg-' + (type || 'primary');
    const iconMap = {
        success: 'bi-check-circle-fill',
        danger: 'bi-x-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill',
        primary: 'bi-info-circle-fill'
    };
    const icon = iconMap[type] || iconMap.primary;

    const toastEl = document.createElement('div');
    toastEl.className = 'toast align-items-center ' + bgClass + ' border-0';
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML =
        '<div class="d-flex">' +
            '<div class="toast-body"><i class="bi ' + icon + ' me-2"></i>' +
                escapeHtml(message) + '</div>' +
            '<button type="button" class="btn-close btn-close-white me-2 m-auto" ' +
                'data-bs-dismiss="toast" aria-label="关闭"></button>' +
        '</div>';
    container.appendChild(toastEl);

    const toast = new bootstrap.Toast(toastEl, { delay: 3500 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', function() { toastEl.remove(); });
}

// ---- Utils ----

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
