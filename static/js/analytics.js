// SCS Checker - Analytics Page JavaScript
// Handles: tab switching (Bootstrap tabs), trend analysis charts (dual-axis line + stacked bar),
// compliance check, dependency provenance with tree display.

let trendLineChart = null;
let trendStackedChart = null;

// Dark theme constants
const ANA_TEXT_COLOR = '#d1d5db';
const ANA_GRID_COLOR = 'rgba(55, 65, 81, 0.3)';
const ANA_TEXT_MUTED = '#8b949e';

document.addEventListener('DOMContentLoaded', function () {
    // Set Chart.js dark-theme defaults
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = ANA_TEXT_COLOR;
        Chart.defaults.borderColor = ANA_GRID_COLOR;
    }

    // Listen for Bootstrap tab changes to lazy-load data
    var tabEls = document.querySelectorAll('#analyticsTabs button[data-bs-toggle="tab"]');
    tabEls.forEach(function (tabEl) {
        tabEl.addEventListener('shown.bs.tab', function (e) {
            var target = e.target.getAttribute('data-bs-target');
            if (target === '#tab-trend') {
                loadTrends();
            } else if (target === '#tab-compliance') {
                loadComplianceScanList();
            } else if (target === '#tab-provenance') {
                loadProvenanceScanList();
            }
        });
    });

    // Load default tab data (trend tab is active on page load)
    loadTrends();

    // Pre-load scan lists for compliance and provenance dropdowns
    loadComplianceScanList();
    loadProvenanceScanList();

    // Provenance tree search filter
    var provSearch = document.getElementById('provTreeSearch');
    if (provSearch) {
        provSearch.addEventListener('input', function () {
            filterProvenanceTree(this.value);
        });
    }
});

// ---------------------------------------------------------------------------
// Tab 1: Vulnerability Trend Analysis
// ---------------------------------------------------------------------------

function loadTrends() {
    fetch('/api/analytics/trends')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                console.error('Trends error:', data.error);
                return;
            }
            var trends = data.trends || data.scans || [];
            renderTrendStats(data, trends);
            renderTrendLineChart(trends);
            renderTrendStackedChart(trends);
        })
        .catch(function (err) {
            console.error('Trends load error:', err);
        });
}

// Render summary stat cards (matches HTML IDs: trendTotalScans, trendTotalVulns,
// trendAvgRisk, trendRiskTrend, trendMaxRisk, trendMinRisk, trendCriticalCount,
// trendHighCount, trendPkgCount, trendLastScan)
function renderTrendStats(data, trends) {
    var totalScans = data.total_scans || trends.length || 0;
    var avgRisk = data.avg_risk || 0;
    // Calculate total vulns from total_severity or sum of trends
    var totalVulns = 0;
    if (data.total_severity) {
        var ts = data.total_severity;
        totalVulns = (ts.critical || 0) + (ts.high || 0) + (ts.medium || 0) + (ts.low || 0);
    }
    if (!totalVulns) {
        trends.forEach(function (t) { totalVulns += t.vulns || t.total_vulns || 0; });
    }

    // Top stat cards
    setTextById('trendTotalScans', totalScans);
    setTextById('trendTotalVulns', totalVulns);
    setTextById('trendAvgRisk', typeof avgRisk === 'number' ? avgRisk.toFixed(1) : avgRisk);

    // Risk trend indicator
    var riskTrendEl = document.getElementById('trendRiskTrend');
    if (riskTrendEl) {
        if (trends.length >= 2) {
            var latest = trends[trends.length - 1].risk_score || trends[trends.length - 1].risk || 0;
            var prev = trends[trends.length - 2].risk_score || trends[trends.length - 2].risk || 0;
            var diff = latest - prev;
            if (diff > 0) {
                riskTrendEl.textContent = '+' + diff.toFixed(1);
                riskTrendEl.style.color = '#f85149';
            } else if (diff < 0) {
                riskTrendEl.textContent = diff.toFixed(1);
                riskTrendEl.style.color = '#3fb950';
            } else {
                riskTrendEl.textContent = '0';
                riskTrendEl.style.color = '#d29922';
            }
        } else {
            riskTrendEl.textContent = '-';
        }
    }

    // Stats summary grid
    var risks = trends.map(function (t) { return t.risk_score || t.risk || 0; });
    var maxRisk = risks.length > 0 ? Math.max.apply(null, risks) : 0;
    var minRisk = risks.length > 0 ? Math.min.apply(null, risks) : 0;

    var totalCritical = 0, totalHigh = 0, totalPkgs = 0;
    // Use total_severity from API if available
    if (data.total_severity) {
        totalCritical = data.total_severity.critical || 0;
        totalHigh = data.total_severity.high || 0;
    }
    if (!totalCritical && !totalHigh) {
        trends.forEach(function (t) {
            totalCritical += t.critical || 0;
            totalHigh += t.high || 0;
        });
    }
    trends.forEach(function (t) {
        totalPkgs += t.total_packages || t.pkg_count || t.packages || 0;
    });

    var lastScan = '';
    if (trends.length > 0) {
        var last = trends[trends.length - 1];
        lastScan = last.scan_time || last.time || '';
    }

    setTextById('trendMaxRisk', maxRisk);
    setTextById('trendMinRisk', minRisk);
    setTextById('trendCriticalCount', totalCritical);
    setTextById('trendHighCount', totalHigh);
    setTextById('trendPkgCount', totalPkgs);
    setTextById('trendLastScan', lastScan || '-');
}

// Chart 1: Dual-axis line chart (risk score + vuln count over time)
function renderTrendLineChart(trends) {
    var canvas = document.getElementById('trendLineChart');
    if (!canvas) return;
    if (trendLineChart) trendLineChart.destroy();

    var labels = trends.map(function (t) {
        var time = t.scan_time || t.time || '';
        if (time.length >= 16) return time.substring(5, 16);
        return time || ('#' + (t.scan_id || t.id || ''));
    });
    var risks = trends.map(function (t) { return t.risk_score || t.risk || 0; });
    var vulns = trends.map(function (t) { return t.total_vulns || t.vulns || 0; });

    trendLineChart = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: '风险评分',
                    data: risks,
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.12)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y',
                    pointBackgroundColor: '#f85149',
                    pointBorderColor: '#0d1117',
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    borderWidth: 2
                },
                {
                    label: '漏洞数量',
                    data: vulns,
                    borderColor: '#d29922',
                    backgroundColor: 'rgba(210, 153, 34, 0.12)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y1',
                    pointBackgroundColor: '#d29922',
                    pointBorderColor: '#0d1117',
                    pointRadius: 3,
                    pointHoverRadius: 6,
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { labels: { color: ANA_TEXT_COLOR, font: { size: 12 } } },
                tooltip: {
                    callbacks: {
                        title: function (items) {
                            var t = trends[items[0].dataIndex];
                            return t ? (t.project_name || t.name || '') + ' (#' + (t.scan_id || t.id || '') + ')' : '';
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: ANA_TEXT_MUTED, font: { size: 10 }, maxRotation: 45, autoSkip: true },
                    grid: { color: ANA_GRID_COLOR }
                },
                y: {
                    type: 'linear',
                    position: 'left',
                    min: 0,
                    max: 100,
                    title: { display: true, text: '风险评分', color: '#f85149', font: { size: 12 } },
                    ticks: { color: '#f85149', precision: 0 },
                    grid: { color: ANA_GRID_COLOR }
                },
                y1: {
                    type: 'linear',
                    position: 'right',
                    min: 0,
                    title: { display: true, text: '漏洞数量', color: '#d29922', font: { size: 12 } },
                    ticks: { color: '#d29922', precision: 0 },
                    grid: { display: false }
                }
            }
        }
    });
}

// Chart 2: Stacked bar chart (severity distribution per scan)
function renderTrendStackedChart(trends) {
    var canvas = document.getElementById('trendStackedChart');
    if (!canvas) return;
    if (trendStackedChart) trendStackedChart.destroy();

    var labels = trends.map(function (t) {
        return '#' + (t.scan_id || t.id || '');
    });
    var critical = trends.map(function (t) {
        return t.critical || 0;
    });
    var high = trends.map(function (t) {
        return t.high || 0;
    });
    var medium = trends.map(function (t) {
        return t.medium || 0;
    });
    var low = trends.map(function (t) {
        return t.low || 0;
    });

    trendStackedChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: '严重 (Critical)', data: critical, backgroundColor: '#7d1a1a', borderColor: '#ff6b6b', borderWidth: 1 },
                { label: '高危 (High)', data: high, backgroundColor: '#8b2020', borderColor: '#f85149', borderWidth: 1 },
                { label: '中危 (Medium)', data: medium, backgroundColor: '#6b4c10', borderColor: '#d29922', borderWidth: 1 },
                { label: '低危 (Low)', data: low, backgroundColor: '#1a4d1a', borderColor: '#3fb950', borderWidth: 1 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    stacked: true,
                    ticks: { color: ANA_TEXT_MUTED, font: { size: 10 } },
                    grid: { color: ANA_GRID_COLOR }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: { color: ANA_TEXT_MUTED, precision: 0 },
                    grid: { color: ANA_GRID_COLOR }
                }
            },
            plugins: {
                legend: { labels: { color: ANA_TEXT_COLOR, font: { size: 12 } } },
                tooltip: { mode: 'index' }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Tab 2: Compliance Check
// ---------------------------------------------------------------------------

// Load scan list into the compliance scan dropdown (HTML ID: complianceScanSelect)
function loadComplianceScanList() {
    var select = document.getElementById('complianceScanSelect');
    if (!select) return;

    fetch('/api/history')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var scans = data.scans || data || [];
            select.innerHTML = '<option value="">-- 请选择扫描 --</option>';
            scans.forEach(function (s) {
                var opt = document.createElement('option');
                opt.value = s.id;
                opt.textContent = '#' + s.id + ' ' + (s.project_name || 'Unknown') + ' (' + (s.scan_time || '') + ')';
                select.appendChild(opt);
            });
        })
        .catch(function (err) {
            console.error('Compliance scan list load error:', err);
        });
}

// Run compliance check (called from HTML onclick="runComplianceCheck()")
function runComplianceCheck() {
    var scanId = document.getElementById('complianceScanSelect').value;
    var standard = document.getElementById('complianceStandard').value;

    if (!scanId) {
        showToast('warning', '提示', '请选择扫描记录');
        return;
    }
    if (!standard) {
        showToast('warning', '提示', '请选择合规标准');
        return;
    }

    // Find the button that triggered this to show loading state
    var btn = event && event.target ? event.target.closest('button') : null;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 检查中...';
    }

    var url = '/api/compliance/' + scanId + '?standard=' + encodeURIComponent(standard);
    fetch(url)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '检查失败', data.error);
                return;
            }
            renderComplianceResult(data, standard);
        })
        .catch(function (err) {
            console.error('Compliance check error:', err);
            showToast('error', '检查失败', '网络错误');
        })
        .finally(function () {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-play-circle"></i> 执行检查';
            }
        });
}

// Render compliance check results
// Updates HTML elements: compliancePass, complianceWarn, complianceFail, complianceDetailBody
function renderComplianceResult(data, standard) {
    var checks = data.checks || data.items || [];
    var passCount = 0, warnCount = 0, failCount = 0;
    checks.forEach(function (c) {
        var status = (c.status || '').toUpperCase();
        if (status === 'PASS') passCount++;
        else if (status === 'WARN') warnCount++;
        else if (status === 'FAIL') failCount++;
    });

    // Update stat cards (HTML IDs: compliancePass, complianceWarn, complianceFail)
    setTextById('compliancePass', passCount);
    setTextById('complianceWarn', warnCount);
    setTextById('complianceFail', failCount);

    // Update detailed check table body (HTML ID: complianceDetailBody)
    var tbody = document.getElementById('complianceDetailBody');
    if (tbody) {
        if (checks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">无检查项</td></tr>';
        } else {
            tbody.innerHTML = checks.map(function (c, idx) {
                var status = (c.status || 'unknown').toUpperCase();
                var badgeClass, badgeColor;
                if (status === 'PASS') { badgeClass = 'bg-success'; badgeColor = '#3fb950'; }
                else if (status === 'WARN') { badgeClass = 'bg-warning'; badgeColor = '#d29922'; }
                else if (status === 'FAIL') { badgeClass = 'bg-danger'; badgeColor = '#f85149'; }
                else { badgeClass = 'bg-secondary'; badgeColor = '#8b949e'; }

                var name = escapeHtml(c.name || c.rule || '-');
                var requirement = escapeHtml(c.requirement || c.standard_desc || c.description || '-');
                var actual = escapeHtml(c.actual || c.detail || c.evidence || '-');
                var explanation = escapeHtml(c.explanation || c.remediation || c.message || '-');

                return '<tr>' +
                    '<td>' + (idx + 1) + '</td>' +
                    '<td><strong>' + name + '</strong></td>' +
                    '<td class="small">' + requirement + '</td>' +
                    '<td class="small">' + actual + '</td>' +
                    '<td><span class="badge ' + badgeClass + '" style="background-color:' + badgeColor + '">' + status + '</span></td>' +
                    '<td class="small">' + explanation + '</td>' +
                '</tr>';
            }).join('');
        }
    }
}

// ---------------------------------------------------------------------------
// Tab 3: Dependency Provenance
// ---------------------------------------------------------------------------

// Load scan list into the provenance scan dropdown (HTML ID: provenanceScanSelect)
function loadProvenanceScanList() {
    var select = document.getElementById('provenanceScanSelect');
    if (!select) return;

    fetch('/api/history')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var scans = data.scans || data || [];
            select.innerHTML = '<option value="">-- 请选择扫描 --</option>';
            scans.forEach(function (s) {
                var opt = document.createElement('option');
                opt.value = s.id;
                opt.textContent = '#' + s.id + ' ' + (s.project_name || 'Unknown') + ' (' + (s.scan_time || '') + ')';
                select.appendChild(opt);
            });
        })
        .catch(function (err) {
            console.error('Provenance scan list load error:', err);
        });
}

// Load provenance data (called from HTML onclick="loadProvenanceData()")
function loadProvenanceData() {
    var scanId = document.getElementById('provenanceScanSelect').value;
    if (!scanId) {
        showToast('warning', '提示', '请选择扫描记录');
        return;
    }

    // Find the button that triggered this to show loading state
    var btn = event && event.target ? event.target.closest('button') : null;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 分析中...';
    }

    fetch('/api/analytics/dependency-trace/' + scanId)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '分析失败', data.error);
                return;
            }
            renderProvenanceResult(data);
        })
        .catch(function (err) {
            console.error('Provenance load error:', err);
            showToast('error', '分析失败', '网络错误');
        })
        .finally(function () {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-search"></i> 查询依赖';
            }
        });
}

// Render provenance results
// Updates HTML elements: provTotalPackages, provDirectDeps, provTransitiveDeps,
// provVulnPackages, provenanceTreeContainer
function renderProvenanceResult(data) {
    // Stat cards (HTML IDs: provTotalPackages, provDirectDeps, provTransitiveDeps, provVulnPackages)
    var stats = data.stats || data.summary || {};
    setTextById('provTotalPackages', stats.total_packages || 0);
    setTextById('provDirectDeps', stats.direct_dependencies || 0);
    setTextById('provTransitiveDeps', stats.transitive_dependencies || 0);
    setTextById('provVulnPackages', stats.vulnerable_packages || 0);

    // Dependency tree (HTML ID: provenanceTreeContainer)
    var treeEl = document.getElementById('provenanceTreeContainer');
    if (treeEl) {
        var tree = data.dependency_tree || data.tree || data.dep_tree || '';
        if (tree) {
            treeEl.innerHTML = '<pre style="font-size:12px; white-space:pre-wrap; color:#c9d1d9; max-height:600px; overflow:auto">' + escapeHtml(tree) + '</pre>';
        } else if (data.packages && Array.isArray(data.packages)) {
            // Render package list as a tree-like display
            var html = '<ul class="list-unstyled mb-0">';
            data.packages.forEach(function (pkg) {
                var vulnBadge = pkg.vulnerable ? ' <span class="badge bg-danger">漏洞</span>' : '';
                var depType = pkg.direct ? '<span class="badge bg-info me-1">直接</span>' : '<span class="badge bg-secondary me-1">传递</span>';
                html += '<li class="py-1 px-2 border-bottom border-secondary">' +
                    depType +
                    '<strong>' + escapeHtml(pkg.name || pkg.package || '') + '</strong>' +
                    (pkg.version ? ' <span class="text-muted">@' + escapeHtml(pkg.version) + '</span>' : '') +
                    vulnBadge +
                '</li>';
            });
            html += '</ul>';
            treeEl.innerHTML = html;
        } else {
            treeEl.innerHTML = '<div class="text-center text-muted py-3"><i class="bi bi-inbox"></i> 依赖树数据不可用</div>';
        }
    }
}

// Filter provenance tree by search term (HTML ID: provTreeSearch)
function filterProvenanceTree(query) {
    var container = document.getElementById('provenanceTreeContainer');
    if (!container) return;
    var items = container.querySelectorAll('li, .dep-tree-item');
    var q = (query || '').toLowerCase();
    items.forEach(function (item) {
        if (!q || item.textContent.toLowerCase().indexOf(q) !== -1) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}

// ---------------------------------------------------------------------------
// Toast notification (HTML ID: toastContainer)
// ---------------------------------------------------------------------------
function showToast(type, title, message) {
    var container = document.getElementById('toastContainer');
    if (!container) return;
    var icons = { success: 'bi-check-circle-fill', error: 'bi-x-circle-fill', info: 'bi-info-circle-fill', warning: 'bi-exclamation-triangle-fill' };
    var colors = { success: '#3fb950', error: '#f85149', info: '#58a6ff', warning: '#d29922' };
    var toast = document.createElement('div');
    toast.className = 'toast-msg ' + type;
    toast.innerHTML = '<div style="display:flex; align-items:start; gap:8px">' +
        '<i class="bi ' + (icons[type] || icons.info) + '" style="color:' + (colors[type] || colors.info) + '; font-size:1.2rem"></i>' +
        '<div><strong>' + escapeHtml(title) + '</strong><br><small class="text-muted">' + escapeHtml(message) + '</small></div></div>';
    container.appendChild(toast);
    setTimeout(function () {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(400px)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(function () { toast.remove(); }, 300);
    }, 3500);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    var div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function setTextById(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
}
