// SCS Checker - Dashboard Page JavaScript
// Handles: aggregated dashboard data loading, stat count-up animation,
// severity doughnut, risk-trend dual-axis line, CWE horizontal bar,
// top packages table, and recent scan cards.

let dashSeverityChart = null;
let dashTrendChart = null;
let dashCweChart = null;

// Dark theme palette (mirrors style.css CSS variables)
const TEXT_MAIN = '#c9d1d9';
const TEXT_MUTED = '#8b949e';
const GRID_COLOR = '#30363d';
const SEV_BG = ['#7d1a1a', '#8b2020', '#6b4c10', '#1a4d1a'];
const SEV_BORDER = ['#ff6b6b', '#f85149', '#d29922', '#3fb950'];

document.addEventListener('DOMContentLoaded', function () {
    // Global Chart.js dark-theme defaults
    Chart.defaults.color = TEXT_MUTED;
    Chart.defaults.borderColor = GRID_COLOR;
    Chart.register(noDataPlugin);
    loadDashboard();
});

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------
function loadDashboard() {
    fetch('/api/dashboard')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            const stats = data.stats || {};
            renderStats(stats);
            renderSeverityChart(stats);
            renderTrendChart(data.risk_trend || []);
            renderCweChart(data.top_cwes || []);
            renderTopPackages(data.top_packages || []);
            renderRecentScans(data.recent_scans || []);
        })
        .catch(function (err) {
            console.error('Dashboard load error:', err);
            ['dashStatScans', 'dashStatPackages', 'dashStatVulns', 'dashStatRisk'].forEach(function (id) {
                const el = document.getElementById(id);
                if (el) el.textContent = '-';
            });
            const tp = document.getElementById('dashTopPackagesBody');
            if (tp) tp.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-4">数据加载失败</td></tr>';
            const rs = document.getElementById('dashRecentScans');
            if (rs) rs.innerHTML = '<div class="col-12 text-center text-danger py-4">数据加载失败</div>';
        });
}

// ---------------------------------------------------------------------------
// Stat cards (with count-up animation)
// ---------------------------------------------------------------------------
function renderStats(stats) {
    animateCount(document.getElementById('dashStatScans'), stats.total_scans || 0, 1000, 0);
    animateCount(document.getElementById('dashStatPackages'), stats.total_packages || 0, 1200, 0);
    animateCount(document.getElementById('dashStatVulns'), stats.total_vulns || 0, 1200, 0);
    animateCount(document.getElementById('dashStatRisk'), stats.avg_risk || 0, 1000, 1);

    // Dynamic risk coloring on the 4th card
    const avg = stats.avg_risk || 0;
    const ri = getRiskInfo(avg);
    const riskCard = document.getElementById('dashRiskCard');
    const riskIcon = document.getElementById('dashRiskIcon');
    const riskLabel = document.getElementById('dashStatRiskLabel');
    const riskScoreEl = document.getElementById('dashStatRisk');
    if (riskCard) riskCard.style.borderColor = ri.color;
    if (riskIcon) riskIcon.style.color = ri.color;
    if (riskLabel) riskLabel.textContent = ri.label;
    if (riskScoreEl) riskScoreEl.className = 'mb-0 ' + ri.cls;
}

// Map a numeric risk score to color class / label
function getRiskInfo(score) {
    if (score >= 70) return { cls: 'risk-critical', label: '严重 (Critical)', short: '严重', color: '#ff6b6b' };
    if (score >= 40) return { cls: 'risk-high', label: '高危 (High)', short: '高危', color: '#f85149' };
    if (score >= 20) return { cls: 'risk-medium', label: '中危 (Medium)', short: '中危', color: '#d29922' };
    if (score > 0) return { cls: 'risk-low', label: '低危 (Low)', short: '低危', color: '#3fb950' };
    return { cls: 'risk-safe', label: '安全 (Safe)', short: '安全', color: '#58a6ff' };
}

// Ease-out cubic count-up animation
function animateCount(el, target, duration, decimals) {
    if (!el) return;
    decimals = decimals || 0;
    const tgt = Number(target) || 0;
    const start = 0;
    const startTime = performance.now();
    function step(now) {
        const p = Math.min((now - startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        const val = start + (tgt - start) * eased;
        el.textContent = decimals > 0 ? val.toFixed(decimals) : Math.round(val).toString();
        if (p < 1) {
            requestAnimationFrame(step);
        } else {
            el.textContent = decimals > 0 ? tgt.toFixed(decimals) : Math.round(tgt).toString();
        }
    }
    requestAnimationFrame(step);
}

// ---------------------------------------------------------------------------
// Chart 1: Severity distribution doughnut
// ---------------------------------------------------------------------------
function renderSeverityChart(stats) {
    const canvas = document.getElementById('dashSeverityChart');
    if (!canvas) return;
    if (dashSeverityChart) dashSeverityChart.destroy();

    const data = [
        stats.total_critical || 0,
        stats.total_high || 0,
        stats.total_medium || 0,
        stats.total_low || 0
    ];
    const total = data.reduce(function (a, b) { return a + b; }, 0);

    dashSeverityChart = new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['严重 (Critical)', '高危 (High)', '中危 (Medium)', '低危 (Low)'],
            datasets: [{
                data: data,
                backgroundColor: SEV_BG,
                borderColor: SEV_BORDER,
                borderWidth: 2,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: TEXT_MAIN, padding: 12, font: { size: 12 } }
                },
                tooltip: {
                    callbacks: {
                        label: function (c) {
                            const v = c.parsed;
                            const pct = total > 0 ? ((v / total) * 100).toFixed(1) : '0.0';
                            return c.label + ': ' + v + ' 个 (' + pct + '%)';
                        }
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Chart 2: Risk score trend line (dual Y-axis)
// ---------------------------------------------------------------------------
function renderTrendChart(trend) {
    const canvas = document.getElementById('dashTrendChart');
    if (!canvas) return;
    if (dashTrendChart) dashTrendChart.destroy();

    const labels = trend.map(formatTrendLabel);
    const risks = trend.map(function (t) { return t.risk || 0; });
    const vulns = trend.map(function (t) { return t.vulns || 0; });

    dashTrendChart = new Chart(canvas.getContext('2d'), {
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
                legend: { labels: { color: TEXT_MAIN, font: { size: 12 } } },
                tooltip: {
                    callbacks: {
                        title: function (items) {
                            const t = trend[items[0].dataIndex];
                            return t ? (t.name + ' (#' + t.id + ')') : '';
                        },
                        afterTitle: function (items) {
                            const t = trend[items[0].dataIndex];
                            return t ? '时间: ' + (t.time || '-') : '';
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: TEXT_MUTED, font: { size: 10 }, maxRotation: 45, autoSkip: true },
                    grid: { color: GRID_COLOR }
                },
                y: {
                    type: 'linear',
                    position: 'left',
                    min: 0,
                    max: 100,
                    title: { display: true, text: '风险评分', color: '#f85149', font: { size: 12 } },
                    ticks: { color: '#f85149', precision: 0 },
                    grid: { color: GRID_COLOR }
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

// Compact x-axis label: "MM-DD HH:mm" when a full timestamp is present
function formatTrendLabel(t) {
    if (t.time && t.time.length >= 16) return t.time.substring(5, 16);
    if (t.time) return t.time;
    return '#' + t.id;
}

// ---------------------------------------------------------------------------
// Chart 3: CWE distribution horizontal bar
// ---------------------------------------------------------------------------
function renderCweChart(cwes) {
    const canvas = document.getElementById('dashCweChart');
    if (!canvas) return;
    if (dashCweChart) dashCweChart.destroy();

    const labels = cwes.map(function (c) { return c.name || 'Unknown'; });
    const data = cwes.map(function (c) { return c.count || 0; });

    dashCweChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: '出现次数',
                data: data,
                backgroundColor: 'rgba(88, 166, 255, 0.55)',
                borderColor: '#58a6ff',
                borderWidth: 1,
                borderRadius: 3
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function (c) { return c.parsed.x + ' 次'; }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: TEXT_MUTED, precision: 0 },
                    grid: { color: GRID_COLOR }
                },
                y: {
                    ticks: { color: TEXT_MAIN, font: { size: 11 } },
                    grid: { display: false }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Top vulnerable packages table
// ---------------------------------------------------------------------------
function renderTopPackages(pkgs) {
    const tbody = document.getElementById('dashTopPackagesBody');
    if (!tbody) return;

    if (!pkgs || pkgs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">暂无高频漏洞包数据</td></tr>';
        return;
    }

    tbody.innerHTML = pkgs.map(function (p, i) {
        let versionsHtml;
        if (p.versions && p.versions.length > 0) {
            versionsHtml = p.versions.map(function (v) {
                return '<code>' + escapeHtml(v || '-') + '</code>';
            }).join(' ');
        } else {
            versionsHtml = '<span class="text-muted">-</span>';
        }
        const vulns = p.total_vulns || 0;
        const vulnsHtml = vulns > 0
            ? '<span class="text-warning fw-bold">' + vulns + '</span>'
            : '0';
        return '<tr>' +
            '<td class="text-muted">' + (i + 1) + '</td>' +
            '<td><strong>' + escapeHtml(p.name || '-') + '</strong></td>' +
            '<td>' + versionsHtml + '</td>' +
            '<td>' + vulnsHtml + '</td>' +
            '<td>' + (p.scans || 0) + '</td>' +
            '</tr>';
    }).join('');
}

// ---------------------------------------------------------------------------
// Recent scan cards
// ---------------------------------------------------------------------------
function renderRecentScans(scans) {
    const container = document.getElementById('dashRecentScans');
    if (!container) return;

    if (!scans || scans.length === 0) {
        container.innerHTML = '<div class="col-12 text-center text-muted py-4">暂无检测记录，<a href="/" class="text-info">点击此处</a>开始第一次检测</div>';
        return;
    }

    container.innerHTML = scans.map(function (s) {
        const ri = getRiskInfo(s.risk_score || 0);
        const sevBadges = buildSevBadges(s);
        const riskBadge = '<span class="badge" style="background-color:#1c2330;color:' + ri.color +
            ';border:1px solid ' + ri.color + ';font-size:0.8rem">' + ri.short + ' ' + (s.risk_score || 0) + '</span>';

        return '<div class="col-12 col-md-6 col-xl-4">' +
            '<div class="card summary-card dashboard-card position-relative h-100" style="cursor:pointer;transition:border-color .2s">' +
                '<div class="card-body" style="border-left:3px solid ' + ri.color + ';border-radius:0">' +
                    '<div class="d-flex justify-content-between align-items-start mb-2">' +
                        '<h6 class="mb-0 text-truncate" style="max-width:65%">' + escapeHtml(s.project_name || 'Unknown') + '</h6>' +
                        riskBadge +
                    '</div>' +
                    '<p class="text-muted small mb-3"><i class="bi bi-clock"></i> ' + escapeHtml(s.scan_time || '-') + '</p>' +
                    '<div class="row text-center g-2 mb-3">' +
                        '<div class="col-4"><div class="stat-box"><div class="stat-number" style="font-size:1.2rem">' + (s.total_packages || 0) + '</div><div class="stat-label">总包数</div></div></div>' +
                        '<div class="col-4"><div class="stat-box"><div class="stat-number" style="font-size:1.2rem;color:#f85149">' + (s.vulnerable_packages || 0) + '</div><div class="stat-label">漏洞包</div></div></div>' +
                        '<div class="col-4"><div class="stat-box"><div class="stat-number" style="font-size:1.2rem;color:#d29922">' + (s.total_vulnerabilities || 0) + '</div><div class="stat-label">漏洞数</div></div></div>' +
                    '</div>' +
                    '<div class="d-flex flex-wrap gap-1">' + sevBadges + '</div>' +
                '</div>' +
                '<a href="/result/' + s.id + '" class="stretched-link" aria-label="查看检测结果 ' + escapeHtml(s.project_name || '') + '"></a>' +
            '</div>' +
        '</div>';
    }).join('');
}

// Build severity badges for a scan row
function buildSevBadges(s) {
    const items = [
        { key: 'critical', label: '严重', cls: 'sev-critical' },
        { key: 'high', label: '高危', cls: 'sev-high' },
        { key: 'medium', label: '中危', cls: 'sev-medium' },
        { key: 'low', label: '低危', cls: 'sev-low' }
    ];
    return items.map(function (it) {
        const v = s[it.key] || 0;
        if (v > 0) {
            return '<span class="badge ' + it.cls + '">' + it.label + ' ' + v + '</span>';
        }
        return '<span class="badge sev-none">' + it.label + ' 0</span>';
    }).join('');
}

// ---------------------------------------------------------------------------
// Chart.js plugin: draw "暂无数据" overlay when a chart has no data
// ---------------------------------------------------------------------------
const noDataPlugin = {
    id: 'noDataOverlay',
    afterDraw: function (chart) {
        const type = chart.config.type;
        let hasData = false;
        if (type === 'line') {
            hasData = (chart.data.labels || []).length > 0;
        } else {
            for (const ds of (chart.data.datasets || [])) {
                if (ds.data && ds.data.some(function (v) { return Number(v) > 0; })) {
                    hasData = true;
                    break;
                }
            }
        }
        if (hasData) return;

        const ctx = chart.ctx;
        const width = chart.width;
        const height = chart.height;
        ctx.save();
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = TEXT_MUTED;
        ctx.font = '14px Segoe UI, -apple-system, sans-serif';
        ctx.fillText('暂无数据', width / 2, height / 2);
        ctx.restore();
    }
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
