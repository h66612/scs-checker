// SCS Checker - History Page JavaScript
// Handles: history loading, charts, search, delete, pagination

let histSeverityChart = null;
let histTrendChart = null;
let allHistory = [];
let currentPage = 1;
let totalPages = 1;
const PER_PAGE = 20;

document.addEventListener('DOMContentLoaded', function() {
    // Read the initial page from URL query parameters (e.g. ?page=2)
    const params = new URLSearchParams(window.location.search);
    const pageParam = parseInt(params.get('page'), 10);
    if (pageParam && pageParam > 0) currentPage = pageParam;
    loadHistory(currentPage);
    loadHistoryStats();
    document.getElementById('historySearch').addEventListener('input', filterHistory);
    document.getElementById('btnConfirmDelete').addEventListener('click', confirmDelete);
    // Keep pagination in sync with browser back/forward navigation
    window.addEventListener('popstate', function() {
        const p = new URLSearchParams(window.location.search).get('page');
        currentPage = (p && parseInt(p, 10) > 0) ? parseInt(p, 10) : 1;
        loadHistory(currentPage);
    });
});

// Load history data (paginated)
function loadHistory(page) {
    currentPage = page || 1;
    const url = '/api/history?page=' + currentPage + '&per_page=' + PER_PAGE;
    fetch(url)
        .then(r => r.json())
        .then(data => {
            // API now returns { scans, total, page, per_page, total_pages }
            allHistory = data.scans || [];
            totalPages = data.total_pages || 1;
            // Clamp the current page if it ended up out of range
            if (currentPage > totalPages && totalPages > 0) {
                currentPage = totalPages;
            }
            renderHistoryTable(allHistory);
            renderPagination();
        })
        .catch(err => console.error('History load error:', err));
}

// Load overall stats
function loadHistoryStats() {
    fetch('/api/stats')
        .then(r => r.json())
        .then(data => {
            document.getElementById('histStatScans').textContent = data.total_scans || 0;
            document.getElementById('histStatPackages').textContent = data.total_packages || 0;
            document.getElementById('histStatVulns').textContent = data.total_vulns || 0;
            document.getElementById('histStatCritical').textContent = data.total_critical || 0;
            renderHistoryCharts(data);
        })
        .catch(err => console.error('Stats load error:', err));
}

// Render history table
function renderHistoryTable(data) {
    const tbody = document.getElementById('historyTableBody');
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="12" class="text-center text-muted py-4">暂无检测记录，<a href="/">点击此处</a>开始第一次检测</td></tr>';
        return;
    }

    tbody.innerHTML = data.map(function(row) {
        const riskClass = getRiskClass(row.risk_score, row);
        return '<tr>' +
            '<td>' + row.id + '</td>' +
            '<td><strong>' + escapeHtml(row.project_name) + '</strong></td>' +
            '<td><small>' + escapeHtml(row.scan_time) + '</small></td>' +
            '<td>' + row.total_packages + '</td>' +
            '<td>' + (row.vulnerable_packages > 0 ? '<span class="text-danger">' + row.vulnerable_packages + '</span>' : '0') + '</td>' +
            '<td>' + (row.total_vulnerabilities > 0 ? '<span class="text-warning">' + row.total_vulnerabilities + '</span>' : '0') + '</td>' +
            '<td>' + (row.critical > 0 ? '<span class="text-danger fw-bold">' + row.critical + '</span>' : '0') + '</td>' +
            '<td>' + (row.high > 0 ? '<span class="text-danger">' + row.high + '</span>' : '0') + '</td>' +
            '<td>' + (row.medium > 0 ? '<span class="text-warning">' + row.medium + '</span>' : '0') + '</td>' +
            '<td>' + (row.low > 0 ? '<span class="text-success">' + row.low + '</span>' : '0') + '</td>' +
            '<td><span class="' + riskClass + ' fw-bold">' + row.risk_score + '</span></td>' +
            '<td>' +
                '<a href="/result/' + row.id + '" class="btn btn-sm btn-outline-info me-1" title="查看"><i class="bi bi-eye"></i></a>' +
                '<button class="btn btn-sm btn-outline-danger" title="删除" onclick="showDeleteModal(' + row.id + ')"><i class="bi bi-trash"></i></button>' +
            '</td>' +
            '</tr>';
    }).join('');
}

// Render pagination controls below the history table
function renderPagination() {
    const wrapper = document.getElementById('historyPagination');
    const info = document.getElementById('paginationInfo');
    const controls = document.getElementById('paginationControls');
    if (!wrapper || !info || !controls) return;

    // Hide the whole section when there is a single page (or none)
    const hide = totalPages <= 1;
    wrapper.style.display = hide ? 'none' : 'flex';
    if (hide) return;

    info.textContent = '第 ' + currentPage + ' / ' + totalPages + ' 页';

    let html = '';
    // Previous button (disabled on the first page)
    const prevDisabled = currentPage <= 1;
    html += '<button class="btn btn-sm btn-outline-info" ' + (prevDisabled ? 'disabled' : '') +
            ' onclick="goToPage(' + (currentPage - 1) + ')">' +
            '<i class="bi bi-chevron-left"></i> 上一页</button>';

    // Page number buttons with ellipsis for large ranges
    getPageRange(currentPage, totalPages).forEach(function(p) {
        if (p === '...') {
            html += '<span class="text-muted px-1 align-middle">…</span>';
        } else {
            const active = (p === currentPage);
            html += '<button class="btn btn-sm ' + (active ? 'btn-info' : 'btn-outline-info') +
                    '" ' + (active ? 'disabled' : '') +
                    ' onclick="goToPage(' + p + ')">' + p + '</button>';
        }
    });

    // Next button (disabled on the last page)
    const nextDisabled = currentPage >= totalPages;
    html += '<button class="btn btn-sm btn-outline-info" ' + (nextDisabled ? 'disabled' : '') +
            ' onclick="goToPage(' + (currentPage + 1) + ')">' +
            '下一页 <i class="bi bi-chevron-right"></i></button>';

    controls.innerHTML = html;
}

// Build a compact page range with ellipsis, e.g. [1, '...', 4, 5, 6, '...', 10]
function getPageRange(current, total) {
    const delta = 2;
    const range = [];
    const result = [];
    let last = null;

    range.push(1);
    for (let i = current - delta; i <= current + delta; i++) {
        if (i > 1 && i < total) range.push(i);
    }
    if (total > 1) range.push(total);

    range.forEach(function(p) {
        if (last !== null) {
            if (p - last === 2) {
                result.push(last + 1);
            } else if (p - last !== 1) {
                result.push('...');
            }
        }
        result.push(p);
        last = p;
    });
    return result;
}

// Navigate to a specific page
function goToPage(page) {
    if (page < 1 || page > totalPages || page === currentPage) return;
    currentPage = page;
    // Reflect the page in the URL so it is shareable and back/forward works
    const url = new URL(window.location.href);
    if (page === 1) {
        url.searchParams.delete('page');
    } else {
        url.searchParams.set('page', page);
    }
    history.pushState({ page: page }, '', url);
    loadHistory(page);
    // Scroll the table back into view after switching pages
    const table = document.getElementById('historyTable');
    if (table) table.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Filter history by search
function filterHistory() {
    const query = document.getElementById('historySearch').value.toLowerCase();
    const filtered = allHistory.filter(function(row) {
        return row.project_name.toLowerCase().includes(query) ||
               String(row.id).includes(query) ||
               row.scan_time.toLowerCase().includes(query);
    });
    renderHistoryTable(filtered);
}

// Render history charts
function renderHistoryCharts(stats) {
    // Severity distribution pie chart
    const sevCtx = document.getElementById('histSeverityChart').getContext('2d');
    if (histSeverityChart) histSeverityChart.destroy();

    histSeverityChart = new Chart(sevCtx, {
        type: 'doughnut',
        data: {
            labels: ['严重 (Critical)', '高危 (High)', '中危 (Medium)', '低危 (Low)'],
            datasets: [{
                data: [stats.total_critical || 0, stats.total_high || 0, stats.total_medium || 0, stats.total_low || 0],
                backgroundColor: ['#7d1a1a', '#8b2020', '#6b4c10', '#1a4d1a'],
                borderColor: ['#ff6b6b', '#f85149', '#d29922', '#3fb950'],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#c9d1d9', padding: 12, font: { size: 13 } }
                },
                tooltip: {
                    callbacks: {
                        label: function(ctx) { return ctx.label + ': ' + ctx.parsed + ' 个'; }
                    }
                }
            }
        }
    });

    // Risk score trend line chart
    const trendCtx = document.getElementById('histTrendChart').getContext('2d');
    if (histTrendChart) histTrendChart.destroy();

    // Use allHistory (reverse to chronological order)
    const chronData = allHistory.slice().reverse();
    const labels = chronData.map(function(r) { return r.project_name + ' (#' + r.id + ')'; });
    const riskScores = chronData.map(function(r) { return r.risk_score; });
    const vulnCounts = chronData.map(function(r) { return r.total_vulnerabilities; });

    histTrendChart = new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: '风险评分',
                    data: riskScores,
                    borderColor: '#f85149',
                    backgroundColor: 'rgba(248, 81, 73, 0.1)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y'
                },
                {
                    label: '漏洞数量',
                    data: vulnCounts,
                    borderColor: '#d29922',
                    backgroundColor: 'rgba(210, 153, 34, 0.1)',
                    fill: true,
                    tension: 0.3,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: { color: '#c9d1d9', font: { size: 13 } }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#8b949e', font: { size: 11 } },
                    grid: { color: '#30363d' }
                },
                y: {
                    type: 'linear',
                    position: 'left',
                    max: 100,
                    title: { display: true, text: '风险评分', color: '#f85149' },
                    ticks: { color: '#f85149' },
                    grid: { color: '#30363d' }
                },
                y1: {
                    type: 'linear',
                    position: 'right',
                    title: { display: true, text: '漏洞数量', color: '#d29922' },
                    ticks: { color: '#d29922' },
                    grid: { display: false }
                }
            }
        }
    });
}

// Get risk CSS class
function getRiskClass(score, row) {
    if (row.critical > 0) return 'risk-critical';
    if (row.high > 0) return 'risk-high';
    if (row.medium > 0) return 'risk-medium';
    if (row.low > 0) return 'risk-low';
    return 'risk-safe';
}

// Show delete confirmation modal
function showDeleteModal(scanId) {
    document.getElementById('deleteScanId').textContent = scanId;
    const modal = new bootstrap.Modal(document.getElementById('deleteModal'));
    modal.show();
}

// Confirm delete
function confirmDelete() {
    const scanId = document.getElementById('deleteScanId').textContent;
    fetch('/api/scan/' + scanId, { method: 'DELETE' })
        .then(r => r.json())
        .then(function() {
            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('deleteModal'));
            if (modal) modal.hide();
            // Reload data (stay on the current page)
            loadHistory(currentPage);
            loadHistoryStats();
        })
        .catch(function(err) { console.error('Delete error:', err); });
}

// HTML escape
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
