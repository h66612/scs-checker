// SCS Checker - CVE Knowledge Base Page JavaScript
// Handles: CVE search, favorites management, snapshot management.

let currentSearchQuery = '';

document.addEventListener('DOMContentLoaded', function () {
    // Search input - trigger on Enter
    const searchInput = document.getElementById('kbSearchInput');
    if (searchInput) {
        searchInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchCVE();
            }
        });
    }

    // Load initial data
    searchCVE();       // Auto-search to show all CVEs on page load
    loadFavorites();
    loadSnapshots();
});

// ---------------------------------------------------------------------------
// CVE Search
// ---------------------------------------------------------------------------

function searchCVE() {
    const searchInput = document.getElementById('kbSearchInput');
    const sevFilter = document.getElementById('kbSevFilter');
    const query = searchInput ? searchInput.value.trim() : '';
    const sevLevel = sevFilter ? sevFilter.value : 'all';
    currentSearchQuery = query;

    const url = '/api/kb/search' + (query ? ('?q=' + encodeURIComponent(query)) : '');
    fetch(url)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '搜索失败', data.error);
                return;
            }
            let results = data.results || data.cves || data || [];
            // Filter by severity if selected
            if (sevLevel !== 'all') {
                results = results.filter(function (c) {
                    return (c.severity || '').toLowerCase() === sevLevel;
                });
            }
            renderCVEGrid(results);
        })
        .catch(function (err) {
            console.error('CVE search error:', err);
            showToast('error', '搜索失败', '网络错误');
        });
}

// Render CVE cards grid
function renderCVEGrid(cves) {
    const container = document.getElementById('kbCardGrid');
    if (!container) return;

    if (!cves || cves.length === 0) {
        container.innerHTML = '<div class="col-12 text-center text-muted py-5"><i class="bi bi-search" style="font-size:2rem;opacity:0.3"></i><p class="mt-2">未找到匹配的CVE记录</p></div>';
        return;
    }

    container.innerHTML = cves.map(function (cve, idx) {
        const cveId = cve.cve_id || cve.id || 'N/A';
        const severity = cve.severity || 'unknown';
        const sevClass = getSevBadgeClass(severity);
        const pkgName = cve.package_name || cve.package || '-';
        const title = cve.title || cve.name || '';
        const summary = cve.summary || cve.description || '';
        const summaryShort = summary.length > 120 ? summary.substring(0, 120) + '...' : summary;
        const cvss = cve.cvss_score || cve.cvss || '-';
        const cvssText = typeof cvss === 'number' ? cvss.toFixed(1) : cvss;
        const fixedVersion = cve.fixed || cve.fixed_version || cve.patched_version || '-';
        const mitigation = cve.mitigation || cve.mitigations || '';
        const discovered = cve.discovered || cve.discovered_date || '';

        return '<div class="col-md-6 col-lg-4 mb-3">' +
            '<div class="cve-card">' +
                '<div class="cve-header">' +
                    '<span class="cve-id">' + escapeHtml(cveId) + '</span>' +
                    '<span class="badge ' + sevClass + '">' + severity.toUpperCase() + '</span>' +
                '</div>' +
                (title ? '<div class="cve-title">' + escapeHtml(title) + '</div>' : '') +
                '<div class="cve-summary">' + escapeHtml(summaryShort) + '</div>' +
                '<div class="cve-meta">' +
                    '<span class="cve-meta-item"><i class="bi bi-box-seam"></i> ' + escapeHtml(pkgName) + '</span>' +
                    '<span class="cve-meta-item"><i class="bi bi-speedometer"></i> CVSS: <strong>' + escapeHtml(cvssText) + '</strong></span>' +
                    (discovered ? '<span class="cve-meta-item"><i class="bi bi-calendar3"></i> ' + escapeHtml(discovered) + '</span>' : '') +
                '</div>' +
                '<div class="cve-meta mt-1">' +
                    '<span class="cve-meta-item"><i class="bi bi-check-circle"></i> 修复: <code class="text-success">' + escapeHtml(fixedVersion) + '</code></span>' +
                '</div>' +
                (mitigation ? '<div class="cve-mitigation"><i class="bi bi-shield-check"></i> ' + escapeHtml(mitigation.substring(0, 100)) + (mitigation.length > 100 ? '...' : '') + '</div>' : '') +
                '<div class="mt-2">' +
                    '<button class="btn btn-sm btn-outline-warning w-100" onclick="toggleFavorite(' + idx + ')">' +
                        '<i class="bi bi-bookmark-plus"></i> 收藏</button>' +
                '</div>' +
            '</div>' +
        '</div>';
    }).join('');

    // Store CVE data for the favorite toggle
    window._kbCVEData = cves;
}

// ---------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------

function toggleFavorite(idx) {
    const cves = window._kbCVEData || [];
    const cve = cves[idx];
    if (!cve) return;

    const cveId = cve.cve_id || cve.id || '';
    const pkgName = cve.package_name || cve.package || '';
    const severity = cve.severity || '';
    const summary = cve.summary || cve.description || '';

    fetch('/api/favorites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            cve_id: cveId,
            package_name: pkgName,
            severity: severity,
            summary: summary
        })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '收藏失败', data.error);
                return;
            }
            showToast('success', '操作成功', '已收藏 ' + cveId);
            loadFavorites();
        })
        .catch(function (err) {
            console.error('Favorite add error:', err);
            showToast('error', '收藏失败', '网络错误');
        });
}

function loadFavorites() {
    fetch('/api/favorites')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            renderFavorites(data.favorites || data || []);
        })
        .catch(function (err) {
            console.error('Favorites load error:', err);
        });
}

function renderFavorites(favorites) {
    const container = document.getElementById('kbFavoritesList');
    if (!container) return;

    if (!favorites || favorites.length === 0) {
        container.innerHTML = '<div class="empty-state"><i class="bi bi-heart"></i><p>暂无收藏</p><small class="text-muted">点击卡片上的心形图标收藏</small></div>';
        return;
    }

    container.innerHTML = favorites.map(function (fav) {
        const cveId = fav.cve_id || fav.cveId || '';
        const severity = fav.severity || 'unknown';
        const sevClass = getSevBadgeClass(severity);
        const pkgName = fav.package_name || fav.package || '-';

        return '<div class="d-flex justify-content-between align-items-start py-2 px-2 border-bottom border-secondary">' +
            '<div class="flex-grow-1">' +
                '<div class="d-flex align-items-center gap-2 mb-1">' +
                    '<code class="text-info">' + escapeHtml(cveId) + '</code>' +
                    '<span class="badge ' + sevClass + '">' + severity.toUpperCase() + '</span>' +
                '</div>' +
                '<div class="small text-muted"><i class="bi bi-box-seam"></i> ' + escapeHtml(pkgName) + '</div>' +
                (fav.summary ? '<div class="small text-muted mt-1">' + escapeHtml(fav.summary.substring(0, 80)) + (fav.summary.length > 80 ? '...' : '') + '</div>' : '') +
            '</div>' +
            '<button class="btn btn-sm btn-outline-danger" onclick="removeFavorite(\'' + escapeHtml(cveId) + '\')" title="取消收藏">' +
                '<i class="bi bi-bookmark-x"></i></button>' +
        '</div>';
    }).join('');
}

function removeFavorite(cveId) {
    fetch('/api/favorites/' + encodeURIComponent(cveId), { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '操作失败', data.error);
                return;
            }
            showToast('success', '操作成功', '已取消收藏');
            loadFavorites();
        })
        .catch(function (err) {
            console.error('Favorite remove error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Snapshots
// ---------------------------------------------------------------------------

function loadSnapshots() {
    fetch('/api/snapshots')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            renderSnapshots(data.snapshots || data || []);
        })
        .catch(function (err) {
            console.error('Snapshots load error:', err);
        });
}

function renderSnapshots(snapshots) {
    const tbody = document.getElementById('snapshotTableBody');
    if (!tbody) return;

    // Also populate the compare dropdowns
    const baselineSelect = document.getElementById('snapshotBaseline');
    const compareSelect = document.getElementById('snapshotCompare');

    if (!snapshots || snapshots.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">暂无快照</td></tr>';
        if (baselineSelect) baselineSelect.innerHTML = '<option value="">-- 选择快照 --</option>';
        if (compareSelect) compareSelect.innerHTML = '<option value="">-- 选择快照 --</option>';
        return;
    }

    tbody.innerHTML = snapshots.map(function (snap, idx) {
        const id = snap.id || '';
        const name = snap.name || 'Untitled';
        const desc = snap.description || '';
        const scanId = snap.scan_id || '-';
        const createdAt = snap.created_at || snap.created || '-';
        const riskScore = snap.risk_score || 0;

        return '<tr>' +
            '<td>' + (idx + 1) + '</td>' +
            '<td><strong>' + escapeHtml(name) + '</strong></td>' +
            '<td><span class="badge bg-info">#' + escapeHtml(scanId) + '</span></td>' +
            '<td><small class="text-muted">' + escapeHtml(createdAt) + '</small></td>' +
            '<td><small class="text-muted">' + escapeHtml(desc || '无') + '</small></td>' +
            '<td>' +
                '<button class="btn btn-sm btn-outline-info" onclick="location.href=\'/result/' + escapeHtml(scanId) + '\'" title="查看扫描"><i class="bi bi-eye"></i></button> ' +
                '<button class="btn btn-sm btn-outline-danger" onclick="deleteSnapshot(' + id + ')" title="删除快照"><i class="bi bi-trash"></i></button>' +
            '</td>' +
        '</tr>';
    }).join('');

    // Populate compare dropdowns
    const options = '<option value="">-- 选择快照 --</option>' +
        snapshots.map(function (s) {
            return '<option value="' + s.id + '">' + escapeHtml(s.name || 'Untitled') + ' (#' + escapeHtml(s.scan_id) + ')</option>';
        }).join('');
    if (baselineSelect) baselineSelect.innerHTML = options;
    if (compareSelect) compareSelect.innerHTML = options;
}

function createSnapshot() {
    // Use prompt since the HTML template uses a button, not a form
    const name = prompt('请输入快照名称：');
    if (!name || !name.trim()) return;

    const description = prompt('请输入备注（可选）：') || '';
    const scanIdStr = prompt('请输入扫描ID（数字）：');
    const scanId = parseInt(scanIdStr, 10);
    if (!scanId || isNaN(scanId)) {
        showToast('warning', '提示', '请输入有效的扫描ID');
        return;
    }

    fetch('/api/snapshots', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            scan_id: scanId,
            name: name.trim(),
            description: description.trim()
        })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '创建失败', data.error);
                return;
            }
            showToast('success', '操作成功', '快照已创建');
            loadSnapshots();
        })
        .catch(function (err) {
            console.error('Create snapshot error:', err);
            showToast('error', '创建失败', '网络错误');
        });
}

function deleteSnapshot(id) {
    if (!confirm('确定要删除此快照吗?')) return;

    fetch('/api/snapshots/' + id, { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '删除失败', data.error);
                return;
            }
            showToast('success', '操作成功', '快照已删除');
            loadSnapshots();
        })
        .catch(function (err) {
            console.error('Delete snapshot error:', err);
            showToast('error', '删除失败', '网络错误');
        });
}

function compareSnapshots() {
    const snap1 = document.getElementById('snapshotBaseline');
    const snap2 = document.getElementById('snapshotCompare');
    const id1 = snap1 ? snap1.value : '';
    const id2 = snap2 ? snap2.value : '';

    if (!id1 || !id2) {
        showToast('warning', '提示', '请选择两个快照进行对比');
        return;
    }

    fetch('/api/snapshots/compare?snap1=' + id1 + '&snap2=' + id2)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            renderSnapshotCompare(data);
        })
        .catch(function (err) {
            console.error('Compare error:', err);
            showToast('error', '对比失败', '网络错误');
        });
}

function renderSnapshotCompare(data) {
    const modalBody = document.getElementById('snapshotCompareBody');
    if (!modalBody) return;

    const s1 = data.snapshot1 || {};
    const s2 = data.snapshot2 || {};
    const risk1 = s1.risk_score || 0;
    const risk2 = s2.risk_score || 0;
    const diff = risk2 - risk1;

    modalBody.innerHTML =
        '<div class="row g-3">' +
            '<div class="col-md-6">' +
                '<div class="card dashboard-card"><div class="card-body">' +
                    '<h6 class="text-info">基线快照</h6>' +
                    '<p class="mb-1"><strong>' + escapeHtml(s1.name || '-') + '</strong></p>' +
                    '<p class="text-muted small mb-1">' + escapeHtml(s1.created_at || '-') + '</p>' +
                    '<p class="mb-0">风险评分: <span class="badge ' + (risk1 >= 70 ? 'sev-critical' : risk1 >= 40 ? 'sev-high' : 'sev-medium') + '">' + risk1 + '</span></p>' +
                '</div></div>' +
            '</div>' +
            '<div class="col-md-6">' +
                '<div class="card dashboard-card"><div class="card-body">' +
                    '<h6 class="text-info">对比快照</h6>' +
                    '<p class="mb-1"><strong>' + escapeHtml(s2.name || '-') + '</strong></p>' +
                    '<p class="text-muted small mb-1">' + escapeHtml(s2.created_at || '-') + '</p>' +
                    '<p class="mb-0">风险评分: <span class="badge ' + (risk2 >= 70 ? 'sev-critical' : risk2 >= 40 ? 'sev-high' : 'sev-medium') + '">' + risk2 + '</span></p>' +
                '</div></div>' +
            '</div>' +
        '</div>' +
        '<div class="text-center mt-3">' +
            '<h4>风险变化: <span class="' + (diff > 0 ? 'text-danger' : diff < 0 ? 'text-success' : 'text-muted') + '">' +
                (diff > 0 ? '+' : '') + diff + '</span></h4>' +
            (diff > 0 ? '<p class="text-danger">风险评分上升，需要关注新增漏洞</p>' :
             diff < 0 ? '<p class="text-success">风险评分下降，安全状况改善</p>' :
             '<p class="text-muted">风险评分未变化</p>') +
        '</div>';

    // Show modal
    const modal = document.getElementById('snapshotCompareModal');
    if (modal) {
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    }
}

// ---------------------------------------------------------------------------
// Severity badge helper
// ---------------------------------------------------------------------------
function getSevBadgeClass(severity) {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'sev-critical';
    if (s === 'high') return 'sev-high';
    if (s === 'medium') return 'sev-medium';
    if (s === 'low') return 'sev-low';
    return 'bg-secondary';
}

// ---------------------------------------------------------------------------
// Toast notification
// ---------------------------------------------------------------------------
function showToast(type, title, message) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: 'bi-check-circle-fill', error: 'bi-x-circle-fill', info: 'bi-info-circle-fill', warning: 'bi-exclamation-triangle-fill' };
    const colors = { success: '#3fb950', error: '#f85149', info: '#58a6ff', warning: '#d29922' };
    const toast = document.createElement('div');
    toast.className = 'toast-msg ' + type;
    toast.innerHTML = '<div style="display:flex; align-items:start; gap:8px; padding:12px 16px; background:rgba(17,24,39,0.95); border:1px solid rgba(255,255,255,0.1); border-radius:10px; margin-bottom:8px">' +
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
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
