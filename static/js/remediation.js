// SCS Checker - Remediation Page JavaScript
// Handles: remediation data loading, fix suggestion list, whitelist operations, export buttons.
// All element IDs and onclick function names match remediation.html template.

// scan_id and project_name come from template variables set in the HTML:
//   const SCAN_ID = {{ scan_id }};
//   const PROJECT_NAME = "{{ project_name }}";
let scanId = (typeof SCAN_ID !== 'undefined') ? SCAN_ID : null;
if (!scanId) {
    const m = window.location.pathname.match(/\/remediation\/(\d+)/);
    if (m) scanId = m[1];
}

let remediationData = null;

document.addEventListener('DOMContentLoaded', function () {
    if (!scanId) {
        var page = document.getElementById('remediationPage');
        if (page) page.innerHTML = '<div class="text-center text-danger py-5"><i class="bi bi-exclamation-circle"></i> 缺少 scan_id 参数</div>';
        return;
    }

    loadRemediation();

    // Bind filter and search events
    var sevFilter = document.getElementById('remSevFilter');
    if (sevFilter) {
        sevFilter.addEventListener('change', function () {
            applyFilters();
        });
    }

    var searchInput = document.getElementById('remSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            applyFilters();
        });
    }
});

// ---------------------------------------------------------------------------
// Load remediation data
// ---------------------------------------------------------------------------
function loadRemediation() {
    fetch('/api/remediation/' + scanId)
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '加载失败', data.error);
                return;
            }
            remediationData = data;
            renderSummary(data);
            renderRemediationList(data.remediations || data.suggestions || []);
            renderWhitelist(data.whitelist || []);
        })
        .catch(function (err) {
            console.error('Remediation load error:', err);
            showToast('error', '加载失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Render summary cards
// HTML IDs: remStatTotal, remStatCritical, remStatVulns, remStatWhitelisted, remRiskScore
// ---------------------------------------------------------------------------
function renderSummary(data) {
    var summary = data.summary || data;
    var items = data.remediations || data.suggestions || [];

    // Total suggestions
    var elTotal = document.getElementById('remStatTotal');
    if (elTotal) elTotal.textContent = items.length;

    // Critical / high count
    var criticalCount = 0;
    for (var i = 0; i < items.length; i++) {
        var sev = (items[i].severity || items[i].worst_severity || '').toLowerCase();
        if (sev === 'critical' || sev === 'high') {
            criticalCount++;
        }
    }
    var elCritical = document.getElementById('remStatCritical');
    if (elCritical) elCritical.textContent = criticalCount;

    // Affected vulns
    var elVulns = document.getElementById('remStatVulns');
    if (elVulns) elVulns.textContent = summary.total_vulns || summary.affected_vulns || 0;

    // Whitelisted count
    var elWhitelisted = document.getElementById('remStatWhitelisted');
    if (elWhitelisted) elWhitelisted.textContent = (data.whitelist || []).length;

    // Risk score
    var elRisk = document.getElementById('remRiskScore');
    if (elRisk) {
        var riskVal = summary.risk_score || summary.risk_reduction || summary.score || '-';
        elRisk.textContent = riskVal;
    }
}

// ---------------------------------------------------------------------------
// Render remediation suggestion list
// HTML container ID: remSuggestionList
// ---------------------------------------------------------------------------
function renderRemediationList(items) {
    var container = document.getElementById('remSuggestionList');
    if (!container) return;

    if (!items || items.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-check-circle" style="font-size:2rem"></i><p class="mt-2">无需修复的漏洞</p></div>';
        return;
    }

    container.innerHTML = items.map(function (item, idx) {
        var sev = item.severity || item.worst_severity || 'medium';
        var sevClass = getSevBadgeClass(sev);
        var sevText = sev.toUpperCase();
        var pkgName = escapeHtml(item.package || item.name || '-');
        var currentVer = escapeHtml(item.current_version || item.version || '-');
        var fixedVer = escapeHtml(item.fixed_version || item.suggested_version || '-');
        var vulnCount = item.vuln_count || item.affected_vulns || 0;

        return '<div class="card mb-2 remediation-item" data-severity="' + sev.toLowerCase() + '" data-package="' + pkgName.toLowerCase() + '" style="background:rgba(255,255,255,.03);border-color:rgba(255,255,255,.08)">' +
            '<div class="card-body">' +
                '<div class="d-flex justify-content-between align-items-start flex-wrap gap-2">' +
                    '<div class="flex-grow-1">' +
                        '<div class="d-flex align-items-center gap-2 mb-1">' +
                            '<i class="bi bi-box-seam text-info"></i>' +
                            '<strong>' + pkgName + '</strong>' +
                            '<span class="badge ' + sevClass + '">' + sevText + '</span>' +
                        '</div>' +
                        '<div class="version-change">' +
                            '<code class="text-danger">v' + currentVer + '</code>' +
                            ' <i class="bi bi-arrow-right text-muted mx-1"></i> ' +
                            '<code class="text-success">v' + fixedVer + '</code>' +
                            ' <span class="text-muted small ms-2">影响 ' + vulnCount + ' 个漏洞</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="d-flex gap-1">' +
                        '<button class="btn btn-sm btn-outline-info" onclick="showRemediationDetail(' + idx + ')">' +
                            '<i class="bi bi-info-circle"></i> 查看详情</button>' +
                        '<button class="btn btn-sm btn-outline-warning" onclick="addToWhitelist(' + idx + ')">' +
                            '<i class="bi bi-shield-check"></i> 加入白名单</button>' +
                    '</div>' +
                '</div>' +
            '</div>' +
        '</div>';
    }).join('');
}

// ---------------------------------------------------------------------------
// Apply severity filter and package name search
// ---------------------------------------------------------------------------
function applyFilters() {
    var sevFilter = document.getElementById('remSevFilter');
    var searchInput = document.getElementById('remSearch');
    var container = document.getElementById('remSuggestionList');
    if (!container) return;

    var sevValue = sevFilter ? sevFilter.value : 'all';
    var searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';

    var items = container.querySelectorAll('.remediation-item');
    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        var itemSev = item.getAttribute('data-severity') || '';
        var itemPkg = item.getAttribute('data-package') || '';

        var sevMatch = (sevValue === 'all') || (itemSev === sevValue);
        var searchMatch = !searchTerm || itemPkg.indexOf(searchTerm) !== -1;

        item.style.display = (sevMatch && searchMatch) ? '' : 'none';
    }
}

// ---------------------------------------------------------------------------
// Show remediation detail in a modal (reuses whitelistModal structure)
// ---------------------------------------------------------------------------
function showRemediationDetail(idx) {
    var items = (remediationData.remediations || remediationData.suggestions || []);
    var item = items[idx];
    if (!item) return;

    var html = '<div class="mb-3">';
    html += '<h6><i class="bi bi-box-seam text-info"></i> ' + escapeHtml(item.package || item.name || '-') + '</h6>';
    html += '<table class="table table-sm table-dark"><tbody>';
    html += '<tr><th style="width:120px">当前版本</th><td><code>' + escapeHtml(item.current_version || item.version || '-') + '</code></td></tr>';
    html += '<tr><th>建议版本</th><td><code class="text-success">' + escapeHtml(item.fixed_version || item.suggested_version || '-') + '</code></td></tr>';
    html += '<tr><th>影响漏洞数</th><td><span class="text-warning">' + (item.vuln_count || item.affected_vulns || 0) + '</span></td></tr>';
    html += '<tr><th>严重性</th><td><span class="badge ' + getSevBadgeClass(item.severity || item.worst_severity || 'medium') + '">' + (item.severity || item.worst_severity || 'medium').toUpperCase() + '</span></td></tr>';
    html += '</tbody></table>';
    html += '</div>';

    // Affected vulnerabilities
    var vulns = item.vulnerabilities || item.affected_vulnerabilities_list || [];
    if (vulns.length > 0) {
        html += '<h6>受影响漏洞 (' + vulns.length + ')</h6>';
        html += '<div class="table-responsive"><table class="table table-sm table-dark">';
        html += '<thead><tr><th>漏洞ID</th><th>严重性</th><th>CVSS</th><th>摘要</th></tr></thead><tbody>';
        for (var i = 0; i < Math.min(vulns.length, 20); i++) {
            var v = vulns[i];
            var vSev = v.severity || 'unknown';
            html += '<tr>' +
                '<td><code>' + escapeHtml(v.id || v.vuln_id || '-') + '</code></td>' +
                '<td><span class="badge ' + getSevBadgeClass(vSev) + '">' + vSev.toUpperCase() + '</span></td>' +
                '<td>' + (typeof v.cvss === 'number' ? v.cvss.toFixed(1) : escapeHtml(v.cvss || '-')) + '</td>' +
                '<td style="max-width:300px">' + escapeHtml((v.summary || '').substring(0, 80)) + '</td>' +
                '</tr>';
        }
        html += '</tbody></table></div>';
    }

    // Use the whitelistModal to show detail — update title and body dynamically
    var modalEl = document.getElementById('whitelistModal');
    if (modalEl) {
        var titleEl = modalEl.querySelector('.modal-title');
        var bodyEl = modalEl.querySelector('.modal-body');
        var footerEl = modalEl.querySelector('.modal-footer');
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-info-circle"></i> 修复详情: ' + escapeHtml(item.package || item.name || '');
        if (bodyEl) bodyEl.innerHTML = html;
        // Hide the save button in detail view
        if (footerEl) {
            var saveBtn = footerEl.querySelector('[onclick="remediationSaveWhitelist()"]');
            if (saveBtn) saveBtn.style.display = 'none';
            var cancelBtn = footerEl.querySelector('[data-bs-dismiss="modal"]');
            if (cancelBtn) cancelBtn.textContent = '关闭';
        }
        new bootstrap.Modal(modalEl).show();
        // Restore modal on close
        modalEl.addEventListener('hidden.bs.modal', function handler() {
            if (titleEl) titleEl.innerHTML = '<i class="bi bi-plus-circle"></i> 添加白名单';
            if (footerEl) {
                var sb = footerEl.querySelector('[onclick="remediationSaveWhitelist()"]');
                if (sb) sb.style.display = '';
                var cb = footerEl.querySelector('[data-bs-dismiss="modal"]');
                if (cb) cb.textContent = '取消';
            }
            modalEl.removeEventListener('hidden.bs.modal', handler);
        });
    }
}

// ---------------------------------------------------------------------------
// Add a package to whitelist from suggestion list (inline prompt)
// ---------------------------------------------------------------------------
function addToWhitelist(idx) {
    var items = (remediationData.remediations || remediationData.suggestions || []);
    var item = items[idx];
    if (!item) return;

    // Pre-fill the modal fields and open it
    var pkgInput = document.getElementById('wlPkgName');
    var verInput = document.getElementById('wlPkgVersion');
    var reasonInput = document.getElementById('wlReason');

    if (pkgInput) pkgInput.value = item.package || item.name || '';
    if (verInput) verInput.value = item.fixed_version || item.suggested_version || '';
    if (reasonInput) reasonInput.value = '';

    var modalEl = document.getElementById('whitelistModal');
    if (modalEl) {
        // Restore modal to whitelist-add mode
        var titleEl = modalEl.querySelector('.modal-title');
        var footerEl = modalEl.querySelector('.modal-footer');
        if (titleEl) titleEl.innerHTML = '<i class="bi bi-plus-circle"></i> 添加白名单';
        if (footerEl) {
            var saveBtn = footerEl.querySelector('[onclick="remediationSaveWhitelist()"]');
            if (saveBtn) saveBtn.style.display = '';
            var cancelBtn = footerEl.querySelector('[data-bs-dismiss="modal"]');
            if (cancelBtn) cancelBtn.textContent = '取消';
        }
        // Restore modal body to original whitelist form
        var bodyEl = modalEl.querySelector('.modal-body');
        if (bodyEl) {
            bodyEl.innerHTML =
                '<div class="mb-3">' +
                    '<label class="form-label text-muted">包名</label>' +
                    '<input type="text" class="form-control" id="wlPkgName" placeholder="例如：requests" value="' + escapeHtml(item.package || item.name || '') + '">' +
                '</div>' +
                '<div class="mb-3">' +
                    '<label class="form-label text-muted">版本</label>' +
                    '<input type="text" class="form-control" id="wlPkgVersion" placeholder="例如：2.28.0" value="' + escapeHtml(item.fixed_version || item.suggested_version || '') + '">' +
                '</div>' +
                '<div class="mb-3">' +
                    '<label class="form-label text-muted">原因</label>' +
                    '<textarea class="form-control" id="wlReason" rows="2" placeholder="说明加入白名单的原因..."></textarea>' +
                '</div>';
        }
        new bootstrap.Modal(modalEl).show();
    }
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationAddWhitelist() — open modal for manual entry
// ---------------------------------------------------------------------------
function remediationAddWhitelist() {
    // Clear fields
    var modalEl = document.getElementById('whitelistModal');
    if (!modalEl) return;

    // Restore modal to whitelist-add mode
    var titleEl = modalEl.querySelector('.modal-title');
    var footerEl = modalEl.querySelector('.modal-footer');
    if (titleEl) titleEl.innerHTML = '<i class="bi bi-plus-circle"></i> 添加白名单';
    if (footerEl) {
        var saveBtn = footerEl.querySelector('[onclick="remediationSaveWhitelist()"]');
        if (saveBtn) saveBtn.style.display = '';
        var cancelBtn = footerEl.querySelector('[data-bs-dismiss="modal"]');
        if (cancelBtn) cancelBtn.textContent = '取消';
    }

    // Restore modal body to original whitelist form with empty fields
    var bodyEl = modalEl.querySelector('.modal-body');
    if (bodyEl) {
        bodyEl.innerHTML =
            '<div class="mb-3">' +
                '<label class="form-label text-muted">包名</label>' +
                '<input type="text" class="form-control" id="wlPkgName" placeholder="例如：requests">' +
            '</div>' +
            '<div class="mb-3">' +
                '<label class="form-label text-muted">版本</label>' +
                '<input type="text" class="form-control" id="wlPkgVersion" placeholder="例如：2.28.0">' +
            '</div>' +
            '<div class="mb-3">' +
                '<label class="form-label text-muted">原因</label>' +
                '<textarea class="form-control" id="wlReason" rows="2" placeholder="说明加入白名单的原因..."></textarea>' +
            '</div>';
    }

    new bootstrap.Modal(modalEl).show();
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationSaveWhitelist() — save whitelist from modal
// ---------------------------------------------------------------------------
function remediationSaveWhitelist() {
    var pkgInput = document.getElementById('wlPkgName');
    var verInput = document.getElementById('wlPkgVersion');
    var reasonInput = document.getElementById('wlReason');

    var pkgName = pkgInput ? pkgInput.value.trim() : '';
    var pkgVersion = verInput ? verInput.value.trim() : '';
    var reason = reasonInput ? reasonInput.value.trim() : '';

    if (!pkgName) {
        showToast('warning', '输入错误', '请填写包名');
        return;
    }

    fetch('/api/remediation/' + scanId + '/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            package: pkgName,
            version: pkgVersion,
            reason: reason
        })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '操作失败', data.error);
                return;
            }
            showToast('success', '操作成功', '已加入白名单');
            // Close modal
            var modalEl = document.getElementById('whitelistModal');
            if (modalEl) {
                var bsModal = bootstrap.Modal.getInstance(modalEl);
                if (bsModal) bsModal.hide();
            }
            loadRemediation();
        })
        .catch(function (err) {
            console.error('Whitelist save error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Remove a vuln from whitelist
// ---------------------------------------------------------------------------
function removeFromWhitelist(vulnId) {
    if (!confirm('确定要移除此白名单项吗?')) return;

    fetch('/api/remediation/' + scanId + '/whitelist/' + encodeURIComponent(vulnId), {
        method: 'DELETE'
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '操作失败', data.error);
                return;
            }
            showToast('success', '操作成功', '已移除白名单项');
            loadRemediation();
        })
        .catch(function (err) {
            console.error('Whitelist remove error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Render whitelist table
// HTML container ID: whitelistTableBody (a <tbody> element)
// ---------------------------------------------------------------------------
function renderWhitelist(whitelist) {
    var container = document.getElementById('whitelistTableBody');
    if (!container) return;

    if (!whitelist || whitelist.length === 0) {
        container.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">暂无白名单项</td></tr>';
        return;
    }

    container.innerHTML = whitelist.map(function (w, i) {
        var vulnId = w.vuln_id || w.id || '';
        var pkg = escapeHtml(w.package || '-');
        var version = escapeHtml(w.version || '-');
        var reason = escapeHtml(w.reason || '');
        var addedAt = escapeHtml(w.added_at || w.created_at || '-');

        return '<tr>' +
            '<td>' + (i + 1) + '</td>' +
            '<td><strong>' + pkg + '</strong></td>' +
            '<td><code>' + version + '</code></td>' +
            '<td>' + (reason || '<span class="text-muted">-</span>') + '</td>' +
            '<td>' + addedAt + '</td>' +
            '<td>' +
                '<button class="btn btn-sm btn-outline-danger" onclick="removeFromWhitelist(\'' + escapeHtml(vulnId) + '\')">' +
                    '<i class="bi bi-x-circle"></i>' +
                '</button>' +
            '</td>' +
        '</tr>';
    }).join('');
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationDownloadScript() — download batch fix shell script
// ---------------------------------------------------------------------------
function remediationDownloadScript() {
    window.location.href = '/api/remediation/' + scanId + '/fix-script';
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationDownloadRequirements() — download fixed requirements.txt
// ---------------------------------------------------------------------------
function remediationDownloadRequirements() {
    window.location.href = '/api/remediation/' + scanId + '/fixed-requirements';
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationExportExcel() — export Excel report
// ---------------------------------------------------------------------------
function remediationExportExcel() {
    window.location.href = '/api/export/' + scanId + '/excel';
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationExportWord() — export Word report
// ---------------------------------------------------------------------------
function remediationExportWord() {
    window.location.href = '/api/export/' + scanId + '/word';
}

// ---------------------------------------------------------------------------
// HTML onclick: remediationExportPDF() — export PDF report
// ---------------------------------------------------------------------------
function remediationExportPDF() {
    window.open('/api/export/' + scanId + '/pdf');
}

// ---------------------------------------------------------------------------
// Severity badge helper
// ---------------------------------------------------------------------------
function getSevBadgeClass(severity) {
    var s = (severity || '').toLowerCase();
    if (s === 'critical') return 'sev-critical';
    if (s === 'high') return 'sev-high';
    if (s === 'medium') return 'sev-medium';
    if (s === 'low') return 'sev-low';
    return 'bg-secondary';
}

// ---------------------------------------------------------------------------
// Toast notification
// HTML container ID: toastContainer
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
