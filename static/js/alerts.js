// SCS Checker - Alerts Page JavaScript
// Handles: alert rules CRUD, notifications list, read/unread marking, unread count.

document.addEventListener('DOMContentLoaded', function () {
    loadAlertRules();
    loadNotifications();
    loadUnreadCount();

    // Create rule form — HTML uses id="alertRuleForm"
    var alertRuleForm = document.getElementById('alertRuleForm');
    if (alertRuleForm) alertRuleForm.addEventListener('submit', createAlertRule);
});

// ---------------------------------------------------------------------------
// Alert Rules
// ---------------------------------------------------------------------------

// Load alert rules from API
function loadAlertRules() {
    fetch('/api/alert-rules')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            renderAlertRules(data.rules || data || []);
        })
        .catch(function (err) {
            console.error('Alert rules load error:', err);
            var tbody = document.getElementById('alertRulesBody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-3">加载失败</td></tr>';
        });
}

// Render alert rules table
function renderAlertRules(rules) {
    var tbody = document.getElementById('alertRulesBody');
    if (!tbody) return;

    if (!rules || rules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">暂无告警规则，请在上方创建</td></tr>';
        return;
    }

    tbody.innerHTML = rules.map(function (rule, idx) {
        var id = rule.id || '';
        var sevThreshold = rule.severity_threshold || 'any';
        var sevBadge = sevThreshold !== 'any'
            ? '<span class="badge ' + getSevBadgeClass(sevThreshold) + '">' + sevThreshold.toUpperCase() + '</span>'
            : '<span class="text-muted">任意</span>';
        var createdAt = rule.created_at || '-';

        return '<tr>' +
            '<td>' + (idx + 1) + '</td>' +
            '<td><strong>' + escapeHtml(rule.name || '-') + '</strong></td>' +
            '<td>' + sevBadge + '</td>' +
            '<td>' + (rule.vuln_count_threshold || 0) + '</td>' +
            '<td>' + (rule.risk_score_threshold || 0) + '</td>' +
            '<td>' + escapeHtml(createdAt) + '</td>' +
            '<td>' +
                '<button class="btn btn-sm btn-outline-danger" onclick="deleteAlertRule(' + id + ')">' +
                    '<i class="bi bi-trash"></i></button>' +
            '</td>' +
            '</tr>';
    }).join('');
}

// Create a new alert rule
function createAlertRule(e) {
    e.preventDefault();

    var name = document.getElementById('ruleName').value.trim();
    var sevThreshold = document.getElementById('ruleSeverity').value;
    var vulnCountThreshold = parseInt(document.getElementById('ruleVulnCount').value, 10) || 0;
    var riskScoreThreshold = parseInt(document.getElementById('ruleRiskScore').value, 10) || 0;

    if (!name) {
        showToast('warning', '提示', '请输入规则名称');
        return;
    }

    // Disable the submit button inside the form (no separate btnCreateRule ID in HTML)
    var form = document.getElementById('alertRuleForm');
    var btn = form ? form.querySelector('button[type="submit"]') : null;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 创建中...';
    }

    var body = {
        name: name,
        severity_threshold: sevThreshold,
        vuln_count_threshold: vulnCountThreshold,
        risk_score_threshold: riskScoreThreshold
    };

    fetch('/api/alert-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '创建失败', data.error);
                return;
            }
            showToast('success', '操作成功', '告警规则已创建');
            document.getElementById('alertRuleForm').reset();
            loadAlertRules();
        })
        .catch(function (err) {
            console.error('Create rule error:', err);
            showToast('error', '创建失败', '网络错误');
        })
        .finally(function () {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-plus-circle"></i> 创建规则';
            }
        });
}

// Delete an alert rule
function deleteAlertRule(id) {
    if (!confirm('确定要删除此告警规则吗?')) return;

    fetch('/api/alert-rules/' + id, { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '删除失败', data.error);
                return;
            }
            showToast('success', '操作成功', '规则已删除');
            loadAlertRules();
        })
        .catch(function (err) {
            console.error('Delete rule error:', err);
            showToast('error', '删除失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

// Load notifications list
function loadNotifications() {
    fetch('/api/notifications')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            renderNotifications(data.notifications || data || []);
        })
        .catch(function (err) {
            console.error('Notifications load error:', err);
            var container = document.getElementById('notificationList');
            if (container) container.innerHTML = '<div class="text-center text-danger py-3">加载失败</div>';
        });
}

// Render notifications list
function renderNotifications(notifications) {
    var container = document.getElementById('notificationList');
    if (!container) return;

    if (!notifications || notifications.length === 0) {
        container.innerHTML = '<div class="text-center text-muted py-5"><i class="bi bi-bell-slash" style="font-size:2rem"></i><p class="mt-2">暂无通知</p></div>';
        return;
    }

    container.innerHTML = notifications.map(function (n) {
        var isRead = n.read || n.is_read || false;
        var sev = n.severity || 'info';
        var sevClass = getSevBadgeClass(sev);
        var readClass = isRead ? 'opacity-50' : '';
        var unreadDot = isRead ? '' : '<span class="badge bg-primary ms-1">未读</span>';

        return '<div class="notification-item ' + readClass + '" style="cursor:pointer;padding:12px;border-bottom:1px solid rgba(255,255,255,.08)" onclick="markAsRead(' + (n.id || 0) + ')">' +
            '<div class="d-flex justify-content-between align-items-start">' +
                '<div class="flex-grow-1">' +
                    '<div class="d-flex align-items-center gap-2 mb-1">' +
                        '<span class="badge ' + sevClass + '">' + sev.toUpperCase() + '</span>' +
                        '<strong>' + escapeHtml(n.title || n.message || '-') + '</strong>' +
                        unreadDot +
                    '</div>' +
                    '<p class="text-muted small mb-0">' + escapeHtml(n.description || n.detail || n.message || '') + '</p>' +
                    '<small class="text-muted">' + escapeHtml(n.created_at || n.time || '') + '</small>' +
                '</div>' +
                '<div class="text-end">' +
                    '<small class="text-muted">来源: ' + escapeHtml(n.source || n.scan_name || '-') + '</small>' +
                '</div>' +
            '</div>' +
        '</div>';
    }).join('');
}

// Mark a single notification as read
function markAsRead(id) {
    if (!id) return;

    fetch('/api/notifications/' + id + '/read', { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function () {
            loadNotifications();
            loadUnreadCount();
        })
        .catch(function (err) {
            console.error('Mark read error:', err);
        });
}

// Mark all notifications as read — HTML onclick calls markAllNotificationsRead()
function markAllNotificationsRead() {
    fetch('/api/notifications/read-all', { method: 'POST' })
        .then(function (r) { return r.json(); })
        .then(function () {
            showToast('success', '操作成功', '所有通知已标记为已读');
            loadNotifications();
            loadUnreadCount();
        })
        .catch(function (err) {
            console.error('Mark all read error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// Load unread count and update stats
function loadUnreadCount() {
    fetch('/api/notifications/unread-count')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            var count = data.count || data.unread_count || 0;

            var el = document.getElementById('unreadCount');
            if (el) el.textContent = count;

            var totalEl = document.getElementById('totalNotifications');
            if (totalEl && data.total !== undefined) totalEl.textContent = data.total;

            var critEl = document.getElementById('criticalAlerts');
            if (critEl && data.critical !== undefined) critEl.textContent = data.critical;
        })
        .catch(function (err) {
            console.error('Unread count error:', err);
        });
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
