// SCS Checker - Admin Panel JavaScript
// Handles: tab switching, user management (list, role change, deactivate),
// audit log viewing with search filtering.

let allUsers = [];
let allAuditLogs = [];

document.addEventListener('DOMContentLoaded', function () {
    // Tab switching
    const tabLinks = document.querySelectorAll('.nav-link[data-tab]');
    tabLinks.forEach(function (link) {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            switchTab(link.getAttribute('data-tab'));
        });
    });

    // Load default tab (users)
    loadUsers();

    // Audit log search
    const auditSearch = document.getElementById('auditSearch');
    if (auditSearch) auditSearch.addEventListener('input', filterAuditLogs);

    // Load audit logs on init so they're ready when the tab is opened
    loadAuditLogs();
});

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
function switchTab(tabId) {
    document.querySelectorAll('.nav-link[data-tab]').forEach(function (link) {
        link.classList.remove('active');
        if (link.getAttribute('data-tab') === tabId) link.classList.add('active');
    });
    document.querySelectorAll('.tab-pane').forEach(function (pane) {
        pane.classList.remove('active', 'show');
        if (pane.id === tabId) pane.classList.add('active', 'show');
    });

    if (tabId === 'tab-users') {
        loadUsers();
    } else if (tabId === 'tab-audit') {
        loadAuditLogs();
    }
}

// ---------------------------------------------------------------------------
// Tab 1: User Management
// ---------------------------------------------------------------------------

// Load users list
function loadUsers() {
    fetch('/api/users')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            allUsers = data.users || data || [];
            renderUsersTable(allUsers);
        })
        .catch(function (err) {
            console.error('Users load error:', err);
            const tbody = document.getElementById('usersTableBody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="text-center text-danger py-3">加载失败</td></tr>';
        });
}

// Render users table
function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-3">暂无用户</td></tr>';
        return;
    }

    tbody.innerHTML = users.map(function (u) {
        const id = u.id || '';
        const role = u.role || 'user';
        const roleBadge = role === 'admin'
            ? '<span class="badge bg-danger"><i class="bi bi-shield-fill"></i> 管理员</span>'
            : '<span class="badge bg-info"><i class="bi bi-person"></i> 用户</span>';
        const isActive = u.is_active !== false && u.active !== false;
        const statusBadge = isActive
            ? '<span class="badge bg-success">活跃</span>'
            : '<span class="badge bg-secondary">已停用</span>';
        const created = u.created_at || u.created || '-';
        const lastLogin = u.last_login || u.last_login_at || '从未';
        const roleBtnLabel = role === 'admin' ? '降为用户' : '升为管理员';
        const roleBtnIcon = role === 'admin' ? 'bi-arrow-down' : 'bi-arrow-up';
        const roleBtnClass = role === 'admin' ? 'btn-outline-warning' : 'btn-outline-info';
        const toggleBtnLabel = isActive ? '停用' : '启用';
        const toggleBtnIcon = isActive ? 'bi-person-dash' : 'bi-person-check';
        const toggleBtnClass = isActive ? 'btn-outline-danger' : 'btn-outline-success';

        return '<tr>' +
            '<td>' + id + '</td>' +
            '<td><strong>' + escapeHtml(u.username || '-') + '</strong></td>' +
            '<td>' + escapeHtml(u.email || '-') + '</td>' +
            '<td>' + roleBadge + '</td>' +
            '<td><small class="text-muted">' + escapeHtml(created) + '</small></td>' +
            '<td><small class="text-muted">' + escapeHtml(lastLogin) + '</small></td>' +
            '<td>' +
                '<div class="d-flex gap-1">' +
                    '<span class="me-1">' + statusBadge + '</span>' +
                    '<button class="btn btn-sm ' + roleBtnClass + '" onclick="changeUserRole(' + id + ', \'' + (role === 'admin' ? 'user' : 'admin') + '\')" title="' + roleBtnLabel + '">' +
                        '<i class="bi ' + roleBtnIcon + '"></i></button>' +
                    (isActive
                        ? '<button class="btn btn-sm ' + toggleBtnClass + '" onclick="deactivateUser(' + id + ')" title="' + toggleBtnLabel + '">' +
                            '<i class="bi ' + toggleBtnIcon + '"></i></button>'
                        : '<button class="btn btn-sm ' + toggleBtnClass + '" onclick="changeUserRole(' + id + ', \'user\')" title="' + toggleBtnLabel + '">' +
                            '<i class="bi ' + toggleBtnIcon + '"></i></button>') +
                '</div>' +
            '</td>' +
            '</tr>';
    }).join('');
}

// Change user role
function changeUserRole(userId, newRole) {
    if (!confirm('确定要将该用户角色变更为 "' + newRole + '" 吗?')) return;

    fetch('/api/users/' + userId + '/role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: newRole })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '操作失败', data.error);
                return;
            }
            showToast('success', '操作成功', '用户角色已更新');
            loadUsers();
        })
        .catch(function (err) {
            console.error('Change role error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// Deactivate user
function deactivateUser(userId) {
    if (!confirm('确定要停用该用户吗?')) return;

    fetch('/api/users/' + userId, { method: 'DELETE' })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showToast('error', '操作失败', data.error);
                return;
            }
            showToast('success', '操作成功', '用户已停用');
            loadUsers();
        })
        .catch(function (err) {
            console.error('Deactivate user error:', err);
            showToast('error', '操作失败', '网络错误');
        });
}

// ---------------------------------------------------------------------------
// Tab 2: Audit Logs
// ---------------------------------------------------------------------------

// Load audit logs
function loadAuditLogs() {
    fetch('/api/audit-logs')
        .then(function (r) { return r.json(); })
        .then(function (data) {
            allAuditLogs = data.logs || data || [];
            renderAuditTable(allAuditLogs);
        })
        .catch(function (err) {
            console.error('Audit logs load error:', err);
            const tbody = document.getElementById('auditLogTableBody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-3">加载失败</td></tr>';
        });
}

// Render audit logs table
function renderAuditTable(logs) {
    const tbody = document.getElementById('auditLogTableBody');
    if (!tbody) return;

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-3">暂无审计日志</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map(function (log) {
        const action = log.action || '-';
        let actionBadge;
        const actLower = action.toLowerCase();
        if (actLower.includes('delete') || actLower.includes('remove')) {
            actionBadge = '<span class="badge bg-danger">' + escapeHtml(action) + '</span>';
        } else if (actLower.includes('create') || actLower.includes('add') || actLower.includes('register')) {
            actionBadge = '<span class="badge bg-success">' + escapeHtml(action) + '</span>';
        } else if (actLower.includes('update') || actLower.includes('change') || actLower.includes('modify')) {
            actionBadge = '<span class="badge bg-warning">' + escapeHtml(action) + '</span>';
        } else if (actLower.includes('login') || actLower.includes('logout')) {
            actionBadge = '<span class="badge bg-info">' + escapeHtml(action) + '</span>';
        } else {
            actionBadge = '<span class="badge bg-secondary">' + escapeHtml(action) + '</span>';
        }

        return '<tr>' +
            '<td><small class="text-muted">' + escapeHtml(log.timestamp || log.time || log.created_at || '-') + '</small></td>' +
            '<td><strong>' + escapeHtml(log.username || log.user || '-') + '</strong></td>' +
            '<td>' + actionBadge + '</td>' +
            '<td>' + escapeHtml(log.target || log.resource || '-') + '</td>' +
            '<td><small class="text-muted">' + escapeHtml(log.detail || log.details || '-') + '</small></td>' +
            '<td><code>' + escapeHtml(log.ip || log.ip_address || '-') + '</code></td>' +
            '</tr>';
    }).join('');
}

// Filter audit logs by search query
function filterAuditLogs() {
    const query = (document.getElementById('auditSearch').value || '').toLowerCase().trim();
    if (!query) {
        renderAuditTable(allAuditLogs);
        return;
    }
    const filtered = allAuditLogs.filter(function (log) {
        const fields = [
            log.username || log.user || '',
            log.action || '',
            log.target || log.resource || '',
            log.detail || log.details || '',
            log.ip || log.ip_address || '',
            log.timestamp || log.time || ''
        ].join(' ').toLowerCase();
        return fields.includes(query);
    });
    renderAuditTable(filtered);
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
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}
