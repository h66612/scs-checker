// SCS Checker - Auth Page JavaScript
// Handles: form submission, session check, nav user area, dynamic messages

document.addEventListener('DOMContentLoaded', function () {
    // Populate navbar user area on every page
    updateNavUserArea();

    // Auth form handler (only active on the login page)
    var loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
});

// ---------------------------------------------------------------------------
// Detect which mode the server rendered
// ---------------------------------------------------------------------------
function getAuthMode() {
    if (document.getElementById('loginForm')) return 'login';
    return null; // not on auth page
}

// ---------------------------------------------------------------------------
// Check current user session
// - On auth page: redirect to home if already logged in
// - Returns promise for nav area usage
// ---------------------------------------------------------------------------
function checkCurrentUser() {
    return fetch('/api/current-user')
        .then(function (r) {
            if (!r.ok) return null;
            return r.json();
        })
        .then(function (data) {
            if (data && data.username && getAuthMode()) {
                // Already logged in while on auth page -> redirect away
                if (data.role === 'admin') {
                    window.location.href = '/admin';
                } else {
                    window.location.href = '/';
                }
            }
            return data;
        })
        .catch(function () {
            return null;
        });
}

// ---------------------------------------------------------------------------
// Update #navUserArea in base.html navbar
// Shows login button for guests, user dropdown for logged-in users
// ---------------------------------------------------------------------------
function updateNavUserArea() {
    var navUserArea = document.getElementById('navUserArea');
    if (!navUserArea) return;

    fetch('/api/current-user')
        .then(function (r) {
            if (!r.ok) return null;
            return r.json();
        })
        .then(function (data) {
            if (data && data.username) {
                var roleBadge = data.role === 'admin'
                    ? '<span class="badge bg-danger ms-1" style="font-size:0.6rem">ADMIN</span>'
                    : '';
                navUserArea.innerHTML =
                    '<div class="dropdown">' +
                        '<a class="nav-link dropdown-toggle text-info" href="#" role="button" data-bs-toggle="dropdown">' +
                            '<i class="bi bi-person-circle"></i> ' + escapeHtml(data.username) + roleBadge +
                        '</a>' +
                        '<ul class="dropdown-menu dropdown-menu-end dropdown-menu-dark">' +
                            '<li><a class="dropdown-item" href="/dashboard"><i class="bi bi-speedometer2"></i> 仪表盘</a></li>' +
                            '<li><hr class="dropdown-divider"></li>' +
                            '<li><a class="dropdown-item text-danger" href="/logout"><i class="bi bi-box-arrow-right"></i> 退出登录</a></li>' +
                        '</ul>' +
                    '</div>';
            } else {
                navUserArea.innerHTML =
                    '<a class="nav-link text-info" href="/login">' +
                        '<i class="bi bi-box-arrow-in-right"></i> 登录' +
                    '</a>';
            }
        })
        .catch(function () {
            navUserArea.innerHTML =
                '<a class="nav-link text-info" href="/login">' +
                    '<i class="bi bi-box-arrow-in-right"></i> 登录' +
                '</a>';
        });
}

// ---------------------------------------------------------------------------
// Login form handler
// ---------------------------------------------------------------------------
function handleLogin(e) {
    e.preventDefault();
    hideAuthMessage();

    var username = document.getElementById('loginUsername').value.trim();
    var password = document.getElementById('loginPassword').value;

    if (!username || !password) {
        showAuthMessage('danger', '请输入用户名和密码');
        return;
    }

    var btn = document.getElementById('loginBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 登录中...';
    }

    fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showAuthMessage('danger', data.error);
                resetLoginButton();
                return;
            }
            // Success - redirect based on role
            if (data.role === 'admin') {
                window.location.href = '/admin';
            } else {
                window.location.href = data.redirect || '/';
            }
        })
        .catch(function (err) {
            console.error('Login error:', err);
            showAuthMessage('danger', '登录失败: 网络错误，请重试');
            resetLoginButton();
        });
}

function resetLoginButton() {
    var btn = document.getElementById('loginBtn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-box-arrow-in-right"></i> 登录';
    }
}

// ---------------------------------------------------------------------------
// Dynamic message display
// The HTML template has no static error/success containers, so we create
// them dynamically inside the auth card (the .neon-card element).
// ---------------------------------------------------------------------------
function showAuthMessage(type, message) {
    hideAuthMessage();

    var cardBody = document.querySelector('.neon-card .card-body');
    if (!cardBody) return;

    var icons = {
        danger: 'bi-exclamation-circle-fill',
        success: 'bi-check-circle-fill',
        warning: 'bi-exclamation-triangle-fill',
        info: 'bi-info-circle-fill'
    };
    var icon = icons[type] || icons.info;

    var alert = document.createElement('div');
    alert.id = 'authAlert';
    alert.className = 'alert alert-' + type + ' alert-dismissible fade show';
    alert.setAttribute('role', 'alert');
    alert.innerHTML =
        '<i class="bi ' + icon + '"></i> ' + escapeHtml(message) +
        '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';

    // Insert at the top of the card body (before the form title)
    cardBody.insertBefore(alert, cardBody.firstChild);
}

function hideAuthMessage() {
    var existing = document.getElementById('authAlert');
    if (existing) existing.remove();
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
