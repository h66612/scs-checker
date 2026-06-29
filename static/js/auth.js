// SCS Checker - Auth Page JavaScript
// Handles: form submission, session check, nav user area, dynamic messages
// Compatible with login.html template (server-side mode switching via ?mode=register)

document.addEventListener('DOMContentLoaded', function () {
    // Populate navbar user area on every page
    updateNavUserArea();

    // Auth form handlers (only active on the login page)
    var loginForm = document.getElementById('loginForm');
    var registerForm = document.getElementById('registerForm');
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    if (registerForm) registerForm.addEventListener('submit', handleRegister);

    // Show success message after redirect from registration
    checkRegisteredMessage();
});

// ---------------------------------------------------------------------------
// Detect which mode the server rendered
// ---------------------------------------------------------------------------
function getAuthMode() {
    if (document.getElementById('loginForm')) return 'login';
    if (document.getElementById('registerForm')) return 'register';
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
// After successful registration, the user is redirected to /login.
// Detect the URL parameter and show a success banner.
// ---------------------------------------------------------------------------
function checkRegisteredMessage() {
    var params = new URLSearchParams(window.location.search);
    if (params.get('registered') === '1') {
        var username = params.get('username') || '';
        showAuthMessage(
            'success',
            '注册成功！' + (username ? '用户 ' + escapeHtml(username) + ' ' : '') + '请登录您的账户。'
        );
        // Pre-fill username field
        var loginUsername = document.getElementById('loginUsername');
        if (loginUsername && username) {
            loginUsername.value = username;
        }
    }
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
// Register form handler
// ---------------------------------------------------------------------------
function handleRegister(e) {
    e.preventDefault();
    hideAuthMessage();

    var username = document.getElementById('regUsername').value.trim();
    var email = document.getElementById('regEmail').value.trim();
    var password = document.getElementById('regPassword').value;
    var confirmPassword = document.getElementById('regPasswordConfirm').value;

    if (!username || !email || !password) {
        showAuthMessage('danger', '请填写所有必填字段');
        return;
    }
    if (password !== confirmPassword) {
        showAuthMessage('danger', '两次输入的密码不一致');
        return;
    }
    if (password.length < 6) {
        showAuthMessage('danger', '密码长度至少6位');
        return;
    }

    var btn = document.getElementById('registerBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> 注册中...';
    }

    fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, email: email, password: password })
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.error) {
                showAuthMessage('danger', data.error);
                resetRegisterButton();
                return;
            }
            // Success - redirect to login page with success flag
            window.location.href = '/login?registered=1&username=' + encodeURIComponent(username);
        })
        .catch(function (err) {
            console.error('Register error:', err);
            showAuthMessage('danger', '注册失败: 网络错误，请重试');
            resetRegisterButton();
        });
}

function resetRegisterButton() {
    var btn = document.getElementById('registerBtn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-person-plus-fill"></i> 注册';
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
