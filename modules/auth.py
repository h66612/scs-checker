#!/usr/bin/env python3
"""
SCS Checker - Authentication & User Management Module
Provides password hashing, session management, and role-based access control.
"""
import hashlib
import hmac
import os
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, jsonify, redirect, url_for, render_template


def _now_beijing():
    """Return current Beijing time (UTC+8)."""
    return datetime.utcnow() + timedelta(hours=8)


def hash_password(password, salt=None):
    """Hash a password with salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt + ':' + pw_hash.hex()


def verify_password(password, stored_hash):
    """Verify a password against stored hash."""
    try:
        salt, pw_hash = stored_hash.split(':')
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return hmac.compare_digest(computed.hex(), pw_hash)
    except:
        return False


def _is_api_request():
    """Detect if the request expects JSON (fetch/XHR) rather than HTML."""
    if request.path.startswith('/api/'):
        return True
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        ct = (request.content_type or '').lower()
        if 'json' in ct:
            return True
    accept = (request.headers.get('Accept') or '').lower()
    if 'application/json' in accept and 'text/html' not in accept:
        return True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True
    return False


def login_required(f):
    """Decorator: require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if _is_api_request():
                return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator: require admin role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if _is_api_request():
                return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
            return redirect(url_for('login_page'))
        if session.get('role') != 'admin':
            if _is_api_request():
                return jsonify({'error': 'Admin access required', 'code': 'FORBIDDEN'}), 403
            return render_template('error.html', message='需要管理员权限'), 403
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """Get current logged-in user info from session."""
    if 'user_id' not in session:
        return None
    return {
        'id': session.get('user_id'),
        'username': session.get('username'),
        'role': session.get('role'),
        'email': session.get('email', ''),
    }


def log_audit(conn, user_id, username, action, target='', details=''):
    """Insert an audit log entry."""
    try:
        ip = request.remote_addr or 'unknown'
        conn.execute(
            '''INSERT INTO audit_logs (user_id, username, action, target, details, ip_address, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (user_id, username, action, target, details, ip, _now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
    except:
        pass


def init_auth_tables(conn):
    """Create auth-related tables if not exist."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            details TEXT DEFAULT '',
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    # Create default admin if no users exist
    row = conn.execute('SELECT COUNT(*) as cnt FROM users').fetchone()
    if row['cnt'] == 0:
        default_pw = os.environ.get('ADMIN_PASSWORD')
        if not default_pw:
            default_pw = secrets.token_urlsafe(12)
            print("=" * 55)
            print("  [SECURITY] Generated random admin password:")
            print(f"  Username: admin")
            print(f"  Password: {default_pw}")
            print("  [SECURITY] Set ADMIN_PASSWORD env var to override.")
            print("  [SECURITY] Change this password after first login!")
            print("=" * 55)
        else:
            print("  [SECURITY] Admin password loaded from ADMIN_PASSWORD env var")
        admin_hash = hash_password(default_pw)
        conn.execute(
            '''INSERT INTO users (username, password_hash, email, role, created_at)
               VALUES (?, ?, ?, 'admin', ?)''',
            ('admin', admin_hash, 'admin@scs-checker.local', _now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
