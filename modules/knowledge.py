#!/usr/bin/env python3
"""
SCS Checker - Knowledge Base & Utility Features Module
Provides CVE knowledge base, favorites, snapshots, and compliance checking.
"""
import json
import os
from datetime import datetime, timedelta


def _now_beijing():
    """Return current time in Beijing timezone (UTC+8)."""
    return datetime.utcnow() + timedelta(hours=8)


def init_kb_tables(conn):
    """Create knowledge base and utility tables."""
    conn.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            package_name TEXT DEFAULT '',
            severity TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(cve_id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            snapshot_data TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            severity_threshold TEXT DEFAULT 'high',
            vuln_count_threshold INTEGER DEFAULT 0,
            risk_score_threshold INTEGER DEFAULT 0,
            email_notify INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT DEFAULT 'alert',
            title TEXT NOT NULL,
            message TEXT,
            scan_id INTEGER,
            severity TEXT DEFAULT 'info',
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS compliance_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            standard TEXT NOT NULL,
            total_checks INTEGER DEFAULT 0,
            passed INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            warnings INTEGER DEFAULT 0,
            details TEXT,
            checked_at TEXT NOT NULL
        )
    ''')


# === CVE Knowledge Base ===

CVE_KNOWLEDGE_BASE = [
    {
        'cve_id': 'CVE-2024-3094', 'severity': 'critical', 'cvss': 10.0,
        'package': 'xz-utils', 'title': 'XZ Utils 后门漏洞',
        'summary': 'XZ Utils 5.6.0和5.6.1版本被植入后门，攻击者可利用liblzma通过SSH认证绕过获取系统访问权限。这是一起供应链投毒事件。',
        'affected': '5.6.0-5.6.1', 'fixed': '5.6.2+',
        'category': '供应链投毒', 'discovered': '2024-03-28',
        'mitigation': '立即降级至5.4.x或升级至5.6.2以上版本，检查系统是否被入侵'
    },
    {
        'cve_id': 'CVE-2021-44228', 'severity': 'critical', 'cvss': 10.0,
        'package': 'log4j', 'title': 'Log4Shell - Apache Log4j 远程代码执行',
        'summary': 'Apache Log4j2 2.14.1及以下版本的JNDI功能存在RCE漏洞，攻击者可通过构造特殊日志消息远程执行代码。',
        'affected': '2.0-beta9 to 2.14.1', 'fixed': '2.15.0+',
        'category': '远程代码执行', 'discovered': '2021-12-09',
        'mitigation': '升级至Log4j 2.17.1+，或移除JndiLookup.class，设置log4j2.formatMsgNoLookups=true'
    },
    {
        'cve_id': 'CVE-2014-0160', 'severity': 'critical', 'cvss': 7.5,
        'package': 'openssl', 'title': 'Heartbleed - OpenSSL 内存泄露',
        'summary': 'OpenSSL 1.0.1到1.0.1f版本的TLS heartbeat扩展存在内存泄露漏洞，可泄露服务器内存中的敏感数据。',
        'affected': '1.0.1 to 1.0.1f', 'fixed': '1.0.1g+',
        'category': '内存泄露', 'discovered': '2014-04-07',
        'mitigation': '升级OpenSSL至1.0.1g+，吊销并重新生成SSL证书，检查是否有数据泄露'
    },
    {
        'cve_id': 'CVE-2017-5638', 'severity': 'critical', 'cvss': 10.0,
        'package': 'struts2', 'title': 'Apache Struts2 远程代码执行',
        'summary': 'Apache Struts2的Jakarta Multipart解析器在处理异常时执行OGNL表达式，导致远程代码执行。',
        'affected': '2.3.x before 2.3.32, 2.5.x before 2.5.10.1', 'fixed': '2.3.32+ / 2.5.10.1+',
        'category': '远程代码执行', 'discovered': '2017-03-10',
        'mitigation': '升级至最新版本，或使用防火墙规则拦截含恶意Content-Type的请求'
    },
    {
        'cve_id': 'CVE-2023-44487', 'severity': 'high', 'cvss': 7.5,
        'package': 'http2', 'title': 'HTTP/2 Rapid Reset DDoS攻击',
        'summary': 'HTTP/2协议的流取消机制可被滥用发起高效DDoS攻击，影响所有支持HTTP/2的服务器。',
        'affected': 'All HTTP/2 implementations', 'fixed': '各厂商补丁',
        'category': 'DDoS', 'discovered': '2023-10-10',
        'mitigation': '应用厂商补丁，限制HTTP/2并发流数量，部署DDoS防护'
    },
    {
        'cve_id': 'CVE-2022-40897', 'severity': 'medium', 'cvss': 6.5,
        'package': 'setuptools', 'title': 'Python setuptools ReDoS漏洞',
        'summary': 'setuptools 65.5.0及以下版本的package_index模块存在正则表达式拒绝服务漏洞，恶意包名可导致CPU耗尽。',
        'affected': '<65.6.0', 'fixed': '65.6.0+',
        'category': '拒绝服务', 'discovered': '2022-12-23',
        'mitigation': '升级setuptools至65.6.0+，避免处理不可信的包名'
    },
    {
        'cve_id': 'CVE-2023-50387', 'severity': 'high', 'cvss': 7.5,
        'package': 'glibc', 'title': 'glibc getaddrinfo DNS解析漏洞',
        'summary': 'glibc的getaddrinfo函数存在DNS解析缓冲区溢出漏洞，可导致DoS或潜在的RCE。',
        'affected': 'glibc < 2.39', 'fixed': '2.39+',
        'category': '缓冲区溢出', 'discovered': '2024-01-31',
        'mitigation': '升级glibc，限制DNS响应大小'
    },
    {
        'cve_id': 'CVE-2024-6387', 'severity': 'critical', 'cvss': 8.1,
        'package': 'openssh', 'title': 'SSH RegreSSHion 远程代码执行',
        'summary': 'OpenSSH服务器sshd中的信号处理程序竞态条件可导致RCE，影响基于glibc的Linux系统。',
        'affected': 'OpenSSH 8.5p1 to 9.7p1', 'fixed': '9.8p1+',
        'category': '远程代码执行', 'discovered': '2024-07-01',
        'mitigation': '升级至OpenSSH 9.8p1+，限制SSH访问源IP，设置LoginGraceTime'
    },
]


def search_kb(query=''):
    """Search the CVE knowledge base."""
    if not query:
        return CVE_KNOWLEDGE_BASE

    query_lower = query.lower()
    results = []
    for cve in CVE_KNOWLEDGE_BASE:
        if (query_lower in cve['cve_id'].lower() or
            query_lower in cve['package'].lower() or
            query_lower in cve['title'].lower() or
            query_lower in cve['summary'].lower() or
            query_lower in cve['category'].lower()):
            results.append(cve)
    return results


# === Compliance Checking ===

COMPLIANCE_STANDARDS = {
    'OWASP Top 10': {
        'description': 'OWASP Top 10 应用安全风险检查',
        'checks': [
            {'id': 'A06', 'name': '脆弱和过时的组件', 'description': '检查是否使用已知漏洞的依赖包',
             'severity_threshold': 'high', 'fail_msg': '发现高危及以上漏洞的依赖包'},
            {'id': 'A08', 'name': '软件和数据完整性故障', 'description': '检查供应链完整性',
             'severity_threshold': 'critical', 'fail_msg': '发现严重漏洞，可能影响供应链完整性'},
            {'id': 'A09', 'name': '安全日志和监控故障', 'description': '检查是否记录安全事件',
             'severity_threshold': 'medium', 'fail_msg': '存在中危漏洞需监控'},
        ]
    },
    'NIST SSDF': {
        'description': 'NIST安全软件开发框架(SP 800-218)',
        'checks': [
            {'id': 'PS.1', 'name': '保护软件组件', 'description': '验证第三方组件安全性',
             'severity_threshold': 'high', 'fail_msg': '第三方组件存在高危漏洞'},
            {'id': 'PS.3', 'name': '验证组件来源', 'description': '确认依赖来源可信',
             'severity_threshold': 'medium', 'fail_msg': '部分组件存在漏洞需验证'},
            {'id': 'PW.4', 'name': '复用安全软件', 'description': '使用经过验证的第三方组件',
             'severity_threshold': 'critical', 'fail_msg': '存在严重漏洞的组件'},
        ]
    },
    'ISO 27001': {
        'description': 'ISO/IEC 27001 信息安全管理体系',
        'checks': [
            {'id': 'A.8.28', 'name': '安全编码', 'description': '确保使用安全的第三方库',
             'severity_threshold': 'high', 'fail_msg': '第三方库存在高危漏洞'},
            {'id': 'A.8.29', 'name': '安全开发环境', 'description': '开发环境安全检查',
             'severity_threshold': 'medium', 'fail_msg': '开发依赖存在中危漏洞'},
        ]
    },
}


def run_compliance_check(scan_data, standard_name):
    """Run compliance check against a standard."""
    standard = COMPLIANCE_STANDARDS.get(standard_name)
    if not standard:
        return None

    sev = scan_data.get('severity_counts', {})
    sev_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
    max_severity = 'none'
    if sev.get('critical', 0) > 0: max_severity = 'critical'
    elif sev.get('high', 0) > 0: max_severity = 'high'
    elif sev.get('medium', 0) > 0: max_severity = 'medium'
    elif sev.get('low', 0) > 0: max_severity = 'low'

    results = []
    passed = 0
    failed = 0
    warnings = 0

    for check in standard['checks']:
        threshold = check['severity_threshold']
        if sev_levels.get(max_severity, 0) >= sev_levels.get(threshold, 0):
            results.append({
                'check_id': check['id'],
                'check_name': check['name'],
                'status': 'FAIL',
                'message': check['fail_msg'],
                'severity': threshold,
            })
            failed += 1
        elif sev_levels.get(max_severity, 0) > 0:
            results.append({
                'check_id': check['id'],
                'check_name': check['name'],
                'status': 'WARN',
                'message': f'存在低级别漏洞，建议关注',
                'severity': threshold,
            })
            warnings += 1
        else:
            results.append({
                'check_id': check['id'],
                'check_name': check['name'],
                'status': 'PASS',
                'message': '未发现相关安全问题',
                'severity': threshold,
            })
            passed += 1

    return {
        'standard': standard_name,
        'description': standard['description'],
        'total_checks': len(results),
        'passed': passed,
        'failed': failed,
        'warnings': warnings,
        'max_severity': max_severity,
        'details': results,
    }


def check_alert_rules(scan_data, scan_id, conn):
    """Check scan result against alert rules and create notifications."""
    sev = scan_data.get('severity_counts', {})
    risk_score = min(100, sev.get('critical', 0) * 25 + sev.get('high', 0) * 15 +
                     sev.get('medium', 0) * 5 + sev.get('low', 0) * 1)

    rules = conn.execute('SELECT * FROM alert_rules WHERE active = 1').fetchall()

    sev_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'none': 0}
    max_severity = 'none'
    if sev.get('critical', 0) > 0: max_severity = 'critical'
    elif sev.get('high', 0) > 0: max_severity = 'high'
    elif sev.get('medium', 0) > 0: max_severity = 'medium'
    elif sev.get('low', 0) > 0: max_severity = 'low'

    notifications_created = 0
    for rule in rules:
        triggered = False
        reasons = []

        sev_threshold = rule['severity_threshold']
        if sev_levels.get(max_severity, 0) >= sev_levels.get(sev_threshold, 0):
            triggered = True
            reasons.append(f'检测到{max_severity.upper()}级别漏洞 {sev.get(max_severity, 0)} 个')

        if rule['vuln_count_threshold'] > 0 and scan_data.get('total_vulnerabilities', 0) >= rule['vuln_count_threshold']:
            triggered = True
            reasons.append(f'漏洞总数 {scan_data.get("total_vulnerabilities", 0)} 超过阈值 {rule["vuln_count_threshold"]}')

        if rule['risk_score_threshold'] > 0 and risk_score >= rule['risk_score_threshold']:
            triggered = True
            reasons.append(f'风险评分 {risk_score} 超过阈值 {rule["risk_score_threshold"]}')

        if triggered:
            title = f'安全告警: {rule["name"]} - {max_severity.upper()}'
            message = f'扫描ID {scan_id}: ' + '；'.join(reasons)
            conn.execute(
                '''INSERT INTO notifications (type, title, message, scan_id, severity, is_read, created_at)
                   VALUES (?, ?, ?, ?, ?, 0, ?)''',
                ('alert', title, message, scan_id, max_severity, _now_beijing().strftime('%Y-%m-%d %H:%M:%S'))
            )
            notifications_created += 1

    if notifications_created > 0:
        conn.commit()

    return notifications_created
