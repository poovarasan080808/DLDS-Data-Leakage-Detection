"""
DLDS — Shared Utility Functions (app/utils.py)
"""

import os, hashlib, re
from datetime import datetime
from flask import current_app
from app import mysql


# ── Audit Logging ──────────────────────────────────────────────────────────

def log_audit(user_id, action, resource_type, resource_id, detail, ip=None):
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, action, resource_type, resource_id, detail, ip_address) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (user_id, action, resource_type, resource_id, detail, ip)
        )
        mysql.connection.commit()
        cur.close()
    except Exception:
        pass  # Never let audit failure break the main flow


# ── File Helpers ──────────────────────────────────────────────────────────

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    return ext in current_app.config['ALLOWED_EXTENSIONS']


def secure_stored_name(filename):
    """Return a collision-safe stored filename."""
    ext  = os.path.splitext(filename)[1].lower()
    ts   = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
    base = hashlib.md5(filename.encode()).hexdigest()[:8]
    return f"{ts}_{base}{ext}"


def compute_md5(filepath):
    h = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


# ── Leakage Detection ────────────────────────────────────────────────────

def classify_file(filename, filesize):
    """Return ('classification', risk_score, [reasons])."""
    reasons = []
    score   = 0
    ext     = os.path.splitext(filename)[1].lower()
    name_lc = filename.lower()

    # Flagged extension
    if ext in current_app.config['FLAGGED_EXTENSIONS']:
        reasons.append(f'Executable or script file detected ({ext})')
        score += 40

    # Large file
    if filesize > current_app.config['LARGE_FILE_BYTES']:
        mb = filesize / (1024 * 1024)
        reasons.append(f'Large file ({mb:.1f} MB exceeds 50 MB threshold)')
        score += 25

    # Sensitive keywords in filename
    for kw in current_app.config['HIGH_RISK_KEYWORDS']:
        if kw in name_lc:
            reasons.append(f'Sensitive keyword in filename: "{kw}"')
            score += 20
            break

    # Database dumps
    if ext in ('.sql', '.bak', '.dump'):
        reasons.append('Database backup / dump file type')
        score += 20

    # Classification bucket
    if score >= 60:
        classification = 'restricted'
    elif score >= 35:
        classification = 'confidential'
    elif score >= 15:
        classification = 'internal'
    else:
        classification = 'public'

    return classification, min(score, 100), reasons


def scan_content_for_pii(filepath):
    """
    Lightweight PII scanner for text-based files.
    Returns list of finding dicts.
    """
    findings = []
    patterns = {
        'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        'SSN':         r'\b\d{3}-\d{2}-\d{4}\b',
        'Email':       r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        'IP Address':  r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'API Key':     r'(?i)(api[_\-]?key|token|secret)["\s:=]+[A-Za-z0-9/+_\-]{16,}',
    }
    try:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in ('.txt', '.csv', '.json', '.xml', '.sql', '.log', '.md'):
            return findings
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read(512_000)   # scan first 500 KB only
        for label, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    'type': label,
                    'count': len(matches),
                    'sample': str(matches[0])[:40]
                })
    except Exception:
        pass
    return findings


def check_bulk_upload(user_id, window_minutes=60, threshold=10):
    """Return True if user exceeded bulk upload threshold."""
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM uploaded_files "
            "WHERE user_id=%s AND uploaded_at >= NOW() - INTERVAL %s MINUTE",
            (user_id, window_minutes)
        )
        (count,) = cur.fetchone()
        cur.close()
        return count >= threshold
    except Exception:
        return False


def after_hours():
    """Return True if current server time is between 22:00 and 06:00."""
    hour = datetime.now().hour
    return hour >= 22 or hour < 6


def generate_alert(event_id, user_id, alert_type, severity, title, description,
                   risk_score=0.0, detection_method='rule'):
    """Insert an alert and a dashboard notification for all admins/analysts."""
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO alerts (event_id, user_id, alert_type, severity, title, "
            "description, risk_score, detection_method) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (event_id, user_id, alert_type, severity, title, description,
             risk_score, detection_method)
        )
        alert_id = cur.lastrowid

        # Notify all admins and analysts
        cur.execute("SELECT user_id FROM users WHERE role IN ('admin','analyst') AND is_active=1")
        recipients = cur.fetchall()
        for (rid,) in recipients:
            cur.execute(
                "INSERT INTO notifications (alert_id, recipient_id, channel) VALUES (%s,%s,'dashboard')",
                (alert_id, rid)
            )
        mysql.connection.commit()
        cur.close()
        return alert_id
    except Exception:
        return None
