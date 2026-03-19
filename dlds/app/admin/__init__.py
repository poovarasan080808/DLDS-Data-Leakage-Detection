"""
DLDS — Admin Blueprint (app/admin/__init__.py)
User management, detection rules, system stats, audit log.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash
from functools import wraps
from app import mysql
from app.utils import log_audit

admin_bp = Blueprint('admin', __name__)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash('Admin access required.', 'danger')
            return redirect(url_for('main.dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Users ─────────────────────────────────────────────────────

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT user_id, username, email, role, department, is_active, created_at, last_login "
        "FROM users ORDER BY created_at DESC"
    )
    all_users = cur.fetchall()
    cur.close()
    return render_template('admin/users.html', users=all_users)


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username   = request.form['username'].strip()
        email      = request.form['email'].strip()
        password   = request.form['password']
        role       = request.form.get('role', 'user')
        department = request.form.get('department', '').strip()

        pw_hash = generate_password_hash(password)
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role, department) "
                "VALUES (%s,%s,%s,%s,%s)",
                (username, email, pw_hash, role, department)
            )
            mysql.connection.commit()
            log_audit(current_user.id, 'USER_CREATE', 'user', str(cur.lastrowid),
                      f'Created user {username}', request.remote_addr)
            flash(f'User {username} created.', 'success')
        except Exception as e:
            flash(f'Error: {e}', 'danger')
        finally:
            cur.close()
        return redirect(url_for('admin.users'))

    return render_template('admin/create_user.html')


@admin_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT is_active FROM users WHERE user_id=%s", (user_id,))
    row = cur.fetchone()
    if row:
        new_state = 0 if row[0] else 1
        cur.execute("UPDATE users SET is_active=%s WHERE user_id=%s", (new_state, user_id))
        mysql.connection.commit()
        log_audit(current_user.id, 'USER_TOGGLE', 'user', str(user_id),
                  f'Set is_active={new_state}', request.remote_addr)
    cur.close()
    flash('User status updated.', 'success')
    return redirect(url_for('admin.users'))


# ── Detection Rules ───────────────────────────────────────────

@admin_bp.route('/rules')
@login_required
@admin_required
def rules():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT r.rule_id, r.rule_name, r.rule_type, r.severity, r.is_enabled, "
        "r.created_at, COALESCE(u.username,'—') "
        "FROM detection_rules r LEFT JOIN users u ON r.created_by=u.user_id "
        "ORDER BY r.created_at DESC"
    )
    all_rules = cur.fetchall()
    cur.close()
    return render_template('admin/rules.html', rules=all_rules)


@admin_bp.route('/rules/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_rule():
    if request.method == 'POST':
        import json as _json
        rule_name  = request.form['rule_name'].strip()
        rule_type  = request.form['rule_type']
        severity   = request.form.get('severity', 'medium')
        cond_raw   = request.form.get('condition_json', '{}')
        try:
            cond_json = _json.dumps(_json.loads(cond_raw))
        except Exception:
            flash('Invalid JSON in condition.', 'danger')
            return redirect(request.url)

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO detection_rules (rule_name, rule_type, condition_json, severity, created_by) "
            "VALUES (%s,%s,%s,%s,%s)",
            (rule_name, rule_type, cond_json, severity, current_user.id)
        )
        mysql.connection.commit()
        cur.close()
        log_audit(current_user.id, 'RULE_CREATE', 'rule', '', f'Created rule: {rule_name}',
                  request.remote_addr)
        flash('Detection rule created.', 'success')
        return redirect(url_for('admin.rules'))

    return render_template('admin/create_rule.html')


@admin_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_rule(rule_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT is_enabled FROM detection_rules WHERE rule_id=%s", (rule_id,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE detection_rules SET is_enabled=%s WHERE rule_id=%s",
                    (0 if row[0] else 1, rule_id))
        mysql.connection.commit()
    cur.close()
    flash('Rule status updated.', 'success')
    return redirect(url_for('admin.rules'))


# ── Audit Log ─────────────────────────────────────────────────

@admin_bp.route('/audit')
@login_required
@admin_required
def audit():
    page     = int(request.args.get('page', 1))
    per_page = 30
    offset   = (page - 1) * per_page

    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM audit_log")
    (total,) = cur.fetchone()
    cur.execute(
        "SELECT l.log_id, COALESCE(u.username,'system'), l.action, "
        "l.resource_type, l.resource_id, l.detail, l.ip_address, l.logged_at "
        "FROM audit_log l LEFT JOIN users u ON l.user_id=u.user_id "
        "ORDER BY l.logged_at DESC LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    logs = cur.fetchall()
    cur.close()

    return render_template('admin/audit.html',
        logs=logs, page=page,
        total_pages=(total + per_page - 1) // per_page,
        total=total,
    )


# ── System Stats ──────────────────────────────────────────────

@admin_bp.route('/stats')
@login_required
@admin_required
def stats():
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE is_active=1")
    (active_users,) = cur.fetchone()
    cur.execute("SELECT COUNT(*), COALESCE(SUM(file_size),0) FROM uploaded_files")
    file_row = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='new'")
    (open_alerts,) = cur.fetchone()
    cur.execute(
        "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
    )
    sev_dist = dict(cur.fetchall())
    cur.execute(
        "SELECT DATE(created_at) as d, COUNT(*) FROM alerts "
        "WHERE created_at >= NOW() - INTERVAL 30 DAY GROUP BY d ORDER BY d"
    )
    alert_trend = cur.fetchall()
    cur.execute(
        "SELECT u.username, COUNT(a.alert_id) as cnt "
        "FROM users u LEFT JOIN alerts a ON u.user_id=a.user_id "
        "GROUP BY u.user_id ORDER BY cnt DESC LIMIT 10"
    )
    top_users = cur.fetchall()
    cur.close()

    return render_template('admin/stats.html',
        active_users=active_users,
        total_files=file_row[0],
        total_size=file_row[1],
        open_alerts=open_alerts,
        sev_dist=sev_dist,
        alert_trend=alert_trend,
        top_users=top_users,
    )
