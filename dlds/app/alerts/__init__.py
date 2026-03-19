"""
DLDS — Alerts Blueprint (app/alerts/__init__.py)
Alert listing, detail view, and status management.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app import mysql
from app.utils import log_audit

alerts_bp = Blueprint('alerts', __name__)


@alerts_bp.route('/')
@login_required
def index():
    severity_filter = request.args.get('severity', '')
    status_filter   = request.args.get('status', '')
    page     = int(request.args.get('page', 1))
    per_page = 20
    offset   = (page - 1) * per_page

    where_parts = []
    params      = []

    if not current_user.is_analyst():
        where_parts.append("a.user_id = %s")
        params.append(current_user.id)

    if severity_filter:
        where_parts.append("a.severity = %s")
        params.append(severity_filter)

    if status_filter:
        where_parts.append("a.status = %s")
        params.append(status_filter)

    where_clause = ('WHERE ' + ' AND '.join(where_parts)) if where_parts else ''

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT COUNT(*) FROM alerts a {where_clause}", params)
    (total,) = cur.fetchone()

    cur.execute(
        f"SELECT a.alert_id, a.title, a.severity, a.status, a.risk_score, "
        f"a.detection_method, a.created_at, u.username, "
        f"COALESCE(aa.username,'—') as assigned_name "
        f"FROM alerts a "
        f"JOIN users u ON a.user_id=u.user_id "
        f"LEFT JOIN users aa ON a.assigned_to=aa.user_id "
        f"{where_clause} "
        f"ORDER BY FIELD(a.severity,'critical','high','medium','low','info'), "
        f"a.created_at DESC LIMIT %s OFFSET %s",
        params + [per_page, offset]
    )
    alerts = cur.fetchall()
    cur.close()

    return render_template('alerts/index.html',
        alerts=alerts,
        page=page,
        total_pages=(total + per_page - 1) // per_page,
        total=total,
        severity_filter=severity_filter,
        status_filter=status_filter,
    )


@alerts_bp.route('/<int:alert_id>')
@login_required
def detail(alert_id):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT a.*, u.username, u.email, u.department, "
        "COALESCE(aa.username,'Unassigned') as assigned_name "
        "FROM alerts a "
        "JOIN users u ON a.user_id=u.user_id "
        "LEFT JOIN users aa ON a.assigned_to=aa.user_id "
        "WHERE a.alert_id=%s", (alert_id,)
    )
    alert = cur.fetchone()
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts.index'))

    # Related event
    cur.execute(
        "SELECT e.*, f.original_name FROM data_events e "
        "LEFT JOIN uploaded_files f ON e.file_id=f.file_id "
        "WHERE e.event_id=%s", (alert[1],)   # alert[1] = event_id
    )
    event = cur.fetchone()

    # Analysts list (for assign dropdown)
    cur.execute("SELECT user_id, username FROM users WHERE role IN ('admin','analyst') AND is_active=1")
    analysts = cur.fetchall()

    # Mark dashboard notification as read
    cur.execute(
        "UPDATE notifications SET is_read=1 "
        "WHERE alert_id=%s AND recipient_id=%s", (alert_id, current_user.id)
    )
    mysql.connection.commit()
    cur.close()

    return render_template('alerts/detail.html', alert=alert, event=event, analysts=analysts)


@alerts_bp.route('/<int:alert_id>/update', methods=['POST'])
@login_required
def update_status(alert_id):
    if not current_user.is_analyst():
        flash('Permission denied.', 'danger')
        return redirect(url_for('alerts.index'))

    new_status  = request.form.get('status')
    notes       = request.form.get('notes', '')
    assigned_to = request.form.get('assigned_to') or None
    valid_statuses = ('new','acknowledged','investigating','resolved','false_positive')

    if new_status not in valid_statuses:
        flash('Invalid status.', 'danger')
        return redirect(url_for('alerts.detail', alert_id=alert_id))

    cur = mysql.connection.cursor()
    resolved_clause = ", resolved_at=NOW()" if new_status in ('resolved','false_positive') else ""
    cur.execute(
        f"UPDATE alerts SET status=%s, notes=%s, assigned_to=%s {resolved_clause} "
        f"WHERE alert_id=%s",
        (new_status, notes, assigned_to, alert_id)
    )
    mysql.connection.commit()
    cur.close()

    log_audit(current_user.id, 'ALERT_UPDATE', 'alert', str(alert_id),
              f'Status changed to {new_status}', request.remote_addr)
    flash('Alert updated.', 'success')
    return redirect(url_for('alerts.detail', alert_id=alert_id))


@alerts_bp.route('/api/unread')
@login_required
def unread_count():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM notifications WHERE recipient_id=%s AND is_read=0",
        (current_user.id,)
    )
    (count,) = cur.fetchone()
    cur.close()
    return jsonify({'count': count})
