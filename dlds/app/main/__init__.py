"""
DLDS — Main / Dashboard Blueprint (app/main/__init__.py)
"""

from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app import mysql

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@main_bp.route('/dashboard')
@login_required
def dashboard():
    cur = mysql.connection.cursor()

    # KPI tiles
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='new'")
    (open_alerts,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('high','critical') AND status='new'")
    (critical_alerts,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM uploaded_files WHERE DATE(uploaded_at)=CURDATE()")
    (files_today,) = cur.fetchone()

    cur.execute("SELECT COUNT(*) FROM users WHERE is_active=1")
    (active_users,) = cur.fetchone()

    # Recent alerts (last 10)
    cur.execute(
        "SELECT a.alert_id, a.title, a.severity, a.status, a.created_at, u.username "
        "FROM alerts a JOIN users u ON a.user_id=u.user_id "
        "ORDER BY a.created_at DESC LIMIT 10"
    )
    recent_alerts = cur.fetchall()

    # Recent file uploads (last 10)
    cur.execute(
        "SELECT f.file_id, f.original_name, f.file_size, f.classification, "
        "f.uploaded_at, u.username "
        "FROM uploaded_files f JOIN users u ON f.user_id=u.user_id "
        "ORDER BY f.uploaded_at DESC LIMIT 10"
    )
    recent_files = cur.fetchall()

    # Alert severity distribution (for chart)
    cur.execute(
        "SELECT severity, COUNT(*) FROM alerts "
        "WHERE created_at >= NOW() - INTERVAL 30 DAY GROUP BY severity"
    )
    severity_chart = dict(cur.fetchall())

    # Events last 7 days (for line chart)
    cur.execute(
        "SELECT DATE(event_time) as d, COUNT(*) FROM data_events "
        "WHERE event_time >= NOW() - INTERVAL 7 DAY GROUP BY d ORDER BY d"
    )
    events_trend = cur.fetchall()

    # Unread notifications for current user
    cur.execute(
        "SELECT COUNT(*) FROM notifications "
        "WHERE recipient_id=%s AND is_read=0", (current_user.id,)
    )
    (unread_notifs,) = cur.fetchone()

    cur.close()

    return render_template('main/dashboard.html',
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        files_today=files_today,
        active_users=active_users,
        recent_alerts=recent_alerts,
        recent_files=recent_files,
        severity_chart=severity_chart,
        events_trend=events_trend,
        unread_notifs=unread_notifs,
    )


@main_bp.route('/api/stats')
@login_required
def api_stats():
    """JSON endpoint for live dashboard refresh."""
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts WHERE status='new'")
    (open_alerts,) = cur.fetchone()
    cur.execute("SELECT COUNT(*) FROM notifications WHERE recipient_id=%s AND is_read=0",
                (current_user.id,))
    (unread,) = cur.fetchone()
    cur.close()
    return jsonify({'open_alerts': open_alerts, 'unread_notifications': unread})
