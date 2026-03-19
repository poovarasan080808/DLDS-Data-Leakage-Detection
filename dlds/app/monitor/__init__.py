"""
DLDS — Data Monitoring Blueprint (app/monitor/__init__.py)
Shows event timeline, risk heatmap, and behaviour analytics.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app import mysql
from app.utils import log_audit

monitor_bp = Blueprint('monitor', __name__)


@monitor_bp.route('/')
@login_required
def index():
    page     = int(request.args.get('page', 1))
    per_page = 25
    offset   = (page - 1) * per_page

    user_filter  = request.args.get('user', '')
    type_filter  = request.args.get('type', '')
    date_filter  = request.args.get('date', '')

    where_parts  = []
    params       = []

    if not current_user.is_admin():
        where_parts.append("e.user_id = %s")
        params.append(current_user.id)

    if user_filter and current_user.is_admin():
        where_parts.append("u.username LIKE %s")
        params.append(f'%{user_filter}%')

    if type_filter:
        where_parts.append("e.event_type = %s")
        params.append(type_filter)

    if date_filter:
        where_parts.append("DATE(e.event_time) = %s")
        params.append(date_filter)

    where_clause = ('WHERE ' + ' AND '.join(where_parts)) if where_parts else ''

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT COUNT(*) FROM data_events e JOIN users u ON e.user_id=u.user_id {where_clause}",
        params
    )
    (total,) = cur.fetchone()

    cur.execute(
        f"SELECT e.event_id, e.event_type, e.source_ip, e.destination, "
        f"e.bytes_involved, e.protocol, e.description, e.event_time, "
        f"u.username, f.original_name "
        f"FROM data_events e "
        f"JOIN users u ON e.user_id=u.user_id "
        f"LEFT JOIN uploaded_files f ON e.file_id=f.file_id "
        f"{where_clause} "
        f"ORDER BY e.event_time DESC LIMIT %s OFFSET %s",
        params + [per_page, offset]
    )
    events = cur.fetchall()

    # Risk heatmap: events per user per day (last 7 days, admin only)
    heatmap = []
    if current_user.is_admin():
        cur.execute(
            "SELECT u.username, DATE(e.event_time) as d, COUNT(*) as cnt "
            "FROM data_events e JOIN users u ON e.user_id=u.user_id "
            "WHERE e.event_time >= NOW() - INTERVAL 7 DAY "
            "GROUP BY u.username, d ORDER BY u.username, d"
        )
        heatmap = cur.fetchall()

    # Event type breakdown
    cur.execute(
        "SELECT event_type, COUNT(*) FROM data_events "
        "WHERE event_time >= NOW() - INTERVAL 30 DAY GROUP BY event_type"
    )
    type_breakdown = dict(cur.fetchall())

    cur.close()

    total_pages = (total + per_page - 1) // per_page
    return render_template('monitor/index.html',
        events=events,
        page=page,
        total_pages=total_pages,
        total=total,
        heatmap=heatmap,
        type_breakdown=type_breakdown,
        user_filter=user_filter,
        type_filter=type_filter,
        date_filter=date_filter,
    )


@monitor_bp.route('/api/live')
@login_required
def live_events():
    """Returns latest 5 events as JSON for live feed widget."""
    uid_filter = '' if current_user.is_admin() else f"WHERE e.user_id={current_user.id}"
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT e.event_id, e.event_type, e.description, e.event_time, u.username "
        f"FROM data_events e JOIN users u ON e.user_id=u.user_id "
        f"{uid_filter} ORDER BY e.event_time DESC LIMIT 5"
    )
    rows = cur.fetchall()
    cur.close()
    data = [{'id': r[0], 'type': r[1], 'desc': r[2],
              'time': str(r[3]), 'user': r[4]} for r in rows]
    return jsonify(data)
