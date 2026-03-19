"""
DLDS — File Upload Blueprint (app/upload/__init__.py)
Handles file upload, classification, PII scanning, and alert generation.
"""

import os, json
from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import mysql
from app.utils import (allowed_file, secure_stored_name, classify_file,
                        scan_content_for_pii, check_bulk_upload,
                        after_hours, generate_alert, log_audit)

upload_bp = Blueprint('upload', __name__)


@upload_bp.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part in request.', 'danger')
            return redirect(request.url)

        files = request.files.getlist('file')
        results = []

        for file in files:
            if file.filename == '':
                continue
            if not allowed_file(file.filename):
                flash(f'File type not allowed: {file.filename}', 'danger')
                continue

            original_name = file.filename
            stored_name   = secure_stored_name(original_name)
            upload_folder = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                'app', 'static', 'uploads'
            )
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, stored_name)
            file.save(filepath)
            filesize  = os.path.getsize(filepath)
            mime_type = file.mimetype or 'application/octet-stream'

            # ── Classify & detect ──────────────────────────────
            classification, risk_score, reasons = classify_file(original_name, filesize)
            pii_findings = scan_content_for_pii(filepath)
            bulk_flag    = check_bulk_upload(current_user.id)
            ah_flag      = after_hours()

            # Extra risk from PII
            if pii_findings:
                for pf in pii_findings:
                    reasons.append(f'PII detected: {pf["type"]} ({pf["count"]} occurrence(s))')
                risk_score = min(risk_score + 20 * len(pii_findings), 100)

            if bulk_flag:
                reasons.append('Bulk upload threshold exceeded (>10 files/hour)')
                risk_score = min(risk_score + 15, 100)

            if ah_flag:
                reasons.append('After-hours upload activity detected')
                risk_score = min(risk_score + 10, 100)

            # ── Persist file record ────────────────────────────
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO uploaded_files "
                "(user_id, original_name, stored_name, file_size, mime_type, "
                "classification, upload_ip) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (current_user.id, original_name, stored_name, filesize,
                 mime_type, classification, request.remote_addr)
            )
            file_id = cur.lastrowid

            # ── Log data event ─────────────────────────────────
            metadata = {'pii': pii_findings, 'reasons': reasons}
            cur.execute(
                "INSERT INTO data_events "
                "(user_id, file_id, event_type, source_ip, bytes_involved, "
                "protocol, description, raw_metadata) VALUES (%s,%s,'upload',%s,%s,'HTTP',%s,%s)",
                (current_user.id, file_id, request.remote_addr, filesize,
                 f'File upload: {original_name}', json.dumps(metadata))
            )
            event_id = cur.lastrowid
            mysql.connection.commit()
            cur.close()

            # ── Generate alerts ────────────────────────────────
            if reasons:
                severity = (
                    'critical' if risk_score >= 70
                    else 'high'   if risk_score >= 50
                    else 'medium' if risk_score >= 25
                    else 'low'
                )
                alert_desc = '; '.join(reasons)
                generate_alert(
                    event_id, current_user.id,
                    'FILE_UPLOAD_RISK', severity,
                    f'Suspicious file upload: {original_name}',
                    alert_desc, risk_score
                )

            log_audit(current_user.id, 'FILE_UPLOAD', 'file', str(file_id),
                      f'Uploaded {original_name} ({filesize} bytes)', request.remote_addr)

            results.append({
                'filename':       original_name,
                'size':           filesize,
                'classification': classification,
                'risk_score':     risk_score,
                'reasons':        reasons,
                'pii':            pii_findings,
            })

        if results:
            return render_template('upload/result.html', results=results)
        flash('No valid files uploaded.', 'warning')
        return redirect(request.url)

    # GET — show upload form with recent uploads
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT f.file_id, f.original_name, f.file_size, f.classification, "
        "f.uploaded_at FROM uploaded_files f "
        "WHERE f.user_id=%s ORDER BY f.uploaded_at DESC LIMIT 20",
        (current_user.id,)
    )
    my_files = cur.fetchall()
    cur.close()

    return render_template('upload/index.html', my_files=my_files)


@upload_bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT stored_name, user_id FROM uploaded_files WHERE file_id=%s",
        (file_id,)
    )
    row = cur.fetchone()
    if not row:
        flash('File not found.', 'danger')
        return redirect(url_for('upload.index'))
    if row[1] != current_user.id and not current_user.is_admin():
        flash('Unauthorised.', 'danger')
        return redirect(url_for('upload.index'))

    stored = row[0]
    upload_folder = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        'app', 'static', 'uploads'
    )
    try:
        os.remove(os.path.join(upload_folder, stored))
    except FileNotFoundError:
        pass

    cur.execute("DELETE FROM uploaded_files WHERE file_id=%s", (file_id,))
    mysql.connection.commit()
    cur.close()
    log_audit(current_user.id, 'FILE_DELETE', 'file', str(file_id), '', request.remote_addr)
    flash('File deleted.', 'success')
    return redirect(url_for('upload.index'))
