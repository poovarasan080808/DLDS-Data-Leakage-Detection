"""
DLDS — Authentication Blueprint (app/auth/__init__.py)
Handles login, logout, and registration.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import mysql
from app.models import User
from app.utils import log_audit

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        row = User.get_by_username(username)
        if row and check_password_hash(row[3], password) and row[6]:
            user = User(row[0], row[1], row[2], row[4], row[5], row[6])
            login_user(user, remember=remember)

            # Update last_login
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET last_login = NOW() WHERE user_id = %s", (user.id,))
            mysql.connection.commit()
            cur.close()

            log_audit(user.id, 'LOGIN', 'session', str(user.id),
                      f'Successful login from {request.remote_addr}', request.remote_addr)
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))

        flash('Invalid username or password.', 'danger')
        log_audit(None, 'LOGIN_FAIL', 'session', None,
                  f'Failed login attempt for "{username}" from {request.remote_addr}',
                  request.remote_addr)

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username   = request.form.get('username', '').strip()
        email      = request.form.get('email', '').strip()
        password   = request.form.get('password', '')
        confirm    = request.form.get('confirm_password', '')
        department = request.form.get('department', '').strip()

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')

        if not errors:
            cur = mysql.connection.cursor()
            cur.execute("SELECT user_id FROM users WHERE username=%s OR email=%s",
                        (username, email))
            if cur.fetchone():
                errors.append('Username or email already registered.')
            else:
                pw_hash = generate_password_hash(password)
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role, department) "
                    "VALUES (%s,%s,%s,'user',%s)",
                    (username, email, pw_hash, department)
                )
                mysql.connection.commit()
                cur.close()
                flash('Account created. Please log in.', 'success')
                return redirect(url_for('auth.login'))
            cur.close()

        for e in errors:
            flash(e, 'danger')

    return render_template('auth/register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log_audit(current_user.id, 'LOGOUT', 'session', str(current_user.id),
              f'Logout from {request.remote_addr}', request.remote_addr)
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
