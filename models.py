"""
DLDS — User Model (app/models.py)
Flask-Login compatible user class backed by MySQL.
"""

from flask_login import UserMixin
from app import mysql, login_manager


class User(UserMixin):
    def __init__(self, user_id, username, email, role, department, is_active):
        self.id         = user_id
        self.username   = username
        self.email      = email
        self.role       = role
        self.department = department
        self._active    = bool(is_active)

    @property
    def is_active(self):
        return self._active

    def is_admin(self):
        return self.role == 'admin'

    def is_analyst(self):
        return self.role in ('admin', 'analyst')

    @staticmethod
    def get_by_id(user_id):
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT user_id, username, email, role, department, is_active "
            "FROM users WHERE user_id = %s", (user_id,)
        )
        row = cur.fetchone()
        cur.close()
        if row:
            return User(*row)
        return None

    @staticmethod
    def get_by_username(username):
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT user_id, username, email, password_hash, role, department, is_active "
            "FROM users WHERE username = %s", (username,)
        )
        row = cur.fetchone()
        cur.close()
        return row   # returns raw tuple so auth can verify password


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))
