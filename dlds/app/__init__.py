"""
DLDS — Application Factory (app/__init__.py)
"""

from flask import Flask
from flask_mysqldb import MySQL
from flask_login import LoginManager
from config import DevelopmentConfig

mysql = MySQL()
login_manager = LoginManager()

def create_app(config_class=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Extensions
    mysql.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    # Blueprints
    from app.auth    import auth_bp
    from app.main    import main_bp
    from app.upload  import upload_bp
    from app.monitor import monitor_bp
    from app.alerts  import alerts_bp
    from app.admin   import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(upload_bp,  url_prefix='/upload')
    app.register_blueprint(monitor_bp, url_prefix='/monitor')
    app.register_blueprint(alerts_bp,  url_prefix='/alerts')
    app.register_blueprint(admin_bp,   url_prefix='/admin')

    import os
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    return app
