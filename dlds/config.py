"""
Data Leakage Detection System (DLDS)
Flask Application — Configuration & Initialisation
BSc Computer Science Final Year Project
"""

import os
from datetime import timedelta

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dlds-secret-key-change-in-production-2024')
    
    # MySQL connection via PyMySQL
    MYSQL_HOST     = os.environ.get('MYSQL_HOST',     'localhost')
    MYSQL_USER     = os.environ.get('MYSQL_USER',     'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'root1234')
    MYSQL_DB       = os.environ.get('MYSQL_DB',       'dlds_db')
    MYSQL_PORT     = int(os.environ.get('MYSQL_PORT', 3306))

    # File uploads
    UPLOAD_FOLDER     = os.path.join(os.path.dirname(__file__), 'app', 'static', 'uploads')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024   # 100 MB hard limit
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
        'csv', 'png', 'jpg', 'jpeg', 'zip', 'rar',
        'ppt', 'pptx', 'json', 'xml', 'sql',
        # Flagged types (still allowed but generate alerts)
        'exe', 'sh', 'bat', 'ps1', 'msi'
    }

    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Leakage detection thresholds
    LARGE_FILE_BYTES    = 50 * 1024 * 1024   # 50 MB
    BULK_UPLOAD_LIMIT   = 10                  # files per hour
    HIGH_RISK_KEYWORDS  = [
        'password', 'passwd', 'secret', 'confidential', 'private',
        'ssn', 'social_security', 'credit_card', 'api_key', 'token',
        'private_key', 'credentials', 'salary', 'medical', 'patient'
    ]
    FLAGGED_EXTENSIONS  = {'.exe', '.sh', '.bat', '.ps1', '.msi', '.dll'}

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
