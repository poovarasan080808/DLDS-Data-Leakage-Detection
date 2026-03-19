# Data Leakage Detection System (DLDS)
## BSc Computer Science Final Year Project

### Project Structure
```
dlds/
├── run.py                   # Flask entry point
├── config.py                # Configuration (DB, thresholds)
├── requirements.txt
├── schema.sql               # MySQL database schema + seed data
└── app/
    ├── __init__.py          # App factory + extensions
    ├── models.py            # User model (Flask-Login)
    ├── utils.py             # Detection engine, PII scanner, helpers
    ├── auth/                # Login, logout, register
    ├── main/                # Dashboard
    ├── upload/              # File upload + leakage scanning
    ├── monitor/             # Data event monitoring
    ├── alerts/              # Alert console + detail
    ├── admin/               # Users, rules, audit, stats
    ├── templates/           # Jinja2 HTML templates
    └── static/
        ├── css/dlds.css
        └── uploads/         # Uploaded files (auto-created)
```

### Setup Instructions

#### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

#### 2. Create MySQL database
```bash
mysql -u root -p < schema.sql
```

#### 3. Configure environment (optional .env)
```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=yourpassword
MYSQL_DB=dlds_db
SECRET_KEY=your-secret-key
```

#### 4. Create admin account
The schema seeds a placeholder admin. Create the real admin via registration
or update the password hash directly:
```python
from werkzeug.security import generate_password_hash
print(generate_password_hash('YourPassword'))
```
Then: `UPDATE users SET password_hash='<hash>' WHERE username='admin';`

#### 5. Run the application
```bash
python run.py
```
Visit: http://localhost:5000

### Default Roles
| Role     | Permissions                                      |
|----------|--------------------------------------------------|
| admin    | Full access including user & rule management     |
| analyst  | View all alerts, update status, view audit log   |
| user     | Upload files, view own events and alerts         |

### Leakage Detection Rules (Built-in)
- Large file upload (>50 MB) → HIGH
- Sensitive keyword in filename → CRITICAL
- Executable/script file type (.exe, .sh, .bat) → HIGH
- Bulk upload (>10 files/hour) → MEDIUM
- After-hours activity (22:00–06:00) → MEDIUM
- PII content scan (credit cards, SSN, emails, API keys) → varies

### Technology Stack
- **Backend:** Python 3.11, Flask 3.0, Flask-Login, Flask-MySQLdb
- **Database:** MySQL 8.0
- **Frontend:** Bootstrap 5.3, Chart.js 4.4, Bootstrap Icons
- **Security:** Werkzeug password hashing (PBKDF2-SHA256)
