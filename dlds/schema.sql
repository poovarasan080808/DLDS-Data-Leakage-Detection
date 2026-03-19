-- ============================================================
-- DATA LEAKAGE DETECTION SYSTEM — MySQL Database Schema
-- BSc Computer Science Final Year Project
-- ============================================================

CREATE DATABASE IF NOT EXISTS dlds_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dlds_db;

-- ── Users ────────────────────────────────────────────────────
CREATE TABLE users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(80)  NOT NULL UNIQUE,
    email         VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('admin','analyst','user') NOT NULL DEFAULT 'user',
    department    VARCHAR(100),
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME
);

-- ── Uploaded Files ───────────────────────────────────────────
CREATE TABLE uploaded_files (
    file_id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT          NOT NULL,
    original_name    VARCHAR(255) NOT NULL,
    stored_name      VARCHAR(255) NOT NULL,
    file_size        BIGINT       NOT NULL DEFAULT 0,
    mime_type        VARCHAR(100),
    classification   ENUM('public','internal','confidential','restricted') DEFAULT 'internal',
    upload_ip        VARCHAR(45),
    uploaded_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ── Data Events (all monitored data movements) ───────────────
CREATE TABLE data_events (
    event_id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT          NOT NULL,
    file_id          INT,
    event_type       ENUM('upload','download','email','usb','print','clipboard','api') NOT NULL,
    source_ip        VARCHAR(45),
    destination      VARCHAR(255),
    bytes_involved   BIGINT       DEFAULT 0,
    protocol         VARCHAR(20),
    description      TEXT,
    raw_metadata     JSON,
    event_time       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (file_id) REFERENCES uploaded_files(file_id) ON DELETE SET NULL
);

-- ── Alerts ───────────────────────────────────────────────────
CREATE TABLE alerts (
    alert_id         INT AUTO_INCREMENT PRIMARY KEY,
    event_id         INT,
    user_id          INT          NOT NULL,
    alert_type       VARCHAR(100) NOT NULL,
    severity         ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'medium',
    title            VARCHAR(255) NOT NULL,
    description      TEXT,
    risk_score       DECIMAL(5,2) DEFAULT 0.00,
    status           ENUM('new','acknowledged','investigating','resolved','false_positive') NOT NULL DEFAULT 'new',
    detection_method ENUM('rule','ml','manual') DEFAULT 'rule',
    assigned_to      INT,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at      DATETIME,
    notes            TEXT,
    FOREIGN KEY (event_id)    REFERENCES data_events(event_id) ON DELETE SET NULL,
    FOREIGN KEY (user_id)     REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_to) REFERENCES users(user_id) ON DELETE SET NULL
);

-- ── Detection Rules ──────────────────────────────────────────
CREATE TABLE detection_rules (
    rule_id          INT AUTO_INCREMENT PRIMARY KEY,
    rule_name        VARCHAR(200) NOT NULL,
    rule_type        ENUM('volume','keyword','destination','behaviour','filetype') NOT NULL,
    condition_json   JSON         NOT NULL,
    severity         ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'medium',
    is_enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    created_by       INT,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(user_id) ON DELETE SET NULL
);

-- ── Audit Log ────────────────────────────────────────────────
CREATE TABLE audit_log (
    log_id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id          INT,
    action           VARCHAR(100) NOT NULL,
    resource_type    VARCHAR(50),
    resource_id      VARCHAR(50),
    detail           TEXT,
    ip_address       VARCHAR(45),
    logged_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- ── Notifications ────────────────────────────────────────────
CREATE TABLE notifications (
    notif_id         INT AUTO_INCREMENT PRIMARY KEY,
    alert_id         INT          NOT NULL,
    recipient_id     INT          NOT NULL,
    channel          ENUM('dashboard','email') NOT NULL DEFAULT 'dashboard',
    is_read          TINYINT(1)   NOT NULL DEFAULT 0,
    sent_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id)      REFERENCES alerts(alert_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id)  REFERENCES users(user_id)   ON DELETE CASCADE
);

-- ── Indexes ──────────────────────────────────────────────────
CREATE INDEX idx_events_user_time  ON data_events(user_id, event_time);
CREATE INDEX idx_alerts_status     ON alerts(status, severity, created_at);
CREATE INDEX idx_alerts_user       ON alerts(user_id);
CREATE INDEX idx_files_user        ON uploaded_files(user_id, uploaded_at);
CREATE INDEX idx_audit_user_time   ON audit_log(user_id, logged_at);
CREATE INDEX idx_notif_recipient   ON notifications(recipient_id, is_read);

-- ── Seed Data ────────────────────────────────────────────────
-- Default admin (password: Admin@1234)
INSERT INTO users (username, email, password_hash, role, department)
VALUES ('admin', 'admin@dlds.local',
        'pbkdf2:sha256:600000$defaulthash$placeholder',
        'admin', 'IT Security');

-- Default detection rules
INSERT INTO detection_rules (rule_name, rule_type, condition_json, severity, created_by) VALUES
('Large File Upload (>50MB)',   'volume',      '{"field":"file_size","operator":">","value":52428800}',           'high',   1),
('Sensitive Keyword in Filename','keyword',    '{"keywords":["password","secret","confidential","private","ssn"]}','critical',1),
('Executable File Upload',      'filetype',    '{"extensions":[".exe",".sh",".bat",".ps1",".msi"]}',             'high',   1),
('Bulk Upload (>10 files/hour)','behaviour',   '{"field":"upload_count","window_minutes":60,"threshold":10}',    'medium', 1),
('External Destination Upload', 'destination', '{"pattern":"external","blocked_tlds":[".ru",".cn",".tk"]}',     'high',   1),
('After-Hours Activity',        'behaviour',   '{"hours_start":22,"hours_end":6,"days":["sat","sun"]}',          'medium', 1);
