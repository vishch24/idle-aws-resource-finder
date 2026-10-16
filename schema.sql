-- Idle AWS Resource Finder for Learners
-- Run once against your RDS MySQL instance before starting the app.
-- Create the database first, then run this file.
--
-- mysql -h <rds-endpoint> -u <user> -p idle_aws_finder < schema.sql

CREATE TABLE IF NOT EXISTS users (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(100)  NOT NULL,
    email         VARCHAR(150)  NOT NULL UNIQUE,
    password_hash VARCHAR(255)  NOT NULL,
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One AWS connection per user: the role ARN and server-generated external ID.
CREATE TABLE IF NOT EXISTS aws_connections (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL UNIQUE,
    external_id VARCHAR(64)  NOT NULL,
    role_arn    VARCHAR(256),
    account_id  VARCHAR(12),
    status      ENUM('pending','active') NOT NULL DEFAULT 'pending',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_conn_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- One settings row per user, created on first login.
-- connection_method has only one value: there is no supported way for the
-- deployed app to scan with a local CLI profile.
CREATE TABLE IF NOT EXISTS user_settings (
    id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id             INT UNSIGNED NOT NULL UNIQUE,
    connection_method   ENUM('iam_role') NOT NULL DEFAULT 'iam_role',
    default_region      VARCHAR(50)  NOT NULL DEFAULT 'all',
    cpu_threshold       DECIMAL(4,1) NOT NULL DEFAULT 5.0,
    snapshot_age_days   INT          NOT NULL DEFAULT 90,
    include_pricing     TINYINT(1)   NOT NULL DEFAULT 1,
    scan_all_regions    TINYINT(1)   NOT NULL DEFAULT 0,
    scan_notifications  TINYINT(1)   NOT NULL DEFAULT 1,
    cost_notifications  TINYINT(1)   NOT NULL DEFAULT 1,
    CONSTRAINT fk_settings_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- One row per scan attempt. Every scan belongs to one AWS connection.
CREATE TABLE IF NOT EXISTS scans (
    id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id           INT UNSIGNED NOT NULL,
    connection_id     INT UNSIGNED NOT NULL,
    regions           JSON,                          -- list of regions scanned
    status            ENUM('pending','running','completed','failed')
                      NOT NULL DEFAULT 'pending',
    started_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at      DATETIME,
    resources_checked INT      NOT NULL DEFAULT 0,
    skipped_regions   JSON,                          -- regions that errored
    error_message     TEXT,
    CONSTRAINT fk_scan_user
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_connection
        FOREIGN KEY (connection_id) REFERENCES aws_connections(id) ON DELETE CASCADE
);

-- One row per finding within a scan.
CREATE TABLE IF NOT EXISTS findings (
    id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    scan_id          INT UNSIGNED NOT NULL,
    user_id          INT UNSIGNED NOT NULL,
    region           VARCHAR(50)  NOT NULL,
    resource_type    VARCHAR(100) NOT NULL,   -- matches scanner.py type strings
    resource_id      VARCHAR(100) NOT NULL,
    detail           TEXT,
    monthly_inr      DECIMAL(10,2),
    price_source     VARCHAR(50),             -- 'AWS price list' | 'estimate' | 'flat AWS rate'
    upper_bound      TINYINT(1)   NOT NULL DEFAULT 0,  -- 1 = cost is "up to" not exact
    cleanup_command  TEXT,
    priority         ENUM('High','Medium','Low') NOT NULL DEFAULT 'Medium',
    created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_finding_scan
        FOREIGN KEY (scan_id)  REFERENCES scans(id)  ON DELETE CASCADE,
    CONSTRAINT fk_finding_user
        FOREIGN KEY (user_id)  REFERENCES users(id)  ON DELETE CASCADE
);

-- Index to speed up "latest scan for this user" lookups.
CREATE INDEX idx_scans_user_started ON scans (user_id, started_at DESC);
-- Index to speed up dashboard aggregation.
CREATE INDEX idx_findings_scan     ON findings (scan_id);
CREATE INDEX idx_findings_user     ON findings (user_id);