-- Initialize SOC IoT Platform Database

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ============================================
-- Devices Table
-- ============================================
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    ip_address INET UNIQUE NOT NULL,
    mac_address MACADDR UNIQUE NOT NULL,
    hostname VARCHAR(255),
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    firmware_version VARCHAR(100),
    device_type VARCHAR(50),  -- router, camera, sensor, etc.
    os_family VARCHAR(100),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'active',  -- active, inactive, suspicious
    confidence_score FLOAT DEFAULT 0.0,  -- ML classification confidence
    metadata JSONB,  -- Additional device info
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_devices_ip ON devices(ip_address);
CREATE INDEX idx_devices_mac ON devices(mac_address);
CREATE INDEX idx_devices_status ON devices(status);
CREATE INDEX idx_devices_lastseen ON devices(last_seen DESC);

-- ============================================
-- Network Flows (TimescaleDB Hypertable)
-- ============================================
CREATE TABLE IF NOT EXISTS flows (
    timestamp TIMESTAMPTZ NOT NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),  -- TCP, UDP, ICMP, etc.
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    packets_sent INTEGER DEFAULT 0,
    packets_received INTEGER DEFAULT 0,
    duration_ms INTEGER,
    flags VARCHAR(50),
    anomaly_score FLOAT DEFAULT 0.0,
    metadata JSONB
);

SELECT create_hypertable('flows', 'timestamp', if_not_exists => TRUE);

CREATE INDEX idx_flows_src_ip ON flows(src_ip, timestamp DESC);
CREATE INDEX idx_flows_dst_ip ON flows(dst_ip, timestamp DESC);
CREATE INDEX idx_flows_anomaly ON flows(anomaly_score DESC) WHERE anomaly_score > 0.5;

-- ============================================
-- Suricata Alerts
-- ============================================
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    signature TEXT NOT NULL,
    signature_id INTEGER,
    severity INTEGER,  -- 1=High, 2=Medium, 3=Low
    category VARCHAR(100),
    payload TEXT,
    packet_data BYTEA,
    acknowledged BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    notes TEXT,
    metadata JSONB
);

CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX idx_alerts_acknowledged ON alerts(acknowledged) WHERE acknowledged = FALSE;

-- ============================================
-- Firmware Analysis
-- ============================================
CREATE TABLE IF NOT EXISTS firmware (
    id SERIAL PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    firmware_hash VARCHAR(64) UNIQUE NOT NULL,
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    version VARCHAR(100),
    filename VARCHAR(255),
    file_size BIGINT,
    upload_date TIMESTAMPTZ DEFAULT NOW(),
    analysis_status VARCHAR(20) DEFAULT 'pending',  -- pending, analyzing, completed, failed
    filesystem_extracted BOOLEAN DEFAULT FALSE,
    emulation_possible BOOLEAN DEFAULT FALSE,
    metadata JSONB
);

CREATE INDEX idx_firmware_hash ON firmware(firmware_hash);
CREATE INDEX idx_firmware_device ON firmware(device_id);
CREATE INDEX idx_firmware_status ON firmware(analysis_status);

-- ============================================
-- Firmware Vulnerabilities
-- ============================================
CREATE TABLE IF NOT EXISTS firmware_vulnerabilities (
    id SERIAL PRIMARY KEY,
    firmware_id INTEGER REFERENCES firmware(id) ON DELETE CASCADE,
    cve_id VARCHAR(20) NOT NULL,
    cvss_score FLOAT,
    cvss_vector VARCHAR(100),
    severity VARCHAR(20),  -- CRITICAL, HIGH, MEDIUM, LOW
    description TEXT,
    affected_component VARCHAR(255),
    exploitable BOOLEAN DEFAULT FALSE,
    patch_available BOOLEAN DEFAULT FALSE,
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX idx_fwvuln_firmware ON firmware_vulnerabilities(firmware_id);
CREATE INDEX idx_fwvuln_cve ON firmware_vulnerabilities(cve_id);
CREATE INDEX idx_fwvuln_severity ON firmware_vulnerabilities(severity);

-- ============================================
-- Hardcoded Secrets/Credentials
-- ============================================
CREATE TABLE IF NOT EXISTS firmware_secrets (
    id SERIAL PRIMARY KEY,
    firmware_id INTEGER REFERENCES firmware(id) ON DELETE CASCADE,
    secret_type VARCHAR(50),  -- password, api_key, private_key, cert
    file_path VARCHAR(500),
    line_number INTEGER,
    content TEXT,
    severity VARCHAR(20),
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_secrets_firmware ON firmware_secrets(firmware_id);
CREATE INDEX idx_secrets_type ON firmware_secrets(secret_type);

-- ============================================
-- Scan History
-- ============================================
CREATE TABLE IF NOT EXISTS scan_history (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(50),  -- passive, active, firmware
    target VARCHAR(255),  -- IP range, device ID, etc.
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(20),  -- running, completed, failed
    devices_found INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    metadata JSONB
);

CREATE INDEX idx_scan_history_time ON scan_history(started_at DESC);

-- ============================================
-- Reports
-- ============================================
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    report_type VARCHAR(50),  -- executive, technical, compliance
    format VARCHAR(10),  -- pdf, html, json
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    generated_by VARCHAR(100),
    file_path VARCHAR(500),
    metadata JSONB
);

-- ============================================
-- Users (for future multi-user support)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'analyst',  -- admin, analyst, viewer
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ,
    active BOOLEAN DEFAULT TRUE
);

-- ============================================
-- Audit Log
-- ============================================
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100),  -- scan_started, alert_acknowledged, etc.
    target_type VARCHAR(50),
    target_id INTEGER,
    details JSONB
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);

-- ============================================
-- Initial Data
-- ============================================

-- Insert default admin user (password: admin - CHANGE IN PRODUCTION!)
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@soc-platform.local', '$2b$12$LQv3c1yqBWVHxkd0L.MoF.0j8Y8Z9dQ9oZ9YZ9YZ9YZ9YZ9YZ9Y', 'admin')
ON CONFLICT (username) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO socuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO socuser;
