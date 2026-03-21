CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  hashed_password VARCHAR(255) NOT NULL,
  role VARCHAR(50) DEFAULT 'analyst',
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS assets (
  id SERIAL PRIMARY KEY,
  hostname VARCHAR(255) UNIQUE NOT NULL,
  ip_address INET NOT NULL,
  asset_type VARCHAR(50),
  criticality VARCHAR(20),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  asset_id INTEGER REFERENCES assets(id),
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(20),
  cvss_score NUMERIC(3,1),
  status VARCHAR(50) DEFAULT 'OPEN',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id SERIAL PRIMARY KEY,
  job_type VARCHAR(50),
  status VARCHAR(50),
  started_at TIMESTAMP,
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id SERIAL PRIMARY KEY,
  finding_id INTEGER REFERENCES findings(id),
  ticket_number VARCHAR(50),
  external_id VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  action VARCHAR(255),
  resource VARCHAR(255),
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS compliance_mappings (
  id SERIAL PRIMARY KEY,
  finding_id INTEGER REFERENCES findings(id),
  framework VARCHAR(50),
  requirement VARCHAR(255),
  mapped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
