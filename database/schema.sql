-- Domain Manager v7.7
-- Initialize a brand-new Cloudflare D1 database only.
-- Do not run this as an upgrade script against an existing production database.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL COLLATE NOCASE UNIQUE,
  remark TEXT NOT NULL DEFAULT '',
  group_name TEXT NOT NULL DEFAULT '',
  target_url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  redirect_type INTEGER NOT NULL DEFAULT 302 CHECK (redirect_type IN (301, 302)),
  paused_message TEXT NOT NULL DEFAULT '此域名暂时不可用，请稍后再试。',
  health_status TEXT NOT NULL DEFAULT 'unknown' CHECK (health_status IN ('unknown', 'ok', 'degraded', 'down')),
  health_code INTEGER,
  health_checked_at TEXT,
  health_error TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  source TEXT NOT NULL DEFAULT 'direct',
  referer TEXT,
  user_agent TEXT,
  visited_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS target_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  old_target TEXT NOT NULL,
  new_target TEXT NOT NULL,
  changed_by TEXT NOT NULL DEFAULT 'admin',
  changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL DEFAULT 'system',
  action TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '',
  domain_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_domains_enabled_health
  ON domains(enabled, health_checked_at);
CREATE INDEX IF NOT EXISTS idx_visits_domain_time
  ON visits(domain_id, visited_at DESC);
CREATE INDEX IF NOT EXISTS idx_visits_time
  ON visits(visited_at);
CREATE INDEX IF NOT EXISTS idx_target_history_domain_time
  ON target_history(domain_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created
  ON audit_logs(created_at DESC);
