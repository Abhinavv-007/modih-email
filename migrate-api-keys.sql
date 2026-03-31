-- API Keys & Usage Tracking for Developer Plan
-- Run against your D1 database:
--   wrangler d1 execute modih-mail-db --file=migrate-api-keys.sql

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  uid TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT 'Default Key',
  key_prefix TEXT NOT NULL,     -- First ~12 chars for display (e.g., mdh_xxxxxxxx...)
  key_hash TEXT NOT NULL,       -- SHA-256 hash of the full key (never store plaintext)
  created_at INTEGER NOT NULL,
  last_used_at INTEGER DEFAULT NULL,
  is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS api_usage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uid TEXT NOT NULL,
  action TEXT NOT NULL,         -- 'inbox_create' | 'message_read'
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_uid ON api_keys(uid);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_usage_uid_created ON api_usage(uid, created_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_uid_action_created ON api_usage(uid, action, created_at);
