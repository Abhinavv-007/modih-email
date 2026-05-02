-- Per-key API limits and usage details.
-- Run against existing D1 databases before deploying the matching code:
--   wrangler d1 execute modih-mail-db --remote --file=migrate-api-key-limits.sql

ALTER TABLE api_keys ADD COLUMN monthly_create_limit INTEGER NOT NULL DEFAULT 5000;
ALTER TABLE api_keys ADD COLUMN monthly_read_limit INTEGER NOT NULL DEFAULT 50000;

ALTER TABLE api_usage ADD COLUMN key_id TEXT DEFAULT NULL;
ALTER TABLE api_usage ADD COLUMN endpoint TEXT DEFAULT NULL;
ALTER TABLE api_usage ADD COLUMN inbox_id TEXT DEFAULT NULL;
ALTER TABLE api_usage ADD COLUMN ip TEXT DEFAULT NULL;
ALTER TABLE api_usage ADD COLUMN status_code INTEGER DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_api_usage_key_created ON api_usage(key_id, created_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_key_action_created ON api_usage(key_id, action, created_at);
