-- ─────────────────────────────────────────────────────────────────────────────
-- Security hardening migration
-- Run:  wrangler d1 execute modih-mail-db --remote --file=migrate-security-hardening.sql
--
-- BREAKING CHANGES (noted inline):
--   - owner_token column is no longer used for new inboxes (token_version = 2).
--     Existing inboxes (token_version = 1 / raw) continue to work until their
--     TTL expires (max 30 days). After that the column can be dropped.
--   - API key peppered hashes are populated lazily on first use. During the
--     migration window both SHA-256 and HMAC hashes are accepted. New keys
--     created after this deploy only ever store the peppered hash.
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. inboxes — secure owner token columns
--    token_version = 1  raw token in owner_token (legacy, expires within 30 days)
--    token_version = 2  HMAC-SHA256(token, TOKEN_PEPPER) in owner_token_hash
ALTER TABLE inboxes ADD COLUMN owner_token_hash TEXT;
ALTER TABLE inboxes ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;

CREATE INDEX IF NOT EXISTS idx_inboxes_token_hash ON inboxes(owner_token_hash);

-- 2. api_keys — peppered hash column
--    key_hash_peppered = HMAC-SHA256(SHA-256(rawKey), API_KEY_PEPPER)
--    Existing rows start as NULL and are written on first successful validation.
ALTER TABLE api_keys ADD COLUMN key_hash_peppered TEXT;

CREATE INDEX IF NOT EXISTS idx_api_keys_peppered ON api_keys(key_hash_peppered);

-- 3. Audit log — structured security event trail (no secret material stored)
CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event      TEXT    NOT NULL,           -- e.g. "api_key.created", "owner_token.invalid"
  uid        TEXT,                       -- developer uid (nullable)
  inbox_id   TEXT,                       -- inbox id (nullable)
  ip         TEXT,                       -- client IP (nullable)
  details    TEXT,                       -- JSON metadata, never contains secrets
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_event_time ON audit_log(event, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_uid        ON audit_log(uid, created_at);
