-- ============================================================================
-- Pro / Developer feature backing storage
--   * sender block list per user        (table: user_blocklist)
--   * reserved-alias flag on an inbox    (column: inboxes.reserved)
--
-- Idempotent. Safe to re-run.
-- ============================================================================

-- ---- Sender block list ---------------------------------------------------
-- One row per (uid, entry).
-- `entry` is either a full lower-cased email address (foo@bar.com) or a
-- bare domain (bar.com). The email worker should filter on both.
CREATE TABLE IF NOT EXISTS user_blocklist (
  uid          TEXT NOT NULL,
  entry        TEXT NOT NULL,
  kind         TEXT NOT NULL DEFAULT 'auto',   -- 'address' | 'domain' | 'auto'
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (uid, entry)
);

CREATE INDEX IF NOT EXISTS idx_user_blocklist_uid ON user_blocklist (uid);

-- ---- Reserved alias flag -------------------------------------------------
-- D1 has no IF NOT EXISTS for ADD COLUMN, so we tolerate the "duplicate
-- column" error at apply time. Run this once after deploy:
--   wrangler d1 execute modih-mail --file migrate-pro-features.sql --remote
ALTER TABLE inboxes ADD COLUMN reserved INTEGER NOT NULL DEFAULT 0;

-- Backfill index for fast "list reserved by user" queries used by /api/inbox/mine.
CREATE INDEX IF NOT EXISTS idx_inboxes_creator_uid_reserved ON inboxes (creator_uid, reserved);
