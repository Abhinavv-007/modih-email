-- Inboxes table
CREATE TABLE IF NOT EXISTS inboxes (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  owner_token TEXT NOT NULL,
  owner_token_hash TEXT,
  token_version INTEGER NOT NULL DEFAULT 1,
  creator_ip TEXT DEFAULT NULL,
  creator_token TEXT DEFAULT NULL,
  creator_uid TEXT DEFAULT NULL,
  creator_email TEXT DEFAULT NULL,
  creator_plan TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL DEFAULT 0
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  inbox_id TEXT NOT NULL,
  from_address TEXT NOT NULL,
  from_name TEXT DEFAULT '',
  subject TEXT DEFAULT '(no subject)',
  body_html TEXT DEFAULT '',
  body_text TEXT DEFAULT '',
  received_at INTEGER NOT NULL,
  FOREIGN KEY (inbox_id) REFERENCES inboxes(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_inboxes_email ON inboxes(email);
CREATE INDEX IF NOT EXISTS idx_inboxes_token_hash ON inboxes(owner_token_hash);
CREATE INDEX IF NOT EXISTS idx_inboxes_creator_uid_created ON inboxes(creator_uid, created_at);
CREATE INDEX IF NOT EXISTS idx_inboxes_creator_email ON inboxes(creator_email);
CREATE INDEX IF NOT EXISTS idx_inboxes_created ON inboxes(created_at);
CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(inbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);

-- Permanent admin analytics ledger. Temporary inbox/message rows can expire,
-- but these aggregate events remain for lifetime admin stats.
CREATE TABLE IF NOT EXISTS admin_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL, -- 'inbox_created' | 'message_received' | 'api_usage' | 'auth_seen'
  uid TEXT DEFAULT NULL,
  email TEXT DEFAULT NULL,
  inbox_id TEXT DEFAULT NULL,
  inbox_email TEXT DEFAULT NULL,
  ip TEXT DEFAULT NULL,
  browser_token TEXT DEFAULT NULL,
  subject TEXT DEFAULT NULL,
  is_otp INTEGER NOT NULL DEFAULT 0,
  metadata TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_events_type_time ON admin_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_events_uid_time ON admin_events(uid, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_events_inbox ON admin_events(inbox_id);
CREATE INDEX IF NOT EXISTS idx_admin_events_email ON admin_events(email);

-- Permanent never-reuse ledger: every address ever issued, never deleted.
-- Inbox creation writes here atomically with the inbox row, so an address is
-- handed out at most once for all time — even after its inbox expires and is
-- cleaned up. See functions/api/inbox.js insertInbox() and
-- migrate-unique-addresses.sql.
CREATE TABLE IF NOT EXISTS used_addresses (
  email         TEXT PRIMARY KEY,
  first_used_at INTEGER NOT NULL,
  creator_uid   TEXT DEFAULT NULL,
  creator_ip    TEXT DEFAULT NULL
);
