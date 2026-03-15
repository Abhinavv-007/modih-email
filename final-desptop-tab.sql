-- Inboxes table
CREATE TABLE IF NOT EXISTS inboxes (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  owner_token TEXT NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_messages_inbox ON messages(inbox_id);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);
