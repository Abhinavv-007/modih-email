-- Admin analytics + subscription expiry support
-- Run:
--   wrangler d1 execute modih-mail-db --remote --file=migrate-admin-analytics.sql

-- Timed admin-issued subscriptions. If plan_expires_at is NULL, the plan is lifetime/current.
ALTER TABLE user_plans ADD COLUMN plan_started_at INTEGER DEFAULT NULL;
ALTER TABLE user_plans ADD COLUMN plan_expires_at INTEGER DEFAULT NULL;
ALTER TABLE user_plans ADD COLUMN plan_source TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_user_plans_expires ON user_plans(plan_expires_at);

-- Durable creator attribution for admin analytics. Existing rows stay anonymous.
ALTER TABLE inboxes ADD COLUMN creator_uid TEXT DEFAULT NULL;
ALTER TABLE inboxes ADD COLUMN creator_email TEXT DEFAULT NULL;
ALTER TABLE inboxes ADD COLUMN creator_plan TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_inboxes_creator_uid_created ON inboxes(creator_uid, created_at);
CREATE INDEX IF NOT EXISTS idx_inboxes_creator_email ON inboxes(creator_email);
CREATE INDEX IF NOT EXISTS idx_inboxes_created ON inboxes(created_at);

-- Permanent admin analytics ledger. Unlike inboxes/messages, this table is not
-- purged when temporary mailboxes expire.
CREATE TABLE IF NOT EXISTS admin_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,        -- 'inbox_created' | 'message_received' | 'api_usage' | 'auth_seen'
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

-- Backfill what still exists at migration time. Expired/purged rows cannot be
-- reconstructed, but future events stay durable.
INSERT INTO admin_events
  (event_type, uid, email, inbox_id, inbox_email, ip, browser_token, subject, is_otp, metadata, created_at)
SELECT
  'inbox_created',
  creator_uid,
  creator_email,
  id,
  email,
  creator_ip,
  creator_token,
  NULL,
  0,
  NULL,
  created_at
FROM inboxes
WHERE NOT EXISTS (
  SELECT 1 FROM admin_events e WHERE e.event_type = 'inbox_created' AND e.inbox_id = inboxes.id
);

INSERT INTO admin_events
  (event_type, uid, email, inbox_id, inbox_email, ip, browser_token, subject, is_otp, metadata, created_at)
SELECT
  'message_received',
  i.creator_uid,
  i.creator_email,
  m.inbox_id,
  i.email,
  i.creator_ip,
  i.creator_token,
  m.subject,
  CASE
    WHEN LOWER(COALESCE(m.subject, '')) LIKE '%otp%'
      OR LOWER(COALESCE(m.subject, '')) LIKE '%verification%'
      OR LOWER(COALESCE(m.subject, '')) LIKE '%code%'
      OR LOWER(COALESCE(m.body_text, '')) LIKE '%otp%'
      OR LOWER(COALESCE(m.body_text, '')) LIKE '%verification%'
      OR LOWER(COALESCE(m.body_text, '')) LIKE '%code%'
      OR LOWER(COALESCE(m.body_html, '')) LIKE '%otp%'
      OR LOWER(COALESCE(m.body_html, '')) LIKE '%verification%'
      OR LOWER(COALESCE(m.body_html, '')) LIKE '%code%'
    THEN 1 ELSE 0
  END,
  NULL,
  m.received_at
FROM messages m
LEFT JOIN inboxes i ON i.id = m.inbox_id
WHERE NOT EXISTS (
  SELECT 1 FROM admin_events e
  WHERE e.event_type = 'message_received'
    AND e.inbox_id = m.inbox_id
    AND e.created_at = m.received_at
    AND COALESCE(e.subject, '') = COALESCE(m.subject, '')
);

INSERT INTO admin_events
  (event_type, uid, email, inbox_id, inbox_email, ip, browser_token, subject, is_otp, metadata, created_at)
SELECT
  'api_usage',
  a.uid,
  u.email,
  NULL,
  NULL,
  NULL,
  NULL,
  a.action,
  0,
  NULL,
  a.created_at
FROM api_usage a
LEFT JOIN user_plans u ON u.uid = a.uid
WHERE NOT EXISTS (
  SELECT 1 FROM admin_events e
  WHERE e.event_type = 'api_usage'
    AND e.uid = a.uid
    AND e.created_at = a.created_at
    AND COALESCE(e.subject, '') = COALESCE(a.action, '')
    AND COALESCE(e.metadata, '') = ''
);
