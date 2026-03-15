-- Migration: Add visitor tracking for free-tier abuse prevention
-- Tracks inbox creation actions per visitor (IP + browser token)

CREATE TABLE IF NOT EXISTS visitor_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  browser_token TEXT NOT NULL,
  action TEXT NOT NULL DEFAULT 'inbox_create',
  created_at INTEGER NOT NULL
);

-- Index for querying creation count per IP in time window
CREATE INDEX IF NOT EXISTS idx_visitor_ip_time ON visitor_actions(ip, created_at);

-- Index for querying creation count per browser token in time window
CREATE INDEX IF NOT EXISTS idx_visitor_token_time ON visitor_actions(browser_token, created_at);
