-- ============================================================
-- Modih Mail — Auth Migration
-- Run in Cloudflare D1:
--   wrangler d1 execute modih-mail-db --remote --file=migrate-auth.sql
-- ============================================================

CREATE TABLE IF NOT EXISTS user_plans (
  uid TEXT PRIMARY KEY,         -- Firebase UID
  email TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',   -- 'free', 'pro', 'developer'
  plan_started_at INTEGER DEFAULT NULL,
  plan_expires_at INTEGER DEFAULT NULL,
  plan_source TEXT DEFAULT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_plans_email ON user_plans(email);
CREATE INDEX IF NOT EXISTS idx_user_plans_plan ON user_plans(plan);
CREATE INDEX IF NOT EXISTS idx_user_plans_expires ON user_plans(plan_expires_at);
