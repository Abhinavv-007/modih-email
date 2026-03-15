-- Migration: add creator_ip and creator_token to inboxes
-- Run with: wrangler d1 execute modih-mail-db --file=migrate-add-creator-cols.sql
--
-- These columns replace the fragile ±5-second visitor_actions timestamp join.
-- Existing rows will have empty strings, which is fine — they'll expire naturally.

ALTER TABLE inboxes ADD COLUMN creator_ip    TEXT NOT NULL DEFAULT '';
ALTER TABLE inboxes ADD COLUMN creator_token TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_inboxes_creator_ip    ON inboxes(creator_ip);
CREATE INDEX IF NOT EXISTS idx_inboxes_creator_token ON inboxes(creator_token);
