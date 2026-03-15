-- Migration: Add owner_token to inboxes and invalidate all old inboxes
-- Old inboxes are deleted (not given a shared default token) to prevent bypass.

-- Step 1: Add the column with a placeholder default so ALTER succeeds
ALTER TABLE inboxes ADD COLUMN owner_token TEXT NOT NULL DEFAULT '';

-- Step 2: Delete all pre-existing inboxes (they have no real owner_token)
-- Their messages cascade-delete via FK ON DELETE CASCADE
DELETE FROM inboxes;

-- Done. New inboxes created via the API will receive unique tokens.
