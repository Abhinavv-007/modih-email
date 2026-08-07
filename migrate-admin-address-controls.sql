-- Admin address controls.
--
-- `blocked` lets an admin stop a live address from receiving new mail without
-- deleting it (e.g. an abused address). The inbound Email Worker rejects mail
-- for blocked inboxes; the admin can later reactivate (unblock + extend) or
-- delete the address. Deleting keeps the used_addresses ledger row, so a
-- deleted address is still never handed to a second user.
--
-- SQLite has no "ADD COLUMN IF NOT EXISTS"; run this once. Application code
-- tolerates the column being absent (pre-migration) via query fallbacks.
ALTER TABLE inboxes ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_inboxes_blocked ON inboxes(blocked);
