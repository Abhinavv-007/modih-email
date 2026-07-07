-- Permanent "never reuse an address" ledger.
--
-- inboxes.email is UNIQUE, but only among LIVE rows: when an inbox expires the
-- cleanup job DELETEs it, which frees its address for a future user. That means
-- the same address could be handed to two different people over time.
--
-- used_addresses records every address that has EVER been issued and is never
-- deleted (the expiry cleanup does not touch it). Inbox creation writes here in
-- the same atomic batch as the inbox insert, so a collision on this table's
-- PRIMARY KEY guarantees an address is issued at most once, forever.
CREATE TABLE IF NOT EXISTS used_addresses (
  email         TEXT PRIMARY KEY,          -- the full address, e.g. abc123@modih.in
  first_used_at INTEGER NOT NULL,          -- unix seconds the address was first issued
  creator_uid   TEXT DEFAULT NULL,         -- who first created it (nullable / anonymous)
  creator_ip    TEXT DEFAULT NULL
);

-- Backfill from any addresses that currently exist as live inboxes so the
-- ledger is complete from day one. INSERT OR IGNORE keeps this migration
-- idempotent and avoids clobbering rows written by newer app code.
INSERT OR IGNORE INTO used_addresses (email, first_used_at, creator_uid, creator_ip)
SELECT email, created_at, creator_uid, creator_ip FROM inboxes;
