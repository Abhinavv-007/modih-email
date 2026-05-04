-- WebAuthn passkey login for the /admin gate.
-- Run:
--   wrangler d1 execute modih-mail-db --remote --file=migrate-admin-passkeys.sql

-- Each row is one registered authenticator. Registration is gated by the
-- existing X-Admin-Secret check, so only the operator who already knows the
-- admin secret can enroll a passkey.
CREATE TABLE IF NOT EXISTS admin_passkeys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credential_id TEXT NOT NULL UNIQUE,        -- base64url, identifier returned by the authenticator
  public_key_jwk TEXT NOT NULL,              -- JSON-encoded JWK (ES256 / P-256)
  algorithm INTEGER NOT NULL DEFAULT -7,     -- COSE alg, currently only -7 (ES256)
  sign_count INTEGER NOT NULL DEFAULT 0,     -- monotonic counter; replay guard
  transports TEXT DEFAULT NULL,              -- comma-separated, e.g. "internal,hybrid"
  label TEXT DEFAULT NULL,                   -- operator-provided device name
  aaguid TEXT DEFAULT NULL,                  -- hex-encoded authenticator AAGUID
  created_at INTEGER NOT NULL,
  last_used_at INTEGER DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_passkeys_credential ON admin_passkeys(credential_id);
