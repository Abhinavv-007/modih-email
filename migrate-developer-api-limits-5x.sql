-- Raise existing Developer API keys that still use the former plan defaults.
-- Custom lower per-key limits remain unchanged.
UPDATE api_keys
SET monthly_create_limit = 25000
WHERE monthly_create_limit = 5000;

UPDATE api_keys
SET monthly_read_limit = 250000
WHERE monthly_read_limit = 50000;
