ALTER TABLE users ADD COLUMN username TEXT;
ALTER TABLE users ADD COLUMN contact_email TEXT;
ALTER TABLE users ADD COLUMN daily_limit INTEGER;

UPDATE users
SET username = lower(trim(email))
WHERE username IS NULL OR trim(username) = '';

CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username);
CREATE UNIQUE INDEX IF NOT EXISTS users_contact_email_unique ON users(contact_email);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO app_settings (key, value) VALUES ('daily_limit', '100');
INSERT OR IGNORE INTO app_settings (key, value) VALUES ('theme', '{"accent":"#1f6b45","bg":"#f3f4f1","ink":"#1c1f1a","card":"#ffffff","muted":"#66706a","line":"#e6e8e3","fontSize":15,"font":"Segoe UI","heading":"Palatino","radius":18,"glow":true,"density":"comfortable"}');

CREATE TABLE IF NOT EXISTS usage_days (
  user_id TEXT NOT NULL,
  day TEXT NOT NULL,
  checks INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);
