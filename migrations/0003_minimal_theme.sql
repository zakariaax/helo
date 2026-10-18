-- Move workspaces still on the old default look to the new Minimal-style default.
-- A workspace whose admin already picked custom colors keeps its accent; only the font is reset,
-- because the old font names are no longer offered.
UPDATE app_settings
SET value = '{"accent":"#00a76f","bg":"#ffffff","ink":"#1c252e","card":"#ffffff","muted":"#637381","line":"#dfe3e8","fontSize":15,"font":"Public Sans","heading":"Public Sans","radius":16,"glow":false,"density":"comfortable"}'
WHERE key = 'theme' AND value LIKE '%"accent":"#1f6b45"%';
