CREATE TABLE IF NOT EXISTS shares (
  slug TEXT PRIMARY KEY,
  label TEXT,
  auth_mode TEXT NOT NULL CHECK (auth_mode IN ('password', 'public')),
  sha256 TEXT NOT NULL,
  files_json TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  scan_result_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  uploader TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_shares_created_at ON shares(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_shares_expires_at ON shares(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  details_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_slug_created_at
  ON audit_events(slug, created_at DESC);

-- View tracking: `view` events share the audit_events table. This index serves
-- the per-event aggregates — total opens per slug for `drop list`, and the
-- `WHERE event = 'view' GROUP BY slug` rollup.
CREATE INDEX IF NOT EXISTS idx_audit_events_event_slug
  ON audit_events(event, slug);
