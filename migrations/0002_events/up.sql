CREATE TABLE events (
  uuid TEXT PRIMARY KEY,
  event_type INTEGER NOT NULL,
  user_uuid TEXT,
  org_uuid TEXT,
  cipher_uuid TEXT,
  collection_uuid TEXT,
  group_uuid TEXT,
  member_uuid TEXT,
  act_user_uuid TEXT,
  device_type INTEGER,
  ip_address TEXT,
  event_date TEXT NOT NULL
);

CREATE INDEX idx_events_org ON events(org_uuid, event_date);
CREATE INDEX idx_events_user ON events(user_uuid, event_date);
