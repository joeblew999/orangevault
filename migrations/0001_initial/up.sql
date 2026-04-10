-- OrangeVault initial schema

CREATE TABLE users (
  uuid TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash BLOB NOT NULL,
  salt BLOB NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 600000,
  akey TEXT,
  private_key TEXT,
  public_key TEXT,
  security_stamp TEXT NOT NULL,
  client_kdf_type INTEGER NOT NULL DEFAULT 0,
  client_kdf_iter INTEGER NOT NULL DEFAULT 600000,
  client_kdf_memory INTEGER,
  client_kdf_parallelism INTEGER,
  api_key TEXT,
  avatar_color TEXT,
  email_verified INTEGER NOT NULL DEFAULT 0,
  totp_recover TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE devices (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  name TEXT NOT NULL,
  atype INTEGER NOT NULL,
  push_uuid TEXT,
  push_token TEXT,
  refresh_token TEXT NOT NULL,
  twofactor_remember TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE ciphers (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT REFERENCES users(uuid),
  organization_uuid TEXT REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  fields TEXT,
  data TEXT NOT NULL,
  akey TEXT,
  password_history TEXT,
  reprompt INTEGER DEFAULT 0,
  deleted_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE folders (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders(uuid),
  PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE favorites (
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  PRIMARY KEY (user_uuid, cipher_uuid)
);

CREATE TABLE attachments (
  id TEXT PRIMARY KEY,
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),
  file_name TEXT,
  file_size INTEGER,
  akey TEXT
);

CREATE TABLE organizations (
  uuid TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  billing_email TEXT NOT NULL,
  private_key TEXT,
  public_key TEXT
);

CREATE TABLE memberships (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  akey TEXT,
  atype INTEGER NOT NULL,
  status INTEGER NOT NULL,
  access_all INTEGER DEFAULT 0,
  external_id TEXT,
  reset_password_key TEXT
);

CREATE TABLE collections (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  name TEXT NOT NULL,
  external_id TEXT
);

CREATE TABLE users_collections (
  user_uuid TEXT NOT NULL,
  collection_uuid TEXT NOT NULL,
  read_only INTEGER DEFAULT 0,
  hide_passwords INTEGER DEFAULT 0,
  manage INTEGER DEFAULT 0,
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE ciphers_collections (
  cipher_uuid TEXT NOT NULL,
  collection_uuid TEXT NOT NULL,
  PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE groups (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  name TEXT NOT NULL
);

CREATE TABLE groups_users (
  group_uuid TEXT NOT NULL,
  user_uuid TEXT NOT NULL,
  PRIMARY KEY (group_uuid, user_uuid)
);

CREATE TABLE collections_groups (
  collection_uuid TEXT NOT NULL,
  group_uuid TEXT NOT NULL,
  read_only INTEGER DEFAULT 0,
  hide_passwords INTEGER DEFAULT 0,
  PRIMARY KEY (collection_uuid, group_uuid)
);

CREATE TABLE org_policies (
  uuid TEXT PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,
  enabled INTEGER DEFAULT 0,
  data TEXT
);

CREATE TABLE two_factor (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  atype INTEGER NOT NULL,
  enabled INTEGER DEFAULT 1,
  data TEXT NOT NULL,
  last_used INTEGER DEFAULT 0
);

CREATE TABLE sends (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT REFERENCES users(uuid),
  organization_uuid TEXT REFERENCES organizations(uuid),
  atype INTEGER NOT NULL,
  name TEXT NOT NULL,
  notes TEXT,
  data TEXT NOT NULL,
  akey TEXT NOT NULL,
  password_hash BLOB,
  password_salt BLOB,
  password_iter INTEGER,
  max_access_count INTEGER,
  access_count INTEGER DEFAULT 0,
  disabled INTEGER DEFAULT 0,
  hide_email INTEGER DEFAULT 0,
  expiration_date TEXT,
  deletion_date TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE equivalent_domains (
  uuid TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL REFERENCES users(uuid),
  global_equiv_domains TEXT,
  custom_equiv_domains TEXT
);

-- Indexes for common queries
CREATE INDEX idx_devices_user ON devices(user_uuid);
CREATE INDEX idx_ciphers_user ON ciphers(user_uuid);
CREATE INDEX idx_ciphers_org ON ciphers(organization_uuid);
CREATE INDEX idx_folders_user ON folders(user_uuid);
CREATE INDEX idx_memberships_user ON memberships(user_uuid);
CREATE INDEX idx_memberships_org ON memberships(org_uuid);
CREATE INDEX idx_collections_org ON collections(org_uuid);
CREATE INDEX idx_two_factor_user ON two_factor(user_uuid);
CREATE INDEX idx_sends_user ON sends(user_uuid);
CREATE INDEX idx_sends_deletion ON sends(deletion_date);
