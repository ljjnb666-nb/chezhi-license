-- Offline staging schema. Portable SQL subset; exercised on SQLite only.
-- Not the OpenLicensd production schema. Never run on a live application DB.
CREATE TABLE migration_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  qq TEXT NOT NULL
);
CREATE TABLE staged_cards (
  ordinal INTEGER PRIMARY KEY CHECK (ordinal >= 0),
  id TEXT NOT NULL UNIQUE CHECK (length(id) = 24),
  key_hash TEXT NOT NULL UNIQUE CHECK (length(key_hash) = 64),
  prefix TEXT NOT NULL CHECK (length(prefix) = 5),
  days INTEGER NOT NULL CHECK (days BETWEEN 0 AND 3650),
  sale_ref TEXT NOT NULL CHECK (length(sale_ref) BETWEEN 1 AND 80),
  channel TEXT NOT NULL CHECK (channel IN ('test','wechat','alipay')),
  amount_cents INTEGER NOT NULL CHECK (amount_cents BETWEEN 0 AND 100000000),
  created TEXT NOT NULL,
  activated TEXT,
  expires TEXT,
  device_hash TEXT CHECK (device_hash IS NULL OR length(device_hash) = 64),
  revoked INTEGER NOT NULL CHECK (revoked IN (0,1)),
  CHECK (activated IS NOT NULL OR (expires IS NULL AND device_hash IS NULL)),
  CHECK ((days = 0 AND expires IS NULL) OR (days > 0 AND ((activated IS NULL AND expires IS NULL) OR (activated IS NOT NULL AND expires IS NOT NULL))))
);
CREATE INDEX staged_sale_ref ON staged_cards(sale_ref);
CREATE TABLE staged_audit (
  ordinal INTEGER PRIMARY KEY CHECK (ordinal >= 0),
  at_time TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('issue','bind','unbind','revoke','support_config','plans_config','login_success','login_failed','logout','logout_all','password_changed','password_failed','member-create','member-reset','member-role','member-disable','member-enable')),
  card_id TEXT REFERENCES staged_cards(id),
  actor TEXT,
  target TEXT,
  CHECK ((action IN ('issue','bind','unbind','revoke') AND card_id IS NOT NULL) OR (action NOT IN ('issue','bind','unbind','revoke') AND card_id IS NULL))
);
