CREATE TABLE chezhi_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    qq text NOT NULL DEFAULT '----------' CHECK (qq ~ '^([0-9]{5,12}|----------)$'),
    accounts_revision bigint NOT NULL DEFAULT 0
);
INSERT INTO chezhi_config DEFAULT VALUES;

-- Exact UTC seconds since 0001-01-01, preserving legacy nanoseconds.
CREATE DOMAIN chezhi_instant AS numeric(21,9)
    CHECK (VALUE >= 0 AND VALUE < 315537897600);

CREATE TABLE chezhi_orders (
    ref text PRIMARY KEY CHECK (octet_length(ref) BETWEEN 1 AND 80),
    channel text NOT NULL CHECK (channel IN ('test', 'wechat', 'alipay')),
    cents integer NOT NULL CHECK (cents BETWEEN 0 AND 100000000),
    days integer NOT NULL CHECK (days BETWEEN 0 AND 3650),
    created chezhi_instant NOT NULL,
    UNIQUE (ref, created, days)
);
CREATE TABLE chezhi_cards (
    position bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    id text PRIMARY KEY,
    hash text NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$' AND id = left(hash,24)),
    prefix text NOT NULL CHECK (prefix ~ '^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}$'),
    ref text NOT NULL,
    created chezhi_instant NOT NULL,
    days integer NOT NULL,
    activated chezhi_instant,
    expires chezhi_instant,
    device text NOT NULL DEFAULT '' CHECK (device = '' OR device ~ '^[0-9a-f]{64}$'),
    revoked boolean NOT NULL DEFAULT false,
    FOREIGN KEY (ref, created, days) REFERENCES chezhi_orders (ref, created, days),
    CHECK ((activated IS NULL AND expires IS NULL AND device = '') OR
           (activated IS NOT NULL AND activated >= created AND
           ((days = 0 AND expires IS NULL) OR
            (days > 0 AND expires IS NOT NULL AND expires = activated + days * 86400))))
);
CREATE TABLE chezhi_audit (
    position bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred chezhi_instant NOT NULL,
    action text NOT NULL,
    card_id text REFERENCES chezhi_cards (id),
    actor text NOT NULL,
    target text NOT NULL,
    CHECK (
        (action IN ('issue','bind','unbind','revoke') AND card_id IS NOT NULL AND target = '') OR
        (action IN ('member-create','member-reset','member-role','member-disable','member-enable') AND card_id IS NULL AND target ~ '^[a-zA-Z][a-zA-Z0-9_-]{2,31}$') OR
        (action IN ('support_config','plans_config','login_success','login_failed','logout','logout_all','password_changed','password_failed') AND card_id IS NULL AND target = '')
    )
);
CREATE TABLE chezhi_plans (
    days integer PRIMARY KEY CHECK (days IN (0,1,7,30,90,365)),
    cents integer CHECK (cents BETWEEN 0 AND 100000000),
    visible boolean NOT NULL
);
INSERT INTO chezhi_plans (days, visible) VALUES (0,true),(1,true),(7,true),(30,true),(90,true),(365,true);
CREATE TABLE chezhi_members (
    name text PRIMARY KEY CHECK (name <> 'admin' AND name ~ '^[a-zA-Z][a-zA-Z0-9_-]{2,31}$'),
    role text NOT NULL CHECK (role IN ('operator','viewer')),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-fA-F]{64}$'),
    disabled boolean NOT NULL,
    revision bigint NOT NULL
);
CREATE TABLE chezhi_owner (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version = 1),
    salt text NOT NULL CHECK (salt ~ '^[0-9a-fA-F]{64}$'),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-fA-F]{64}$'),
    revision bigint NOT NULL
);
CREATE TABLE chezhi_import (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    fingerprint text NOT NULL,
    imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
