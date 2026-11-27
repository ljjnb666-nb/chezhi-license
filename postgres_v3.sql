CREATE TABLE chezhi_sessions (
    token_digest text PRIMARY KEY CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    principal text NOT NULL CHECK (principal ~ '^[a-zA-Z][a-zA-Z0-9_-]{2,31}$'),
    role text NOT NULL CHECK ((principal='admin' AND role='owner') OR
                         (principal<>'admin' AND role IN ('operator','viewer'))),
    revision bigint NOT NULL CHECK (revision > 0),
    expires timestamptz NOT NULL
);
CREATE INDEX chezhi_sessions_principal_idx ON chezhi_sessions(principal);
CREATE INDEX chezhi_sessions_expiry_idx ON chezhi_sessions(expires);

CREATE TABLE chezhi_rate_limits (
    scope text NOT NULL CHECK (scope IN ('login','license')),
    source text NOT NULL CHECK (source = '*' OR source ~ '^[0-9a-f]{64}$'),
    window_start bigint NOT NULL CHECK (window_start >= 0),
    used integer NOT NULL CHECK (used > 0),
    PRIMARY KEY (scope,source,window_start)
);
CREATE INDEX chezhi_rate_limits_expiry_idx ON chezhi_rate_limits(window_start);
CREATE INDEX chezhi_orders_created_ref_idx ON chezhi_orders (created DESC, ref);
CREATE INDEX chezhi_cards_bound_idx ON chezhi_cards (position DESC) WHERE device <> '';
