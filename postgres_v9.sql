-- Public signing history only; never store private seeds.
CREATE TABLE chezhi_signing_history (
    deployment text PRIMARY KEY CHECK (deployment ~ '^[0-9a-f]{64}$'),
    public_key text NOT NULL CHECK (public_key ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK (action IN ('initialize','rotate','recovery','migration_baseline')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO chezhi_signing_history(deployment,public_key,action)
SELECT deployment,public_key,'migration_baseline' FROM chezhi_signing_policy;
