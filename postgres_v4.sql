ALTER TABLE chezhi_rate_limits DROP CONSTRAINT chezhi_rate_limits_scope_check;
ALTER TABLE chezhi_rate_limits ADD CONSTRAINT chezhi_rate_limits_scope_check
    CHECK (scope IN ('login','account','license'));

CREATE TABLE chezhi_deployment (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    mode text NOT NULL CHECK (mode IN ('local','server','test')),
    database_name text NOT NULL,
    database_oid oid NOT NULL,
    cluster_id bigint NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0)
);
INSERT INTO chezhi_deployment(mode,database_name,database_oid,cluster_id,generation)
    SELECT 'local',datname,oid,(SELECT system_identifier FROM pg_control_system()),1
    FROM pg_database WHERE datname=current_database();

-- This upgrade is performed with all application instances offline.
DELETE FROM chezhi_sessions;
DELETE FROM chezhi_rate_limits;

ALTER TABLE chezhi_audit DROP CONSTRAINT chezhi_audit_check;
ALTER TABLE chezhi_audit ADD CONSTRAINT chezhi_audit_check CHECK (
    (action IN ('issue','bind','unbind','revoke') AND card_id IS NOT NULL AND target = '') OR
    (action IN ('member-create','member-reset','member-role','member-disable','member-enable') AND card_id IS NULL AND target ~ '^[a-zA-Z][a-zA-Z0-9_-]{2,31}$') OR
    (action IN ('support_config','plans_config','login_success','login_failed','logout','logout_all',
        'password_changed','password_failed','runtime_mode_changed','security_recovered') AND card_id IS NULL AND target = '')
);
CREATE INDEX chezhi_cards_ref_position_idx ON chezhi_cards (ref,position DESC);
