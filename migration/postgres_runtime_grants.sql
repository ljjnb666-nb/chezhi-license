-- Run as the schema owner after db-init. Create the LOGIN role separately.
GRANT USAGE ON SCHEMA public TO chezhi_runtime;
GRANT SELECT ON chezhi_schema, chezhi_config, chezhi_orders, chezhi_cards,
    chezhi_audit, chezhi_plans, chezhi_members, chezhi_owner TO chezhi_runtime;
GRANT UPDATE (qq, accounts_revision) ON chezhi_config TO chezhi_runtime;
GRANT INSERT ON chezhi_orders, chezhi_cards, chezhi_audit, chezhi_members, chezhi_owner TO chezhi_runtime;
GRANT UPDATE (activated, expires, device, revoked) ON chezhi_cards TO chezhi_runtime;
GRANT UPDATE (cents, visible) ON chezhi_plans TO chezhi_runtime;
GRANT UPDATE (role, digest, disabled, revision) ON chezhi_members TO chezhi_runtime;
GRANT UPDATE (version, salt, digest, revision) ON chezhi_owner TO chezhi_runtime;
GRANT USAGE ON SEQUENCE chezhi_cards_position_seq, chezhi_audit_position_seq TO chezhi_runtime;
GRANT SELECT, INSERT, DELETE ON chezhi_sessions TO chezhi_runtime;
GRANT SELECT, INSERT, DELETE ON chezhi_rate_limits TO chezhi_runtime;
GRANT UPDATE (used) ON chezhi_rate_limits TO chezhi_runtime;
GRANT SELECT ON chezhi_deployment TO chezhi_runtime;
GRANT SELECT, INSERT, DELETE ON chezhi_challenges TO chezhi_runtime;
GRANT SELECT, INSERT ON chezhi_secure_bindings TO chezhi_runtime;
GRANT UPDATE (public_key, revision) ON chezhi_secure_bindings TO chezhi_runtime;
GRANT UPDATE (auth_epoch) ON chezhi_cards TO chezhi_runtime;
GRANT SELECT ON chezhi_signing_policy TO chezhi_runtime;
GRANT SELECT ON chezhi_signing_history TO chezhi_runtime;
