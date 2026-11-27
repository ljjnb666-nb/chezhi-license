package main

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

//go:embed postgres_catalog.sql
var postgresCatalogSQL string

//go:embed postgres_catalog_v3.json
var postgresCatalogV3 string

func verifyPostgresCatalog(ctx context.Context, tx *sql.Tx) error {
	var manifest string
	if err := tx.QueryRowContext(ctx, postgresCatalogSQL).Scan(&manifest); err != nil {
		return errors.New("cannot read PostgreSQL catalog")
	}
	var actual, expected map[string]string
	if json.Unmarshal([]byte(manifest), &actual) != nil || json.Unmarshal([]byte(postgresCatalogV3), &expected) != nil {
		return errors.New("invalid PostgreSQL catalog manifest")
	}
	var mismatches []string
	for key, definition := range expected {
		if actual[key] != definition {
			mismatches = append(mismatches, key)
		}
	}
	if len(mismatches) > 0 {
		sort.Strings(mismatches)
		return fmt.Errorf("PostgreSQL catalog mismatch: %s", strings.Join(mismatches, ", "))
	}
	return nil
}

func (p *postgresStore) verifyDatabase(ctx context.Context, profile string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return p.runTransaction(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
		version, err := schemaVersion(ctx, tx)
		if err != nil || version != len(postgresMigrations) {
			return errors.New("PostgreSQL migration history does not match the binary")
		}
		if err := verifyPostgresCatalog(ctx, tx); err != nil {
			return err
		}
		if err := verifyPostgresData(ctx, tx, profile != "--runtime"); err != nil {
			return err
		}
		switch profile {
		case "--runtime":
			return verifyRuntimeRole(ctx, tx)
		case "--migrator":
			return verifyMigratorRole(ctx, tx)
		}
		return nil
	})
}

func verifyPostgresData(ctx context.Context, tx *sql.Tx, includeImport bool) error {
	var singleton, history, orders, links bool
	if err := tx.QueryRowContext(ctx, `SELECT
        (SELECT count(*) = 1 AND coalesce(bool_and(singleton AND accounts_revision>=0),false) FROM chezhi_config),
        NOT EXISTS (SELECT 1 FROM chezhi_schema WHERE NOT isfinite(applied_at)),
        NOT EXISTS (SELECT 1 FROM chezhi_orders o WHERE NOT EXISTS (SELECT 1 FROM chezhi_cards c WHERE c.ref=o.ref)),
        NOT EXISTS (SELECT 1 FROM chezhi_cards c LEFT JOIN chezhi_orders o
            ON (c.ref,c.created,c.days)=(o.ref,o.created,o.days) WHERE o.ref IS NULL)`).Scan(&singleton, &history, &orders, &links); err != nil {
		return errDatabase
	}
	if !singleton {
		return errors.New("missing or invalid PostgreSQL configuration singleton")
	}
	if !history {
		return errors.New("invalid PostgreSQL migration timestamp")
	}
	if !orders || !links {
		return errors.New("incomplete PostgreSQL order and card relationships")
	}
	if _, err := readPlans(ctx, tx); err != nil {
		return errors.New("invalid or incomplete PostgreSQL fixed plan catalog")
	}
	state, err := readState(ctx, tx, true)
	if err != nil {
		return err
	}
	if err = validateState(state); err != nil {
		return fmt.Errorf("invalid PostgreSQL business records: %w", err)
	}
	accounts, err := readAccounts(ctx, tx)
	if err != nil {
		return err
	}
	if len(accounts.members) > 100 {
		return errors.New("invalid PostgreSQL member count")
	}
	for _, rev := range accounts.revisions {
		if rev <= 0 || rev > accounts.revision {
			return errors.New("invalid PostgreSQL account revision")
		}
	}
	var sessionsOK bool
	if tx.QueryRowContext(ctx, `SELECT NOT EXISTS (
        SELECT FROM chezhi_sessions s LEFT JOIN chezhi_members m ON m.name=s.principal
        LEFT JOIN chezhi_owner o ON o.singleton AND s.principal='admin'
        WHERE NOT isfinite(s.expires) OR (s.principal='admin' AND o.revision IS DISTINCT FROM s.revision)
        OR (s.principal<>'admin' AND (m.disabled IS DISTINCT FROM false OR m.revision IS DISTINCT FROM s.revision OR m.role IS DISTINCT FROM s.role))
    )`).Scan(&sessionsOK) != nil {
		return errDatabase
	}
	if !sessionsOK {
		return errors.New("invalid PostgreSQL session ownership or revision")
	}
	if includeImport {
		var valid bool
		if err := tx.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM chezhi_import
            WHERE fingerprint !~ '^[0-9a-f]{64}$' OR NOT isfinite(imported_at)
              OR (SELECT accounts_revision FROM chezhi_config WHERE singleton)<1)`).Scan(&valid); err != nil {
			return errDatabase
		}
		if !valid {
			return errors.New("invalid PostgreSQL import marker")
		}
	}
	return nil
}

func verifyMigratorRole(ctx context.Context, tx *sql.Tx) error {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT has_schema_privilege('public','CREATE')
      AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND relname IN
        ('chezhi_schema','chezhi_config','chezhi_orders','chezhi_cards','chezhi_audit','chezhi_plans',
         'chezhi_members','chezhi_owner','chezhi_import','chezhi_sessions','chezhi_rate_limits','chezhi_cards_position_seq','chezhi_audit_position_seq')
        AND NOT pg_has_role(current_user,c.relowner,'USAGE'))
      AND EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
        WHERE n.nspname='public' AND t.typname='chezhi_instant' AND pg_has_role(current_user,t.typowner,'USAGE'))`).Scan(&ok); err != nil {
		return errDatabase
	}
	if !ok {
		return errors.New("PostgreSQL migration role lacks schema ownership or creation rights")
	}
	return nil
}

func verifyRuntimeRole(ctx context.Context, tx *sql.Tx) error {
	var limited bool
	if err := tx.QueryRowContext(ctx, `SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
        AND has_schema_privilege('public','USAGE')
        AND NOT has_schema_privilege('public','CREATE')
        AND NOT has_database_privilege(current_database(),'CREATE')
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=pg_roles.oid)
        AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='public' AND c.relname IN
            ('chezhi_schema','chezhi_config','chezhi_orders','chezhi_cards','chezhi_audit','chezhi_plans',
             'chezhi_members','chezhi_owner','chezhi_import','chezhi_sessions','chezhi_rate_limits','chezhi_cards_position_seq','chezhi_audit_position_seq')
            AND pg_has_role(current_user,c.relowner,'USAGE'))
        FROM pg_roles WHERE rolname=current_user`).Scan(&limited); err != nil {
		return errDatabase
	}
	if !limited {
		return errors.New("PostgreSQL runtime role has owner or administrative privileges")
	}
	var privileges bool
	if err := tx.QueryRowContext(ctx, `
        WITH expected(rel, can_select, can_insert, can_delete, updates) AS (VALUES
            ('chezhi_schema', true, false, false, ARRAY[]::text[]),
            ('chezhi_config', true, false, false, ARRAY['qq','accounts_revision']),
            ('chezhi_orders', true, true, false, ARRAY[]::text[]),
            ('chezhi_cards', true, true, false, ARRAY['activated','expires','device','revoked']),
            ('chezhi_audit', true, true, false, ARRAY[]::text[]),
            ('chezhi_plans', true, false, false, ARRAY['cents','visible']),
            ('chezhi_members', true, true, false, ARRAY['role','digest','disabled','revision']),
            ('chezhi_owner', true, true, false, ARRAY['version','salt','digest','revision']),
            ('chezhi_import', false, false, false, ARRAY[]::text[]),
            ('chezhi_sessions', true, true, true, ARRAY[]::text[]),
            ('chezhi_rate_limits', true, true, true, ARRAY['used'])
        )
        SELECT NOT EXISTS (
            SELECT 1 FROM expected e, LATERAL (SELECT to_regclass('public.' || e.rel) AS oid) c
            WHERE c.oid IS NULL OR has_table_privilege(c.oid,'SELECT') <> e.can_select
               OR has_table_privilege(c.oid,'INSERT') <> e.can_insert
               OR has_table_privilege(c.oid,'DELETE') <> e.can_delete
               OR has_table_privilege(c.oid,'TRUNCATE,TRIGGER,REFERENCES,MAINTAIN')
               OR EXISTS (
                   SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
                   AND (has_column_privilege(c.oid,a.attname,'UPDATE') <> (a.attname=ANY(e.updates))
                     OR has_column_privilege(c.oid,a.attname,'INSERT') <> e.can_insert
                     OR has_column_privilege(c.oid,a.attname,'SELECT') <> e.can_select
                     OR has_column_privilege(c.oid,a.attname,'REFERENCES'))
               )
        ) AND NOT EXISTS (
            SELECT 1 FROM unnest(ARRAY['public.chezhi_cards_position_seq','public.chezhi_audit_position_seq']) s(name)
            WHERE NOT has_sequence_privilege(s.name,'USAGE') OR has_sequence_privilege(s.name,'SELECT,UPDATE')
        )`).Scan(&privileges); err != nil {
		return errDatabase
	}
	if !privileges {
		return errors.New("PostgreSQL runtime privileges do not match the documented grants")
	}
	return nil
}
