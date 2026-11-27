package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"
	"unicode/utf8"
)

type legacyData struct {
	state       State
	plans       []Plan
	members     map[string]Member
	owner       *ownerCredential
	fingerprint string
}

func legacyFingerprint(dir string) (string, error) {
	hash := sha256.New()
	files := 0
	for _, name := range []string{"state.json", "plans.json", "members.json", "owner.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("cannot read %s", name)
		}
		if !utf8.Valid(b) {
			return "", fmt.Errorf("%s contains invalid UTF-8", name)
		}
		files++
		sum := sha256.Sum256(b)
		fmt.Fprintf(hash, "%s:%x\n", name, sum)
	}
	if files == 0 {
		return "", errors.New("no legacy JSON files found")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func loadLegacy(dir string) (legacyData, error) {
	var d legacyData
	if _, err := os.Stat(filepath.Join(dir, "instance.lock")); !errors.Is(err, os.ErrNotExist) {
		return d, errors.New("legacy source must be stopped and accessible")
	}
	fingerprint, err := legacyFingerprint(dir)
	if err != nil {
		return d, err
	}
	s, err := openStore(filepath.Join(dir, "state.json"))
	if err != nil {
		return d, errors.New("legacy state.json or plans.json validation failed")
	}
	g := newAdminGateway(Web{s, "", "", ""})
	if g.loadErr != nil {
		return d, errors.New("legacy members.json or owner.json validation failed")
	}
	after, err := legacyFingerprint(dir)
	if err != nil || after != fingerprint {
		return d, errors.New("legacy files changed during preflight")
	}
	for i := range s.state.Cards {
		c := &s.state.Cards[i]
		c.Created = c.Created.UTC()
		if !validPostgresInstant(c.Created) {
			return d, errors.New("card creation time outside PostgreSQL import range")
		}
		if c.Activated != nil {
			t := c.Activated.UTC()
			if !validPostgresInstant(t) {
				return d, errors.New("activation time outside PostgreSQL import range")
			}
			c.Activated = &t
		}
		if c.Expires != nil {
			t := c.Expires.UTC()
			if !validPostgresInstant(t) {
				return d, errors.New("expiry outside PostgreSQL import range")
			}
			c.Expires = &t
		}
	}
	for i := range s.state.Audit {
		s.state.Audit[i].At = s.state.Audit[i].At.UTC()
		if !validPostgresInstant(s.state.Audit[i].At) {
			return d, errors.New("audit timestamp outside PostgreSQL import range")
		}
	}
	return legacyData{s.state, s.plans, g.members, g.owner, fingerprint}, nil
}

func validPostgresInstant(t time.Time) bool { return t.Year() >= 1 && t.Year() <= 9999 }

func (p *postgresStore) importLegacy(ctx context.Context, d legacyData) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return p.runTransaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sql.Tx) error {
		if err := dbExec(ctx, tx, "SELECT pg_advisory_xact_lock(39184272002)"); err != nil {
			return err
		}
		var fingerprint string
		err := tx.QueryRowContext(ctx, "SELECT fingerprint FROM chezhi_import WHERE singleton").Scan(&fingerprint)
		switch {
		case err == nil && fingerprint == d.fingerprint:
			return errors.New("this legacy snapshot was already imported")
		case err == nil:
			return errors.New("a different legacy snapshot was already imported")
		case !errors.Is(err, sql.ErrNoRows):
			return errDatabase
		}
		var empty bool
		if err := tx.QueryRowContext(ctx, `SELECT NOT (EXISTS (SELECT 1 FROM chezhi_orders)
            OR EXISTS (SELECT 1 FROM chezhi_audit) OR EXISTS (SELECT 1 FROM chezhi_owner)
            OR EXISTS (SELECT 1 FROM chezhi_members) OR EXISTS (SELECT 1 FROM chezhi_plans WHERE cents IS NOT NULL OR NOT visible)
            OR EXISTS (SELECT 1 FROM chezhi_config WHERE qq <> '----------' OR accounts_revision<>0))`).Scan(&empty); err != nil {
			return errDatabase
		}
		if !empty {
			return errors.New("target PostgreSQL database already contains business data")
		}
		orders := map[string]bool{}
		for _, c := range d.state.Cards {
			if !orders[c.SaleRef] {
				if err := insertOrder(ctx, tx, c); err != nil {
					return err
				}
				orders[c.SaleRef] = true
			}
			if err := insertCard(ctx, tx, c); err != nil {
				return err
			}
		}
		for _, a := range d.state.Audit {
			if err := appendAudit(ctx, tx, a); err != nil {
				return err
			}
		}
		if err := writePlans(ctx, tx, d.plans); err != nil {
			return err
		}
		if err := dbExec(ctx, tx, "UPDATE chezhi_config SET qq=$1,accounts_revision=1 WHERE singleton", d.state.QQ); err != nil {
			return err
		}
		for _, m := range d.members {
			if err := writeMember(ctx, tx, m, 1); err != nil {
				return err
			}
		}
		if d.owner != nil {
			if err := writeOwner(ctx, tx, *d.owner, 1); err != nil {
				return err
			}
		}
		state, err := readState(ctx, tx, true)
		if err != nil {
			return err
		}
		plans, err := readPlans(ctx, tx)
		if err != nil {
			return err
		}
		accounts, err := readAccounts(ctx, tx)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(state, clone(d.state)) || !reflect.DeepEqual(plans, d.plans) ||
			!reflect.DeepEqual(accounts.members, d.members) || !reflect.DeepEqual(accounts.owner, d.owner) {
			return errors.New("legacy reconciliation failed")
		}
		return dbExec(ctx, tx, "INSERT INTO chezhi_import(fingerprint) VALUES ($1)", d.fingerprint)
	})
}
func databaseCommand(ctx context.Context, args []string) error {
	command := args[0]
	var d legacyData
	if command == "db-import" {
		if len(args) != 3 || (args[1] != "--dry-run" && args[1] != "--apply") {
			return errors.New("usage: db-import --dry-run|--apply <legacy-dir>")
		}
		var err error
		d, err = loadLegacy(args[2])
		if err != nil {
			return err
		}
		fmt.Printf("Validated legacy snapshot: cards=%d audit=%d plans=%d members=%d owner=%t\n",
			len(d.state.Cards), len(d.state.Audit), len(d.plans), len(d.members), d.owner != nil)
		if args[1] == "--dry-run" {
			return nil
		}
	} else if len(args) != 1 {
		return errors.New("unexpected database command arguments")
	}
	p, err := openPostgres(ctx, os.Getenv("CHEZHI_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer p.db.Close()
	switch command {
	case "db-init":
		err = p.migrate(ctx)
	case "db-check":
		err = p.checkSchema(ctx)
	case "db-import":
		if err = p.checkSchema(ctx); err == nil {
			err = p.importLegacy(ctx, d)
		}
	}
	if err == nil {
		fmt.Println(command + " completed")
	}
	return err
}
