package main

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

//go:embed postgres_v1.sql
var postgresV1 string

//go:embed postgres_v2.sql
var postgresV2 string

//go:embed postgres_v3.sql
var postgresV3 string

//go:embed postgres_v4.sql
var postgresV4 string

//go:embed postgres_v5.sql
var postgresV5 string

var postgresMigrations = []string{postgresV1, postgresV2, postgresV3, postgresV4, postgresV5}

var errCommitUnknown = errors.New("database commit result unknown")

var errDatabase = errors.New("database operation failed")
var errOrderExists = errors.New("sale reference already issued")
var errAccountChanged = errors.New("account configuration changed; retry")

type postgresStore struct {
	db         *sql.DB
	deployment *deploymentLease
}

func openPostgres(ctx context.Context, dsn string) (*postgresStore, error) {
	if dsn == "" {
		return nil, errors.New("CHEZHI_DATABASE_URL is required")
	}
	cfg, err := pq.NewConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL configuration")
	}
	cfg.ConnectTimeout = 3 * time.Second
	cfg.Options += " -c search_path=public -c timezone=UTC -c statement_timeout=8000 -c lock_timeout=5000 -c idle_in_transaction_session_timeout=10000"
	connector, err := pq.NewConnectorConfig(cfg)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL configuration")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, errDatabase
	}
	return &postgresStore{db: db}, nil
}

func (p *postgresStore) transaction(ctx context.Context, opts *sql.TxOptions, f func(context.Context, *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return p.runTransaction(ctx, opts, f)
}

func (p *postgresStore) runTransaction(ctx context.Context, opts *sql.TxOptions, f func(context.Context, *sql.Tx) error) error {
	tx, err := p.db.BeginTx(ctx, opts)
	if err != nil {
		return errDatabase
	}
	defer tx.Rollback()
	if p.deployment != nil {
		// The dedicated lease normally excludes offline operations. A write
		// also holds its own transaction lock, including after a pool reconnect.
		if opts == nil || !opts.ReadOnly {
			var acquired bool
			if tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock_shared($1)", deploymentLock).Scan(&acquired) != nil || !acquired {
				return errDeployment
			}
		}
		if err := p.checkDeployment(ctx, tx); err != nil {
			return err
		}
	}
	if opts == nil {
		if err := dbExec(ctx, tx, "SELECT pg_advisory_xact_lock_shared(39184272002)"); err != nil {
			return err
		}
	}
	if err := f(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		var server *pq.Error
		if (opts == nil || !opts.ReadOnly) &&
			(!errors.As(err, &server) || server.Code.Class() == "08" || server.Code == "40003" || server.Severity == "FATAL") {
			return errCommitUnknown
		}
		return errDatabase
	}
	return nil
}

func (p *postgresStore) migrate(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return p.runTransaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sql.Tx) error {
		var acquired bool
		if tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", deploymentLock).Scan(&acquired) != nil {
			return errDatabase
		}
		if !acquired {
			return errors.New("PostgreSQL deployment is online; stop every instance before migrating")
		}

		if err := dbExec(ctx, tx, `SELECT pg_advisory_xact_lock(39184272002);
            CREATE TABLE IF NOT EXISTS chezhi_schema (version integer PRIMARY KEY CHECK(version>0),
            applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`); err != nil {
			return err
		}
		version, err := schemaVersion(ctx, tx)
		if err != nil {
			return err
		}
		for version < len(postgresMigrations) {
			if err := dbExec(ctx, tx, postgresMigrations[version]); err != nil {
				return fmt.Errorf("PostgreSQL migration %d failed: %w", version+1, err)
			}
			version++
			if err := dbExec(ctx, tx, "INSERT INTO chezhi_schema(version) VALUES ($1)", version); err != nil {
				return err
			}
		}
		return nil
	})
}

type rowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func schemaVersion(ctx context.Context, db rowQueryer) (int, error) {
	var version, count, minimum int
	if err := db.QueryRowContext(ctx, "SELECT coalesce(max(version),0),count(*),coalesce(min(version),1) FROM chezhi_schema").Scan(&version, &count, &minimum); err != nil {
		return 0, errDatabase
	}
	if version != count || minimum != 1 || version > len(postgresMigrations) {
		return 0, errors.New("unsupported PostgreSQL schema history")
	}
	return version, nil
}

func (p *postgresStore) checkSchema(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if version, err := schemaVersion(ctx, p.db); err != nil || version != len(postgresMigrations) {
		return errors.New("PostgreSQL schema unavailable or unsupported; run db-init")
	}
	return nil
}

const utcEpochOffset = 62135596800

func sqlTime(t time.Time) string {
	return fmt.Sprintf("%d.%09d", t.Unix()+utcEpochOffset, t.Nanosecond())
}
func sqlOptionalTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return sqlTime(*t)
}
func parseSQLTime(s string) (time.Time, error) {
	seconds, fraction, ok := strings.Cut(s, ".")
	sec, err := strconv.ParseInt(seconds, 10, 64)
	if err != nil || !ok || len(fraction) != 9 {
		return time.Time{}, errDatabase
	}
	ns, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return time.Time{}, errDatabase
	}
	return time.Unix(sec-utcEpochOffset, ns).UTC(), nil
}
func parseOptionalTime(s sql.NullString) (*time.Time, error) {
	if !s.Valid {
		return nil, nil
	}
	t, err := parseSQLTime(s.String)
	return &t, err
}

const selectCards = `SELECT c.id,c.hash,c.prefix,c.days,c.ref,o.channel,o.cents,c.created,c.activated,c.expires,c.device,c.revoked
FROM chezhi_cards c JOIN chezhi_orders o ON o.ref=c.ref`

func queryCards(ctx context.Context, tx *sql.Tx, suffix string, args ...any) ([]Card, error) {
	rows, err := tx.QueryContext(ctx, selectCards+suffix, args...)
	if err != nil {
		return nil, errDatabase
	}
	defer rows.Close()
	var out []Card
	for rows.Next() {
		var c Card
		var created string
		var activated, expires sql.NullString
		if err = rows.Scan(&c.ID, &c.Hash, &c.Prefix, &c.Days, &c.SaleRef, &c.Channel, &c.AmountCents, &created, &activated, &expires, &c.Device, &c.Revoked); err != nil {
			return nil, errDatabase
		}
		if c.Created, err = parseSQLTime(created); err != nil {
			return nil, err
		}
		if c.Activated, err = parseOptionalTime(activated); err != nil {
			return nil, err
		}
		if c.Expires, err = parseOptionalTime(expires); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, errDatabase
	}
	return out, nil
}

func insertOrder(ctx context.Context, tx *sql.Tx, c Card) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO chezhi_orders (ref,channel,cents,days,created)
        VALUES ($1,$2,$3,$4,$5) ON CONFLICT (ref) DO NOTHING`, c.SaleRef, c.Channel, c.AmountCents, c.Days, sqlTime(c.Created))
	if err != nil {
		return errDatabase
	}
	n, err := result.RowsAffected()
	if err != nil {
		return errDatabase
	}
	if n != 1 {
		return errOrderExists
	}
	return nil
}
func insertCard(ctx context.Context, tx *sql.Tx, c Card) error {
	return dbExec(ctx, tx, `INSERT INTO chezhi_cards (id,hash,prefix,ref,created,days,activated,expires,device,revoked)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, c.ID, c.Hash, c.Prefix, c.SaleRef, sqlTime(c.Created), c.Days, sqlOptionalTime(c.Activated), sqlOptionalTime(c.Expires), c.Device, c.Revoked)
}
func appendAudit(ctx context.Context, tx *sql.Tx, a Audit) error {
	return dbExec(ctx, tx, `INSERT INTO chezhi_audit(occurred,action,card_id,actor,target) VALUES ($1,$2,nullif($3,''),$4,$5)`,
		sqlTime(a.At), a.Action, a.CardID, a.Actor, a.Target)
}
func dbExec(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return errDatabase
	}
	return nil
}

// Account changes take an exclusive row lock. Authenticated business writes hold
// a shared lock until commit, so a revoked session cannot write after revocation.
type accountRevisionKey struct{}

func lockAccountRevision(ctx context.Context, tx *sql.Tx, exclusive bool) (int64, error) {
	query := "SELECT accounts_revision FROM chezhi_config WHERE singleton FOR SHARE"
	if exclusive {
		query = "SELECT accounts_revision FROM chezhi_config WHERE singleton FOR UPDATE"
	}
	var actual int64
	if err := tx.QueryRowContext(ctx, query).Scan(&actual); err != nil {
		return 0, errDatabase
	}
	if expected, ok := ctx.Value(accountRevisionKey{}).(int64); ok && expected != actual {
		return 0, errAccountChanged
	}
	if digest, ok := ctx.Value(sharedSessionKey{}).(string); ok {
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
            SELECT FROM chezhi_sessions WHERE token_digest=$1 AND expires>clock_timestamp()
        )`, digest).Scan(&active); err != nil {
			return 0, errDatabase
		}
		if !active {
			return 0, errSessionInvalid
		}
	}
	return actual, nil
}

type mutationScope struct {
	order    string
	hash     string
	ids      []string
	support  bool
	readOnly bool
}

func (p *postgresStore) mutate(ctx context.Context, scope mutationScope, apply func(*State) error) error {
	if scope.readOnly {
		return p.transaction(ctx, &sql.TxOptions{ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
			cards, err := queryCards(ctx, tx, " WHERE c.hash=$1", scope.hash)
			if err != nil {
				return err
			}
			return apply(&State{Cards: cards})
		})
	}
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		if _, ok := ctx.Value(accountRevisionKey{}).(int64); ok {
			if _, err := lockAccountRevision(ctx, tx, scope.support); err != nil {
				return err
			}
		}
		var previous State
		var err error
		switch {
		case scope.hash != "":
			previous.Cards, err = queryCards(ctx, tx, " WHERE c.hash=$1 FOR UPDATE OF c", scope.hash)
		case len(scope.ids) > 0:
			previous.Cards, err = queryCards(ctx, tx, " WHERE c.id=ANY($1) ORDER BY c.id FOR UPDATE OF c", pq.Array(scope.ids))
		}
		if err != nil {
			return err
		}
		next := clone(previous)
		if err = apply(&next); err != nil {
			return err
		}
		if scope.order != "" {
			if err = insertOrder(ctx, tx, next.Cards[0]); err != nil {
				return err
			}
			for _, c := range next.Cards {
				if err = insertCard(ctx, tx, c); err != nil {
					return err
				}
			}
		} else {
			for i, c := range next.Cards {
				if c == previous.Cards[i] {
					continue
				}
				if err = dbExec(ctx, tx, `UPDATE chezhi_cards SET activated=$2,expires=$3,device=$4,revoked=$5 WHERE id=$1`,
					c.ID, sqlOptionalTime(c.Activated), sqlOptionalTime(c.Expires), c.Device, c.Revoked); err != nil {
					return err
				}
			}
		}
		if scope.support {
			if err = dbExec(ctx, tx, "UPDATE chezhi_config SET qq=$1 WHERE singleton", next.QQ); err != nil {
				return err
			}
		}
		for _, a := range next.Audit {
			if err = appendAudit(ctx, tx, a); err != nil {
				return err
			}
		}
		return nil
	})
}

func (p *postgresStore) readView(ctx context.Context, full bool) (State, []Plan, error) {
	var state State
	var plans []Plan
	err := p.transaction(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		if state, err = readState(ctx, tx, full); err != nil {
			return err
		}
		plans, err = readPlans(ctx, tx)
		return err
	})
	return state, plans, err
}
func readState(ctx context.Context, tx *sql.Tx, full bool) (State, error) {
	var state State
	if err := tx.QueryRowContext(ctx, "SELECT qq FROM chezhi_config WHERE singleton").Scan(&state.QQ); err != nil {
		return state, errDatabase
	}
	if !full {
		return state, nil
	}
	var err error
	if state.Cards, err = queryCards(ctx, tx, " ORDER BY c.position"); err != nil {
		return state, err
	}
	state.Audit, err = queryAudit(ctx, tx, " ORDER BY position")
	return state, err
}

func queryAudit(ctx context.Context, tx *sql.Tx, suffix string, args ...any) ([]Audit, error) {
	var audit []Audit
	rows, err := tx.QueryContext(ctx, "SELECT occurred,action,coalesce(card_id,''),actor,target FROM chezhi_audit"+suffix, args...)
	if err != nil {
		return nil, errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var occurred string
		var a Audit
		if err := rows.Scan(&occurred, &a.Action, &a.CardID, &a.Actor, &a.Target); err != nil {
			return nil, errDatabase
		}
		if a.At, err = parseSQLTime(occurred); err != nil {
			return nil, err
		}
		audit = append(audit, a)
	}
	if rows.Err() != nil {
		return nil, errDatabase
	}
	return audit, nil
}
func readPlans(ctx context.Context, tx *sql.Tx) ([]Plan, error) {
	rows, err := tx.QueryContext(ctx, "SELECT days,cents,visible FROM chezhi_plans ORDER BY CASE WHEN days=0 THEN 366 ELSE days END")
	if err != nil {
		return nil, errDatabase
	}
	defer rows.Close()
	plans := defaultPlans()
	i := 0
	for rows.Next() {
		var days int
		if i >= len(plans) {
			return nil, errDatabase
		}
		if err := rows.Scan(&days, &plans[i].PriceCents, &plans[i].Visible); err != nil || plans[i].Days != days {
			return nil, errDatabase
		}
		i++
	}
	if rows.Err() != nil || i != len(plans) {
		return nil, errDatabase
	}
	return plans, nil
}
func writePlans(ctx context.Context, tx *sql.Tx, plans []Plan) error {
	for _, p := range plans {
		if err := dbExec(ctx, tx, "UPDATE chezhi_plans SET cents=$2,visible=$3 WHERE days=$1", p.Days, p.PriceCents, p.Visible); err != nil {
			return err
		}
	}
	return nil
}
func (p *postgresStore) savePlans(ctx context.Context, plans []Plan, a Audit) error {
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := lockAccountRevision(ctx, tx, false); err != nil {
			return err
		}
		if err := writePlans(ctx, tx, plans); err != nil {
			return err
		}
		return appendAudit(ctx, tx, a)
	})
}

type accountData struct {
	members   map[string]Member
	revisions map[string]int64
	owner     *ownerCredential
	revision  int64
}

func readAccounts(ctx context.Context, tx *sql.Tx) (accountData, error) {
	a := accountData{members: map[string]Member{}, revisions: map[string]int64{}}
	if err := tx.QueryRowContext(ctx, "SELECT accounts_revision FROM chezhi_config WHERE singleton").Scan(&a.revision); err != nil {
		return a, errDatabase
	}
	var owner ownerCredential
	var revision int64
	err := tx.QueryRowContext(ctx, "SELECT version,salt,digest,revision FROM chezhi_owner WHERE singleton").Scan(&owner.Version, &owner.Salt, &owner.Digest, &revision)
	if err == nil {
		a.owner = &owner
		a.revisions["admin"] = revision
	} else if !errors.Is(err, sql.ErrNoRows) {
		return a, errDatabase
	}
	rows, err := tx.QueryContext(ctx, "SELECT name,role,digest,disabled,revision FROM chezhi_members")
	if err != nil {
		return a, errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.Name, &m.Role, &m.Digest, &m.Disabled, &revision); err != nil {
			return a, errDatabase
		}
		a.members[m.Name] = m
		a.revisions[m.Name] = revision
	}
	if rows.Err() != nil {
		return a, errDatabase
	}
	return a, nil
}

func (p *postgresStore) accounts(ctx context.Context) (accountData, error) {
	var a accountData
	err := p.transaction(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		a, err = readAccounts(ctx, tx)
		return err
	})
	return a, err
}

func writeMember(ctx context.Context, tx *sql.Tx, m Member, revision int64) error {
	return dbExec(ctx, tx, `INSERT INTO chezhi_members(name,role,digest,disabled,revision) VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT(name) DO UPDATE SET role=excluded.role,digest=excluded.digest,disabled=excluded.disabled,revision=excluded.revision`, m.Name, m.Role, m.Digest, m.Disabled, revision)
}
func writeOwner(ctx context.Context, tx *sql.Tx, c ownerCredential, revision int64) error {
	return dbExec(ctx, tx, `INSERT INTO chezhi_owner(version,salt,digest,revision) VALUES ($1,$2,$3,$4)
    ON CONFLICT(singleton) DO UPDATE SET version=excluded.version,salt=excluded.salt,digest=excluded.digest,revision=excluded.revision`, c.Version, c.Salt, c.Digest, revision)
}
func (p *postgresStore) changeAccount(ctx context.Context, a Audit, write func(context.Context, *sql.Tx, int64) error) (int64, error) {
	var revision int64
	err := p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		previous, err := lockAccountRevision(ctx, tx, true)
		if err != nil {
			return err
		}
		revision = previous + 1
		if err := write(ctx, tx, revision); err != nil {
			return err
		}
		name := a.Target
		if name == "" {
			name = a.Actor
		}
		if err := dbExec(ctx, tx, "DELETE FROM chezhi_sessions WHERE principal=$1", name); err != nil {
			return err
		}
		if err := dbExec(ctx, tx, "UPDATE chezhi_config SET accounts_revision=$1 WHERE singleton", revision); err != nil {
			return err
		}
		return appendAudit(ctx, tx, a)
	})
	return revision, err
}
