package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

func postgresFixture(t *testing.T) (*Store, string) {
	t.Helper()
	base := os.Getenv("CHEZHI_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("CHEZHI_TEST_DATABASE_URL required for real PostgreSQL")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "postgres" || u.Host == "" {
		t.Fatal("expected a postgres:// test URL")
	}
	admin, err := openPostgres(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.db.Close() })
	name := "chezhi_test_" + randomToken()[:16]
	if _, err = admin.db.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal("test database creation failed")
	}
	t.Cleanup(func() {
		if _, err := admin.db.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); err != nil {
			t.Error("test database cleanup failed")
		}
	})
	u.Path = "/" + name
	p, err := openPostgres(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.db.Close() })
	return &Store{pg: p, now: time.Now}, u.String()
}
func pgExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.pg.db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}
func pgSnapshot(t *testing.T, s *Store) State {
	t.Helper()
	state, _, err := s.readView(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func pgInitialize(t *testing.T, s *Store) {
	t.Helper()
	if err := s.pg.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresConcurrencyAndRollback(t *testing.T) {
	s, dsn := postgresFixture(t)
	ctx := context.Background()
	if s.pg.checkSchema(ctx) == nil {
		t.Fatal("accepted uninitialized schema")
	}
	pgInitialize(t, s)
	other, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.db.Close()
	peer := &Store{pg: other, now: time.Now}
	const workers = 24
	keys := make([]string, workers)
	errs := make([]error, workers)
	run := func(f func(int)) {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); <-start; f(i) }(i)
		}
		close(start)
		wg.Wait()
	}
	run(func(i int) {
		store := []*Store{s, peer}[i%2]
		result, err := store.issue(7, 1, 159, "test", "racing-order", "admin")
		errs[i] = err
		if len(result) == 1 {
			keys[i] = result[0]
		}
	})
	var raw string
	for i, err := range errs {
		if err == nil && raw == "" && keys[i] != "" {
			raw = keys[i]
		} else if !errors.Is(err, errOrderExists) || keys[i] != "" {
			t.Fatalf("duplicate protection: %v", err)
		}
	}
	if raw == "" {
		t.Fatal("no issuing winner")
	}
	winners := make([]bool, workers)
	run(func(i int) {
		result, err := []*Store{s, peer}[i%2].validate(raw, fmt.Sprintf("device-%d", i))
		errs[i] = err
		winners[i] = result.Valid
		if err == nil && !result.Valid && result.Reason != "device_mismatch" {
			errs[i] = fmt.Errorf("unexpected %s", result.Reason)
		}
	})
	count := 0
	for i, win := range winners {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if win {
			count++
		}
	}
	before := pgSnapshot(t, s)
	c := before.Cards[0]
	if count != 1 || len(before.Cards) != 1 || len(before.Audit) != 2 || c.Activated == nil ||
		c.Expires == nil || c.Expires.Sub(*c.Activated) != 7*24*time.Hour {
		t.Fatal("inconsistent first activation")
	}
	if err := s.changeBatch([]string{c.ID, strings.Repeat("0", 24)}, "unbind", "admin"); err == nil {
		t.Fatal("missing batch ID accepted")
	}
	pgExec(t, s, "ALTER TABLE chezhi_audit ADD CONSTRAINT reject_actions CHECK (action NOT IN ('issue','unbind','plans_config','member-create','password_changed')) NOT VALID")
	if result, err := s.issue(30, 2, 1, "test", "failed-order", "admin"); err == nil || len(result) != 0 {
		t.Fatal("uncommitted card returned")
	}
	if err := s.change(c.ID, "unbind", "admin"); err == nil {
		t.Fatal("batch audit rollback missing")
	}
	g := newAdminGateway(Web{s, "temp", "", ""})
	if secret, err := g.updateMember("viewer1", "viewer", "member-create"); err == nil || secret != "" {
		t.Fatal("member rollback missing")
	}
	if err := g.saveOwner("synthetic password 123"); err == nil {
		t.Fatal("owner rollback missing")
	}
	plans := url.Values{}
	for _, p := range defaultPlans() {
		plans.Set(fmt.Sprintf("price_%d", p.Days), "123")
	}
	if err := s.savePlans(plans); err == nil {
		t.Fatal("plan rollback missing")
	}
	after := pgSnapshot(t, s)
	accounts, err := s.pg.accounts(ctx)
	if err != nil || accounts.owner != nil || len(accounts.members) != 0 || accounts.revision != 0 || !reflect.DeepEqual(before, after) {
		t.Fatal("failed write changed persisted data")
	}
	_, actualPlans, err := s.readView(ctx, false)
	if err != nil || !reflect.DeepEqual(actualPlans, defaultPlans()) {
		t.Fatal("plan rollback failed")
	}
	pgExec(t, s, "ALTER TABLE chezhi_audit DROP CONSTRAINT reject_actions")
	if _, err := s.issue(1, 1, 0, "test", "failed-order", "admin"); err != nil {
		t.Fatal("order did not roll back", err)
	}
	if err := s.change(c.ID, "unbind", "admin"); err != nil {
		t.Fatal(err)
	}
	if result, err := s.validate(raw, "new-device"); err != nil || !result.Valid {
		t.Fatal("rebind failed", err)
	}
	if err := s.change(c.ID, "revoke", "admin"); err != nil {
		t.Fatal(err)
	}
	if result, err := peer.validate(raw, "new-device"); err != nil || result.Reason != "revoked" {
		t.Fatal("revoke failed", err)
	}
	pgInitialize(t, peer)
	restarted, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.db.Close()
	if !reflect.DeepEqual(pgSnapshot(t, s), pgSnapshot(t, &Store{pg: restarted, now: time.Now})) {
		t.Fatal("restart changed state")
	}
	if got := s.pg.db.Stats().InUse; got != 0 {
		t.Fatalf("leaked %d connections", got)
	}
}

func TestPostgresLegacyImport(t *testing.T) {
	pg, _ := postgresFixture(t)
	pgInitialize(t, pg)
	dir := t.TempDir()
	jsonStore, err := openStore(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2025, 1, 1, 0, 0, 0, 123456789, time.UTC)
	jsonStore.now = func() time.Time { return now }
	keys, err := jsonStore.issue(7, 4, 987, "wechat", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	permanent, err := jsonStore.issue(0, 1, 0, "test", "permanent")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{keys[0], keys[1], keys[2], permanent[0]} {
		if result, err := jsonStore.validate(key, "device"); err != nil || !result.Valid {
			t.Fatal(err)
		}
	}
	cards := jsonStore.snapshot().Cards
	if err := jsonStore.change(cards[1].ID, "unbind"); err != nil {
		t.Fatal(err)
	}
	if err := jsonStore.change(cards[2].ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	if err := jsonStore.setQQ("123456"); err != nil {
		t.Fatal(err)
	}
	g := newAdminGateway(Web{jsonStore, "temp", "", ""})
	secret, err := g.updateMember("member1", "operator", "member-create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.updateMember("disabled1", "viewer", "member-create"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.updateMember("disabled1", "", "member-disable"); err != nil {
		t.Fatal(err)
	}
	if err := g.saveOwner("synthetic migration password"); err != nil {
		t.Fatal(err)
	}
	plans := url.Values{}
	for _, p := range defaultPlans() {
		plans.Set(fmt.Sprintf("price_%d", p.Days), "1.23")
	}
	if err := jsonStore.savePlans(plans); err != nil {
		t.Fatal(err)
	}
	d, err := loadLegacy(dir)
	if err != nil {
		t.Fatal(err)
	}
	pgExec(t, pg, "ALTER TABLE chezhi_audit ADD CONSTRAINT reject_legacy CHECK (false) NOT VALID")
	if err := pg.pg.importLegacy(context.Background(), d); err == nil || len(pgSnapshot(t, pg).Cards) != 0 {
		t.Fatal("failed import left data")
	}
	pgExec(t, pg, "ALTER TABLE chezhi_audit DROP CONSTRAINT reject_legacy")
	if err := pg.pg.importLegacy(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if err := pg.pg.importLegacy(context.Background(), d); err == nil {
		t.Fatal("duplicate import accepted")
	}
	after, err := legacyFingerprint(dir)
	if err != nil || after != d.fingerprint {
		t.Fatal("source changed")
	}
	imported := newAdminGateway(Web{pg, "other", "", ""})
	if role, ok := imported.authenticate("member1", secret); !ok || role != "operator" ||
		!imported.verifyOwner("synthetic migration password") || !imported.members["disabled1"].Disabled {
		t.Fatal("credential migration failed")
	}
	now = now.Add(8 * 24 * time.Hour)
	pg.now = jsonStore.now
	for _, key := range append(keys, permanent...) {
		a, e := jsonStore.validate(key, "device")
		b, f := pg.validate(key, "device")
		if e != nil || f != nil || !reflect.DeepEqual(a, b) {
			t.Fatal("backend activation behavior differed", e, f)
		}
	}
	if !reflect.DeepEqual(pgSnapshot(t, pg), jsonStore.snapshot()) {
		t.Fatal("backend states differed")
	}
	if b, err := pg.backup(); err != nil || len(b) == 0 {
		t.Fatal("business archive failed", err)
	}
}

func TestPostgresSessionsAndReconnect(t *testing.T) {
	s, dsn := postgresFixture(t)
	pgInitialize(t, s)
	ctx := context.Background()
	other, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.db.Close()
	g := newAdminGateway(Web{s, "bootstrap", "csrf-a", "localhost"})
	peer := newAdminGateway(Web{&Store{pg: other, now: time.Now}, "bootstrap-peer", "csrf-b", "localhost"})
	call := func(g *adminGateway, method, path string, f url.Values, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(f.Encode()))
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c != nil {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		g.ServeHTTP(w, r)
		return w
	}
	login := func(g *adminGateway, user, password string) *http.Cookie {
		w := call(g, "POST", "/login", url.Values{"username": {user}, "password": {password}, "login_csrf": {g.loginToken()}}, nil)
		if w.Code != 303 || len(w.Result().Cookies()) != 1 {
			t.Fatalf("login failed: %d", w.Code)
		}
		return w.Result().Cookies()[0]
	}
	owner := login(g, "admin", "bootstrap")
	secret, err := g.updateMember("operator1", "operator", "member-create")
	if err != nil {
		t.Fatal(err)
	}
	member := login(peer, "operator1", secret)
	if call(peer, "GET", "/?view=issue", nil, member).Code != 200 {
		t.Fatal("operator initially denied")
	}
	f := url.Values{"csrf": {g.sessions[owner.Value].csrf}, "name": {"operator1"}, "role": {"viewer"}, "action": {"member-role"}}
	if call(g, "POST", "/members", f, owner).Code != 200 || call(peer, "GET", "/?view=issue", nil, member).Code != 303 {
		t.Fatal("old peer session not revoked")
	}
	member = login(peer, "operator1", secret)
	if call(peer, "GET", "/?view=issue", nil, member).Code != 403 {
		t.Fatal("updated role not enforced")
	}
	// An admin mutation authorized before the role change must fail at commit.
	stale := context.WithValue(ctx, accountRevisionKey{}, int64(1))
	if keys, err := s.issueContext(stale, 1, 1, 0, "test", "stale-role", "operator1"); !errors.Is(err, errAccountChanged) || len(keys) != 0 {
		t.Fatal("stale authorization committed an order", err)
	}
	peerOwner := login(peer, "admin", "bootstrap-peer")
	rotated := "synthetic rotated password 42"
	form := url.Values{"csrf": {g.sessions[owner.Value].csrf}, "current_password": {"bootstrap"},
		"new_password": {rotated}, "confirm_password": {rotated}}
	if call(g, "POST", "/account/password", form, owner).Code != 303 ||
		call(peer, "GET", "/?view=account", nil, peerOwner).Code != 303 {
		t.Fatal("owner rotation did not invalidate prior sessions")
	}
	newOwner := login(peer, "admin", rotated)
	if call(peer, "GET", "/?view=account", nil, newOwner).Code != 200 {
		t.Fatal("rotated credential unavailable on peer")
	}
	audit := pgSnapshot(t, s).Audit
	var changed int
	for _, entry := range audit {
		if entry.Action == "password_changed" && entry.Actor == "admin" {
			changed++
		}
	}
	if changed != 1 {
		t.Fatal("owner rotation audit missing or duplicated")
	}
	// Terminate a connection with an in-flight write and verify rollback and recovery.
	conn, err := s.pg.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&pid) != nil {
		t.Fatal("pid unavailable")
	}
	if err := insertOrder(ctx, tx, Card{SaleRef: "disconnect", Channel: "test", Created: time.Now()}); err != nil {
		t.Fatal(err)
	}
	pgExec(t, &Store{pg: other}, "SELECT pg_terminate_backend($1,5000)", pid)
	if tx.Commit() == nil {
		t.Fatal("wrongly acknowledged disconnected transaction")
	}
	conn.Close()
	if _, err := s.issue(1, 1, 0, "test", "disconnect"); err != nil {
		t.Fatal("pool did not recover after disconnection", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if keys, err := s.issueContext(cancelled, 1, 1, 0, "test", "cancelled"); err == nil || len(keys) != 0 {
		t.Fatal("cancelled request wrote a card")
	}
	if s.pg.db.Stats().InUse != 0 {
		t.Fatal("connection leak")
	}
}

func TestPostgresLoad(t *testing.T) {
	s, _ := postgresFixture(t)
	pgInitialize(t, s)
	const cards = 2000
	const concurrency = 16
	const samples = 320
	keys := make([]string, 0, cards)
	for i := 0; i < cards/100; i++ {
		batch, err := s.issue(30, 100, 25, "test", fmt.Sprintf("load-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, batch...)
	}
	durations := make([]time.Duration, samples)
	outcomes := make([]string, samples)
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < samples; i += concurrency {
				start := time.Now()
				result, err := s.validate(keys[i], "load-device")
				durations[i] = time.Since(start)
				if err != nil {
					outcomes[i] = "storage_error"
				} else if !result.Valid {
					outcomes[i] = result.Reason
				} else {
					outcomes[i] = "success"
				}
			}
		}(worker)
	}
	wg.Wait()
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	counts := map[string]int{}
	for _, status := range outcomes {
		counts[status]++
	}
	stats := s.pg.db.Stats()
	t.Logf("cards=%d workers=%d requests=%d outcomes=%v p50=%s p95=%s p99=%s pool_max=%d open=%d idle=%d in_use=%d waits=%d",
		cards, concurrency, samples, counts, durations[samples*50/100-1], durations[samples*95/100-1], durations[(samples*99+99)/100-1],
		stats.MaxOpenConnections, stats.OpenConnections, stats.Idle, stats.InUse, stats.WaitCount)
	state := pgSnapshot(t, s)
	if counts["success"] != samples || stats.InUse != 0 || len(state.Cards) != cards || len(state.Audit) != cards+samples ||
		validateState(state) != nil {
		t.Fatal("load consistency failed")
	}
}

func TestPostgresUpgradeExisting(t *testing.T) {
	store, _ := postgresFixture(t)
	pgExec(t, store, "CREATE TABLE chezhi_schema(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())")
	pgExec(t, store, postgresV1)
	pgExec(t, store, "INSERT INTO chezhi_schema(version) VALUES (1)")
	if _, err := store.issue(7, 2, 450, "test", "existing-v1"); err != nil {
		t.Fatal(err)
	}
	before := pgSnapshot(t, store)
	if store.pg.checkSchema(context.Background()) == nil {
		t.Fatal("outdated schema accepted")
	}
	pgInitialize(t, store)
	if err := store.pg.checkSchema(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, pgSnapshot(t, store)) {
		t.Fatal("upgrade changed business records")
	}
	var count int
	if err := store.pg.db.QueryRow("SELECT count(*) FROM pg_indexes WHERE indexname IN ('chezhi_cards_order_idx','chezhi_audit_card_idx')").Scan(&count); err != nil || count != 2 {
		t.Fatal("upgrade indexes absent", err)
	}
}
