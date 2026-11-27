package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitPostgresTest(t *testing.T, store *Store, sql string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		var ready bool
		if err := store.pg.db.QueryRow(sql).Scan(&ready); err != nil {
			t.Fatal(err)
		}
		if ready {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("PostgreSQL test barrier was not observed")
}

func TestPostgresLegacySourceLock(t *testing.T) {
	store, dsn := postgresFixture(t)
	pgInitialize(t, store)
	t.Setenv("CHEZHI_DATABASE_URL", dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	lock := filepath.Join(dir, "instance.lock")
	original := []byte(`{"QQ":"123456","Cards":[],"Audit":[]}`)
	changed := []byte(`{"QQ":"654321","Cards":[],"Audit":[]}`)
	write := func(data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	checkSource := func(data []byte) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatal("importer changed the source bytes")
		}
		if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("owned lock was not released")
		}
	}
	apply := func() error { return databaseCommand(ctx, []string{"db-import", "--apply", dir}) }
	write(original)
	if err := databaseCommand(ctx, []string{"db-import", "--dry-run", dir}); err != nil {
		t.Fatal(err)
	}
	checkSource(original)
	_, release, err := openLocalRuntime([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(); err == nil {
		release()
		t.Fatal("import acquired an active JSON lock")
	}
	if _, err := os.Stat(lock); err != nil {
		release()
		t.Fatal("import removed the JSON owner's lock")
	}
	release()
	checkSource(original)

	barrier, err := store.pg.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Rollback()
	if _, err := barrier.Exec("SELECT pg_advisory_xact_lock(39184272002)"); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- apply() }()
	waitPostgresTest(t, store, `SELECT EXISTS (SELECT FROM pg_locks
        WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
          AND NOT granted)`)
	if _, secondRelease, err := openLocalRuntime([]string{dir}); err == nil {
		secondRelease()
		t.Fatal("old JSON startup acquired the importer's lock")
	}
	if err := apply(); err == nil {
		t.Fatal("second import acquired the source lock")
	}
	write(changed) // Simulate a non-cooperating writer bypassing the sentinel.
	if err := barrier.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "legacy files changed") {
			t.Fatalf("unexpected result: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	checkSource(changed)
	var count int
	if err := store.pg.db.QueryRow("SELECT count(*) FROM chezhi_import").Scan(&count); err != nil ||
		count != 0 || pgSnapshot(t, store).QQ != "----------" {
		t.Fatal("changed source committed database data", err)
	}

	pgExec(t, store, "ALTER TABLE chezhi_import ADD CONSTRAINT reject_import CHECK (false) NOT VALID")
	if err := apply(); err == nil {
		t.Fatal("injected SQL import failure passed")
	}
	checkSource(changed)
	pgExec(t, store, "ALTER TABLE chezhi_import DROP CONSTRAINT reject_import")
	if err := apply(); err != nil {
		t.Fatal(err)
	}
	checkSource(changed)
	if pgSnapshot(t, store).QQ != "654321" {
		t.Fatal("consistent source was not imported")
	}
}

type lostAdminResponse struct {
	header http.Header
	writes int
}

func (w *lostAdminResponse) Header() http.Header       { return w.header }
func (*lostAdminResponse) WriteHeader(int)             {}
func (w *lostAdminResponse) Write([]byte) (int, error) { w.writes++; return 0, io.ErrClosedPipe }

func TestPostgresIssueResponseFailures(t *testing.T) {
	store, _ := postgresFixture(t)
	pgInitialize(t, store)
	g := newAdminGateway(Web{store, "synthetic", "csrf", "localhost"})
	const keyLabel = `aria-label="生成卡密"`
	req := func(ref string) *http.Request {
		form := url.Values{"action": {"issue"}, "csrf": {"csrf"}, "days": {"30"}, "quantity": {"1"},
			"amount_yuan": {"0"}, "confirmed": {"yes"}, "channel": {"test"}, "sale_ref": {ref}}
		r := httptest.NewRequest("POST", "http://localhost/?view=issue", strings.NewReader(form.Encode()))
		r.SetBasicAuth("admin", "synthetic")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	record := func(ref string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		g.ServeHTTP(w, req(ref))
		return w
	}
	pgExec(t, store, "ALTER TABLE chezhi_audit ADD CONSTRAINT reject_issue CHECK (action <> 'issue') NOT VALID")
	if w := record("before-commit"); strings.Contains(w.Body.String(), keyLabel) || len(pgSnapshot(t, store).Cards) != 0 {
		t.Fatal("uncommitted keys or cards visible")
	}
	pgExec(t, store, "ALTER TABLE chezhi_audit DROP CONSTRAINT reject_issue")
	pgExec(t, store, `CREATE FUNCTION pg_test_issue_commit() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_sleep(8); RETURN NEW; END $$;
        CREATE CONSTRAINT TRIGGER pg_test_issue_commit AFTER INSERT ON chezhi_orders
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pg_test_issue_commit()`)
	commit := make(chan *httptest.ResponseRecorder, 1)
	go func() { commit <- record("unknown-commit") }()
	waitPostgresTest(t, store, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database()
        AND pid<>pg_backend_pid() AND query='COMMIT' AND wait_event='PgSleep')`)
	pgExec(t, store, `SELECT pg_terminate_backend(pid,3000) FROM pg_stat_activity
        WHERE datname=current_database() AND pid<>pg_backend_pid() AND query='COMMIT' AND wait_event='PgSleep'`)
	w := <-commit
	if strings.Contains(w.Body.String(), keyLabel) || !strings.Contains(w.Body.String(), "保存结果待核验") ||
		len(pgSnapshot(t, store).Cards) != 0 {
		t.Fatal("ambiguous commit response disclosed keys or omitted reconciliation guidance")
	}
	pgExec(t, store, "DROP TRIGGER pg_test_issue_commit ON chezhi_orders; DROP FUNCTION pg_test_issue_commit()")

	pgExec(t, store, "ALTER TABLE chezhi_plans RENAME TO pg_test_unavailable_plans")
	if w := record("after-commit"); w.Code != 200 || !strings.Contains(w.Body.String(), keyLabel) ||
		!strings.Contains(w.Body.String(), "业务数据暂不可用") || strings.Contains(w.Body.String(), "无匹配记录") ||
		strings.Contains(w.Body.String(), "选择套餐") || strings.Contains(w.Body.String(), `id="preset"`) {
		t.Fatal("post-commit snapshot failure hid committed keys or rendered unknown business data")
	}
	unavailable := httptest.NewRecorder()
	get := httptest.NewRequest("GET", "http://localhost/?view=overview", nil)
	get.SetBasicAuth("admin", "synthetic")
	g.ServeHTTP(unavailable, get)
	if unavailable.Code != 503 || strings.Contains(unavailable.Body.String(), "累计发卡") ||
		!strings.Contains(unavailable.Body.String(), "业务数据暂不可用") {
		t.Fatal("unavailable statistics rendered as real counts")
	}
	forbidden := httptest.NewRecorder()
	r := req("forbidden")
	g.w.ServeHTTP(forbidden, withPrincipal(r, Principal{Name: "viewer1", Role: "viewer"}))
	if forbidden.Code != 403 || strings.Contains(forbidden.Body.String(), keyLabel) {
		t.Fatal("role protection weakened")
	}
	pgExec(t, store, "ALTER TABLE pg_test_unavailable_plans RENAME TO chezhi_plans")

	lost := &lostAdminResponse{header: make(http.Header)}
	g.ServeHTTP(lost, req("lost-response"))
	if lost.writes == 0 {
		t.Fatal("response did not encounter the injected failure")
	}
	repeated := record("lost-response")
	if strings.Contains(repeated.Body.String(), keyLabel) || !strings.Contains(repeated.Body.String(), "该订单已生成卡密") {
		t.Fatal("lost response retry generated a second key")
	}
	state := pgSnapshot(t, store)
	if len(state.Cards) != 2 || len(state.Audit) != 2 ||
		state.Cards[0].SaleRef != "after-commit" || state.Cards[1].SaleRef != "lost-response" {
		t.Fatal("post-commit/lost response database state disagreed")
	}
}

func TestPostgresDeepIntegrityNegative(t *testing.T) {
	cases := []struct{ name, sql, expected string }{
		{"missing-table", "DROP TABLE chezhi_owner", "table/chezhi_owner"},
		{"missing-column", "ALTER TABLE chezhi_audit DROP COLUMN actor", "column/chezhi_audit/actor"},
		{"missing-index", "DROP INDEX chezhi_cards_order_idx", "index/chezhi_cards/chezhi_cards_order_idx"},
		{"wrong-index", "DROP INDEX chezhi_cards_order_idx; CREATE INDEX chezhi_cards_order_idx ON chezhi_cards (days)", "index/chezhi_cards/chezhi_cards_order_idx"},
		{"missing-constraint", "ALTER TABLE chezhi_cards DROP CONSTRAINT chezhi_cards_ref_created_days_fkey", "constraint/chezhi_cards/chezhi_cards_ref_created_days_fkey"},
		{"missing-config", "DELETE FROM chezhi_config", "configuration singleton"},
		{"missing-plan", "DELETE FROM chezhi_plans WHERE days=90", "fixed plan catalog"},
		{"version-gap", "DELETE FROM chezhi_schema WHERE version=1", "migration history"},
		{"invalid-migration-time", "UPDATE chezhi_schema SET applied_at='infinity' WHERE version=1", "migration timestamp"},
		{"invalid-audit", "INSERT INTO chezhi_audit(occurred,action,actor,target) VALUES(63870000000,'login_failed','!', '')", "invalid PostgreSQL business records"},
		{"invalid-account-revision", "INSERT INTO chezhi_members VALUES('operator1','operator',repeat('a',64),false,999)", "account revision"},
		{"orphaned-restore", "INSERT INTO chezhi_orders VALUES('missing-cards','test',0,30,63870000000)", "order and card relationships"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := postgresFixture(t)
			pgInitialize(t, s)
			if err := s.pg.verifyDatabase(context.Background(), "--migrator"); err != nil {
				t.Fatal(err)
			}
			pgExec(t, s, tc.sql)
			err := s.pg.verifyDatabase(context.Background(), "")
			if err == nil || !strings.Contains(err.Error(), tc.expected) {
				t.Fatalf("incorrect integrity outcome: %v", err)
			}
			if tc.name == "orphaned-restore" && s.pg.checkSchema(context.Background()) != nil {
				t.Fatal("startup check unexpectedly ran full-data verification")
			}
		})
	}
}

func TestPostgresSessionCapacityReclamation(t *testing.T) {
	store, dsn := postgresFixture(t)
	pgInitialize(t, store)
	ctx := context.Background()
	remote, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.db.Close()
	primary := newAdminGateway(Web{store, "primary-bootstrap", "one", "localhost"})
	secret, err := primary.updateMember("changed1", "operator", "member-create")
	if err != nil {
		t.Fatal(err)
	}
	stable, err := primary.updateMember("stable1", "viewer", "member-create")
	if err != nil {
		t.Fatal(err)
	}
	peer := newAdminGateway(Web{&Store{pg: remote, now: time.Now}, "peer-bootstrap", "two", "localhost"})
	clock := time.Now()
	peer.now = func() time.Time { return clock }
	call := func(method, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		peer.ServeHTTP(w, r)
		return w
	}
	login := func(name, secret string, status int) *http.Cookie {
		t.Helper()
		clock = clock.Add(time.Minute)
		w := call("POST", "/login", url.Values{"username": {name}, "password": {secret}, "login_csrf": {peer.loginToken()}}, nil)
		if w.Code != status {
			t.Fatalf("login %s: got %d want %d", name, w.Code, status)
		}
		if status == 303 {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing login cookie")
			}
			return cookies[0]
		}
		return nil
	}
	stableCookie := login("stable1", stable, 303)
	oldOwner := login("admin", "peer-bootstrap", 303)
	oldCookies := make([]*http.Cookie, 30)
	for i := range oldCookies {
		oldCookies[i] = login("changed1", secret, 303)
	}
	login("changed1", secret, 429)
	if len(peer.sessions) != 32 {
		t.Fatal("capacity fixture did not fill the session pool")
	}
	if _, err := primary.updateMember("changed1", "viewer", "member-role"); err != nil {
		t.Fatal(err)
	}
	viewer := login("changed1", secret, 303)
	if len(peer.sessions) != 3 {
		t.Fatal("role-invalidated sessions still consume capacity")
	}
	for _, old := range oldCookies {
		if w := call("GET", "/?view=cards", nil, old); w.Code != 303 {
			t.Fatal("old role session was accepted")
		}
	}
	if w := call("GET", "/?view=issue", nil, viewer); w.Code != 403 {
		t.Fatal("new role was not enforced")
	}
	replacement, err := primary.updateMember("changed1", "", "member-reset")
	if err != nil {
		t.Fatal(err)
	}
	login("changed1", secret, 401)
	if w := call("GET", "/?view=cards", nil, viewer); w.Code != 303 {
		t.Fatal("reset session was accepted")
	}
	viewer = login("changed1", replacement, 303)
	if _, err := primary.updateMember("changed1", "", "member-disable"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/?view=cards", nil, viewer); w.Code != 303 {
		t.Fatal("disabled session was accepted")
	}
	login("changed1", replacement, 401)
	if err := primary.saveOwner("Synthetic-owner-rotation-2026"); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/?view=cards", nil, oldOwner); w.Code != 303 {
		t.Fatal("old owner session was accepted")
	}
	login("admin", "Synthetic-owner-rotation-2026", 303)
	if w := call("GET", "/?view=cards", nil, stableCookie); w.Code != 200 || len(peer.sessions) != 2 {
		t.Fatal("unrelated legitimate session was lost or stale sessions remained")
	}
	if err := remote.db.Close(); err != nil {
		t.Fatal(err)
	}
	if w := call("GET", "/?view=cards", nil, stableCookie); w.Code != 503 {
		t.Fatal("authentication failed open during outage")
	}
	login("stable1", stable, 503)
}
