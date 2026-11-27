package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPostgresServerProjectionParity(t *testing.T) {
	s, _ := postgresFixture(t)
	pgInitialize(t, s)
	now := time.Date(2026, 11, 27, 1, 20, 0, 123456789, time.UTC)
	clock := now.Add(-3 * 24 * time.Hour)
	s.now = func() time.Time { return clock }
	first, err := s.issue(1, 24, 91, "wechat", "Case-Sales")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range first[:3] {
		if result, err := s.validate(key, "device"); err != nil || !result.Valid {
			t.Fatal(err)
		}
	}
	cards := pgSnapshot(t, s).Cards
	if err := s.change(cards[0].ID, "unbind"); err != nil {
		t.Fatal(err)
	}
	if err := s.change(cards[1].ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	clock = now
	keys, err := s.issue(30, 6, 50, "alipay", "Late-Order")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := s.validate(keys[0], "active-device"); err != nil || !result.Valid {
		t.Fatal(err)
	}
	if _, err := s.issue(0, 3, 600, "test", "Exclude-Trend"); err != nil {
		t.Fatal(err)
	}
	state := pgSnapshot(t, s)
	for _, test := range []struct{ section, raw string }{
		{"overview", ""}, {"cards", "q=cASE&channel=wechat&page=2"},
		{"cards", "status=已过期"}, {"cards", "status=已解绑"}, {"cards", "status=已吊销"},
		{"orders", "oc=wechat&oq=cASE"}, {"orders", "op=99"},
		{"devices", "ds=已吊销"}, {"devices", "ds=已激活"}, {"devices", "ds=已过期"},
		{"audit", "ap=2"}, {"settings", ""}, {"issue", ""}, {"plans", ""},
	} {
		t.Run(test.section+test.raw, func(t *testing.T) {
			q, err := url.ParseQuery(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			v := View{Section: test.section, Now: now}
			if err := s.pg.dashboardPage(context.Background(), &v, q); err != nil {
				t.Fatal(err)
			}
			d := buildDashboard(state, now, q)
			o := buildOperations(state, now, test.section, q)
			switch test.section {
			case "overview":
				if v.Dashboard.Stats != d.Stats || !reflect.DeepEqual(v.Operations.Trend, o.Trend) {
					t.Fatal("overview parity failed")
				}
			case "cards":
				if v.Dashboard.Count != d.Count || v.Dashboard.Page != d.Page ||
					v.Dashboard.Stats.Total != d.Stats.Total || !reflect.DeepEqual(v.Dashboard.Cards, d.Cards) {
					t.Fatal("card parity failed")
				}
			case "orders":
				if v.Operations.Count != o.Count || v.Operations.Page != o.Page ||
					!reflect.DeepEqual(v.Operations.Orders, o.Orders) {
					t.Fatal("order parity failed")
				}
			case "devices":
				if v.Operations.Count != o.Count || !reflect.DeepEqual(v.Operations.Devices, o.Devices) {
					t.Fatal("device parity failed")
				}
			case "audit":
				if v.Dashboard.AuditCount != d.AuditCount || !reflect.DeepEqual(v.Dashboard.Audits, d.Audits) {
					t.Fatal("audit parity failed")
				}
			case "settings":
				if v.Dashboard.QQ != d.QQ {
					t.Fatal("support parity failed")
				}
			default:
				if !reflect.DeepEqual(v.Plans, defaultPlans()) {
					t.Fatal("catalog parity failed")
				}
			}
		})
	}
}

func TestPostgresServerDashboardScale(t *testing.T) {
	const readers = 16
	const perSection = 32
	sections := []string{"overview", "cards", "orders", "devices", "audit"}
	for _, size := range []int{10_000, 100_000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, _ := postgresFixture(t)
			pgInitialize(t, s)
			now := time.Now().UTC()
			created := now.Add(-time.Hour)
			// Ten cards per order; include unactivated, bound and revoked cards.
			pgExec(t, s, `INSERT INTO chezhi_orders(ref,channel,cents,days,created)
                SELECT 'scale-'||i,CASE WHEN i%3=0 THEN 'test' ELSE 'wechat' END,110,30,$2
                FROM generate_series(1,$1::int/10) i`, size, sqlTime(created))
			pgExec(t, s, `INSERT INTO chezhi_cards(id,hash,prefix,ref,created,days,activated,expires,device,revoked)
                SELECT left(hash,24),hash,'ABCDE','scale-'||((i-1)/10+1),$2::numeric,30,
                CASE WHEN i%3=0 THEN $2::numeric END,
                CASE WHEN i%3=0 THEN $2::numeric+2592000 END,
                CASE WHEN i%3=0 THEN repeat('a',64) ELSE '' END,i%11=0
                FROM (SELECT i,md5(i::text)||md5('scale'||i) AS hash FROM generate_series(1,$1::int) i) s`, size, sqlTime(created))
			pgExec(t, s, `INSERT INTO chezhi_audit(occurred,action,card_id,actor,target)
                SELECT created,'issue',id,'admin','' FROM chezhi_cards`)
			pgExec(t, s, "ANALYZE")
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			var maxHeap atomic.Uint64
			maxHeap.Store(before.HeapAlloc)
			done, watched := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(watched)
				sample := time.NewTicker(20 * time.Millisecond)
				defer sample.Stop()
				for {
					select {
					case <-done:
						return
					case <-sample.C:
						var m runtime.MemStats
						runtime.ReadMemStats(&m)
						if m.HeapAlloc > maxHeap.Load() {
							maxHeap.Store(m.HeapAlloc)
						}
					}
				}
			}()
			count := perSection * len(sections)
			durations := make([]time.Duration, count)
			errs := make([]error, count)
			var wg sync.WaitGroup
			for worker := 0; worker < readers; worker++ {
				wg.Add(1)
				go func(worker int) {
					defer wg.Done()
					for i := worker; i < count; i += readers {
						view := View{Section: sections[i%len(sections)], Now: now}
						query := url.Values{"page": {"5"}, "op": {"5"}, "ap": {"5"}}
						start := time.Now()
						err := s.pg.dashboardPage(context.Background(), &view, query)
						durations[i] = time.Since(start)
						if err == nil {
							switch view.Section {
							case "overview":
								if view.Dashboard.Stats.Total != size {
									err = fmt.Errorf("incorrect overview count")
								}
							case "cards":
								if view.Dashboard.Count != size || len(view.Dashboard.Cards) != 20 {
									err = fmt.Errorf("incorrect card page")
								}
							case "devices":
								if view.Operations.Count != size/3 || len(view.Operations.Devices) != 20 {
									err = fmt.Errorf("incorrect device page")
								}
							case "orders":
								if view.Operations.Count != size/10 || len(view.Operations.Orders) != 20 {
									err = fmt.Errorf("incorrect order page")
								}
							case "audit":
								if view.Dashboard.AuditCount != size || len(view.Dashboard.Audits) != 20 {
									err = fmt.Errorf("incorrect audit page")
								}
							}
						}
						errs[i] = err
					}
				}(worker)
			}
			wg.Wait()
			close(done)
			<-watched
			runtime.ReadMemStats(&after)
			for i, err := range errs {
				if err != nil {
					t.Errorf("%s: %v", sections[i%len(sections)], err)
				}
			}
			for idx, section := range sections {
				times := make([]time.Duration, 0, perSection)
				slow := 0
				for i := idx; i < count; i += len(sections) {
					times = append(times, durations[i])
					if durations[i] > 500*time.Millisecond {
						slow++
					}
				}
				sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
				t.Logf("dashboard cards=%d audits=%d readers=%d section=%s samples=%d p95=%s max=%s slow_over_500ms=%d",
					size, size, readers, section, len(times), times[(95*len(times)+99)/100-1], times[len(times)-1], slow)
			}
			stats := s.pg.db.Stats()
			t.Logf("dashboard resources cards=%d sampled_heap_peak_bytes=%d allocation_delta_bytes=%d pool_max=%d open=%d idle=%d in_use=%d waits=%d",
				size, max(maxHeap.Load(), after.HeapAlloc), after.TotalAlloc-before.TotalAlloc, stats.MaxOpenConnections,
				stats.OpenConnections, stats.Idle, stats.InUse, stats.WaitCount)
			if stats.InUse != 0 {
				t.Fatal("database connections remained checked out")
			}
			if size == 100_000 {
				if _, _, err := s.pg.readServerExport(context.Background(), false); err != errExportLimit {
					t.Fatal("large export was not bounded", err)
				}
				if _, _, err := s.pg.readServerExport(context.Background(), true); err != errExportLimit {
					t.Fatal("large backup was not bounded", err)
				}
			}
		})
	}
}

func TestPostgresServerSharedStateReclamation(t *testing.T) {
	store, _ := postgresFixture(t)
	pgInitialize(t, store)
	ctx := context.Background()
	if err := store.pg.initializeOwner(ctx, "synthetic owner 24681"); err != nil {
		t.Fatal(err)
	}
	ctx = context.WithValue(ctx, accountRevisionKey{}, int64(1))
	issued := make([]string, 32)
	for i := range issued {
		issued[i] = randomToken()
		if err := store.pg.createSharedSession(ctx, "", issued[i], "admin", "owner", 1); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.pg.createSharedSession(ctx, "", randomToken(), "admin", "owner", 1); err != errSessionCapacity {
		t.Fatal("shared capacity was exceeded", err)
	}
	pgExec(t, store, "UPDATE chezhi_sessions SET expires=clock_timestamp()-interval '1 second' WHERE token_digest=$1", digestSecret(issued[0]))
	pgExec(t, store, `INSERT INTO chezhi_rate_limits(scope,source,window_start,used)
        VALUES ('login','*',floor(extract(epoch FROM clock_timestamp())/60)::bigint-2,7)`)
	if allowed, err := store.pg.allowShared(ctx, "login", digestSecret("active-source"), 60, 5); err != nil || !allowed {
		t.Fatal("current limit unavailable", err)
	}
	if err := store.pg.cleanShared(ctx); err != nil {
		t.Fatal(err)
	}
	var sessions, rates int
	if err := store.pg.db.QueryRow("SELECT (SELECT count(*) FROM chezhi_sessions),(SELECT count(*) FROM chezhi_rate_limits)").Scan(&sessions, &rates); err != nil || sessions != 31 || rates != 2 {
		t.Fatal("cleanup removed currently valid state or retained expired state", err)
	}
	if err := store.pg.createSharedSession(ctx, "", randomToken(), "admin", "owner", 1); err != nil {
		t.Fatal("expired capacity not recovered", err)
	}
	if _, err := store.pg.sharedSession(ctx, issued[0]); err != errSessionInvalid {
		t.Fatal("expired session accepted", err)
	}
}

func TestServerConnectionLimit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bound := limitConnections(listener, 1)
	defer bound.Close()
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first, err := bound.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		second, _ := bound.Accept()
		accepted <- second
	}()
	select {
	case <-accepted:
		t.Fatal("accepted over capacity")
	case <-time.After(30 * time.Millisecond):
	}
	first.Close()
	select {
	case second := <-accepted:
		if second == nil {
			t.Fatal("queued connection not accepted")
		}
		defer second.Close()
	case <-time.After(time.Second):
		t.Fatal("capacity not released")
	}
	closed := make(chan error, 1)
	go func() { _, err := bound.Accept(); closed <- err }()
	bound.Close()
	select {
	case err := <-closed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("listener shutdown was not propagated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener failed to stop while at capacity")
	}
}

func TestPostgresServerUpgradeV4RetainsBusinessAndClearsOldSecurity(t *testing.T) {
	s, _ := postgresFixture(t)
	ctx := context.Background()
	pgExec(t, s, `CREATE TABLE chezhi_schema (version integer PRIMARY KEY CHECK(version>0),
        applied_at timestamptz NOT NULL DEFAULT clock_timestamp())`)
	for i, migration := range postgresMigrations[:3] {
		pgExec(t, s, migration)
		pgExec(t, s, "INSERT INTO chezhi_schema(version) VALUES ($1)", i+1)
	}
	seedHistoricalCards(t,s,30,1,700,"wechat","upgrade-order")
	if err := s.pg.initializeOwner(ctx, "synthetic migration owner"); err != nil {
		t.Fatal(err)
	}
	key := randomToken()
	if err := s.pg.createSharedSession(ctx, "", key, "admin", "owner", 1); err != nil {
		t.Fatal(err)
	}
	if allowed, err := s.pg.allowShared(ctx, "login", digestSecret("example"), 60, 5); err != nil || !allowed {
		t.Fatal(err)
	}
	before := pgSnapshot(t, s)
	pgInitialize(t, s)
	after := pgSnapshot(t, s)
	if !reflect.DeepEqual(after, before) {
		t.Fatal("V4 migration modified business or audit history")
	}
	if _, err := s.pg.sharedSession(ctx, key); err != errSessionInvalid {
		t.Fatal("V3 session survived deployment binding", err)
	}
	var remaining int
	if err := s.pg.db.QueryRow("SELECT count(*) FROM chezhi_rate_limits").Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("V3 rate state survived deployment binding", err)
	}
	binding, matched, err := deploymentState(ctx, s.pg.db)
	if err != nil || !matched || binding.mode != "local" || binding.generation != 1 {
		t.Fatal("V4 default deployment binding was not initialized", err)
	}
	if err := s.pg.verifyDatabase(ctx, "--migrator"); err != nil {
		t.Fatal(err)
	}
}
