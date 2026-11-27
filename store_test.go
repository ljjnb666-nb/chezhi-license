package main

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := openStore(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func issueOne(t *testing.T, s *Store, days int) string {
	t.Helper()
	k, e := s.issue(days, 1, 0, "test", "test-1")
	if e != nil {
		t.Fatal(e)
	}
	return k[0]
}
func check(t *testing.T, s *Store, k, d string, valid bool, reason string) {
	t.Helper()
	r, e := s.validate(k, d)
	if e != nil || r.Valid != valid || r.Reason != reason {
		t.Fatalf("validation mismatch: %+v %v", r, e)
	}
}
func TestIssueAndHashStorage(t *testing.T) {
	s := testStore(t)
	ks, e := s.issue(30, 100, 900, "wechat", "order-1")
	if e != nil || len(ks) != 100 {
		t.Fatal(e, len(ks))
	}
	b, e := os.ReadFile(s.path)
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, k := range ks {
		if seen[k] || bytes.Contains(b, []byte(k)) {
			t.Fatal("duplicate or plaintext key")
		}
		seen[k] = true
	}
	if len(s.snapshot().Cards) != 100 {
		t.Fatal("wrong count")
	}
	if _, e = s.issue(30, 1, 900, "wechat", "order-1"); e == nil {
		t.Fatal("duplicate order")
	}
}
func TestExpiryAndRebind(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	k := issueOne(t, s, 7)
	now = now.Add(48 * time.Hour)
	check(t, s, k, "A", true, "")
	c := s.snapshot().Cards[0]
	if !c.Activated.Equal(now) || !c.Expires.Equal(now.Add(7*24*time.Hour)) {
		t.Fatal("incorrect first activation")
	}
	now = now.Add(time.Hour)
	check(t, s, k, "A", true, "")
	check(t, s, k, "B", false, "device_mismatch")
	if e := s.change(c.ID, "unbind"); e != nil {
		t.Fatal(e)
	}
	check(t, s, k, "B", true, "")
	if !s.snapshot().Cards[0].Expires.Equal(*c.Expires) {
		t.Fatal("rebind extended expiry")
	}
	now = *c.Expires
	check(t, s, k, "B", false, "expired")
}
func TestRevokedAndPerpetual(t *testing.T) {
	s := testStore(t)
	k := issueOne(t, s, 0)
	check(t, s, k, "A", true, "")
	c := s.snapshot().Cards[0]
	if c.Expires != nil {
		t.Fatal("perpetual expires")
	}
	if e := s.change(c.ID, "revoke"); e != nil {
		t.Fatal(e)
	}
	check(t, s, k, "A", false, "revoked")
	check(t, s, "wrong", "A", false, "not_found")
	check(t, s, k, "", false, "invalid_input")
}
func TestPersistentState(t *testing.T) {
	s := testStore(t)
	k := issueOne(t, s, 30)
	check(t, s, k, "A", true, "")
	if e := s.setQQ("123456789"); e != nil {
		t.Fatal(e)
	}
	s2, e := openStore(s.path)
	if e != nil {
		t.Fatal(e)
	}
	check(t, s2, k, "A", true, "")
	check(t, s2, k, "B", false, "device_mismatch")
	if s2.snapshot().QQ != "123456789" || len(s2.snapshot().Audit) != 3 {
		t.Fatal("lost state")
	}
	if e := s2.setQQ("<script>"); e == nil {
		t.Fatal("accepted invalid QQ")
	}
}
func TestConcurrentBinding(t *testing.T) {
	s := testStore(t)
	k := issueOne(t, s, 1)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, e := s.validate(k, string(rune('A'+i)))
			if e != nil {
				t.Error(e)
			}
			if r.Valid {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("success=%d", ok.Load())
	}
}
func TestCommitFailureDoesNotPublishKey(t *testing.T) {
	s := testStore(t)
	s.path = filepath.Join(t.TempDir(), "missing", "state.json")
	keys, e := s.issue(1, 1, 0, "test", "ref")
	if e == nil || len(keys) != 0 || len(s.snapshot().Cards) != 0 {
		t.Fatal("failed commit published a card")
	}
}
func TestInvalidIssue(t *testing.T) {
	s := testStore(t)
	for _, x := range []struct {
		d, n, a int
		c, r    string
	}{{-1, 1, 0, "test", "r"}, {3651, 1, 0, "test", "r"}, {1, 101, 0, "test", "r"}, {1, 1, -1, "test", "r"}, {1, 1, 0, "bad", "r"}, {1, 1, 0, "test", ""}} {
		if _, e := s.issue(x.d, x.n, x.a, x.c, x.r); e == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
func TestHTTPProtectionAndFlow(t *testing.T) {
	s := testStore(t)
	w := Web{s, "test-password", "csrf-token", "127.0.0.1:12345"}
	req := func(method, host string, auth bool, data url.Values, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+"/", strings.NewReader(data.Encode()))
		if auth {
			r.SetBasicAuth("admin", "test-password")
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		return rr
	}
	if r := req("GET", w.host, false, nil, ""); r.Code != 401 {
		t.Fatal(r.Code)
	}
	if r := req("GET", "evil.test", true, nil, ""); r.Code != 400 {
		t.Fatal(r.Code)
	}
	if r := req("POST", w.host, true, url.Values{"action": {"qq"}, "qq": {"123456"}}, ""); r.Code != 403 {
		t.Fatal(r.Code)
	}
	v := url.Values{"action": {"qq"}, "qq": {"123456"}, "csrf": {"csrf-token"}}
	if r := req("POST", w.host, true, v, "http://evil.test"); r.Code != 403 {
		t.Fatal(r.Code)
	}
	if r := req("POST", w.host, true, v, "http://"+w.host); r.Code != 200 || !strings.Contains(r.Body.String(), "123456") {
		t.Fatal(r.Code)
	}
	if r := req("GET", w.host, true, nil, ""); r.Code != 200 || r.Header().Get("Cache-Control") != "no-store" || !strings.Contains(r.Body.String(), "人工发卡") {
		t.Fatal(r.Code)
	}
}
