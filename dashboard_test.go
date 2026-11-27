package main

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDashboardFiltersAndPagination(t *testing.T) {
	s := testStore(t)
	now := time.Date(2026, 11, 27, 7, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	keys, e := s.issue(30, 25, 990, "wechat", "order-alpha")
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.issue(7, 2, 999, "test", "test-beta")
	if e != nil {
		t.Fatal(e)
	}
	check(t, s, keys[0], "A", true, "")
	d := buildDashboard(s.snapshot(), now, url.Values{})
	if d.Stats.Total != 27 || d.Stats.Active != 1 || d.Stats.Unused != 26 || d.Stats.ManualCents != 24750 || d.Stats.Orders != 1 || len(d.Cards) != 20 || d.Pages != 2 || d.Next == "" {
		t.Fatal(d.Stats, d.Pages)
	}
	d = buildDashboard(s.snapshot(), now, url.Values{"q": {"ALPHA"}, "status": {"未激活"}, "channel": {"wechat"}, "page": {"999"}})
	if d.Count != 24 || d.Page != 2 || len(d.Cards) != 4 || d.Prev == "" || d.Next != "" {
		t.Fatal(d.Count, d.Page)
	}
	d = buildDashboard(s.snapshot(), now, url.Values{"q": {"nonexistent"}, "page": {"-1"}})
	if d.Count != 0 || d.Page != 1 || len(d.Cards) != 0 {
		t.Fatal(d)
	}
	if localTime(now) != "2026-11-27 15:00:00" || money(990) != "9.90" {
		t.Fatal("format")
	}
}
func TestBatchAtomicity(t *testing.T) {
	s := testStore(t)
	keys, e := s.issue(7, 2, 0, "test", "batch")
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range keys {
		check(t, s, k, "A", true, "")
	}
	cs := s.snapshot().Cards
	ids := []string{cs[0].ID, cs[1].ID}
	if e = s.changeBatch([]string{ids[0], strings.Repeat("0", 24)}, "revoke"); e == nil || s.snapshot().Cards[0].Revoked {
		t.Fatal("partial mutation")
	}
	if e = s.changeBatch([]string{ids[0], ids[0]}, "revoke"); e == nil {
		t.Fatal("duplicate")
	}
	if e = s.changeBatch(ids, "unbind"); e != nil {
		t.Fatal(e)
	}
	for i, c := range s.snapshot().Cards {
		if c.Device != "" || !c.Expires.Equal(*cs[i].Expires) {
			t.Fatal("unbind")
		}
	}
	if e = s.changeBatch(ids, "revoke"); e != nil {
		t.Fatal(e)
	}
	for _, k := range keys {
		check(t, s, k, "B", false, "revoked")
	}
	s2, e := openStore(s.path)
	if e != nil || !s2.snapshot().Cards[1].Revoked {
		t.Fatal("restart")
	}
}
func TestSeparatedUserRoute(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "admin-csrf", "127.0.0.1:12345"}
	k := issueOne(t, s, 30)
	base := "http://" + w.host
	call := func(method, path string, v url.Values, auth bool, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, base+path, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if auth {
			r.SetBasicAuth("admin", "secret")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		return rr
	}
	page := call("GET", "/activate", nil, false, "")
	if page.Code != 200 || strings.Contains(page.Body.String(), w.csrf) || strings.Contains(page.Body.String(), "卡密记录") || strings.Contains(page.Body.String(), "test-1") {
		t.Fatal("admin data leaked")
	}
	form := url.Values{"csrf": {w.activationCSRF()}, "key": {k}, "device": {"A"}}
	if call("POST", "/", form, false, base).Code != 401 || call("POST", "/", form, true, base).Code != 403 {
		t.Fatal("admin gate")
	}
	if call("POST", "/activate", form, false, "null").Code != 403 || call("POST", "/activate", form, false, "http://evil.test").Code != 403 {
		t.Fatal("origin")
	}
	form.Set("csrf", w.csrf)
	if call("POST", "/activate", form, false, base).Code != 403 {
		t.Fatal("admin token accepted")
	}
	form.Set("csrf", w.activationCSRF())
	if r := call("POST", "/activate", form, false, base); r.Code != 200 || !strings.Contains(r.Body.String(), "授权验证成功") {
		t.Fatal(r.Code)
	}
	for i := 0; i < 59; i++ {
		if call("POST", "/activate", form, false, base).Code != 200 {
			t.Fatal("early limit")
		}
	}
	if call("POST", "/activate", form, false, base).Code != 429 {
		t.Fatal("missing limit")
	}
}
func TestLegacyStateUpgrade(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	if e := os.WriteFile(p, []byte(`{"QQ":"123456789","Cards":[{"id":"123456789012345678901234","hash":"1234567890123456789012345678901234567890123456789012345678901234","prefix":"ABCDE","days":30,"sale_ref":"legacy-order","channel":"test","amount_cents":0,"created":"2026-11-27T07:00:00Z","revoked":false}],"Audit":[]}`), 0600); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(p)
	if e != nil {
		t.Fatal(e)
	}
	d := buildDashboard(s.snapshot(), time.Now(), url.Values{})
	if d.QQ != "123456789" || d.Count != 1 || d.Cards[0].SaleRef != "legacy-order" {
		t.Fatal("legacy data lost")
	}
}
