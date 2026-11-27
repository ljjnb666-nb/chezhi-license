package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestActorAuditPersistence(t *testing.T) {
	s := testStore(t)
	keys, e := s.issue(30, 1, 0, "test", "audit-order", "staff1")
	if e != nil {
		t.Fatal(e)
	}
	id := s.snapshot().Cards[0].ID
	if res, e := s.validate(keys[0], "test-device"); e != nil || !res.Valid {
		t.Fatal(res, e)
	}
	if e = s.change(id, "unbind", "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.setQQ("123456789", "admin"); e != nil {
		t.Fatal(e)
	}
	if e = s.recordAudit("admin", "member-create", "staff1"); e != nil {
		t.Fatal(e)
	}
	reopened, e := openStore(s.path)
	if e != nil {
		t.Fatal(e)
	}
	a := reopened.snapshot().Audit
	want := []string{"staff1", "user", "admin", "admin", "admin"}
	if len(a) != len(want) {
		t.Fatal(len(a))
	}
	for i, v := range a {
		if v.Actor != want[i] {
			t.Fatal(i, v.Actor)
		}
	}
	if a[4].Target != "staff1" || a[4].CardID != "" {
		t.Fatal(a[4])
	}
}
func TestLogoutAllOwnSessions(t *testing.T) {
	g := newAdminGateway(Web{testStore(t), "secret", "csrf", "127.0.0.1:12345"})
	g.sessions[strings.Repeat("a", 64)] = adminSession{name: "staff1", role: "operator", csrf: "a", expiry: time.Now().Add(time.Hour)}
	g.sessions[strings.Repeat("b", 64)] = adminSession{name: "staff1", role: "operator", csrf: "b", expiry: time.Now().Add(time.Hour)}
	g.sessions[strings.Repeat("c", 64)] = adminSession{name: "admin", role: "owner", csrf: "c", expiry: time.Now().Add(time.Hour)}
	call := func(csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+g.w.host+"/logout-all", strings.NewReader(url.Values{"logout_csrf": {csrf}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: strings.Repeat("a", 64)})
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		return rr
	}
	if call("bad").Code != 403 || len(g.sessions) != 3 {
		t.Fatal("csrf")
	}
	if call("a").Code != 303 || len(g.sessions) != 1 || g.sessions[strings.Repeat("c", 64)].name != "admin" {
		t.Fatal("scope")
	}
}
