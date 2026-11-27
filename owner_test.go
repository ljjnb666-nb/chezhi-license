package main

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestOwnerKDFKnownVector(t *testing.T) {
	if got := hex.EncodeToString(deriveOwner("password", []byte("salt"), 2)); got != "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43" {
		t.Fatal(got)
	}
}
func TestOwnerPasswordLifecycle(t *testing.T) {
	w := Web{testStore(t), "temporary-secret", "csrf", "127.0.0.1:12345"}
	g := newAdminGateway(w)
	oldID := strings.Repeat("a", 64)
	otherID := strings.Repeat("b", 64)
	memberID := strings.Repeat("c", 64)
	g.sessions[oldID] = adminSession{name: "admin", role: "owner", csrf: "owner-csrf", expiry: time.Now().Add(time.Hour)}
	g.sessions[otherID] = g.sessions[oldID]
	g.sessions[memberID] = adminSession{name: "staff", role: "viewer", csrf: "member-csrf", expiry: time.Now().Add(time.Hour)}
	const password = "a-long-unique-password-2026"
	form := url.Values{"csrf": {"owner-csrf"}, "current_password": {"temporary-secret"}, "new_password": {password}, "confirm_password": {password}}
	call := func(id string, f url.Values, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://"+w.host+"/account/password", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		return rr
	}
	origin := "http://" + w.host
	if call(memberID, form, origin).Code != 403 || call(oldID, form, "http://evil.test").Code != 403 {
		t.Fatal("authorization")
	}
	form.Set("current_password", "bad")
	if rr := call(oldID, form, origin); !strings.Contains(rr.Body.String(), "当前密码不正确") || g.owner != nil {
		t.Fatal("wrong password")
	}
	form.Set("current_password", "temporary-secret")
	form.Set("confirm_password", "mismatch")
	if rr := call(oldID, form, origin); !strings.Contains(rr.Body.String(), "两次输入一致") || g.owner != nil {
		t.Fatal("mismatch")
	}
	form.Set("confirm_password", password)
	if rr := call(oldID, form, origin); rr.Code != 303 || len(g.sessions) != 1 || g.sessions[memberID].name != "staff" {
		t.Fatal("session revocation", rr.Code, len(g.sessions))
	}
	b, e := os.ReadFile(g.ownerPath())
	if e != nil || strings.Contains(string(b), password) || strings.Contains(string(b), w.token) {
		t.Fatal("secret persisted in plaintext", e)
	}
	reopened := newAdminGateway(Web{w.s, "new-bootstrap", "other-csrf", w.host})
	if reopened.loadErr != nil || !reopened.verifyOwner(password) || reopened.verifyOwner("new-bootstrap") || reopened.verifyOwner(w.token) {
		t.Fatal("persistent credential")
	}
	r := httptest.NewRequest("GET", "http://"+w.host+"/", nil)
	r.SetBasicAuth("admin", "new-bootstrap")
	rr := httptest.NewRecorder()
	reopened.ServeHTTP(rr, r)
	if rr.Code != 401 {
		t.Fatal("basic bypass")
	}
	a := w.s.snapshot().Audit
	if len(a) != 2 || a[0].Action != "password_failed" || a[1].Action != "password_changed" || a[1].Actor != "admin" {
		t.Fatal("security audit", a)
	}
	if e = os.WriteFile(g.ownerPath(), []byte(`{"Version":1}`), 0600); e != nil {
		t.Fatal(e)
	}
	bad := newAdminGateway(w)
	if bad.loadErr == nil {
		t.Fatal("corrupt credential accepted")
	}
}
