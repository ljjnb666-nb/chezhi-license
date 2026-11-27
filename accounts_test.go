package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMemberPermissionsAndRevocation(t *testing.T) {
	s := testStore(t)
	g := newAdminGateway(Web{s, "secret", "root-csrf", "127.0.0.1:12345"})
	origin := "http://" + g.w.host
	call := func(method, path string, f url.Values, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+path, strings.NewReader(f.Encode()))
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		if c != nil {
			r.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		return rr
	}
	login := func(n, p string) *http.Cookie {
		rr := call("POST", "/login", url.Values{"username": {n}, "password": {p}, "login_csrf": {g.loginToken()}}, nil)
		if rr.Code != 303 {
			t.Fatalf("login %s: %d", n, rr.Code)
		}
		return rr.Result().Cookies()[0]
	}
	owner := login("admin", "secret")
	ownerCSRF := g.sessions[owner.Value].csrf
	create := func(n, role string) string {
		rr := call("POST", "/members", url.Values{"csrf": {ownerCSRF}, "action": {"member-create"}, "name": {n}, "role": {role}}, owner)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), "成员登录凭据") {
			t.Fatal("create failed", rr.Code)
		}
		return strings.Split(strings.Split(rr.Body.String(), `aria-label="成员登录凭据" rows="2">`)[1], "</textarea>")[0]
	}
	opSecret := create("operator1", "operator")
	viewSecret := create("viewer1", "viewer")
	op := login("operator1", opSecret)
	viewer := login("viewer1", viewSecret)
	for _, c := range []*http.Cookie{op, viewer} {
		for _, section := range []string{"overview", "cards", "orders", "devices", "account"} {
			rr := call("GET", "/?view="+section, nil, c)
			if rr.Code != 200 || !strings.HasSuffix(rr.Body.String(), "</html>\n") {
				t.Fatal("read", section, rr.Code, rr.Body.String()[max(0, rr.Body.Len()-150):])
			}
		}
		for _, section := range []string{"members", "backup", "plans", "settings", "audit"} {
			if call("GET", "/?view="+section, nil, c).Code != 403 {
				t.Fatal("private view", section)
			}
		}
		csrf := g.sessions[c.Value].csrf
		for _, action := range []string{"revoke", "unbind", "batch-revoke", "batch-unbind", "qq", "plans"} {
			if call("POST", "/?view=cards", url.Values{"csrf": {csrf}, "action": {action}}, c).Code != 403 {
				t.Fatal("mutation", action)
			}
		}
		if call("POST", "/backup", url.Values{"csrf": {csrf}}, c).Code != 403 || call("POST", "/members", url.Values{"csrf": {csrf}, "action": {"member-create"}}, c).Code != 403 {
			t.Fatal("privileged endpoint")
		}
	}
	f := url.Values{"csrf": {g.sessions[viewer.Value].csrf}, "action": {"issue"}, "preset": {"30"}, "quantity": {"1"}, "amount": {"0"}, "channel": {"test"}, "sale_ref": {"role-test"}, "confirmed": {"yes"}}
	if call("POST", "/?view=cards", f, viewer).Code != 403 || len(s.snapshot().Cards) != 0 {
		t.Fatal("viewer issuance")
	}
	f.Set("csrf", g.sessions[op.Value].csrf)
	if rr := call("POST", "/?view=issue", f, op); rr.Code != 200 || len(s.snapshot().Cards) != 1 {
		t.Fatal("operator issuance")
	}
	if call("POST", "/members", url.Values{"csrf": {"bad"}, "action": {"member-disable"}, "name": {"operator1"}}, owner).Code != 403 {
		t.Fatal("csrf")
	}
	rr := call("POST", "/members", url.Values{"csrf": {ownerCSRF}, "action": {"member-disable"}, "name": {"operator1"}}, owner)
	if rr.Code != 200 || call("GET", "/?view=cards", nil, op).Code != 303 {
		t.Fatal("disable old session")
	}
	g2 := newAdminGateway(g.w)
	if g2.loadErr != nil {
		t.Fatal(g2.loadErr)
	}
	if _, ok := g2.authenticate("operator1", opSecret); ok {
		t.Fatal("disabled after restart")
	}
	if _, ok := g2.authenticate("viewer1", viewSecret); !ok {
		t.Fatal("persisted member")
	}
	if g2.members["viewer1"].Digest == viewSecret {
		t.Fatal("plaintext credential")
	}
}
func TestBusinessBackup(t *testing.T) {
	s := testStore(t)
	keys, e := s.issue(30, 1, 123, "test", "backup-test")
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.backup()
	if e != nil {
		t.Fatal(e)
	}
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		t.Fatal(e)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		files[f.Name], e = io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	if len(files) != 3 || bytes.Contains(files["state.json"], []byte(keys[0])) {
		t.Fatal("backup scope")
	}
	var manifest struct{ SHA256 map[string]string }
	if json.Unmarshal(files["manifest.json"], &manifest) != nil {
		t.Fatal("manifest")
	}
	for _, name := range []string{"state.json", "plans.json"} {
		if manifest.SHA256[name] != digestSecret(string(files[name])) {
			t.Fatal("digest", name)
		}
	}
	var state State
	if json.Unmarshal(files["state.json"], &state) != nil || len(state.Cards) != 1 || state.Cards[0].SaleRef != "backup-test" {
		t.Fatal("state")
	}
}
func TestMemberResetAndInvalidRoles(t *testing.T) {
	g := newAdminGateway(Web{testStore(t), "secret", "csrf", "localhost"})
	if _, e := g.updateMember("admin", "viewer", "member-create"); e == nil {
		t.Fatal("reserved")
	}
	if _, e := g.updateMember("user1", "owner", "member-create"); e == nil {
		t.Fatal("role")
	}
	a, e := g.updateMember("user1", "viewer", "member-create")
	if e != nil {
		t.Fatal(e)
	}
	b, e := g.updateMember("user1", "", "member-reset")
	if e != nil || a == b {
		t.Fatal("reset", e)
	}
	if _, ok := g.authenticate("user1", a); ok {
		t.Fatal("old credential")
	}
	if _, ok := g.authenticate("user1", b); !ok {
		t.Fatal("new credential")
	}
}
func TestExportCSV(t *testing.T) {
	s := testStore(t)
	keys, e := s.issue(30, 1, 123, "test", "=1+1")
	if e != nil {
		t.Fatal(e)
	}
	w := Web{s, "secret", "csrf", "127.0.0.1:1"}
	r := httptest.NewRequest("POST", "http://"+w.host+"/export", strings.NewReader("csrf=csrf"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	w.ServeHTTP(rr, r)
	b := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(b, "'=1+1") || strings.Contains(b, keys[0]) || strings.Contains(b, s.snapshot().Cards[0].Hash) {
		t.Fatal("export safety")
	}
}
