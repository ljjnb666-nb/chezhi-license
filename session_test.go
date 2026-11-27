package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAdminSessionLifecycle(t *testing.T) {
	s := testStore(t)
	g := newAdminGateway(Web{s, "secret", "root-csrf", "127.0.0.1:12345"})
	now := time.Now()
	g.now = func() time.Time { return now }
	call := func(method, path string, f url.Values, c *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+g.w.host+path, strings.NewReader(f.Encode()))
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
	origin := "http://" + g.w.host
	if rr := call("GET", "/", nil, nil, origin); rr.Code != 303 || rr.Header().Get("Location") != "/login" {
		t.Fatal("login redirect")
	}
	if rr := call("GET", "/login", nil, nil, origin); rr.Code != 200 || strings.Contains(rr.Body.String(), g.w.csrf) {
		t.Fatal("login page")
	}
	f := url.Values{"username": {"admin"}, "password": {"secret"}, "login_csrf": {g.loginToken()}}
	if call("POST", "/login", f, nil, "http://evil.test").Code != 403 {
		t.Fatal("origin")
	}
	f.Set("password", "bad")
	if call("POST", "/login", f, nil, origin).Code != 401 {
		t.Fatal("bad credential")
	}
	f.Set("password", "secret")
	rr := call("POST", "/login", f, nil, origin)
	if rr.Code != 303 || len(rr.Result().Cookies()) != 1 {
		t.Fatal("login")
	}
	c := rr.Result().Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie")
	}
	a := g.sessions[c.Value]
	if a.csrf == g.w.csrf || a.csrf == g.loginToken() {
		t.Fatal("csrf separation")
	}
	if call("GET", "/?view=account", nil, c, origin).Code != 200 || call("GET", "/admin-ui.js", nil, c, origin).Code != 200 {
		t.Fatal("authenticated pages")
	}
	if call("POST", "/logout", url.Values{"logout_csrf": {"bad"}}, c, origin).Code != 403 {
		t.Fatal("logout csrf")
	}
	if call("POST", "/logout", url.Values{"logout_csrf": {a.csrf}}, c, origin).Code != 303 || call("GET", "/", nil, c, origin).Code != 303 {
		t.Fatal("logout invalidation")
	}
	c = call("POST", "/login", f, nil, origin).Result().Cookies()[0]
	now = now.Add(8 * time.Hour)
	if call("GET", "/", nil, c, origin).Code != 303 {
		t.Fatal("expiry")
	}
}
func TestLoginRateAndBrowserBasic(t *testing.T) {
	g := newAdminGateway(Web{testStore(t), "secret", "csrf", "127.0.0.1:1"})
	for i := 0; i < 6; i++ {
		f := url.Values{"username": {"admin"}, "password": {"bad"}, "login_csrf": {g.loginToken()}}
		r := httptest.NewRequest("POST", "http://"+g.w.host+"/login", strings.NewReader(f.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		want := 401
		if i == 5 {
			want = 429
		}
		if rr.Code != want {
			t.Fatal(i, rr.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://"+g.w.host+"/", nil)
	r.Header.Set("Accept", "text/html")
	r.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, r)
	if rr.Code != 303 {
		t.Fatal("browser basic fallback")
	}
}
