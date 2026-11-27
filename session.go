package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed login.html
var loginHTML string
var loginPage = template.Must(template.New("login").Parse(loginHTML))

const sessionCookie = "chezhi_admin"

type adminSession struct {
	expiry     time.Time
	csrf       string
	name, role string
	revision   int64
}
type adminGateway struct {
	w               Web
	mu              sync.Mutex
	dispatch        sync.Mutex
	sessions        map[string]adminSession
	attempts        []time.Time
	members         map[string]Member
	loadErr         error
	accountRevision int64
	revisions       map[string]int64
	owner           *ownerCredential
	now             func() time.Time
}

func newAdminGateway(w Web) *adminGateway {
	g := &adminGateway{w: w, sessions: map[string]adminSession{}, members: map[string]Member{}, now: time.Now}
	if w.s.pg != nil {
		g.loadErr = g.refreshAccounts(context.Background())
		return g
	}
	g.loadErr = g.loadMembers()
	if g.loadErr == nil {
		g.loadErr = g.loadOwner()
	}
	return g
}
func (g *adminGateway) refreshAccounts(ctx context.Context) error {
	a, err := g.w.s.pg.accounts(ctx)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.members, g.owner, g.accountRevision, g.revisions = a.members, a.owner, a.revision, a.revisions
	g.pruneSessions(g.now())
	return nil
}
func (g *adminGateway) loginToken() string {
	return keyedDigest(g.w.csrf, "admin-login-v1")
}
func (g *adminGateway) renderLogin(rw http.ResponseWriter, status int, msg string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	_ = loginPage.Execute(rw, struct{ CSRF, Error string }{g.loginToken(), msg})
}

// Session map and account revisions are read together under g.mu.
func (g *adminGateway) sessionActive(s adminSession, now time.Time) bool {
	return now.Before(s.expiry) && s.revision == g.revisions[s.name]
}

func (g *adminGateway) pruneSessions(now time.Time) {
	for id, s := range g.sessions {
		if !g.sessionActive(s, now) {
			delete(g.sessions, id)
		}
	}
}

func (g *adminGateway) session(r *http.Request) (string, adminSession, bool) {
	c, e := r.Cookie(sessionCookie)
	if e != nil || len(c.Value) != 64 {
		return "", adminSession{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[c.Value]
	if !ok || !g.sessionActive(s, g.now()) {
		delete(g.sessions, c.Value)
		return "", adminSession{}, false
	}
	return c.Value, s, true
}
func (g *adminGateway) budget() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	var keep []time.Time
	for _, a := range g.attempts {
		if now.Sub(a) < time.Minute {
			keep = append(keep, a)
		}
	}
	g.attempts = keep
	if len(keep) >= 5 {
		return false
	}
	g.attempts = append(g.attempts, now)
	return true
}
func (g *adminGateway) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Referrer-Policy", "same-origin")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if g.loadErr != nil {
		http.Error(rw, "账户配置无法读取", 503)
		return
	}
	if r.Host != g.w.host {
		http.Error(rw, "invalid host", 400)
		return
	}
	if isV2Path(r.URL.Path) || strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1" {
		g.w.ServeHTTP(rw, r)
		return
	}
	switch r.URL.Path {
	case "/activate", "/purchase", "/api/demo/activate":
		g.w.ServeHTTP(rw, r)
		return
	}
	settings, shared := r.Context().Value(serverRequestKey{}).(serverRequest)
	if !shared {
		// Local account configuration and sessions are process-owned.
		g.dispatch.Lock()
		defer g.dispatch.Unlock()
	}
	if g.w.s.pg != nil {
		if err := g.refreshAccounts(r.Context()); err != nil {
			http.Error(rw, "账户配置无法读取", 503)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), accountRevisionKey{}, g.accountRevision))
	}
	var id string
	var s adminSession
	var ok bool
	if shared {
		if cookie, err := r.Cookie(sessionCookieFor(r, "", 0).Name); err == nil && len(cookie.Value) == 64 {
			if decoded, err := hex.DecodeString(cookie.Value); err == nil && len(decoded) == 32 {
				var lookupErr error
				s, lookupErr = g.w.s.pg.sharedSession(r.Context(), cookie.Value)
				if lookupErr != nil && !errors.Is(lookupErr, errSessionInvalid) {
					http.Error(rw, "service unavailable", 503)
					return
				}
				if lookupErr == nil && s.revision == g.revisions[s.name] {
					id, ok = cookie.Value, true
					r = r.WithContext(context.WithValue(r.Context(), sharedSessionKey{}, digestSecret(id)))
				}
			}
		}
	} else {
		id, s, ok = g.session(r)
	}
	if r.URL.Path == "/login" {
		if r.Method == http.MethodGet {
			if ok {
				http.Redirect(rw, r, "/", 303)
				return
			}
			g.renderLogin(rw, 200, "")
			return
		}
		if r.Method != http.MethodPost {
			rw.Header().Set("Allow", "GET, POST")
			http.Error(rw, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, 4096)
		if parseScalarForm(r) != nil || !g.w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("login_csrf")), []byte(g.loginToken())) != 1 {
			http.Error(rw, "请求无效，请重新打开登录页", 403)
			return
		}
		allowed := false
		if shared {
			var err error
			allowed, err = g.w.s.pg.allowShared(r.Context(), "login", settings.source, 60, settings.config.loginRate)
			if err != nil {
				g.renderLogin(rw, 503, "授权服务暂不可用")
				return
			}
		} else {
			allowed = g.budget()
		}
		if !allowed {
			rw.Header().Set("Retry-After", "60")
			g.renderLogin(rw, 429, "尝试次数过多，请稍后再试。")
			return
		}
		name := r.PostForm.Get("username")
		role, valid := g.authenticate(name, r.PostForm.Get("password"))
		if !valid {
			g.securityAuditContext(r.Context(), "unknown", "login_failed")
			g.renderLogin(rw, 401, "账号或密码不正确。")
			return
		}
		sid := randomToken()
		if shared {
			err := g.w.s.pg.createSharedSession(r.Context(), id, sid, name, role, g.revisions[name])
			switch {
			case errors.Is(err, errSessionCapacity):
				g.renderLogin(rw, 429, "会话数量已达上限，请退出其他会话。")
			case err != nil:
				g.renderLogin(rw, 503, "会话暂不可用")
			default:
				http.SetCookie(rw, sessionCookieFor(r, sid, 28800))
				http.Redirect(rw, r, "/", 303)
			}
			return
		}
		now := g.now()
		g.mu.Lock()
		g.pruneSessions(now)
		if len(g.sessions) >= 32 && !ok {
			g.mu.Unlock()
			g.renderLogin(rw, 429, "会话数量已达上限，请退出其他会话。")
			return
		}
		delete(g.sessions, id)
		// Recheck member state while holding the session lock.
		if name != "admin" {
			m, exists := g.members[name]
			if !exists || m.Disabled || m.Role != role || subtle.ConstantTimeCompare([]byte(m.Digest), []byte(digestSecret(r.PostForm.Get("password")))) != 1 {
				g.mu.Unlock()
				g.renderLogin(rw, 401, "账号或密码不正确。")
				return
			}
		}
		if !g.securityAuditContext(r.Context(), name, "login_success") {
			g.mu.Unlock()
			g.renderLogin(rw, 503, "安全日志无法写入，请检查数据目录。")
			return
		}
		g.sessions[sid] = adminSession{expiry: now.Add(8 * time.Hour), csrf: randomToken(), name: name, role: role, revision: g.revisions[name]}
		g.mu.Unlock()
		http.SetCookie(rw, sessionCookieFor(r, sid, 28800))
		http.Redirect(rw, r, "/", 303)
		return
	}
	if r.URL.Path == "/logout" || r.URL.Path == "/logout-all" {
		if r.Method != http.MethodPost {
			rw.Header().Set("Allow", "POST")
			http.Error(rw, "method not allowed", 405)
			return
		}
		r.Body = http.MaxBytesReader(rw, r.Body, 4096)
		if !ok || parseScalarForm(r) != nil || !g.w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("logout_csrf")), []byte(s.csrf)) != 1 {
			http.Error(rw, "请求无效", 403)
			return
		}
		if shared {
			if err := g.w.s.pg.revokeSharedSession(r.Context(), id, s.name, r.URL.Path == "/logout-all"); err != nil {
				http.Error(rw, "service unavailable", 503)
				return
			}
			http.SetCookie(rw, sessionCookieFor(r, "", -1))
			http.Redirect(rw, r, "/login", 303)
			return
		}
		g.mu.Lock()
		if r.URL.Path == "/logout-all" {
			for k, active := range g.sessions {
				if active.name == s.name {
					delete(g.sessions, k)
				}
			}
		} else {
			delete(g.sessions, id)
		}
		g.mu.Unlock()
		action := "logout"
		if r.URL.Path == "/logout-all" {
			action = "logout_all"
		}
		g.securityAuditContext(r.Context(), s.name, action)
		http.SetCookie(rw, sessionCookieFor(r, "", -1))
		http.Redirect(rw, r, "/login", 303)
		return
	}
	if ok {
		w := g.w
		w.csrf = s.csrf
		p := Principal{Name: s.name, Role: s.role}
		if s.role == "owner" {
			p.Members = g.memberList()
		}
		if r.URL.Path == "/account/password" {
			g.handleOwnerPassword(rw, r, s)
			return
		}
		p.OwnerConfigured = g.owner != nil
		if r.URL.Path == "/members" {
			g.handleMembers(rw, r, s)
			return
		}
		rr := withPrincipal(r.Clone(r.Context()), p)
		w.ServeHTTP(rw, rr)
		return
	}
	// Preserve explicit non-browser automation compatibility. Never prompt browsers for Basic Auth.
	if !shared && g.owner == nil && r.Header.Get("Authorization") != "" && r.Header.Get("Sec-Fetch-Site") == "" && !strings.Contains(r.Header.Get("Accept"), "text/html") {
		u, p, valid := r.BasicAuth()
		if !valid || u != "admin" || subtle.ConstantTimeCompare([]byte(p), []byte(g.w.token)) != 1 {
			if !g.budget() {
				rw.Header().Set("Retry-After", "60")
				http.Error(rw, "尝试次数过多，请稍后再试", 429)
				return
			}
			http.Error(rw, "请先登录", 401)
			return
		}
		g.w.ServeHTTP(rw, r)
		return
	}
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") && r.URL.Path == "/" {
		http.Redirect(rw, r, "/login", 303)
		return
	}
	http.Error(rw, "请先登录", 401)
}
