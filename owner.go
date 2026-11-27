package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

const ownerRounds = 600000

type ownerCredential struct {
	Version      int
	Salt, Digest string
}

// PBKDF2-HMAC-SHA256, one 32-byte block (RFC 8018).
func deriveOwner(password string, salt []byte, rounds int) []byte {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < rounds; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}
func (g *adminGateway) ownerPath() string {
	return filepath.Join(filepath.Dir(g.w.s.path), "owner.json")
}
func (g *adminGateway) loadOwner() error {
	b, e := os.ReadFile(g.ownerPath())
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return g.applyOwner(b)
}

func (g *adminGateway) applyOwner(b []byte) error {
	var c ownerCredential
	if len(b) > 4096 || uniqueJSON(b) != nil || json.Unmarshal(b, &c) != nil {
		return errors.New("invalid owner credential")
	}
	salt, se := hex.DecodeString(c.Salt)
	digest, de := hex.DecodeString(c.Digest)
	if c.Version != 1 || se != nil || de != nil || len(salt) != 32 || len(digest) != 32 {
		return errors.New("invalid owner credential")
	}
	g.owner = &c
	return nil
}
func (g *adminGateway) verifyOwner(password string) bool {
	if g.owner == nil {
		return subtle.ConstantTimeCompare([]byte(password), []byte(g.w.token)) == 1
	}
	if len(password) > 128 {
		return false
	}
	salt, _ := hex.DecodeString(g.owner.Salt)
	digest, _ := hex.DecodeString(g.owner.Digest)
	return subtle.ConstantTimeCompare(deriveOwner(password, salt, ownerRounds), digest) == 1
}
func (g *adminGateway) saveOwner(password string) error {
	return g.saveOwnerContext(context.Background(), password)
}
func deriveOwnerCredential(password string) ownerCredential {
	saltHex := randomToken()
	salt, _ := hex.DecodeString(saltHex)
	return ownerCredential{1, saltHex, hex.EncodeToString(deriveOwner(password, salt, ownerRounds))}
}
func (g *adminGateway) saveOwnerContext(ctx context.Context, password string) error {
	c := deriveOwnerCredential(password)
	if g.w.s.pg != nil {
		revision, err := g.w.s.pg.changeAccount(ctx, Audit{At: g.w.s.now().UTC(), Action: "password_changed", Actor: "admin"},
			func(ctx context.Context, tx *sql.Tx, revision int64) error { return writeOwner(ctx, tx, c, revision) })
		if err != nil {
			return err
		}
		g.owner = &c
		g.accountRevision = revision
		g.revisions["admin"] = revision
		return nil
	}
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(g.ownerPath()), ".owner-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), g.ownerPath()); e != nil {
		return e
	}
	g.owner = &c
	return nil
}
func (g *adminGateway) securityAudit(actor, action string) bool {
	return g.securityAuditContext(context.Background(), actor, action)
}
func (g *adminGateway) securityAuditContext(ctx context.Context, actor, action string) bool {
	if e := g.w.s.auditContext(ctx, actor, action, ""); e != nil {
		log.Print("security audit write failed: ", action)
		return false
	}
	return true
}
func (g *adminGateway) handleOwnerPassword(rw http.ResponseWriter, r *http.Request, s adminSession) {
	if s.role != "owner" || s.name != "admin" {
		http.Error(rw, "权限不足", 403)
		return
	}
	if r.Method != "POST" {
		rw.Header().Set("Allow", "POST")
		http.Error(rw, "请求方式无效", 405)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	if parseScalarForm(r) != nil || !g.w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
		http.Error(rw, "请求无效", 403)
		return
	}
	render := func(msg string) {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(rw, View{Section: "account", CSRF: s.csrf, Principal: Principal{Name: s.name, Role: s.role}, Error: msg, OwnerConfigured: g.owner != nil})
	}
	p := r.PostForm.Get("new_password")
	if len(p) > 128 || utf8.RuneCountInString(p) < 14 || !utf8.ValidString(p) || p != r.PostForm.Get("confirm_password") {
		render("请输入 14–128 字节范围内的长密码，并确保两次输入一致（至少 14 个字符）。")
		return
	}
	allowed := false
	if _, shared := r.Context().Value(serverRequestKey{}).(serverRequest); shared {
		var err error
		// All sessions, sources and instances share one budget for the owner.
		allowed, err = g.w.s.pg.allowShared(r.Context(), "account", digestSecret("account:"+s.name), 12, 5)
		if err != nil {
			rw.WriteHeader(http.StatusServiceUnavailable)
			render("密码验证暂不可用。")
			return
		}
	} else {
		allowed = g.budget()
	}
	if !allowed {
		rw.Header().Set("Retry-After", "60")
		rw.WriteHeader(429)
		render("尝试次数过多，请稍后再试。")
		return
	}
	if !g.verifyOwner(r.PostForm.Get("current_password")) {
		g.securityAuditContext(r.Context(), "admin", "password_failed")
		render("当前密码不正确。")
		return
	}
	if g.verifyOwner(p) {
		render("新密码不能与当前密码相同。")
		return
	}
	if e := g.saveOwnerContext(r.Context(), p); e != nil {
		render("密码保存失败，请检查数据目录。")
		return
	}
	g.mu.Lock()
	for k, v := range g.sessions {
		if v.name == "admin" {
			delete(g.sessions, k)
		}
	}
	g.mu.Unlock()
	http.SetCookie(rw, sessionCookieFor(r, "", -1))
	if g.w.s.pg == nil && !g.securityAudit("admin", "password_changed") {
		g.renderLogin(rw, 200, "密码已更新，请使用新密码登录。安全日志写入失败，请检查数据目录。")
		return
	}
	http.Redirect(rw, r, "/login", 303)
}

func (p *postgresStore) initializeOwner(ctx context.Context, password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 14 || len(password) > 128 {
		return errors.New("owner password must be 14 or more characters and at most 128 bytes")
	}
	credential := deriveOwnerCredential(password)
	_, err := p.changeAccount(ctx, Audit{At: time.Now().UTC(), Action: "password_changed", Actor: "admin"},
		func(ctx context.Context, tx *sql.Tx, revision int64) error {
			if err := verifyMigratorRole(ctx, tx); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM chezhi_owner)").Scan(&exists); err != nil {
				return errDatabase
			}
			if exists {
				return errors.New("owner password is already configured")
			}
			return writeOwner(ctx, tx, credential, revision)
		})
	return err
}
