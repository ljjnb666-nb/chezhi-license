package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
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
	saltHex := randomToken()
	salt, _ := hex.DecodeString(saltHex)
	c := ownerCredential{1, saltHex, hex.EncodeToString(deriveOwner(password, salt, ownerRounds))}
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
	if e := g.w.s.recordAudit(actor, action, ""); e != nil {
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
	if !g.budget() {
		rw.Header().Set("Retry-After", "60")
		rw.WriteHeader(429)
		render("尝试次数过多，请稍后再试。")
		return
	}
	if !g.verifyOwner(r.PostForm.Get("current_password")) {
		g.securityAudit("admin", "password_failed")
		render("当前密码不正确。")
		return
	}
	if g.verifyOwner(p) {
		render("新密码不能与当前密码相同。")
		return
	}
	if e := g.saveOwner(p); e != nil {
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
	http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	if !g.securityAudit("admin", "password_changed") {
		g.renderLogin(rw, 200, "密码已更新，请使用新密码登录。安全日志写入失败，请检查数据目录。")
		return
	}
	http.Redirect(rw, r, "/login", 303)
}
