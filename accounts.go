package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Internal prototype: member credentials are server-generated 256-bit random
// secrets, not user-chosen passwords. Store only their SHA-256 digest.
type Member struct {
	Name     string
	Role     string
	Digest   string
	Disabled bool
}
type Principal struct {
	Name, Role      string
	Members         []Member
	OwnerConfigured bool
}
type principalKey struct{}

func principal(r *http.Request) Principal {
	if p, ok := r.Context().Value(principalKey{}).(Principal); ok {
		return p
	}
	return Principal{Name: "admin", Role: "owner"}
}
func withPrincipal(r *http.Request, p Principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}

var memberName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{2,31}$`)

func digestSecret(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func (g *adminGateway) loadMembers() error {
	b, e := os.ReadFile(filepath.Join(filepath.Dir(g.w.s.path), "members.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var list []Member
	if e = uniqueJSON(b); e != nil {
		return e
	}
	if e = json.Unmarshal(b, &list); e != nil {
		return e
	}
	if len(list) > 100 {
		return errors.New("invalid member count")
	}
	for _, m := range list {
		_, err := hex.DecodeString(m.Digest)
		if !memberName.MatchString(m.Name) || m.Name == "admin" || (m.Role != "operator" && m.Role != "viewer") || len(m.Digest) != 64 || err != nil {
			return errors.New("invalid member")
		}
		if _, ok := g.members[m.Name]; ok {
			return errors.New("duplicate member")
		}
		g.members[m.Name] = m
	}
	return nil
}
func (g *adminGateway) saveMembers(next map[string]Member) error {
	list := make([]Member, 0, len(next))
	for _, m := range next {
		list = append(list, m)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, e := json.MarshalIndent(list, "", "  ")
	if e != nil {
		return e
	}
	dir := filepath.Dir(g.w.s.path)
	f, e := os.CreateTemp(dir, ".members-*")
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
	if e = os.Rename(f.Name(), filepath.Join(dir, "members.json")); e != nil {
		return e
	}
	g.members = next
	return nil
}
func (g *adminGateway) authenticate(name, password string) (string, bool) {
	if name == "admin" {
		return "owner", g.verifyOwner(password)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.members[name]
	return m.Role, ok && !m.Disabled && subtle.ConstantTimeCompare([]byte(m.Digest), []byte(digestSecret(password))) == 1
}
func (g *adminGateway) memberList() []Member {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []Member{}
	for _, m := range g.members {
		m.Digest = ""
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (g *adminGateway) updateMember(name, role, action string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !memberName.MatchString(name) || name == "admin" {
		return "", errors.New("账号格式无效或为保留账号。")
	}
	m, exists := g.members[name]
	next := make(map[string]Member, len(g.members)+1)
	for k, v := range g.members {
		next[k] = v
	}
	secret := ""
	switch action {
	case "member-create":
		if exists || len(next) >= 100 || (role != "operator" && role != "viewer") {
			return "", errors.New("账号已存在、角色无效或已达数量上限。")
		}
		secret = randomToken()
		m = Member{Name: name, Role: role, Digest: digestSecret(secret)}
	case "member-reset":
		if !exists {
			return "", errors.New("账号不存在。")
		}
		secret = randomToken()
		m.Digest = digestSecret(secret)
	case "member-role":
		if !exists || (role != "operator" && role != "viewer") {
			return "", errors.New("账号或角色无效。")
		}
		m.Role = role
	case "member-disable", "member-enable":
		if !exists {
			return "", errors.New("账号不存在。")
		}
		m.Disabled = action == "member-disable"
	default:
		return "", errors.New("不支持的操作。")
	}
	next[name] = m
	if e := g.saveMembers(next); e != nil {
		return "", errors.New("保存失败，请检查数据目录。")
	}
	for k, s := range g.sessions {
		if s.name == name {
			delete(g.sessions, k)
		}
	}
	return secret, nil
}
func viewAllowed(role, section string) bool {
	if role == "owner" {
		return true
	}
	switch section {
	case "overview", "cards", "orders", "devices", "account":
		return role == "operator" || role == "viewer"
	case "issue":
		return role == "operator"
	}
	return false
}
func actionAllowed(role, action string) bool {
	return role == "owner" || role == "operator" && action == "issue"
}
func roleLabel(role string) string {
	switch role {
	case "owner":
		return "主管理员"
	case "operator":
		return "发卡员"
	case "viewer":
		return "只读成员"
	}
	return "未知"
}

// Owner-only, consistent business-data snapshot; no member credentials or live sessions.
func (s *Store) backup() ([]byte, error) {
	s.mu.Lock()
	state, e := json.MarshalIndent(s.state, "", "  ")
	plans, e2 := json.MarshalIndent(s.plans, "", "  ")
	s.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if e2 != nil {
		return nil, e2
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	manifest := map[string]string{}
	for _, entry := range []struct {
		name string
		data []byte
	}{{"state.json", state}, {"plans.json", plans}} {
		f, e := z.Create(entry.name)
		if e != nil {
			return nil, e
		}
		if _, e = f.Write(entry.data); e != nil {
			return nil, e
		}
		h := sha256.Sum256(entry.data)
		manifest[entry.name] = hex.EncodeToString(h[:])
	}
	f, e := z.Create("manifest.json")
	if e != nil {
		return nil, e
	}
	if e = json.NewEncoder(f).Encode(struct {
		Format  int
		Created time.Time
		SHA256  map[string]string
	}{1, time.Now().UTC(), manifest}); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func (w Web) downloadBackup(rw http.ResponseWriter, r *http.Request) {
	if principal(r).Role != "owner" {
		http.Error(rw, "权限不足", 403)
		return
	}
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", "POST")
		http.Error(rw, "请求方式无效", 405)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	if parseScalarForm(r) != nil || !w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(w.csrf)) != 1 {
		http.Error(rw, "请求无效", 403)
		return
	}
	if r.URL.Path == "/export" {
		w.exportCards(rw)
		return
	}
	b, e := w.s.backup()
	if e != nil {
		http.Error(rw, "备份失败", 500)
		return
	}
	rw.Header().Set("Content-Type", "application/zip")
	rw.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="chezhi-backup-%s.zip"`, time.Now().UTC().Format("20060102-150405")))
	rw.Write(b)
}
func (g *adminGateway) handleMembers(rw http.ResponseWriter, r *http.Request, s adminSession) {
	if s.role != "owner" {
		http.Error(rw, "权限不足", 403)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(rw, "请求方式无效", 405)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4096)
	if parseScalarForm(r) != nil || !g.w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.csrf)) != 1 {
		http.Error(rw, "请求无效", 403)
		return
	}
	credential, e := g.updateMember(r.PostForm.Get("name"), r.PostForm.Get("role"), r.PostForm.Get("action"))
	v := View{Section: "members", CSRF: s.csrf, Principal: Principal{Name: s.name, Role: s.role, Members: g.memberList()}, Credential: credential}
	if e != nil {
		v.Error = e.Error()
	} else {
		v.Message = "账户设置已保存。"
		if g.w.s.recordAudit(s.name, r.PostForm.Get("action"), r.PostForm.Get("name")) != nil {
			v.Error = "账户已更新，但操作日志写入失败，请检查数据目录。"
		}
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	_ = page.Execute(rw, v)
}

// Prefix spreadsheet-formula-like text, including whitespace-prefixed formulas.
func safeCSV(s string) string {
	t := strings.TrimLeft(s, " \t\r\n")
	if t != s || (len(t) > 0 && strings.ContainsRune("=+-@", rune(t[0]))) {
		return "'" + s
	}
	return s
}
func (w Web) exportCards(rw http.ResponseWriter) {
	state := w.s.snapshot()
	var b bytes.Buffer
	b.WriteString("\xef\xbb\xbf")
	c := csv.NewWriter(&b)
	_ = c.Write([]string{"卡密前缀", "套餐", "订单编号", "付款渠道", "单价（元）", "状态", "生成时间", "首次激活", "到期时间"})
	now := w.s.now()
	for _, v := range state.Cards {
		_ = c.Write([]string{safeCSV(v.Prefix), plan(v.Days), safeCSV(v.SaleRef), channelName(v.Channel), money(int64(v.AmountCents)), cardStatus(v, now), localTime(v.Created), when(v.Activated), when(v.Expires)})
	}
	c.Flush()
	if c.Error() != nil {
		http.Error(rw, "导出失败", 500)
		return
	}
	rw.Header().Set("Content-Type", "text/csv; charset=utf-8")
	rw.Header().Set("Content-Disposition", `attachment; filename="chezhi-cards.csv"`)
	rw.Write(b.Bytes())
}
