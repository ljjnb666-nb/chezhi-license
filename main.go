package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed admin-ui.js
var adminJS string

//go:embed index.html
var html string

//go:embed purchase.html
var purchaseHTML string
var purchasePage = template.Must(template.New("purchase").Parse(purchaseHTML))

//go:embed activate.html
var activationHTML string
var funcs = template.FuncMap{"plan": plan, "when": when, "localTime": localTime, "status": cardStatus, "money": money, "unitMoney": func(c int) string { return money(int64(c)) }, "channel": channelName, "auditLabel": auditLabel, "roleLabel": roleLabel, "viewAllowed": viewAllowed, "actionAllowed": actionAllowed}
var page = template.Must(template.New("index").Funcs(funcs).Parse(html))
var activationPage = template.Must(template.New("activate").Funcs(funcs).Parse(activationHTML))

func randomToken() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}

type Web struct {
	s                 *Store
	token, csrf, host string
}
type View struct {
	Dashboard            Dashboard
	Operations           Operations
	Section              string
	Plans                []Plan
	CSRF, Message, Error string
	Keys                 []string
	Now                  time.Time
	Principal            Principal
	Credential           string
	OwnerConfigured      bool
}

func (w Web) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	// Preserve the same-origin Origin header on native browser form POSTs.
	// no-referrer may make Origin opaque (null), which our CSRF gate rejects.
	rw.Header().Set("Referrer-Policy", "same-origin")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Host != w.host {
		http.Error(rw, "invalid host", 400)
		return
	}
	if r.URL.Path == "/purchase" {
		w.purchase(rw, r)
		return
	}
	if r.URL.Path == "/api/demo/activate" {
		w.demoActivate(rw, r)
		return
	}
	if r.URL.Path == "/activate" {
		w.activate(rw, r)
		return
	}
	u, p, ok := r.BasicAuth()
	if !ok || u != "admin" || subtle.ConstantTimeCompare([]byte(p), []byte(w.token)) != 1 {
		rw.Header().Set("WWW-Authenticate", `Basic realm="CheZhi Local Prototype"`)
		http.Error(rw, "authentication required", 401)
		return
	}
	if r.URL.Path == "/admin-ui.js" {
		if r.Method != http.MethodGet {
			rw.Header().Set("Allow", "GET")
			http.Error(rw, "method not allowed", 405)
			return
		}
		rw.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = rw.Write([]byte(adminJS))
		return
	}
	if r.URL.Path == "/backup" || r.URL.Path == "/export" {
		w.downloadBackup(rw, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	v := View{OwnerConfigured: principal(r).OwnerConfigured, CSRF: w.csrf, Now: w.s.now().UTC(), Section: adminSection(r.URL.Query()), Principal: principal(r)}
	if !viewAllowed(v.Principal.Role, v.Section) {
		http.Error(rw, "权限不足", 403)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(rw, r.Body, 8192)
		if e := parseScalarForm(r); e != nil {
			http.Error(rw, "invalid form", 400)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(w.csrf)) != 1 {
			http.Error(rw, "invalid form token", 403)
			return
		}
		if !w.originOK(r) {
			http.Error(rw, "invalid origin", 403)
			return
		}
		f := r.PostForm.Get
		if !actionAllowed(v.Principal.Role, f("action")) {
			http.Error(rw, "权限不足", 403)
			return
		}
		var e error
		switch f("action") {
		case "issue":
			v.Section = "issue"
			var d, n, a int
			days := f("days")
			if preset := f("preset"); preset != "" && preset != "custom" {
				switch preset {
				case "0", "1", "7", "30", "90", "365":
					days = preset
				default:
					days = "invalid"
				}
			}
			d, e = strconv.Atoi(days)
			if e == nil {
				n, e = strconv.Atoi(f("quantity"))
			}
			if e == nil {
				a, e = parseIssueAmount(r.PostForm)
			}
			if e == nil && f("confirmed") != "yes" {
				e = errors.New("confirm receipt / test before issuing")
			}
			if e == nil {
				v.Keys, e = w.s.issueContext(r.Context(), d, n, a, f("channel"), f("sale_ref"), v.Principal.Name)
			}
			if e == nil {
				v.Message = "已生成，请立即复制卡密。"
			}
		case "revoke", "unbind":
			v.Section = "cards"
			e = w.s.changeContext(r.Context(), []string{f("id")}, f("action"), v.Principal.Name)
			if e == nil {
				v.Message = "操作完成"
			}
		case "batch-revoke", "batch-unbind":
			v.Section = "cards"
			if f("confirm_batch") != "yes" {
				e = errors.New("请确认批量操作")
			} else {
				e = w.s.changeContext(r.Context(), r.PostForm["ids"], strings.TrimPrefix(f("action"), "batch-"), v.Principal.Name)
			}
			if e == nil {
				v.Message = "批量操作完成"
			}
		case "plans":
			v.Section = "plans"
			e = w.s.savePlansContext(r.Context(), r.PostForm, v.Principal.Name)
			if e == nil {
				v.Message = "套餐设置已保存"
				if w.s.pg == nil && w.s.recordAudit(v.Principal.Name, "plans_config", "") != nil {
					v.Error = "套餐已保存，但操作日志写入失败，请检查数据目录。"
				}
			}
		case "qq":
			v.Section = "settings"
			e = w.s.setQQContext(r.Context(), f("qq"), v.Principal.Name)
			if e == nil {
				v.Message = "客服配置已保存"
			}
		default:
			e = errors.New("unknown action")
		}
		if e != nil {
			v.Error = adminError(e)
		}
	} else if r.Method != http.MethodGet {
		rw.Header().Set("Allow", "GET, POST")
		http.Error(rw, "method not allowed", 405)
		return
	}
	snapshot, plans, err := w.s.readView(r.Context(), true)
	if err != nil && len(v.Keys) == 0 && v.Message == "" {
		http.Error(rw, "service unavailable", 503)
		return
	}
	// Deliver committed one-time keys even if a subsequent display read fails.
	v.Plans = plans
	v.Dashboard = buildDashboard(snapshot, v.Now, r.URL.Query())
	v.Operations = buildOperations(snapshot, v.Now, v.Section, r.URL.Query())
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if e := page.Execute(rw, v); e != nil {
		log.Print("render failed")
	}
}
func (w Web) originOK(r *http.Request) bool {
	o := r.Header.Values("Origin")
	return len(o) == 0 || len(o) == 1 && o[0] == "http://"+w.host
}
func (w Web) activationCSRF() string {
	mac := hmac.New(sha256.New, []byte(w.csrf))
	mac.Write([]byte("local-activation-form-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

type ActivationView struct{ QQ, CSRF, Message, Error, Expiry string }

func (w Web) activate(rw http.ResponseWriter, r *http.Request) {
	state, _, err := w.s.readView(r.Context(), false)
	if err != nil {
		http.Error(rw, "service unavailable", 503)
		return
	}
	v := ActivationView{QQ: state.QQ, CSRF: w.activationCSRF()}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(rw, r.Body, 8192)
		if err := parseScalarForm(r); err != nil {
			http.Error(rw, "invalid form", 400)
			return
		}
		if !w.originOK(r) || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(v.CSRF)) != 1 {
			http.Error(rw, "invalid form origin or token", 403)
			return
		}
		if !w.s.allowActivation() {
			rw.Header().Set("Retry-After", "60")
			http.Error(rw, "操作过于频繁，请稍后重试", 429)
			return
		}
		res, err := w.s.validateContext(r.Context(), r.PostForm.Get("key"), r.PostForm.Get("device"))
		if err != nil {
			v.Error = "授权服务暂不可用"
		} else if !res.Valid {
			v.Error = "授权拒绝：" + res.Reason
		} else {
			v.Message = "授权验证成功"
			v.Expiry = "永久"
			if res.ExpiresAt != nil {
				v.Expiry = when(res.ExpiresAt) + "（北京时间）"
			}
		}
	} else if r.Method != http.MethodGet {
		rw.Header().Set("Allow", "GET, POST")
		http.Error(rw, "method not allowed", 405)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := activationPage.Execute(rw, v); err != nil {
		log.Print("activation render failed")
	}
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "db-init", "db-check", "db-import":
			return databaseCommand(ctx, args)
		}
	}
	backend := os.Getenv("CHEZHI_STORAGE")
	var s *Store
	switch backend {
	case "postgres":
		p, err := openPostgres(ctx, os.Getenv("CHEZHI_DATABASE_URL"))
		if err != nil {
			return err
		}
		defer p.db.Close()
		if err = p.checkSchema(ctx); err != nil {
			return err
		}
		s = &Store{pg: p, now: time.Now}
	case "", "json":
		var release func()
		var err error
		s, release, err = openLocalRuntime(args)
		if err != nil {
			return err
		}
		defer release()
	default:
		return errors.New("CHEZHI_STORAGE must be json or postgres")
	}
	return serve(ctx, s)
}
func openLocalRuntime(args []string) (*Store, func(), error) {
	dir := "data"
	if len(args) > 0 {
		dir = args[0]
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, nil, e
	}
	lock := filepath.Join(dir, "instance.lock")
	f, e := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, nil, errors.New("data directory locked; stop previous instance first")
	}
	f.Close()
	release := func() { _ = os.Remove(lock) }
	s, e := openStore(filepath.Join(dir, "state.json"))
	if e != nil {
		release()
		return nil, nil, fmt.Errorf("cannot load state: %w", e)
	}
	return s, release, nil
}
func serve(ctx context.Context, s *Store) error {
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return e
	}
	host := ln.Addr().String()
	token := randomToken()
	gateway := newAdminGateway(Web{s, token, randomToken(), host})
	if gateway.loadErr != nil {
		ln.Close()
		return fmt.Errorf("cannot load account configuration: %w", gateway.loadErr)
	}
	displayPassword := token
	if gateway.owner != nil {
		displayPassword = "(configured; use your saved password)"
	}
	srv := &http.Server{Handler: gateway, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fmt.Printf("CheZhi License P2.2\nURL: http://%s/\nUser: admin\nPassword: %s\nLocal-only; close with Ctrl+C.\n", host, displayPassword)
	done := make(chan struct{})
	shutdown := make(chan struct{})
	go func() {
		defer close(shutdown)
		select {
		case <-done:
		case <-ctx.Done():
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if srv.Shutdown(c) != nil {
				_ = srv.Close()
			}
		}
	}()
	e = srv.Serve(ln)
	close(done)
	<-shutdown
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
