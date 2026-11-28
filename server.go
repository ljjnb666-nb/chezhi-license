package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type serverConfig struct {
	demo                                               bool
	signer *serverSigner
	listen, diagnostics, origin, host, csrf            string
	proxy                                              []netip.Prefix
	certificate                                        *tls.Certificate
	secure                                             bool
	loginRate, licenseRate, publicRate, maxConnections int
}
type serverRequestKey struct{}
type serverRequest struct {
	config     *serverConfig
	source, id string
	secure     bool
}

func listenAddress(raw string, allowZero bool) (netip.Addr, error) {
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return netip.Addr{}, errors.New("listen address must use IP:port")
	}
	address, err := netip.ParseAddr(host)
	n, e := strconv.ParseUint(port, 10, 16)
	if err != nil || e != nil || address.Zone() != "" || n == 0 && !allowZero {
		return netip.Addr{}, errors.New("invalid listen address")
	}
	return address.Unmap(), nil
}

func readProtectedInput(setting string, limit int64) (string, error) {
	f, err := os.Open(os.Getenv(setting))
	if err != nil {
		return "", fmt.Errorf("%s must reference a readable secret file", setting)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(b) == 0 || int64(len(b)) > limit {
		return "", fmt.Errorf("invalid %s", setting)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

var hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validPublicHost(u *url.URL) bool {
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if raw := u.Port(); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || n == 0 {
			return false
		}
	}
	host := u.Hostname()
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func loadServerConfig(mode string) (serverConfig, error) {
	c := serverConfig{listen: os.Getenv("CHEZHI_LISTEN"), diagnostics: os.Getenv("CHEZHI_DIAGNOSTICS"),
		loginRate: 5, licenseRate: 60, publicRate: 240, maxConnections: 128}
	if c.listen == "" {
		c.listen = "127.0.0.1:8080"
	}
	address, err := listenAddress(c.listen, false)
	if err != nil {
		return c, err
	}
	if c.diagnostics != "" {
		addr, err := listenAddress(c.diagnostics, false)
		if err != nil || !addr.IsLoopback() {
			return c, errors.New("diagnostics must use a loopback listen address")
		}
	}
	raw := os.Getenv("CHEZHI_PUBLIC_ORIGIN")
	u, err := url.Parse(raw)
	if err != nil || !validPublicHost(u) || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.ContainsAny(raw, "#%\r\n") ||
		(u.Path != "" && u.Path != "/") || u.Scheme != "https" && u.Scheme != "http" {
		return c, errors.New("CHEZHI_PUBLIC_ORIGIN must be an absolute HTTP(S) origin")
	}
	c.secure = u.Scheme == "https"
	c.host = u.Host
	c.origin = u.Scheme + "://" + u.Host
	proxy := os.Getenv("CHEZHI_TRUSTED_PROXIES")
	for _, value := range strings.Split(proxy, ",") {
		if proxy == "" {
			break
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || p.Bits() == 0 || p.Addr().Is4In6() {
			return c, errors.New("invalid trusted proxy CIDR")
		}
		c.proxy = append(c.proxy, p.Masked())
	}
	cert, key := os.Getenv("CHEZHI_TLS_CERT"), os.Getenv("CHEZHI_TLS_KEY")
	if cert != "" || key != "" {
		if len(c.proxy) > 0 || !c.secure {
			return c, errors.New("direct TLS and trusted proxy configuration are mutually exclusive")
		}
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return c, errors.New("cannot load TLS key pair")
		}
		if pair.Leaf == nil || pair.Leaf.VerifyHostname(u.Hostname()) != nil ||
			time.Now().Before(pair.Leaf.NotBefore) || time.Now().After(pair.Leaf.NotAfter) {
			return c, errors.New("TLS certificate does not cover the public origin or is outside its validity period")
		}
		c.certificate = &pair
	}
	if mode == "test" {
		c.demo = true
		published, err := netip.ParseAddr(u.Hostname())
		if !address.IsLoopback() || err != nil || !published.IsLoopback() || len(c.proxy) > 0 {
			return c, errors.New("test mode requires loopback addresses and cannot use forwarded transport")
		}
	} else if !c.secure {
		return c, errors.New("standalone server requires an HTTPS public origin")
	}
	if c.secure && c.certificate == nil && len(c.proxy) == 0 || !c.secure && len(c.proxy) > 0 {
		return c, errors.New("configure direct TLS or an HTTPS trusted proxy")
	}
	c.csrf, err = readProtectedInput("CHEZHI_CSRF_KEY_FILE", 128)
	if err != nil {
		return c, err
	}
	if b, err := hex.DecodeString(c.csrf); err != nil || len(b) != 32 {
		return c, errors.New("CSRF key file must contain 64 hex characters")
	}
	for _, opt := range []struct {
		name   string
		target *int
		max    int
	}{
		{"CHEZHI_LOGIN_PER_MINUTE", &c.loginRate, 30},
		{"CHEZHI_LICENSE_PER_MINUTE", &c.licenseRate, 600},
		{"CHEZHI_LICENSE_GLOBAL_PER_MINUTE", &c.publicRate, 3000},
	} {
		if value := os.Getenv(opt.name); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > opt.max {
				return c, fmt.Errorf("invalid %s", opt.name)
			}
			*opt.target = n
		}
	}
	if val := os.Getenv("CHEZHI_MAX_CONNECTIONS"); val != "" {
		count, err := strconv.Atoi(val)
		if err != nil || count < 16 || count > 1024 {
			return c, errors.New("invalid CHEZHI_MAX_CONNECTIONS")
		}
		c.maxConnections = count
	}
	if c.licenseRate > c.publicRate {
		return c, errors.New("license source limit exceeds global limit")
	}
	return c, nil
}

func (c *serverConfig) source(r *http.Request) (string, bool) {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	source := remote.Addr().Unmap()
	if len(c.proxy) == 0 {
		return source.String(), !c.secure || r.TLS != nil
	}
	for _, proxy := range c.proxy {
		if !proxy.Contains(source) {
			continue
		}
		proto, forwarded := r.Header.Values("X-Forwarded-Proto"), r.Header.Values("X-Forwarded-For")
		if len(proto) != 1 || proto[0] != "https" || len(forwarded) != 1 {
			return "", false
		}
		ip, err := netip.ParseAddr(forwarded[0])
		if err != nil || ip.Zone() != "" {
			return "", false
		}
		return ip.Unmap().String(), true
	}
	return "", false
}

type requestMetric struct{ count, failed, nanos atomic.Int64 }
type serverRouter struct {
	config                       *serverConfig
	gateway                      *adminGateway
	pg                           *postgresStore
	public, admin, adminIssue, export, ready chan struct{}
	admissionRejected [4]atomic.Uint64
	metrics                      [3]requestMetric
	draining                     atomic.Bool
}

type connectionLimit struct {
	net.Listener
	open      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

func limitConnections(listener net.Listener, n int) *connectionLimit {
	return &connectionLimit{Listener: listener, open: make(chan struct{}, n), closed: make(chan struct{})}
}

func (l *connectionLimit) Accept() (net.Conn, error) {
	select {
	case l.open <- struct{}{}:
	case <-l.closed:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.open
		return nil, err
	}
	return &limitedConnection{Conn: c, release: func() { <-l.open }}, nil
}

func (l *connectionLimit) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type serverResponse struct {
	http.ResponseWriter
	status int
}

func (w *serverResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *serverResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}
func (w *serverResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Reserve one slot for the canonical issuance page POST. This is a
// scheduling hint only: the query does not confer authorization or imply
// the form action. All other admin requests retain the original shared
// admission capacity, including concurrent credential-rate checks.
func (h *serverRouter) adminQueue(r *http.Request) (chan struct{}, int) {
	if r.Method == http.MethodPost && r.URL.Path == "/" && r.URL.RawQuery == "view=issue" {
		return h.adminIssue, 1
	}
	return h.admin, 0
}

func (h *serverRouter) ServeHTTP(raw http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	w := &serverResponse{ResponseWriter: raw}
	start := time.Now()
	id := randomToken()[:32]
	group, label := 0, "admin"
	queue, admission := h.adminQueue(r)
	v2 := isV2Path(r.URL.Path)
	isAPI := v2 || strings.HasPrefix(r.URL.Path, "/api/v1/") || r.URL.Path == "/api/v1"
	switch {
	case isAPI || r.URL.Path == "/activate" || r.URL.Path == "/purchase" || r.URL.Path == "/api/demo/activate":
		group, label, queue = 1, "public", h.public
		admission = 2
	case r.URL.Path == "/healthz" || r.URL.Path == "/readyz":
		group, label = 2, "health"
	}
	defer func() {
		elapsed := time.Since(start)
		h.metrics[group].count.Add(1)
		h.metrics[group].nanos.Add(elapsed.Nanoseconds())
		if w.status >= 500 {
			h.metrics[group].failed.Add(1)
		}
		slog.Info("http_request", "id", id, "group", label, "status", w.status, "duration_ms", elapsed.Milliseconds())
	}()
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.config.secure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	reject := func(status int, code string) {
		if v2 {
			writeV2(w,status,id,nil,code)
			return
		}
		if isAPI {
			writeAPI(w, status, id, nil, code)
			return
		}
		http.Error(w, http.StatusText(status), status)
	}
	if r.Host != h.config.host {
		reject(400, "invalid_host")
		return
	}
	source, ok := h.config.source(r)
	if !ok {
		reject(403, "invalid_transport")
		return
	}
	if r.URL.Path == "/api/demo/activate" && !h.config.demo {
		reject(404, "not_found")
		return
	}
	if group == 2 {
		h.health(w, r.WithContext(ctx))
		return
	}
	if h.draining.Load() {
		reject(503, "unavailable")
		return
	}
	select {
	case queue <- struct{}{}:
		defer func() { <-queue }()
	default:
		h.admissionRejected[admission].Add(1)
		w.Header().Set("Retry-After", "1")
		reject(503, "busy")
		return
	}
	if r.URL.Path == "/export" || r.URL.Path == "/backup" {
		select {
		case h.export <- struct{}{}:
			defer func() { <-h.export }()
		default:
			h.admissionRejected[3].Add(1)
			reject(503, "busy")
			return
		}
	}
	settings := serverRequest{config: h.config, source: keyedDigest(h.config.csrf, "ip:"+source), id: id, secure: h.config.secure}
	// Admin authentication reads a request-local account snapshot. PostgreSQL
	// serializes shared session and account writes at their transaction boundary.
	requestGateway := &adminGateway{w: h.gateway.w, now: time.Now}
	requestGateway.ServeHTTP(w, r.WithContext(context.WithValue(ctx, serverRequestKey{}, settings)))
}

func (h *serverRouter) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", 405)
		return
	}
	if r.URL.Path == "/readyz" {
		select {
		case h.ready <- struct{}{}:
			defer func() { <-h.ready }()
		default:
			http.Error(w, "unavailable", 503)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if h.draining.Load() || !h.pg.serverReady(ctx) {
			http.Error(w, "unavailable", 503)
			return
		}
	}
	w.WriteHeader(200)
	if r.Method == "GET" {
		fmt.Fprintln(w, "ok")
	}
}

func (h *serverRouter) diagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Host != h.config.diagnostics {
		http.Error(w, "invalid host", 400)
		return
	}
	switch r.URL.Path {
	case "/healthz", "/readyz":
		h.health(w, r)
	case "/metrics":
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", 405)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for i, label := range []string{"admin", "public", "health"} {
			m := &h.metrics[i]
			fmt.Fprintf(w, "chezhi_http_requests_total{group=%q} %d\nchezhi_http_errors_total{group=%q} %d\nchezhi_http_duration_seconds_sum{group=%q} %f\n",
				label, m.count.Load(), label, m.failed.Load(), label, float64(m.nanos.Load())/1e9)
		}
		for i, label := range []string{"admin_shared", "admin_issue", "public", "export"} {
			fmt.Fprintf(w, "chezhi_admission_rejected_total{group=%q} %d\n", label, h.admissionRejected[i].Load())
		}
		s := h.pg.db.Stats()
		fmt.Fprintf(w, "chezhi_db_connections_open %d\nchezhi_db_connections_in_use %d\nchezhi_db_connections_idle %d\nchezhi_db_pool_waits_total %d\n", s.OpenConnections, s.InUse, s.Idle, s.WaitCount)
	default:
		http.NotFound(w, r)
	}
}

func serveIndependent(ctx context.Context, c serverConfig, p *postgresStore) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := p.transaction(ctx, &sql.TxOptions{ReadOnly: true}, verifyRuntimeRole); err != nil {
		return errors.New("standalone server requires the restricted PostgreSQL runtime grants; run db-check --runtime")
	}
	signer, err := p.configureSigner(ctx)
	if err != nil { return err }
	if signer != nil && !c.secure { return errors.New("secure signing requires HTTPS") }
	c.signer = signer
	listener, err := net.Listen("tcp", c.listen)
	if err != nil {
		return errors.New("cannot open configured listener")
	}
	defer listener.Close()
	gateway := newAdminGateway(Web{&Store{pg: p, now: time.Now}, randomToken(), c.csrf, c.host})
	if gateway.loadErr != nil || gateway.owner == nil {
		return errors.New("server requires a configured owner credential; run db-owner-init")
	}
	h := &serverRouter{config: &c, gateway: gateway, pg: p, admin: make(chan struct{}, 8), adminIssue: make(chan struct{}, 1), public: make(chan struct{}, 3), export: make(chan struct{}, 1), ready: make(chan struct{}, 2)}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)}
	if c.certificate != nil {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*c.certificate}}
	}
	var diagnostic *http.Server
	errs := make(chan error, 2)
	if c.diagnostics != "" {
		local, err := net.Listen("tcp", c.diagnostics)
		if err != nil {
			return errors.New("cannot open diagnostics listener")
		}
		defer local.Close()
		diagnostic = &http.Server{Handler: http.HandlerFunc(h.diagnostics), ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
		go func() { errs <- diagnostic.Serve(limitConnections(local, 16)) }()
	}
	go func() {
		limited := limitConnections(listener, c.maxConnections)
		if c.certificate != nil {
			errs <- srv.ServeTLS(limited, "", "")
			return
		}
		errs <- srv.Serve(limited)
	}()
	maintenance, stop := context.WithCancel(ctx)
	defer stop()
	maintained := make(chan struct{})
	go func() {
		defer close(maintained)
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-maintenance.Done():
				return
			case <-tick.C:
				if p.cleanShared(maintenance) != nil && maintenance.Err() == nil {
					slog.Warn("shared_state_cleanup_failed")
				}
			}
		}
	}()
	slog.Info("server_started", "transport", strings.Split(c.origin, ":")[0])
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
	}
	h.draining.Store(true)
	stop()
	deadline, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if srv.Shutdown(deadline) != nil {
		_ = srv.Close()
	}
	if diagnostic != nil && diagnostic.Shutdown(deadline) != nil {
		_ = diagnostic.Close()
	}
	<-maintained
	slog.Info("server_stopped")
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return errors.New("server listener failed")
	}
	return nil
}

func keyedDigest(key, domain string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(domain))
	return hex.EncodeToString(mac.Sum(nil))
}

func configuredDatabaseURL() (string, error) {
	value := os.Getenv("CHEZHI_DATABASE_URL")
	if os.Getenv("CHEZHI_DATABASE_URL_FILE") == "" {
		return value, nil
	}
	if value != "" {
		return "", errors.New("configure only one database URL source")
	}
	return readProtectedInput("CHEZHI_DATABASE_URL_FILE", 4096)
}

func probeReadiness(ctx context.Context) error {
	target := os.Getenv("CHEZHI_DIAGNOSTICS")
	ip, err := listenAddress(target, false)
	if err != nil || !ip.IsLoopback() {
		return errors.New("probe requires a loopback diagnostics address")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/readyz", nil)
	if err != nil {
		return errors.New("invalid probe address")
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{}}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return errors.New("readiness probe failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("server is not ready")
	}
	return nil
}

func (p *postgresStore) serverReady(ctx context.Context) bool {
	if p.checkSchema(ctx) != nil || p.checkDeployment(ctx, p.db) != nil {
		return false
	}
	var ready bool
	err := p.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM chezhi_owner)
      AND EXISTS(SELECT FROM chezhi_config)
      AND to_regclass('public.chezhi_sessions') IS NOT NULL
      AND to_regclass('public.chezhi_rate_limits') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}
