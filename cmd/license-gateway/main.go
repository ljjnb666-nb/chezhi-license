// A deliberately narrow, loopback-only gateway for the independent licensing API.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"sync"
	"time"
)

const origin = "https://127.0.0.1:18443"
const listen = "127.0.0.1:18445"
const maxBody = 4096
const maxReply = 32768

var dnsName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func allowed(path string) bool {
	switch path {
	case "/api/v2/licenses/challenge", "/api/v2/licenses/activate", "/api/v2/licenses/validate", "/api/v2/licenses/renew":
		return true
	}
	return false
}

type gateway struct {
	host string
	upstream *url.URL
	client *http.Client
	slots chan struct{}
}

func newGateway(host, target string, roots *x509.CertPool) (*gateway, error) {
	if len(host) > 253 || !dnsName.MatchString(host) || net.ParseIP(host) != nil || roots == nil {
		return nil, errors.New("explicit DNS hostname and private origin trust required")
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("invalid loopback TLS origin")
	}
	t := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{Timeout: 3*time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "127.0.0.1"},
		TLSHandshakeTimeout: 3*time.Second,
		ResponseHeaderTimeout: 8*time.Second,
		MaxConnsPerHost: 8, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30*time.Second,
		DisableCompression: true,
	}
	return &gateway{host:host, upstream:u, client:&http.Client{
		Transport:t, Timeout:12*time.Second,
		CheckRedirect:func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, slots:make(chan struct{},8)}, nil
}

func reject(w http.ResponseWriter, status int, code string) {
	var raw [16]byte
	if _,err:=rand.Read(raw[:]); err!=nil {
		// Fail closed if the OS cannot supply a request identifier.
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	id:=hex.EncodeToString(raw[:])
	w.Header().Set("Content-Type","application/json")
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("X-Request-ID",id)
	w.WriteHeader(status)
	fmt.Fprintf(w, "{\"version\":\"v2\",\"request_id\":%q,\"error\":{\"code\":%q}}\n",id,code)
}

// Enforce the outer V2 envelope. The authorization client must still
// independently validate every signed claim; this is not signature verification.
func responseID(data []byte, status int, ids []string) (string, bool) {
	if len(ids)!=1 || len(ids[0])!=32 { return "",false }
	b,err:=hex.DecodeString(ids[0])
	if err!=nil || hex.EncodeToString(b)!=ids[0] { return "",false }
	d:=json.NewDecoder(bytes.NewReader(data))
	first,err:=d.Token()
	if err!=nil || first!=json.Delim('{') { return "",false }
	fields:=map[string]json.RawMessage{}
	for d.More() {
		key,err:=d.Token()
		name,ok:=key.(string)
		if err!=nil || !ok || len(fields)>=3 { return "",false }
		if _,exists:=fields[name]; exists { return "",false }
		var raw json.RawMessage
		if d.Decode(&raw)!=nil { return "",false }
		fields[name]=raw
	}
	end,err:=d.Token()
	if err!=nil || end!=json.Delim('}') || len(fields)!=3 { return "",false }
	if _,err:=d.Token(); err!=io.EOF { return "",false }
	var version,id string
	if json.Unmarshal(fields["version"],&version)!=nil || version!="v2" ||
		json.Unmarshal(fields["request_id"],&id)!=nil || id!=ids[0] { return "",false }
	name:="error"
	if status==http.StatusOK { name="data" }
	payload:=fields[name]
	if len(payload)==0 || payload[0]!='{' { return "",false }
	if status!=http.StatusOK {
		var e map[string]json.RawMessage
		var code string
		if json.Unmarshal(payload,&e)!=nil || len(e)!=1 || json.Unmarshal(e["code"],&code)!=nil || code=="" { return "",false }
	}
	return id,true
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control","no-store")
	w.Header().Set("X-Content-Type-Options","nosniff")
	// Reject noncanonical targets before any router or URL rewriting.
	if r.TLS == nil || r.Host != g.host || r.URL.IsAbs() || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.RequestURI != r.URL.Path || !allowed(r.URL.Path) {
		reject(w,404,"not_found"); return
	}
	if r.Method != http.MethodPost { w.Header().Set("Allow","POST"); reject(w,405,"method_not_allowed"); return }
	for _, h := range []string{"Origin","Referer","Sec-Fetch-Site","Sec-Fetch-Mode","Sec-Fetch-Dest","Cookie","Authorization","Proxy-Authorization","Upgrade","Content-Encoding","Expect"} {
		if len(r.Header.Values(h)) != 0 { reject(w,403,"forbidden"); return }
	}
	ct := r.Header.Values("Content-Type")
	if len(ct) != 1 { reject(w,415,"json_required"); return }
	media, params, err := mime.ParseMediaType(ct[0])
	if err != nil || media != "application/json" || (len(params) != 0 && (len(params) != 1 || params["charset"] != "utf-8")) {
		reject(w,415,"json_required"); return
	}
	if r.ContentLength > maxBody { reject(w,413,"body_too_large"); return }
	select {
	case g.slots <- struct{}{}:
		defer func(){ <-g.slots }()
	default:
		w.Header().Set("Retry-After","1"); reject(w,503,"busy"); return
	}
	r.Body = http.MaxBytesReader(w,r.Body,maxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err,&tooLarge) { reject(w,413,"body_too_large") } else { reject(w,400,"invalid_input") }
		return
	}
	// Construct a fresh request; never forward caller headers, source IP,
	// cookies, proxy metadata, auth or an arbitrary destination.
	dst := *g.upstream
	dst.Path = r.URL.Path
	req, err := http.NewRequestWithContext(r.Context(),http.MethodPost,dst.String(),bytes.NewReader(body))
	if err != nil { reject(w,503,"unavailable"); return }
	req.Header.Set("Content-Type","application/json")
	resp, err := g.client.Do(req)
	if err != nil { reject(w,503,"unavailable"); return }
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200,400,403,404,405,413,415,429,503:
	default: reject(w,503,"unavailable"); return
	}
	typ, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" || resp.Header.Get("Content-Encoding") != "" {
		reject(w,503,"unavailable"); return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body,maxReply+1))
	if err != nil || len(data)>maxReply { reject(w,503,"unavailable"); return }
	id,ok:=responseID(data,resp.StatusCode,resp.Header.Values("X-Request-ID"))
	if !ok { reject(w,503,"unavailable"); return }
	w.Header().Set("Content-Type","application/json; charset=utf-8")
	w.Header().Set("X-Request-ID",id)
	if values:=resp.Header.Values("Retry-After"); len(values)==1 {
		if seconds,err:=strconv.Atoi(values[0]); err==nil && seconds>=0 && seconds<=3600 {
			w.Header().Set("Retry-After",strconv.Itoa(seconds))
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(data)
}

// Limit accepted connections as well as in-flight application requests.
type limitedListener struct {
	net.Listener
	slots chan struct{}
	done chan struct{}
	once sync.Once
}

type limitedConn struct {
	net.Conn
	once sync.Once
	release func()
}
func (c *limitedConn) Close() error {
	err:=c.Conn.Close()
	c.once.Do(c.release)
	return err
}
func (l *limitedListener) Accept() (net.Conn,error) {
	select {
	case l.slots<-struct{}{}:
	case <-l.done: return nil,net.ErrClosed
	}
	c,err:=l.Listener.Accept()
	if err!=nil { <-l.slots; return nil,err }
	return &limitedConn{Conn:c,release:func(){<-l.slots}},nil
}
func (l *limitedListener) Close() error {
	l.once.Do(func(){close(l.done)})
	return l.Listener.Close()
}

func run() error {
	if len(os.Args) != 1 { return errors.New("no command arguments; configure reviewed local environment") }
	ca, err := os.ReadFile(os.Getenv("CHEZHI_GATEWAY_ORIGIN_CA"))
	if err != nil { return errors.New("cannot read origin CA") }
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) { return errors.New("invalid origin CA") }
	g, err := newGateway(os.Getenv("CHEZHI_GATEWAY_HOST"),origin,roots)
	if err != nil { return err }
	pair, err := tls.LoadX509KeyPair(os.Getenv("CHEZHI_GATEWAY_TLS_CERT"),os.Getenv("CHEZHI_GATEWAY_TLS_KEY"))
	if err != nil { return errors.New("cannot load gateway TLS certificate") }
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname("127.0.0.1") != nil || time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) { return errors.New("gateway certificate must cover 127.0.0.1 and be current") }
	l, err := net.Listen("tcp",listen)
	if err != nil { return errors.New("cannot open gateway loopback listener") }
	defer l.Close()
	srv := &http.Server{Handler:g, TLSConfig:&tls.Config{MinVersion:tls.VersionTLS12, Certificates:[]tls.Certificate{pair}}, ReadHeaderTimeout:3*time.Second, ReadTimeout:8*time.Second, WriteTimeout:18*time.Second, IdleTimeout:15*time.Second, MaxHeaderBytes:8192, ErrorLog:log.New(io.Discard,"",0)}
	ctx, stop := signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
	defer stop()
	errs := make(chan error,1)
	go func(){ errs <- srv.ServeTLS(&limitedListener{Listener:l,slots:make(chan struct{},32),done:make(chan struct{})},"","") }()
	log.Print("local license gateway started")
	select {
	case err := <-errs: return err
	case <-ctx.Done():
		c,cancel := context.WithTimeout(context.Background(),20*time.Second); defer cancel()
		return srv.Shutdown(c)
	}
}

func main(){ if err:=run(); err!=nil { log.Fatal(err) } }
