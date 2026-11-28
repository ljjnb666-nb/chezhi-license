package main

import (
	"crypto/tls"
	"encoding/json"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExactRoutesAndHeaderIsolation(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.Method != "POST" || !allowed(r.URL.Path) || r.URL.RawQuery != "" {
			t.Errorf("unexpected upstream request: %s %s",r.Method,r.URL.Path)
		}
		for _, h := range []string{"Forwarded","X-Forwarded-For","X-Forwarded-Proto","CF-Connecting-IP","Cookie","Authorization","X-Original-URL"} {
			if r.Header.Get(h)!="" { t.Errorf("caller header leaked: %s",h) }
		}
		w.Header().Set("Content-Type","application/json")
		w.Header().Set("Set-Cookie","private=1")
		w.Header().Set("X-Request-ID","test-id")
		io.WriteString(w,`{"version":"v2","data":{}}`)
	}))
	defer up.Close()
	roots:=x509.NewCertPool()
	roots.AddCert(up.Certificate())
	g,err:=newGateway("license.example.invalid",up.URL,roots)
	if err!=nil { t.Fatal(err) }
	test:=func(method,path,host,body string,headers map[string]string,secure bool,want int){
		t.Helper()
		before:=calls.Load()
		req:=httptest.NewRequest(method,path,strings.NewReader(body))
		req.Host=host
		if secure { req.TLS=&tls.ConnectionState{} }
		req.Header.Set("Content-Type","application/json")
		for k,v:=range headers { req.Header.Set(k,v) }
		rec:=httptest.NewRecorder()
		g.ServeHTTP(rec,req)
		if rec.Code!=want { t.Fatalf("%s %s: got %d want %d (%s)",method,path,rec.Code,want,rec.Body.String()) }
		delta:=calls.Load()-before
		if want==200 {
			if delta!=1 || rec.Header().Get("Set-Cookie")!="" || rec.Header().Get("X-Request-ID")!="test-id" { t.Fatal("response/header isolation failed") }
		} else if delta!=0 { t.Fatalf("denied request reached upstream: %s",path) }
	}
	host:="license.example.invalid"
	for _,p:=range []string{"challenge","activate","validate","renew"} {
		test("POST","/api/v2/licenses/"+p,host,"{}",map[string]string{"X-Forwarded-For":"198.51.100.1","CF-Connecting-IP":"198.51.100.2","X-Original-URL":"/"},true,200)
	}
	for _,p:=range []string{"/","/login","/backup","/export","/purchase","/activate","/readyz","/healthz","/metrics","/admin-ui.js","/api/v1/licenses/activate","/api/demo/activate","/api/v2/licenses/unknown","/api/v2/licenses/renew/","/api/v2/licenses/%72enew","/api/v2/licenses//renew","/api/v2/licenses/../licenses/renew","/api/v2/licenses/renew?x=1","/api/v2/licenses/renew?"} {
		test("POST",p,host,"{}",nil,true,404)
	}
	path:="/api/v2/licenses/renew"
	test("GET",path,host,"",nil,true,405)
	test("OPTIONS",path,host,"",nil,true,405)
	test("POST",path,"wrong.example.invalid","{}",nil,true,404)
	test("POST",path,host,"{}",nil,false,404)
	test("POST",path,host,"{}",map[string]string{"Origin":"https://example.invalid"},true,403)
	test("POST",path,host,"{}",map[string]string{"Cookie":"x=1"},true,403)
	test("POST",path,host,"{}",map[string]string{"Authorization":"Bearer example"},true,403)
	test("POST",path,host,"{}",map[string]string{"Content-Type":"text/plain"},true,415)
	test("POST",path,host,strings.Repeat("x",4097),nil,true,413)
}

func TestTrustAndRedirectFailure(t *testing.T) {
	var redirects atomic.Int64
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path=="/private" { redirects.Add(1) }
		http.Redirect(w,r,"/private",http.StatusFound)
	}))
	defer up.Close()
	for _,trusted:=range []bool{false,true} {
		roots:=x509.NewCertPool()
		if trusted { roots.AddCert(up.Certificate()) }
		g,err:=newGateway("license.example.invalid",up.URL,roots)
		if err!=nil { t.Fatal(err) }
		req:=httptest.NewRequest("POST","/api/v2/licenses/renew",strings.NewReader("{}"))
		req.TLS=&tls.ConnectionState{}
		req.Host=g.host
		req.Header.Set("Content-Type","application/json")
		w:=httptest.NewRecorder()
		g.ServeHTTP(w,req)
		if w.Code!=503 || w.Header().Get("Location")!="" { t.Fatalf("unexpected response %d",w.Code) }
	}
	if redirects.Load()!=0 { t.Fatal("redirect followed") }
	if _,err:=newGateway("license.example.invalid","https://192.0.2.1:443",x509.NewCertPool());err==nil { t.Fatal("non-loopback upstream accepted") }
}

func TestBoundariesAndFailureEnvelopes(t *testing.T) {
	var calls atomic.Int64
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		w.Header().Set("Content-Type","application/json")
		switch r.URL.Path {
		case "/api/v2/licenses/activate":
			io.WriteString(w,strings.Repeat("x",maxReply+1))
		case "/api/v2/licenses/validate":
			io.WriteString(w,"not JSON")
		default:
			io.WriteString(w,`{"version":"v2","data":{}}`)
		}
	}))
	defer up.Close()
	roots:=x509.NewCertPool()
	roots.AddCert(up.Certificate())
	g,err:=newGateway("license.example.invalid",up.URL,roots)
	if err!=nil {t.Fatal(err)}
	request:=func(path,body string,length int64,want int){
		t.Helper()
		req:=httptest.NewRequest("POST",path,strings.NewReader(body))
		req.Host=g.host
		req.TLS=&tls.ConnectionState{}
		req.Header.Set("Content-Type","application/json")
		req.ContentLength=length
		w:=httptest.NewRecorder()
		g.ServeHTTP(w,req)
		if w.Code!=want {t.Fatalf("status=%d want=%d",w.Code,want)}
		var e struct {
			Version string `json:"version"`
			ID string `json:"request_id"`
		}
		if json.Unmarshal(w.Body.Bytes(),&e)!=nil || e.Version!="v2" || len(e.ID)!=32 || e.ID!=w.Header().Get("X-Request-ID") {
			t.Fatal("invalid gateway failure envelope")
		}
	}
	for i:=0;i<cap(g.slots);i++ {g.slots<-struct{}{}}
	request("/api/v2/licenses/renew","{}",2,503)
	if calls.Load()!=0 {t.Fatal("saturated request reached origin")}
	for i:=0;i<cap(g.slots);i++ {<-g.slots}
	request("/api/v2/licenses/renew",strings.Repeat("x",maxBody+1),-1,413)
	if calls.Load()!=0 {t.Fatal("oversized streaming body reached origin")}
	request("/api/v2/licenses/activate","{}",2,503)
	request("/api/v2/licenses/validate","{}",2,503)
	if calls.Load()!=2 {t.Fatal("origin failure tests did not reach origin")}
	up.Close()
	request("/api/v2/licenses/renew","{}",2,503)
	if len(g.slots)!=0 {t.Fatal("request slots leaked")}
}
