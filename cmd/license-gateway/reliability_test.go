package main

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActualTLSConcurrencyAndRateRecovery(t *testing.T) {
	var calls atomic.Int64
	entered:=make(chan struct{},2)
	release:=make(chan struct{})
	var once sync.Once
	unblock:=func(){once.Do(func(){close(release)})}
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		n:=calls.Add(1)
		if n<=2 {
			entered<-struct{}{}
			<-release
		}
		w.Header().Set("Content-Type","application/json")
		w.Header().Set("X-Request-ID","0123456789abcdef0123456789abcdef")
		io.WriteString(w,`{"version":"v2","request_id":"0123456789abcdef0123456789abcdef","data":{}}`)
	}))
	defer up.Close()
	defer unblock()
	roots:=x509.NewCertPool()
	roots.AddCert(up.Certificate())
	g,err:=newGateway("license.example.invalid",up.URL,roots)
	if err!=nil {t.Fatal(err)}
	front:=httptest.NewTLSServer(g)
	defer front.Close()
	client:=front.Client()
	client.Timeout=5*time.Second
	request:=func()(int,error){
		req,err:=http.NewRequest("POST",front.URL+"/api/v2/licenses/renew",strings.NewReader("{}"))
		if err!=nil {return 0,err}
		req.Host=g.host
		req.Header.Set("Content-Type","application/json")
		resp,err:=client.Do(req)
		if err!=nil {return 0,err}
		defer resp.Body.Close()
		_,err=io.Copy(io.Discard,resp.Body)
		return resp.StatusCode,err
	}
	results:=make(chan int,2)
	for i:=0;i<2;i++ {go func(){code,_:=request();results<-code}()}
	for i:=0;i<2;i++ {
		select {case <-entered:case <-time.After(3*time.Second):unblock();t.Fatal("origin did not receive two requests")}
	}
	for i:=0;i<4;i++ {
		if code,err:=request();err!=nil || code!=503 {unblock();t.Fatalf("saturation code=%d err=%v",code,err)}
	}
	if calls.Load()!=2 {unblock();t.Fatal("saturated request reached origin")}
	unblock()
	for i:=0;i<2;i++ {if code:=<-results;code!=200 {t.Fatalf("admitted request status %d",code)}}
	// Set the budget under its lock after the admitted requests finish;
	// no wall-clock pacing assumption or live-origin load is required.
	g.budget.mu.Lock()
	g.budget.tokens=0
	g.budget.last=time.Now()
	g.budget.mu.Unlock()
	if code,err:=request();err!=nil || code!=429 {t.Fatalf("rate rejection code=%d err=%v",code,err)}
	if calls.Load()!=2 {t.Fatal("rate-rejected request reached origin")}
	g.budget.mu.Lock()
	g.budget.last=time.Now().Add(-2*time.Second)
	g.budget.mu.Unlock()
	if code,err:=request();err!=nil || code!=200 {t.Fatalf("recovery code=%d err=%v",code,err)}
}

func TestTLSStatusTrustAndWarning(t *testing.T) {
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){t.Error("TLS status sent HTTP request")}))
	defer up.Close()
	roots:=x509.NewCertPool()
	roots.AddCert(up.Certificate())
	future:=&x509.Certificate{NotAfter:time.Now().Add(30*24*time.Hour)}
	if err:=tlsStatus(up.Listener.Addr().String(),roots,future);err!=nil {t.Fatal(err)}
	near:=&x509.Certificate{NotAfter:time.Now().Add(24*time.Hour)}
	if err:=tlsStatus(up.Listener.Addr().String(),roots,near);err==nil {t.Fatal("missing expiry warning")}
	if err:=tlsStatus(up.Listener.Addr().String(),x509.NewCertPool(),future);err==nil {t.Fatal("untrusted origin accepted")}
}
