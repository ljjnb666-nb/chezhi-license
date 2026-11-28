package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOriginWrongNameAndExpiredCertificates(t *testing.T) {
	now:=time.Now()
	for _,tc:=range []struct {
		name string
		ip net.IP
		start,end time.Time
	}{
		{"wrong SAN",net.ParseIP("127.0.0.2"),now.Add(-time.Hour),now.Add(time.Hour)},
		{"expired",net.ParseIP("127.0.0.1"),now.Add(-2*time.Hour),now.Add(-time.Hour)},
		{"not yet valid",net.ParseIP("127.0.0.1"),now.Add(time.Hour),now.Add(2*time.Hour)},
	}{
		t.Run(tc.name,func(t *testing.T){
			key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
			if err!=nil {t.Fatal(err)}
			template:=&x509.Certificate{
				SerialNumber:big.NewInt(1),NotBefore:tc.start,NotAfter:tc.end,
				IPAddresses:[]net.IP{tc.ip},
				KeyUsage:x509.KeyUsageDigitalSignature,
				ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
			if err!=nil {t.Fatal(err)}
			leaf,err:=x509.ParseCertificate(der)
			if err!=nil {t.Fatal(err)}
			var calls atomic.Int64
			up:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){calls.Add(1)}))
			up.TLS=&tls.Config{Certificates:[]tls.Certificate{{Certificate:[][]byte{der},PrivateKey:key}}}
			up.StartTLS()
			defer up.Close()
			roots:=x509.NewCertPool()
			roots.AddCert(leaf)
			g,err:=newGateway("license.example.invalid",up.URL,roots)
			if err!=nil {t.Fatal(err)}
			req:=httptest.NewRequest("POST","/api/v2/licenses/renew",strings.NewReader("{}"))
			req.Host=g.host
			req.TLS=&tls.ConnectionState{}
			req.Header.Set("Content-Type","application/json")
			w:=httptest.NewRecorder()
			g.ServeHTTP(w,req)
			if w.Code!=503 || calls.Load()!=0 {t.Fatalf("invalid origin TLS reached handler: status=%d calls=%d",w.Code,calls.Load())}
		})
	}
}
