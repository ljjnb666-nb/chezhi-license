//go:build sdkfixture

// Disposable loopback protocol fixture, never a production server.
// No DB, real cards, persisted private keys, or external listen address.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

func must[T any](v T,e error) T {if e!=nil {panic(e)};return v}
func check(e error){if e!=nil{panic(e)}}
func hx(b []byte)string{return hex.EncodeToString(b)}
func certs(dir string)tls.Certificate{
	now:=time.Now()
	rootKey:=must(ecdsa.GenerateKey(elliptic.P256(),rand.Reader))
	root:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"CheZhi disposable SDK CI "+filepath.Base(dir)},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign}
	rootDER:=must(x509.CreateCertificate(rand.Reader,root,root,&rootKey.PublicKey,rootKey))
	check(os.WriteFile(filepath.Join(dir,"fixture-ca.cer"),rootDER,0600))
	leafKey:=must(ecdsa.GenerateKey(elliptic.P256(),rand.Reader))
	leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"localhost"},IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},DNSNames:[]string{"localhost"},NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER:=must(x509.CreateCertificate(rand.Reader,leaf,root,&leafKey.PublicKey,rootKey))
	return tls.Certificate{Certificate:[][]byte{leafDER,rootDER},PrivateKey:leafKey}
}
type fixture struct{
	mu sync.Mutex
	scope proof.Scope
	key ed25519.PrivateKey
	nonces map[string]proof.Challenge
	bound proof.Digest
}
func reply(w http.ResponseWriter,status int,data any){
	w.Header().Set("Content-Type","application/json")
	w.Header().Set("X-Request-ID","sdk-fixture")
	w.WriteHeader(status)
	m:=map[string]any{"version":"v2","request_id":"sdk-fixture"}
	if status==200{m["data"]=data}else{m["error"]=map[string]string{"code":"authorization_denied"}}
	_ = json.NewEncoder(w).Encode(m)
}
func (f *fixture) ServeHTTP(w http.ResponseWriter,r *http.Request){
	f.mu.Lock();defer f.mu.Unlock()
	var q struct{Key string `json:"key"`;Public string `json:"public_key"`;Operation string `json:"operation"`;Nonce string `json:"nonce"`;Signature string `json:"signature"`}
	d:=json.NewDecoder(http.MaxBytesReader(w,r.Body,4096));d.DisallowUnknownFields()
	if r.Method!="POST"||d.Decode(&q)!=nil{reply(w,400,nil);return}
	if q.Key!="ABCDE-FGHJK-MNPQR-STVWX-YZ012" && q.Key!="NONCE-FIXTURE"{reply(w,403,nil);return}
	b,e:=hex.DecodeString(q.Public);if e!=nil{reply(w,403,nil);return}
	_,device,e:=proof.DevicePublicKey(b);if e!=nil{reply(w,403,nil);return}
	var hash proof.Digest
	copy(hash[:],must(hex.DecodeString(license.HashKey(q.Key))))
	op:=map[string]proof.Operation{"activate":proof.Activate,"validate":proof.Validate,"renew":proof.Renew}
	const prefix="/api/v2/licenses/"
	now:=time.Now()
	if r.URL.Path==prefix+"challenge"{
		if len(f.nonces)>=64{reply(w,503,nil);return}
		ch,e:=proof.NewChallenge(f.scope,op[q.Operation],hash,b,7,now)
		if e!=nil{reply(w,403,nil);return}
		nonce:=hx(ch.Nonce[:]);f.nonces[nonce]=ch
		reply(w,200,map[string]any{"nonce":nonce,"epoch":ch.Epoch,"issued_at":ch.IssuedAt,"expires_at":ch.ExpiresAt,"deployment":hx(f.scope.Deployment[:]),"product":f.scope.Product,"transcript":hx(must(ch.Transcript()))})
		return
	}
	ch,ok:=f.nonces[q.Nonce];delete(f.nonces,q.Nonce)
	sig,e:=hex.DecodeString(q.Signature)
	var operation proof.Operation
	for name,v:=range op{if r.URL.Path==prefix+name{operation=v}}
	if !ok||e!=nil||proof.VerifyChallenge(ch,f.scope,operation,hash,b,sig,now)!=nil{reply(w,403,nil);return}
	if operation==proof.Activate&&f.bound==(proof.Digest{}){f.bound=device}
	if f.bound!=device{reply(w,403,nil);return}
	var id proof.LicenseID;copy(id[:],hash[:12])
	claims:=proof.Credential{Scope:f.scope,License:id,Device:device,KeyID:sha256.Sum256(f.key[32:]),Nonce:ch.Nonce,Revision:7,IssuedAt:now.Unix(),ExpiresAt:now.Unix()+300}
	if q.Key=="NONCE-FIXTURE"{claims.Nonce=sha256.Sum256([]byte("different challenge"))}
	reply(w,200,map[string]any{"valid":true,"license_id":hx(id[:]),"device":hx(device[:]),"key_id":hx(claims.KeyID[:]),"nonce":hx(claims.Nonce[:]),"deployment":hx(f.scope.Deployment[:]),"product":f.scope.Product,"revision":claims.Revision,"issued_at":claims.IssuedAt,"expires_at":claims.ExpiresAt,"license_expires_at":claims.LicenseExpiresAt,"transcript":hx(must(claims.Transcript())),"signature":hx(must(proof.SignCredential(claims,f.key)))})
}
func main(){
	if len(os.Args)!=2{log.Fatal("fixture directory required")}
	dir:=os.Args[1];cert:=certs(dir)
	pub,key,e:=ed25519.GenerateKey(rand.Reader);check(e)
	f:=&fixture{key:key,scope:proof.Scope{Product:"chezhi"},nonces:make(map[string]proof.Challenge)}
	_,e=rand.Read(f.scope.Deployment[:]);check(e)
	listener:=must(net.Listen("tcp","127.0.0.1:0"))
	srv:=http.Server{Handler:f,ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:10*time.Second,TLSConfig:&tls.Config{MinVersion:tls.VersionTLS12,Certificates:[]tls.Certificate{cert}}}
	cfg:=fmt.Sprintf("https://%s\n%x\n%x\n",listener.Addr(),f.scope.Deployment,pub)
	tmp:=filepath.Join(dir,"fixture.tmp");check(os.WriteFile(tmp,[]byte(cfg),0600));check(os.Rename(tmp,filepath.Join(dir,"fixture.txt")))
	log.Fatal(srv.ServeTLS(listener,"",""))
}
