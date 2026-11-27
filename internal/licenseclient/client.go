// Package licenseclient is the online-only P3 reference client, not a
// production Windows SDK. Device key persistence belongs to the caller.
package licenseclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

const maxCredentialTTL = 5 * time.Minute

var ErrResponse = errors.New("invalid license server response")
var ErrTransport = errors.New("license server unavailable")
var ErrInput = errors.New("invalid license client configuration or input")

// HTTPError deliberately excludes response text, card keys and URLs.
type HTTPError struct { Status int }
func (e *HTTPError) Error() string { return http.StatusText(e.Status) }

type Client struct {
	origin string
	scope proof.Scope
	trusted ed25519.PublicKey
	http *http.Client
}

// New requires independently provisioned scope and verification key. roots
// may contain a private CA for an isolated deployment; nil uses system roots.
// No insecure TLS option, automatic redirects, cookies, or ambient proxy.
func New(origin string, scope proof.Scope, trusted ed25519.PublicKey, roots *x509.CertPool) (*Client,error) {
	u,err:=url.Parse(origin)
	if err!=nil || u.Scheme!="https" || u.Hostname()=="" || u.User!=nil ||
		(u.Path!="" && u.Path!="/") || u.RawPath!="" || u.RawQuery!="" || u.ForceQuery ||
		u.Fragment!="" || strings.ContainsAny(origin,"#%\r\n") ||
		scope.Deployment==(proof.Digest{}) || scope.Product!="chezhi" || len(trusted)!=ed25519.PublicKeySize {
		return nil,ErrInput
	}
	var zero [32]byte
	if bytes.Equal(trusted,zero[:]) { return nil,ErrInput }
	if roots!=nil { roots=roots.Clone() }
	tr:=&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots},
		TLSHandshakeTimeout:5*time.Second,ResponseHeaderTimeout:10*time.Second,
		MaxResponseHeaderBytes:8192,MaxIdleConns:4,MaxIdleConnsPerHost:2,IdleConnTimeout:30*time.Second}
	return &Client{origin:"https://"+u.Host,scope:scope,trusted:append(ed25519.PublicKey(nil),trusted...),
		http:&http.Client{Transport:tr,Timeout:15*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}}},nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func exactObject(raw []byte,names ...string) (map[string]json.RawMessage,error) {
	d:=json.NewDecoder(bytes.NewReader(raw))
	t,e:=d.Token()
	if e!=nil || t!=json.Delim('{') { return nil,ErrResponse }
	m:=make(map[string]json.RawMessage,len(names))
	for d.More() {
		k,e:=d.Token();name,ok:=k.(string)
		if e!=nil || !ok { return nil,ErrResponse }
		if _,exists:=m[name];exists { return nil,ErrResponse }
		var v json.RawMessage
		if d.Decode(&v)!=nil || bytes.Equal(bytes.TrimSpace(v),[]byte("null")) { return nil,ErrResponse }
		m[name]=v
		if len(m)>len(names) { return nil,ErrResponse }
	}
	t,e=d.Token()
	if e!=nil || t!=json.Delim('}') { return nil,ErrResponse }
	if _,e=d.Token();e!=io.EOF { return nil,ErrResponse }
	if len(m)!=len(names) { return nil,ErrResponse }
	for _,n:=range names { if _,ok:=m[n];!ok { return nil,ErrResponse } }
	return m,nil
}

func (c *Client) post(ctx context.Context,path string,body map[string]string) (json.RawMessage,error) {
	b,e:=json.Marshal(body)
	if e!=nil { return nil,ErrInput }
	r,e:=http.NewRequestWithContext(ctx,http.MethodPost,c.origin+"/api/v2/licenses/"+path,bytes.NewReader(b))
	if e!=nil { return nil,ErrInput }
	r.Header.Set("Content-Type","application/json")
	resp,e:=c.http.Do(r)
	if e!=nil { return nil,ErrTransport }
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK { return nil,&HTTPError{Status:resp.StatusCode} }
	media,_,e:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if e!=nil || media!="application/json" { return nil,ErrResponse }
	raw,e:=io.ReadAll(io.LimitReader(resp.Body,8193))
	if e!=nil || len(raw)>8192 { return nil,ErrResponse }
	m,e:=exactObject(raw,"version","request_id","data")
	if e!=nil { return nil,e }
	var version,id string
	if json.Unmarshal(m["version"],&version)!=nil || version!="v2" ||
		json.Unmarshal(m["request_id"],&id)!=nil || len(id)==0 || len(id)>128 ||
		id!=resp.Header.Get("X-Request-ID") { return nil,ErrResponse }
	return m["data"],nil
}

func canonicalHex(s string,n int) ([]byte,bool) {
	if len(s)!=2*n { return nil,false }
	b,e:=hex.DecodeString(s)
	return b,e==nil && hex.EncodeToString(b)==s
}
func opName(op proof.Operation) string {
	switch op {
	case proof.Activate:return "activate"
	case proof.Validate:return "validate"
	case proof.Renew:return "renew"
	}
	return ""
}

type challengeReply struct {
	Nonce string `json:"nonce"`
	Epoch uint64 `json:"epoch"`
	Issued int64 `json:"issued_at"`
	Expires int64 `json:"expires_at"`
	Deployment string `json:"deployment"`
	Product string `json:"product"`
	Transcript string `json:"transcript"`
}

type credentialReply struct {
	Valid bool `json:"valid"`
	License string `json:"license_id"`
	Device string `json:"device"`
	KeyID string `json:"key_id"`
	Nonce string `json:"nonce"`
	Deployment string `json:"deployment"`
	Product string `json:"product"`
	Revision uint64 `json:"revision"`
	Issued int64 `json:"issued_at"`
	Expires int64 `json:"expires_at"`
	LicenseExpires int64 `json:"license_expires_at"`
	Transcript string `json:"transcript"`
	Signature string `json:"signature"`
}

func signDevice(key crypto.Signer, transcript []byte) ([]byte,error) {
	h:=sha256.Sum256(transcript)
	raw,e:=key.Sign(rand.Reader,h[:],crypto.SHA256)
	if e!=nil { return nil,ErrInput }
	var rs struct { R,S *big.Int }
	rest,e:=asn1.Unmarshal(raw,&rs)
	n:=elliptic.P256().Params().N
	if e!=nil || len(rest)!=0 || rs.R==nil || rs.S==nil ||
		rs.R.Sign()<=0 || rs.S.Sign()<=0 || rs.R.Cmp(n)>=0 || rs.S.Cmp(n)>=0 { return nil,ErrInput }
	half:=new(big.Int).Rsh(new(big.Int).Set(n),1)
	if rs.S.Cmp(half)>0 { rs.S.Sub(n,rs.S) }
	out:=make([]byte,64)
	rs.R.FillBytes(out[:32]);rs.S.FillBytes(out[32:])
	return out,nil
}

// Authorize always obtains a new online challenge and verifies the response.
// A successful call returns claims, not a persistent authorization decision.
// The caller must deny protected operations after a failed refresh. No
// offline cache or clock rollback resistance is provided here.
func (c *Client) Authorize(ctx context.Context,op proof.Operation,card string,key crypto.Signer) (proof.Credential,error) {
	empty:=proof.Credential{}
	name:=opName(op)
	if name=="" || len(card)==0 || len(card)>100 || key==nil { return empty,ErrInput }
	pub,ok:=key.Public().(*ecdsa.PublicKey)
	if !ok || pub==nil || pub.Curve!=elliptic.P256() || pub.X==nil || pub.Y==nil ||
		!elliptic.P256().IsOnCurve(pub.X,pub.Y) { return empty,ErrInput }
	point:=elliptic.Marshal(pub.Curve,pub.X,pub.Y)
	_,fp,e:=proof.DevicePublicKey(point)
	if e!=nil { return empty,ErrInput }
	hashBytes,e:=hex.DecodeString(license.HashKey(card))
	if e!=nil || len(hashBytes)!=32 { return empty,ErrInput }
	var hash proof.Digest
	copy(hash[:],hashBytes)
	var id proof.LicenseID
	copy(id[:],hashBytes[:12])
	public:=hex.EncodeToString(point)
	raw,e:=c.post(ctx,"challenge",map[string]string{"key":card,"public_key":public,"operation":name})
	if e!=nil { return empty,e }
	if _,e=exactObject(raw,"nonce","epoch","issued_at","expires_at","deployment","product","transcript");e!=nil { return empty,e }
	var cr challengeReply
	if json.Unmarshal(raw,&cr)!=nil || cr.Deployment!=hex.EncodeToString(c.scope.Deployment[:]) || cr.Product!=c.scope.Product { return empty,ErrResponse }
	nonce,ok:=canonicalHex(cr.Nonce,32)
	if !ok { return empty,ErrResponse }
	ch:=proof.Challenge{Scope:c.scope,Operation:op,CardHash:hash,Device:fp,Epoch:cr.Epoch,IssuedAt:cr.Issued,ExpiresAt:cr.Expires}
	copy(ch.Nonce[:],nonce)
	transcript,e:=ch.Transcript()
	now:=time.Now()
	if e!=nil || hex.EncodeToString(transcript)!=cr.Transcript || now.Unix()<ch.IssuedAt || now.Unix()>=ch.ExpiresAt {
		return empty,ErrResponse
	}
	sig,e:=signDevice(key,transcript)
	if e!=nil { return empty,e }
	// Ensure the local signer actually holds the requested key.
	if proof.VerifyChallenge(ch,c.scope,op,hash,point,sig,now)!=nil { return empty,ErrInput }
	raw,e=c.post(ctx,name,map[string]string{"key":card,"public_key":public,"nonce":cr.Nonce,"signature":hex.EncodeToString(sig)})
	if e!=nil { return empty,e }
	if _,e=exactObject(raw,"valid","license_id","device","key_id","nonce","deployment","product","revision","issued_at","expires_at","license_expires_at","transcript","signature");e!=nil { return empty,e }
	var rr credentialReply
	keyID:=sha256.Sum256(c.trusted)
	if json.Unmarshal(raw,&rr)!=nil || !rr.Valid || rr.License!=hex.EncodeToString(id[:]) ||
		rr.Device!=hex.EncodeToString(fp[:]) || rr.KeyID!=hex.EncodeToString(keyID[:]) || rr.Nonce!=cr.Nonce ||
		rr.Deployment!=hex.EncodeToString(c.scope.Deployment[:]) || rr.Product!=c.scope.Product ||
		rr.Issued<ch.IssuedAt || rr.Revision<ch.Epoch || rr.Revision>ch.Epoch+1 ||
		(op!=proof.Activate && rr.Revision!=ch.Epoch) { return empty,ErrResponse }
	claims:=proof.Credential{Scope:c.scope,License:id,Device:fp,KeyID:keyID,Nonce:ch.Nonce,Revision:rr.Revision,
		IssuedAt:rr.Issued,ExpiresAt:rr.Expires,LicenseExpiresAt:rr.LicenseExpires}
	transcript,e=claims.Transcript()
	if e!=nil || hex.EncodeToString(transcript)!=rr.Transcript ||
		claims.ExpiresAt-claims.IssuedAt>int64(maxCredentialTTL/time.Second) { return empty,ErrResponse }
	sig,ok=canonicalHex(rr.Signature,ed25519.SignatureSize)
	if !ok || proof.VerifyCredential(claims,c.scope,id,fp,c.trusted,sig,time.Now())!=nil { return empty,ErrResponse }
	return claims,nil
}
