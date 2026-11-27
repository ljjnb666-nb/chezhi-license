package licenseclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

type countedSigner struct { crypto.Signer; calls atomic.Int32 }
func (s *countedSigner) Sign(r io.Reader,d []byte,o crypto.SignerOpts)([]byte,error) {
	s.calls.Add(1);return s.Signer.Sign(r,d,o)
}

func TestReferenceClientTrustBoundary(t *testing.T) {
	pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
	dev,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
	scope:=proof.Scope{Deployment:sha256.Sum256([]byte("fixture")),Product:"chezhi"}
	card:="ABCDE-FGHJK-MNPQR-STVWX-YZ012"
	h,_:=hex.DecodeString(license.HashKey(card));var hash proof.Digest;copy(hash[:],h)
	var id proof.LicenseID;copy(id[:],h[:12])
	point:=elliptic.Marshal(dev.Curve,dev.X,dev.Y)
	_,fp,_:=proof.DevicePublicKey(point)
	for _,mode:=range []string{"valid","wrong challenge","duplicate field","wrong signature","wrong device","wrong scope","long ttl","redirect","wrong ca","revision rollback"} {
		t.Run(mode,func(t *testing.T){
			var calls atomic.Int32
			c,e:=proof.NewChallenge(scope,proof.Validate,hash,point,7,time.Now());if e!=nil{t.Fatal(e)}
			tr,_:=c.Transcript()
			s:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
				calls.Add(1)
				w.Header().Set("Content-Type","application/json")
				w.Header().Set("X-Request-ID","fixture")
				if mode=="redirect" { w.Header().Set("Location","https://example.invalid/");w.WriteHeader(307);return }
				if r.URL.Path=="/api/v2/licenses/challenge" {
					data:=map[string]any{"nonce":hex.EncodeToString(c.Nonce[:]),"epoch":c.Epoch,"issued_at":c.IssuedAt,"expires_at":c.ExpiresAt,
						"deployment":hex.EncodeToString(scope.Deployment[:]),"product":scope.Product,"transcript":hex.EncodeToString(tr)}
					if mode=="wrong challenge" { data["transcript"]="00" }
					if mode=="duplicate field" { _,_=w.Write([]byte(`{"version":"v2","version":"v2","request_id":"fixture","data":{}}`));return }
					_=json.NewEncoder(w).Encode(map[string]any{"version":"v2","request_id":"fixture","data":data});return
				}
				now:=time.Now().Unix()
				claim:=proof.Credential{Scope:scope,License:id,Device:fp,KeyID:sha256.Sum256(pub),Revision:7,IssuedAt:now,ExpiresAt:now+300}
				switch mode {
				case "wrong device":claim.Device=sha256.Sum256([]byte("other"))
				case "wrong scope":claim.Scope.Deployment=sha256.Sum256([]byte("other"))
				case "long ttl":claim.ExpiresAt++
				case "revision rollback":claim.Revision--
				}
				signature,_:=proof.SignCredential(claim,priv)
				if mode=="wrong signature" { signature[0]^=1 }
				body,_:=claim.Transcript()
				_=json.NewEncoder(w).Encode(map[string]any{"version":"v2","request_id":"fixture","data":map[string]any{
					"valid":true,"license_id":hex.EncodeToString(id[:]),"device":hex.EncodeToString(claim.Device[:]),
					"key_id":hex.EncodeToString(claim.KeyID[:]),"deployment":hex.EncodeToString(claim.Scope.Deployment[:]),
					"product":claim.Scope.Product,"revision":claim.Revision,"issued_at":claim.IssuedAt,"expires_at":claim.ExpiresAt,
					"license_expires_at":claim.LicenseExpiresAt,"transcript":hex.EncodeToString(body),"signature":hex.EncodeToString(signature)}})
			}))
			defer s.Close()
			pool:=x509.NewCertPool()
			if mode!="wrong ca"{pool.AddCert(s.Certificate())}
			client,e:=New(s.URL,scope,pub,pool);if e!=nil{t.Fatal(e)};defer client.Close()
			key:=&countedSigner{Signer:dev}
			result,e:=client.Authorize(context.Background(),proof.Validate,card,key)
			if mode=="valid" { if e!=nil || result.Revision!=7{t.Fatal("valid response rejected",e)};return }
			if e==nil || result.Revision!=0{t.Fatal("unsafe response accepted")}
			if (mode=="wrong challenge" || mode=="duplicate field" || mode=="redirect" || mode=="wrong ca") && key.calls.Load()!=0 {
				t.Fatal("signed before authenticating challenge")
			}
			if mode=="redirect" && calls.Load()!=1{t.Fatal("redirect followed")}
		})
	}
	if _,e:=New("http://localhost",scope,pub,nil);e==nil{t.Fatal("plaintext transport accepted")}
}
