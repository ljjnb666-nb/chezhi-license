package proof

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

func filled(b byte) (d Digest) {
	for i := range d { d[i]=b }
	return
}

func TestCanonicalChallengeVector(t *testing.T) {
	c:=Challenge{Scope:Scope{filled(1),"chezhi1"},Operation:Activate,Nonce:filled(2),
		CardHash:filled(3),Device:filled(4),IssuedAt:1700000000,ExpiresAt:1700000120}
	b,err:=c.Transcript()
	if err!=nil { t.Fatal(err) }
	h:=sha256.Sum256(b)
	if len(b)!=169 || hex.EncodeToString(h[:])!="ef5ec8802b5dff4b1e57496f0bb1b7914c0de1114f94ba52e794a49fe981817d" {
		t.Fatal("canonical transcript mismatch")
	}
}

func signDevice(t *testing.T,k *ecdsa.PrivateKey,c Challenge) []byte {
	t.Helper()
	b,err:=c.Transcript()
	if err!=nil { t.Fatal(err) }
	h:=sha256.Sum256(b)
	r,s,err:=ecdsa.Sign(rand.Reader,k,h[:])
	if err!=nil { t.Fatal(err) }
	half:=new(big.Int).Rsh(new(big.Int).Set(k.Params().N),1)
	if s.Cmp(half)>0 { s.Sub(k.Params().N,s) }
	out:=make([]byte,64)
	r.FillBytes(out[:32]); s.FillBytes(out[32:])
	return out
}

func TestDeviceProof(t *testing.T) {
	k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	public:=elliptic.Marshal(k.Curve,k.X,k.Y)
	now:=time.Unix(1700000000,0)
	scope:=Scope{filled(1),"chezhi1"}
	card:=filled(3)
	c,err:=NewChallenge(scope,Activate,card,public,now)
	if err!=nil { t.Fatal(err) }
	next,err:=NewChallenge(scope,Activate,card,public,now)
	if err!=nil || next.Nonce==c.Nonce { t.Fatal("challenge generation") }
	sig:=signDevice(t,k,c)
	if err:=VerifyChallenge(c,scope,Activate,card,public,sig,now);err!=nil { t.Fatal(err) }
	other,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	otherPublic:=elliptic.Marshal(other.Curve,other.X,other.Y)
	mutated:=c; mutated.Nonce=next.Nonce
	high:=append([]byte(nil),sig...)
	s:=new(big.Int).SetBytes(high[32:])
	s.Sub(k.Params().N,s).FillBytes(high[32:])
	bad:=append([]byte(nil),sig...);bad[0]^=1
	for _,tc:=range []struct{
		name string
		c Challenge
		scope Scope
		op Operation
		card Digest
		pub,sig []byte
		now time.Time
	}{
		{"wrong private key",c,scope,Activate,card,public,signDevice(t,other,c),now},
		{"wrong public key",c,scope,Activate,card,otherPublic,sig,now},
		{"wrong scope",c,Scope{filled(9),"chezhi1"},Activate,card,public,sig,now},
		{"wrong product",c,Scope{filled(1),"other"},Activate,card,public,sig,now},
		{"wrong operation",c,scope,Validate,card,public,sig,now},
		{"wrong card",c,scope,Activate,filled(5),public,sig,now},
		{"wrong nonce",mutated,scope,Activate,card,public,sig,now},
		{"expired",c,scope,Activate,card,public,sig,now.Add(ChallengeTTL)},
		{"future",c,scope,Activate,card,public,sig,now.Add(-time.Second)},
		{"malformed point",c,scope,Activate,card,make([]byte,65),sig,now},
		{"compressed point",c,scope,Activate,card,elliptic.MarshalCompressed(k.Curve,k.X,k.Y),sig,now},
		{"high-S",c,scope,Activate,card,public,high,now},
		{"tampered signature",c,scope,Activate,card,public,bad,now},
		{"short signature",c,scope,Activate,card,public,sig[:63],now},
	}{
		t.Run(tc.name,func(t *testing.T){
			if VerifyChallenge(tc.c,tc.scope,tc.op,tc.card,tc.pub,tc.sig,tc.now)==nil { t.Fatal("accepted invalid proof") }
		})
	}
}

func TestCredential(t *testing.T) {
	public,private,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil { t.Fatal(err) }
	scope:=Scope{filled(1),"chezhi1"}
	now:=time.Unix(1700000000,0)
	c:=Credential{Scope:scope,License:LicenseID{1},Device:filled(3),KeyID:sha256.Sum256(public),Revision:1,
		IssuedAt:now.Unix(),ExpiresAt:now.Add(CredentialTTL).Unix()}
	sig,err:=SignCredential(c,private)
	if err!=nil { t.Fatal(err) }
	verify:=func(claim Credential, at time.Time) error {
		return VerifyCredential(claim,scope,c.License,c.Device,public,sig,at)
	}
	if err:=verify(c,now);err!=nil { t.Fatal(err) }
	if verify(c,now.Add(CredentialTTL))==nil || verify(c,now.Add(-time.Second))==nil { t.Fatal("time boundary accepted") }
	for _,mutate:=range []func(*Credential){
		func(x *Credential){x.Revision++},
		func(x *Credential){x.Device=filled(4)},
		func(x *Credential){x.Scope.Product="other"},
		func(x *Credential){x.License=LicenseID{2}},
		func(x *Credential){x.KeyID=filled(5)},
		func(x *Credential){x.ExpiresAt--},
		func(x *Credential){x.LicenseExpiresAt=x.ExpiresAt},
	}{
		x:=c;mutate(&x)
		if verify(x,now)==nil { t.Fatal("tampered claims accepted") }
	}
	if VerifyCredential(c,scope,c.License,filled(7),public,sig,now)==nil { t.Fatal("wrong device accepted") }
	if VerifyCredential(c,scope,c.License,c.Device,make([]byte,32),sig,now)==nil { t.Fatal("untrusted key accepted") }
	x:=c;x.LicenseExpiresAt=c.ExpiresAt-1
	if _,err:=SignCredential(x,private);err==nil { t.Fatal("credential exceeds license") }
	x=c;x.ExpiresAt++
	if _,err:=SignCredential(x,private);err==nil { t.Fatal("credential exceeds TTL") }
	x=c;x.KeyID=filled(6)
	if _,err:=SignCredential(x,private);err==nil { t.Fatal("wrong signing key ID") }
	corrupted:=append(ed25519.PrivateKey(nil),private...);corrupted[63]^=1
	if _,err:=SignCredential(c,corrupted);err==nil { t.Fatal("inconsistent private key") }
}
