package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

func TestPostgresCommittedCredential(t *testing.T) {
	s, dsn := postgresFixture(t)
	pgInitialize(t, s)
	ctx := context.Background()
	peer, err := openPostgres(ctx, dsn)
	if err != nil { t.Fatal(err) }
	defer peer.db.Close()
	keys,err:=s.issue(30,1,100,"test","credential-fixture")
	if err!=nil { t.Fatal(err) }
	hashText:=license.HashKey(keys[0])
	raw,err:=hex.DecodeString(hashText)
	if err!=nil { t.Fatal(err) }
	var hash proof.Digest
	copy(hash[:],raw)
	device,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	public:=elliptic.Marshal(device.Curve,device.X,device.Y)
	scope:=proof.Scope{Deployment:sha256.Sum256([]byte("credential fixture")),Product:"chezhi"}
	trusted,private,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil { t.Fatal(err) }

	c,err:=s.pg.issueProofChallenge(ctx,scope,proof.Activate,hash,public)
	if err!=nil { t.Fatal(err) }
	sig:=signTestChallenge(t,c,device)
	badPrivate:=append(ed25519.PrivateKey(nil),private...)
	badPrivate[63]^=1
	failed,err:=peer.authorizeProof(ctx,c.Nonce,scope,proof.Activate,hash,public,sig,badPrivate,time.Minute)
	if err==nil || len(failed.Signature)!=0 || failed.Claims.Revision!=0 {
		t.Fatal("failed signer returned credentials",err)
	}
	card:=pgSnapshot(t,s).Cards[0]
	if card.Activated!=nil || card.Device!="" { t.Fatal("signing failure committed binding") }

	issued,err:=peer.authorizeProof(ctx,c.Nonce,scope,proof.Activate,hash,public,sig,private,time.Minute)
	if err!=nil { t.Fatal(err) }
	card=pgSnapshot(t,s).Cards[0]
	if card.Expires==nil || issued.Claims.Revision!=c.Epoch+1 || issued.Claims.LicenseExpiresAt!=card.Expires.Unix() ||
		issued.Claims.ExpiresAt-issued.Claims.IssuedAt!=60 {
		t.Fatal("wrong confirmed claims")
	}
	if err:=proof.VerifyCredential(issued.Claims,scope,issued.Claims.License,c.Device,trusted,issued.Signature,time.Unix(issued.Claims.IssuedAt,0));err!=nil {
		t.Fatal("cannot verify committed credential",err)
	}
	again,err:=peer.authorizeProof(ctx,c.Nonce,scope,proof.Activate,hash,public,sig,private,time.Minute)
	if !errors.Is(err,errChallengeInvalid) || len(again.Signature)!=0 { t.Fatal("replay",err) }

	renew,err:=s.pg.issueProofChallenge(ctx,scope,proof.Renew,hash,public)
	if err!=nil { t.Fatal(err) }
	refreshed,err:=peer.authorizeProof(ctx,renew.Nonce,scope,proof.Renew,hash,public,signTestChallenge(t,renew,device),private,time.Minute)
	if err!=nil || refreshed.Claims.Revision!=issued.Claims.Revision || refreshed.Claims.LicenseExpiresAt!=issued.Claims.LicenseExpiresAt {
		t.Fatal("renew changed entitlement",err)
	}
	stale,err:=s.pg.issueProofChallenge(ctx,scope,proof.Validate,hash,public)
	if err!=nil { t.Fatal(err) }
	if err:=s.change(card.ID,"revoke");err!=nil { t.Fatal(err) }
	denied,err:=peer.authorizeProof(ctx,stale.Nonce,scope,proof.Validate,hash,public,signTestChallenge(t,stale,device),private,time.Minute)
	if !errors.Is(err,errChallengeInvalid) || len(denied.Signature)!=0 { t.Fatal("revoked pending credential",err) }
}
