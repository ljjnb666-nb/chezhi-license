package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"

	"chezhi.local/licenseprototype/internal/license"
	"chezhi.local/licenseprototype/internal/proof"
)

func TestPostgresAuthorizationEpoch(t *testing.T) {
	s, dsn := postgresFixture(t)
	pgInitialize(t, s)
	ctx := context.Background()
	peer, err := openPostgres(ctx, dsn)
	if err != nil { t.Fatal(err) }
	defer peer.db.Close()

	keys, err := s.issue(30, 1, 100, "test", "epoch-lifecycle")
	if err != nil { t.Fatal(err) }
	hashText := license.HashKey(keys[0])
	var hash proof.Digest
	raw, err := hex.DecodeString(hashText)
	if err != nil { t.Fatal(err) }
	copy(hash[:], raw)
	id := hashText[:24]
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	public := elliptic.Marshal(key.Curve,key.X,key.Y)
	scope := proof.Scope{Deployment: sha256.Sum256([]byte("epoch fixture")), Product:"chezhi"}
	issue := func(op proof.Operation) proof.Challenge {
		t.Helper()
		c, err := s.pg.issueProofChallenge(ctx, scope, op, hash, public)
		if err != nil { t.Fatal(err) }
		return c
	}
	var callbacks int
	apply := func(c proof.Challenge) error {
		t.Helper()
		return peer.consumeProofChallenge(ctx,c.Nonce,scope,c.Operation,hash,public,signTestChallenge(t,c,key),
			func(ctx context.Context, tx *sql.Tx, _ proof.Challenge) error {
				callbacks++
				_,_,err:=lockSecureCard(ctx,tx,hash,public,c.Operation==proof.Activate)
				return err
			})
	}
	stale := func(c proof.Challenge) {
		t.Helper()
		before := callbacks
		if err := apply(c); !errors.Is(err,errChallengeInvalid) || callbacks!=before {
			t.Fatal("stale challenge reached authorization callback",err)
		}
	}

	// A challenge issued before a legacy bind/unbind may not enroll the card
	// after its visible device returns to empty (ABA).
	before := issue(proof.Activate)
	if before.Epoch!=1 { t.Fatal("initial epoch",before.Epoch) }
	legacy,err:=s.validate(keys[0],"legacy")
	if err!=nil || !legacy.Valid { t.Fatal("legacy bind",err) }
	if err:=s.change(id,"unbind");err!=nil { t.Fatal(err) }
	stale(before)
	fresh:=issue(proof.Activate)
	if fresh.Epoch<=before.Epoch { t.Fatal("epoch did not advance") }
	if err:=apply(fresh);err!=nil { t.Fatal("secure enrollment",err) }

	// Multiple independently issued challenges cannot survive a security
	// transition even when the same public key subsequently rebinds.
	oldActivate:=issue(proof.Activate)
	oldValidate:=issue(proof.Validate)
	if err:=s.change(id,"unbind");err!=nil { t.Fatal(err) }
	stale(oldActivate)
	if err:=apply(issue(proof.Activate));err!=nil { t.Fatal("secure rebind",err) }
	stale(oldValidate)
	current:=issue(proof.Validate)
	if err:=apply(current);err!=nil { t.Fatal("current validation",err) }
	pending:=issue(proof.Renew)
	if err:=s.change(id,"revoke");err!=nil { t.Fatal(err) }
	stale(pending)
	if err:=apply(issue(proof.Activate));!errors.Is(err,errSecureBinding) { t.Fatal("revoked card accepted",err) }
	if err:=s.pg.verifyDatabase(ctx,"--migrator");err!=nil { t.Fatal("epoch integrity",err) }
}
