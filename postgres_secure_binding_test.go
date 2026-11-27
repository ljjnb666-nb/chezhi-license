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

func TestPostgresSecureBindingLifecycle(t *testing.T) {
	s, _ := postgresFixture(t)
	pgInitialize(t, s)
	ctx := context.Background()
	scope := proof.Scope{Deployment: sha256.Sum256([]byte("fixture")), Product: "chezhi"}
	keys, err := s.issue(30, 2, 100, "test", "secure-fixture")
	if err != nil { t.Fatal(err) }
	hash := func(raw string) (out proof.Digest) {
		b, err := hex.DecodeString(license.HashKey(raw))
		if err != nil || len(b)!=len(out) { t.Fatal("bad card hash") }
		copy(out[:], b)
		return
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	// This is a storage test, not the future HTTP revision-fenced path.
	// Every attempt creates and consumes a fresh authoritative challenge.
	call := func(raw string, device *ecdsa.PrivateKey, activate bool) (Card, uint64, error) {
		t.Helper()
		public := elliptic.Marshal(device.Curve, device.X, device.Y)
		h := hash(raw)
		op := proof.Validate
		if activate { op = proof.Activate }
		c, err := s.pg.issueProofChallenge(ctx, scope, op, h, public)
		if err != nil { t.Fatal(err) }
		sig := signTestChallenge(t, c, device)
		var result Card
		var revision uint64
		err = s.pg.consumeProofChallenge(ctx, c.Nonce, scope, op, h, public, sig,
			func(ctx context.Context, tx *sql.Tx, _ proof.Challenge) error {
				var e error
				result, revision, e = lockSecureCard(ctx, tx, h, public, activate)
				return e
			})
		if err != nil { return Card{}, 0, err }
		return result, revision, nil
	}
	if _,_,err := call(keys[0],key,false); !errors.Is(err,errSecureBinding) { t.Fatal("validate activated unused card",err) }
	first, revision, err := call(keys[0],key,true)
	if err != nil || revision!=1 || first.Activated==nil || first.Expires==nil { t.Fatal("first binding",revision,err) }
	if _,r,err := call(keys[0],key,false); err!=nil || r!=1 { t.Fatal("same key validation",r,err) }
	if _,_,err := call(keys[0],other,true); !errors.Is(err,errSecureBinding) { t.Fatal("foreign device accepted",err) }
	// Legacy paths use the same guard, including read-only validation.
	for _, bind := range []bool{false,true} {
		r,err := s.checkLicense(ctx,keys[0],"legacy-device",bind)
		if err!=nil || r.Valid || r.Reason!="secure_protocol_required" { t.Fatal("legacy downgrade",r,err) }
	}
	if _,err := s.backup(); !errors.Is(err,errSecureBackup) { t.Fatal("lossy secure backup",err) }
	if err := s.change(first.ID,"unbind"); err!=nil { t.Fatal(err) }
	r,err := s.validate(keys[0],"legacy-device")
	if err!=nil || r.Valid || r.Reason!="secure_protocol_required" { t.Fatal("unbind removed security marker",r,err) }
	second, revision, err := call(keys[0],other,true)
	if err!=nil || revision!=3 || !first.Activated.Equal(*second.Activated) || !first.Expires.Equal(*second.Expires) {
		t.Fatal("rebind changed entitlement",revision,err)
	}
	if err:=s.change(first.ID,"revoke");err!=nil { t.Fatal(err) }
	if _,_,err:=call(keys[0],other,false);!errors.Is(err,errSecureBinding) { t.Fatal("revoked license",err) }

	legacy,err:=s.validate(keys[1],"legacy")
	if err!=nil || !legacy.Valid { t.Fatal("legacy fixture",err) }
	if _,_,err:=call(keys[1],key,true);!errors.Is(err,errLegacyBinding) { t.Fatal("legacy ownership bypass",err) }
	if err:=s.pg.verifyDatabase(ctx,"--migrator");err!=nil { t.Fatal("V6 deep check",err) }
}
