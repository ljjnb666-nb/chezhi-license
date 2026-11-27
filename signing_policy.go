package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"

	"chezhi.local/licenseprototype/internal/proof"
)

const secureProduct = "chezhi"

type signingPolicy struct {
	scope proof.Scope
	public ed25519.PublicKey
}

type serverSigner struct {
	policy signingPolicy
	private ed25519.PrivateKey
}

func readSigningPolicy(ctx context.Context, q rowQueryer) (*signingPolicy,error) {
	var deployment, pub string
	err:=q.QueryRowContext(ctx,"SELECT deployment,public_key FROM chezhi_signing_policy WHERE singleton").Scan(&deployment,&pub)
	if errors.Is(err,sql.ErrNoRows) { return nil,nil }
	if err!=nil { return nil,errDatabase }
	d,e:=hex.DecodeString(deployment)
	k,e2:=hex.DecodeString(pub)
	if e!=nil || e2!=nil || len(d)!=32 || len(k)!=32 { return nil,errDatabase }
	var scope proof.Scope
	copy(scope.Deployment[:],d)
	scope.Product=secureProduct
	if scope.Deployment==(proof.Digest{}) { return nil,errDatabase }
	return &signingPolicy{scope:scope,public:ed25519.PublicKey(k)},nil
}

func freshSigningScope() (string,error) {
	var d proof.Digest
	if _,err:=rand.Read(d[:]);err!=nil || d==(proof.Digest{}) { return "",errors.New("cannot generate signing scope") }
	return hex.EncodeToString(d[:]),nil
}

func generateSigningKey(path string) error {
	public,private,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil { return errors.New("cannot generate signing key") }
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil { return errors.New("cannot create new signing key file") }
	ok:=false
	defer func(){ _=f.Close(); if !ok { _=os.Remove(path) } }()
	if _,err=f.WriteString(hex.EncodeToString(private.Seed())+"\n");err!=nil { return errors.New("cannot write signing key") }
	if err=f.Sync();err!=nil { return errors.New("cannot sync signing key") }
	if err=f.Close();err!=nil { return errors.New("cannot close signing key") }
	ok=true
	fmt.Printf("Signing public key: %s\n",hex.EncodeToString(public))
	return nil
}

func loadSigningKey() (ed25519.PrivateKey,error) {
	path:=os.Getenv("CHEZHI_SIGNING_KEY_FILE")
	stat,err:=os.Stat(path)
	if err!=nil || !stat.Mode().IsRegular() || (runtime.GOOS!="windows" && stat.Mode().Perm()&0077!=0) {
		return nil,errors.New("signing key must be a protected regular file")
	}
	raw,err:=readProtectedInput("CHEZHI_SIGNING_KEY_FILE",66)
	if err!=nil { return nil,err }
	seed,err:=hex.DecodeString(raw)
	if err!=nil || len(seed)!=ed25519.SeedSize || raw!=hex.EncodeToString(seed) {
		return nil,errors.New("invalid signing key seed")
	}
	return ed25519.NewKeyFromSeed(seed),nil
}

func (p *postgresStore) configureSigner(ctx context.Context) (*serverSigner,error) {
	var policy *signingPolicy
	err:=p.transaction(ctx,&sql.TxOptions{ReadOnly:true},func(ctx context.Context,tx *sql.Tx) error {
		var e error
		policy,e=readSigningPolicy(ctx,tx)
		return e
	})
	if err!=nil { return nil,err }
	if policy==nil {
		if os.Getenv("CHEZHI_SIGNING_KEY_FILE")!="" { return nil,errors.New("initialize signing policy offline before loading signing key") }
		return nil,nil
	}
	private,err:=loadSigningKey()
	if err!=nil { return nil,err }
	if !policy.public.Equal(private.Public()) { return nil,errors.New("signing key does not match database policy") }
	return &serverSigner{policy:*policy,private:private},nil
}

// Change the signing policy only while every service is offline. Expected
// current ID prevents accidental overwrites and reinitialization. Each
// rotation changes the deployment scope; clients must update trust explicitly.
func (p *postgresStore) setSigningPolicy(ctx context.Context,name,expected,publicHex string) error {
	pub,err:=hex.DecodeString(publicHex)
	if err!=nil || len(pub)!=ed25519.PublicKeySize || publicHex!=hex.EncodeToString(pub) {
		return errors.New("invalid signing public key")
	}
	var zero [32]byte
	if string(pub)==string(zero[:]) { return errors.New("invalid signing public key") }
	return p.transaction(ctx,&sql.TxOptions{},func(ctx context.Context,tx *sql.Tx) error {
		var acquired,matchedName bool
		if tx.QueryRowContext(ctx,"SELECT pg_try_advisory_xact_lock($1),current_database()=$2",deploymentLock,name).Scan(&acquired,&matchedName)!=nil { return errDatabase }
		if !acquired || !matchedName { return errors.New("stop all services and confirm connected database name") }
		if err:=verifyMigratorRole(ctx,tx);err!=nil { return err }
		_,bound,err:=deploymentState(ctx,tx)
		if err!=nil || !bound { return errDeployment }
		old,err:=readSigningPolicy(ctx,tx)
		if err!=nil { return err }
		if old==nil {
			if expected!="none" { return errors.New("expected signing policy does not match") }
		} else {
			id:=sha256.Sum256(old.public)
			if expected!=hex.EncodeToString(id[:]) || old.public.Equal(ed25519.PublicKey(pub)) { return errors.New("expected signing key mismatch or reused key") }
		}
		scope,err:=freshSigningScope()
		if err!=nil { return err }
		if err:=dbExec(ctx,tx,`INSERT INTO chezhi_signing_policy(singleton,deployment,public_key)
			VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET deployment=excluded.deployment,public_key=excluded.public_key`,scope,publicHex);err!=nil { return err }
		if err:=dbExec(ctx,tx,"DELETE FROM chezhi_challenges");err!=nil { return err }
		return dbExec(ctx,tx,"UPDATE chezhi_deployment SET generation=generation+1 WHERE singleton")
	})
}

func refreshSigningScope(ctx context.Context,tx *sql.Tx) error {
	scope,err:=freshSigningScope()
	if err!=nil { return err }
	return dbExec(ctx,tx,"UPDATE chezhi_signing_policy SET deployment=$1 WHERE singleton",scope)
}
