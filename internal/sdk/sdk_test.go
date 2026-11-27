package sdk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"chezhi.local/licenseprototype/internal/licenseclient"
	"chezhi.local/licenseprototype/internal/proof"
)

func TestDeviceSignerBoundary(t *testing.T) {
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil {t.Fatal(err)}
	point:=elliptic.Marshal(key.Curve,key.X,key.Y)
	provider:=func(d [32]byte)(out [64]byte,err error){
		r,s,err:=ecdsa.Sign(rand.Reader,key,d[:])
		if err==nil {r.FillBytes(out[:32]);s.FillBytes(out[32:])}
		return
	}
	s,err:=NewDeviceSigner(point,provider)
	if err!=nil {t.Fatal(err)}
	d:=sha256.Sum256([]byte("fixture"))
	der,err:=s.Sign(rand.Reader,d[:],crypto.SHA256)
	if err!=nil || !ecdsa.VerifyASN1(&key.PublicKey,d[:],der){t.Fatal("valid provider failed",err)}
	copyPub:=s.Public().(*ecdsa.PublicKey)
	copyPub.X.SetInt64(0)
	der,err=s.Sign(rand.Reader,d[:],crypto.SHA256)
	if err!=nil || !ecdsa.VerifyASN1(&key.PublicKey,d[:],der){t.Fatal("public copy mutated signer")}
	for _,bad:=range []func([32]byte)([64]byte,error){
		func([32]byte)([64]byte,error){return [64]byte{},nil},
		func([32]byte)([64]byte,error){return [64]byte{},errors.New("provider failure")},
		func([32]byte)([64]byte,error){return provider(sha256.Sum256([]byte("wrong digest")))},
	} {
		x,err:=NewDeviceSigner(point,bad)
		if err!=nil{t.Fatal(err)}
		if _,err=x.Sign(rand.Reader,d[:],crypto.SHA256);err==nil{t.Fatal("bad provider accepted")}
	}
	if _,err=s.Sign(rand.Reader,d[:31],crypto.SHA256);err==nil{t.Fatal("short digest accepted")}
	if _,err=NewDeviceSigner(point[:64],provider);err==nil{t.Fatal("invalid point accepted")}
}

func TestStatusAndFailClosed(t *testing.T) {
	ctx:=context.Background()
	for _,tc:=range []struct{err error;want Status}{
		{licenseclient.ErrInput,InvalidInput},{licenseclient.ErrTransport,Unavailable},
		{licenseclient.ErrResponse,UntrustedResponse},{&licenseclient.HTTPError{Status:403},Denied},
		{&licenseclient.HTTPError{Status:429},RetryLater},{&licenseclient.HTTPError{Status:503},RetryLater},
		{&licenseclient.HTTPError{Status:404},Unavailable},{errors.New("other"),InternalFailure},
	} {if got:=classify(ctx,tc.err);got!=tc.want{t.Fatalf("status %d want %d",got,tc.want)}}
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	config:=Config{Origin:"http://localhost",Deployment:sha256.Sum256([]byte("scope")),TrustedKey:pub}
	if r,s:=Authorize(ctx,config,proof.Activate,"fixture",key);s!=InvalidInput||r!=(Result{}){t.Fatal("plain HTTP accepted")}
	ctx,cancel:=context.WithCancel(ctx);cancel()
	config.Origin="https://localhost"
	if r,s:=Authorize(ctx,config,proof.Activate,"fixture",key);s!=Cancelled||r!=(Result{}){t.Fatal("canceled call accepted")}
	out:=make([]byte,ResultSize);Result{7,10,20,0}.Encode(out)
	if binary.BigEndian.Uint64(out[:8])!=7||binary.BigEndian.Uint64(out[16:24])!=20{t.Fatal("ABI encoding")}
}
