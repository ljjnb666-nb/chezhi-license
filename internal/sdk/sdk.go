// Package sdk defines the P4 native boundary around the audited P3 client.
// It never persists a card or private key and has no offline authorization.
package sdk

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"time"

	"chezhi.local/licenseprototype/internal/licenseclient"
	"chezhi.local/licenseprototype/internal/proof"
)

type Status int32

// Stable ABI v1 status values. Only OK authorizes an individual operation.
// Denied does not mean the card is necessarily invalid; V2 deliberately
// returns a generic authorization denial.
const (
	OK Status = iota
	InvalidInput
	Unavailable
	Denied
	RetryLater
	UntrustedResponse
	InternalFailure
	Cancelled
)

const ResultSize = 32
const RequestTimeout = 20 * time.Second

type Config struct {
	Origin string
	Deployment proof.Digest
	TrustedKey ed25519.PublicKey
	// Roots is for independently provisioned private CA roots. The DLL
	// uses system roots only; integration fixtures use an isolated pool.
	Roots *x509.CertPool
}

// DeviceSigner adapts an external P-256 provider that produces IEEE P1363
// signatures. Its caller owns the key lifetime. No key import/export occurs.
type DeviceSigner struct {
	public *ecdsa.PublicKey
	sign func([32]byte) ([64]byte,error)
}

func NewDeviceSigner(point []byte, sign func([32]byte) ([64]byte,error)) (*DeviceSigner,error) {
	if sign==nil { return nil,licenseclient.ErrInput }
	public,_,err:=proof.DevicePublicKey(point)
	if err!=nil { return nil,licenseclient.ErrInput }
	return &DeviceSigner{public:public,sign:sign},nil
}
func (s *DeviceSigner) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve:s.public.Curve,X:new(big.Int).Set(s.public.X),Y:new(big.Int).Set(s.public.Y)}
}
func (s *DeviceSigner) Sign(_ io.Reader,digest []byte,opts crypto.SignerOpts)([]byte,error) {
	if len(digest)!=32 || opts==nil || opts.HashFunc()!=crypto.SHA256 { return nil,licenseclient.ErrInput }
	var h [32]byte
	copy(h[:],digest)
	rs,err:=s.sign(h)
	if err!=nil { return nil,licenseclient.ErrInput }
	r:=new(big.Int).SetBytes(rs[:32]);v:=new(big.Int).SetBytes(rs[32:])
	n:=s.public.Params().N
	if r.Sign()<=0 || v.Sign()<=0 || r.Cmp(n)>=0 || v.Cmp(n)>=0 { return nil,licenseclient.ErrInput }
	if !ecdsa.Verify(s.public,h[:],r,v) { return nil,licenseclient.ErrInput }
	// The P3 client converts DER to canonical low-S P1363.
	return asn1.Marshal(struct{R,S *big.Int}{r,v})
}

type Result struct {
	Revision uint64
	IssuedAt int64
	ExpiresAt int64
	LicenseExpiresAt int64
}

// Encode writes four big-endian 64-bit fields, only after verified success.
// The ABI wrapper must zero the buffer on every failure.
func (r Result) Encode(out []byte) {
	if len(out)!=ResultSize { return }
	binary.BigEndian.PutUint64(out[0:8],r.Revision)
	binary.BigEndian.PutUint64(out[8:16],uint64(r.IssuedAt))
	binary.BigEndian.PutUint64(out[16:24],uint64(r.ExpiresAt))
	binary.BigEndian.PutUint64(out[24:32],uint64(r.LicenseExpiresAt))
}

func classify(ctx context.Context,err error) Status {
	if errors.Is(ctx.Err(),context.Canceled) { return Cancelled }
	if errors.Is(ctx.Err(),context.DeadlineExceeded) || errors.Is(err,licenseclient.ErrTransport) { return Unavailable }
	if errors.Is(err,licenseclient.ErrInput) { return InvalidInput }
	if errors.Is(err,licenseclient.ErrResponse) { return UntrustedResponse }
	var httpErr *licenseclient.HTTPError
	if errors.As(err,&httpErr) {
		switch httpErr.Status {
		case 403: return Denied
		case 429,503: return RetryLater
		case 400,413,415: return InvalidInput
		default: return Unavailable
		}
	}
	return InternalFailure
}

// Authorize uses a new bounded online exchange for each operation. There is
// no cached success, automatic retry, or network-failure authorization.
// A prior success is not a grant to start an unrelated operation.
func Authorize(ctx context.Context,c Config,op proof.Operation,card string,device crypto.Signer)(Result,Status) {
	if ctx==nil || device==nil || len(c.Origin)>2048 || len(card)==0 || len(card)>100 ||
		(op!=proof.Activate && op!=proof.Validate && op!=proof.Renew) { return Result{},InvalidInput }
	ctx,cancel:=context.WithTimeout(ctx,RequestTimeout)
	defer cancel()
	if ctx.Err()!=nil { return Result{},classify(ctx,ctx.Err()) }
	client,err:=licenseclient.New(c.Origin,proof.Scope{Deployment:c.Deployment,Product:"chezhi"},c.TrustedKey,c.Roots)
	if err!=nil { return Result{},classify(ctx,err) }
	defer client.Close()
	claims,err:=client.Authorize(ctx,op,card,device)
	if err!=nil { return Result{},classify(ctx,err) }
	if ctx.Err()!=nil { return Result{},classify(ctx,ctx.Err()) }
	return Result{claims.Revision,claims.IssuedAt,claims.ExpiresAt,claims.LicenseExpiresAt},OK
}
