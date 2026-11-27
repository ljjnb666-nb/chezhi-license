// Package proof defines the P3 licensing protocol's cryptographic boundary.
// It does not perform authorization, consume challenges or persist bindings.
package proof

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

const ChallengeTTL = 120 * time.Second
const CredentialTTL = 24 * time.Hour

var ErrInvalid = errors.New("invalid license proof")

type Digest [32]byte
type LicenseID [12]byte
type Operation byte

const (
	Activate Operation = 1
	Validate Operation = 2
	Renew Operation = 3
)

type Scope struct {
	Deployment Digest
	Product string
}

func (s Scope) valid() bool {
	if s.Deployment == (Digest{}) || len(s.Product) == 0 || len(s.Product) > 64 {
		return false
	}
	for _, c := range []byte(s.Product) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s Scope) appendTo(b []byte) []byte {
	b = append(b, s.Deployment[:]...)
	b = append(b, byte(len(s.Product)))
	return append(b, s.Product...)
}

func appendInt(b []byte, x int64) []byte {
	return binary.BigEndian.AppendUint64(b, uint64(x))
}

func validTime(t int64) bool { return t > 0 && t <= 253402300799 }

// DevicePublicKey accepts only canonical SEC1 uncompressed P-256 points.
func DevicePublicKey(raw []byte) (*ecdsa.PublicKey, Digest, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, Digest{}, ErrInvalid
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), raw)
	if x == nil || y == nil {
		return nil, Digest{}, ErrInvalid
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X:x, Y:y}, sha256.Sum256(raw), nil
}

// Challenge is server-issued state, not a client-selected timestamp or scope.
// CardHash is the existing normalized-card SHA-256 decoded to 32 bytes.
type Challenge struct {
	Scope Scope
	Operation Operation
	Nonce Digest
	CardHash Digest
	Device Digest
	Epoch uint64
	IssuedAt int64
	ExpiresAt int64
}

func (c Challenge) valid() bool {
	return c.Scope.valid() && c.Operation >= Activate && c.Operation <= Renew &&
		c.Nonce != (Digest{}) && c.CardHash != (Digest{}) && c.Device != (Digest{}) &&
		c.Epoch > 0 && c.Epoch <= 1<<63-1 && validTime(c.IssuedAt) && validTime(c.ExpiresAt) && c.ExpiresAt > c.IssuedAt &&
		c.ExpiresAt-c.IssuedAt <= int64(ChallengeTTL/time.Second)
}

func NewChallenge(scope Scope, op Operation, cardHash Digest, public []byte, epoch uint64, now time.Time) (Challenge, error) {
	_, device, err := DevicePublicKey(public)
	if err != nil {
		return Challenge{}, err
	}
	c := Challenge{Scope:scope, Operation:op, CardHash:cardHash, Device:device, Epoch:epoch,
		IssuedAt:now.Unix(), ExpiresAt:now.Add(ChallengeTTL).Unix()}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return Challenge{}, err
	}
	if !c.valid() {
		return Challenge{}, ErrInvalid
	}
	return c, nil
}

// Transcript returns a canonical binary representation, domain-separated from
// credentials. All fields except the explicitly length-prefixed product are fixed width.
func (c Challenge) Transcript() ([]byte, error) {
	if !c.valid() { return nil, ErrInvalid }
	b := c.Scope.appendTo([]byte("CHEZHI/PROOF/V2\x00"))
	b = append(b, byte(c.Operation))
	b = append(b, c.Nonce[:]...)
	b = append(b, c.CardHash[:]...)
	b = append(b, c.Device[:]...)
	b = binary.BigEndian.AppendUint64(b, c.Epoch)
	b = appendInt(b, c.IssuedAt)
	return appendInt(b,c.ExpiresAt), nil
}

// VerifyChallenge verifies proof only. The caller MUST load the authoritative
// challenge from shared storage and consume its nonce atomically with the
// authorized operation. A signature alone is not replay protection.
func VerifyChallenge(c Challenge, scope Scope, op Operation, cardHash Digest, public, signature []byte, now time.Time) error {
	key, device, err := DevicePublicKey(public)
	if err != nil || c.Scope != scope || c.Operation != op || c.CardHash != cardHash ||
		c.Device != device || now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt || len(signature) != 64 {
		return ErrInvalid
	}
	b, err := c.Transcript()
	if err != nil { return err }
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	// IEEE P1363 r||s, with canonical low-S encoding.
	half := new(big.Int).Rsh(new(big.Int).Set(key.Params().N),1)
	if s.Sign() <= 0 || s.Cmp(half) > 0 { return ErrInvalid }
	h := sha256.Sum256(b)
	if !ecdsa.Verify(key,h[:],r,s) { return ErrInvalid }
	return nil
}

// Credential is a bounded server attestation, not an authorization database.
// LicenseExpiresAt == 0 means a perpetual license, never a perpetual credential.
type Credential struct {
	Scope Scope
	License LicenseID
	Device Digest
	KeyID Digest
	Nonce Digest
	Revision uint64
	IssuedAt int64
	ExpiresAt int64
	LicenseExpiresAt int64
}

func (c Credential) Transcript() ([]byte,error) {
	if !c.Scope.valid() || c.License == (LicenseID{}) || c.Device == (Digest{}) ||
		c.KeyID == (Digest{}) || c.Nonce == (Digest{}) || c.Revision == 0 || !validTime(c.IssuedAt) ||
		!validTime(c.ExpiresAt) || c.ExpiresAt <= c.IssuedAt ||
		c.ExpiresAt-c.IssuedAt > int64(CredentialTTL/time.Second) ||
		(c.LicenseExpiresAt != 0 && (!validTime(c.LicenseExpiresAt) || c.ExpiresAt > c.LicenseExpiresAt)) {
		return nil, ErrInvalid
	}
	b := c.Scope.appendTo([]byte("CHEZHI/CREDENTIAL/V2\x00"))
	b = append(b,c.License[:]...)
	b = append(b,c.Device[:]...)
	b = append(b,c.KeyID[:]...)
	b = append(b,c.Nonce[:]...)
	b = binary.BigEndian.AppendUint64(b,c.Revision)
	b = appendInt(b,c.IssuedAt)
	b = appendInt(b,c.ExpiresAt)
	return appendInt(b,c.LicenseExpiresAt),nil
}

// SignCredential requires the caller to set KeyID to the SHA-256 of the
// current public key and construct claims from an authorized DB transaction.
func SignCredential(c Credential, private ed25519.PrivateKey) ([]byte,error) {
	if len(private)!=ed25519.PrivateKeySize { return nil,ErrInvalid }
	// Reject inconsistent seed/public halves rather than signing unusable credentials.
	canonical := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !canonical.Equal(private) || c.KeyID!=sha256.Sum256(canonical[ed25519.SeedSize:]) {
		return nil,ErrInvalid
	}
	b,err:=c.Transcript()
	if err!=nil{return nil,err}
	return ed25519.Sign(canonical,b),nil
}

// VerifyCredential requires a public key from a trusted local keyring, never
// a public key supplied by the untrusted credential. Time must come from the
// caller's trusted time policy; this primitive cannot prevent clock rollback.
// The online caller must compare Nonce to its outstanding challenge and
// prove possession of the matching device key.
func VerifyCredential(c Credential, scope Scope, license LicenseID, device Digest, trusted ed25519.PublicKey, signature []byte, now time.Time) error {
	if len(trusted)!=ed25519.PublicKeySize || len(signature)!=ed25519.SignatureSize ||
		c.Scope!=scope || c.License!=license || c.Device!=device ||
		c.KeyID!=sha256.Sum256(trusted) || now.Unix()<c.IssuedAt || now.Unix()>=c.ExpiresAt {
		return ErrInvalid
	}
	b,err:=c.Transcript()
	if err!=nil{return err}
	if !ed25519.Verify(trusted,b,signature){return ErrInvalid}
	return nil
}
