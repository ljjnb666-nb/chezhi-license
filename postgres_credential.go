package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"chezhi.local/licenseprototype/internal/proof"
)

type signedCredential struct {
	Claims proof.Credential
	Signature []byte
}

// authorizeProof is the internal server-side authorization entry point.
// Only a trusted server caller may select scope, TTL and signing key. It
// deliberately has no HTTP exposure until deployment keyring policy is
// implemented. Never return the provisional result if commit fails or is
// uncertain. Signing failure rolls back both binding and nonce consumption.
func (p *postgresStore) authorizeProof(ctx context.Context, nonce proof.Digest, scope proof.Scope,
	op proof.Operation, cardHash proof.Digest, public, signature []byte,
	private ed25519.PrivateKey, ttl time.Duration) (signedCredential, error) {
	if len(private) != ed25519.PrivateKeySize || ttl < time.Second ||
		ttl > proof.CredentialTTL || ttl%time.Second != 0 {
		return signedCredential{}, proof.ErrInvalid
	}
	var provisional signedCredential
	err := p.consumeProofChallenge(ctx, nonce, scope, op, cardHash, public, signature,
		func(ctx context.Context, tx *sql.Tx, c proof.Challenge) error {
			card, _, err := lockSecureCard(ctx, tx, cardHash, public, op == proof.Activate)
			if err != nil {
				return err
			}
			// The post-mutation epoch is the authoritative credential
			// revision, including earlier legacy transitions.
			epoch, err := lockCardEpoch(ctx, tx, cardHash)
			if err != nil {
				return err
			}
			now, err := databaseProofTime(ctx, tx)
			if err != nil {
				return err
			}
			id, err := hex.DecodeString(card.ID)
			if err != nil || len(id) != len(proof.LicenseID{}) {
				return errDatabase
			}
			var licenseID proof.LicenseID
			copy(licenseID[:], id)
			claims := proof.Credential{
				Scope: scope, License: licenseID, Device: c.Device,
				KeyID: sha256.Sum256(private[ed25519.SeedSize:]),
				Revision: epoch, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(),
			}
			if card.Expires != nil {
				claims.LicenseExpiresAt = card.Expires.Unix()
				if claims.ExpiresAt > claims.LicenseExpiresAt {
					claims.ExpiresAt = claims.LicenseExpiresAt
				}
			}
			if claims.ExpiresAt <= claims.IssuedAt {
				return errSecureBinding
			}
			sig, err := proof.SignCredential(claims, private)
			if err != nil {
				return err
			}
			provisional = signedCredential{Claims: claims, Signature: sig}
			return nil
		})
	if err != nil {
		return signedCredential{}, err
	}
	return provisional, nil
}
