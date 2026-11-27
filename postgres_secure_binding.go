package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"

	"chezhi.local/licenseprototype/internal/proof"
)

var errSecureProtocolRequired = errors.New("secure license protocol required")
var errLegacyBinding = errors.New("existing legacy device must be unbound by an administrator")
var errSecureBinding = errors.New("secure device binding denied")
var errSecureBackup = errors.New("secure licenses require a native PostgreSQL backup")

// All callers modifying security metadata MUST first lock the corresponding
// chezhi_cards row. Rows in the secure table are never deleted by the app.
func secureMarker(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM chezhi_secure_bindings WHERE card_id=$1)", id).Scan(&exists); err != nil {
		return false, errDatabase
	}
	return exists, nil
}

func denyLegacyCard(ctx context.Context, tx *sql.Tx, cards []Card) error {
	for _, c := range cards {
		protected, err := secureMarker(ctx, tx, c.ID)
		if err != nil {
			return err
		}
		if protected {
			return errSecureProtocolRequired
		}
	}
	return nil
}

func resetSecureBinding(ctx context.Context, tx *sql.Tx, id string) error {
	return dbExec(ctx, tx, "UPDATE chezhi_secure_bindings SET public_key='', revision=revision+1 WHERE card_id=$1", id)
}

// lockSecureCard is an internal business primitive, not an exposed activation
// endpoint. The caller must already have verified and consumed a challenge in
// this transaction, and must fence the challenge against the authorization
// revision before using this function. No credentials are issued here.
func lockSecureCard(ctx context.Context, tx *sql.Tx, cardHash proof.Digest, public []byte, activate bool) (Card, uint64, error) {
	_, fingerprint, err := proof.DevicePublicKey(public)
	if err != nil {
		return Card{}, 0, errSecureBinding
	}
	hash := hex.EncodeToString(cardHash[:])
	cards, err := queryCards(ctx, tx, " WHERE c.hash=$1 FOR UPDATE OF c", hash)
	if err != nil {
		return Card{}, 0, err
	}
	if len(cards) != 1 {
		return Card{}, 0, errSecureBinding
	}
	c := cards[0]
	now, err := databaseProofTime(ctx, tx)
	if err != nil {
		return Card{}, 0, err
	}
	if c.Revoked || (c.Expires != nil && !now.Before(*c.Expires)) {
		return Card{}, 0, errSecureBinding
	}

	encoded := hex.EncodeToString(public)
	device := hex.EncodeToString(fingerprint[:])
	var stored string
	var revision int64
	err = tx.QueryRowContext(ctx, "SELECT public_key,revision FROM chezhi_secure_bindings WHERE card_id=$1", c.ID).Scan(&stored, &revision)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if c.Device != "" {
			return Card{}, 0, errLegacyBinding
		}
		if !activate {
			return Card{}, 0, errSecureBinding
		}
		revision = 1
		if err := dbExec(ctx, tx, "INSERT INTO chezhi_secure_bindings(card_id,public_key,revision) VALUES ($1,$2,$3)", c.ID, encoded, revision); err != nil {
			return Card{}, 0, err
		}
	case err != nil:
		return Card{}, 0, errDatabase
	case revision <= 0:
		return Card{}, 0, errDatabase
	case stored != "":
		if stored != encoded || c.Device != device || c.Activated == nil {
			return Card{}, 0, errSecureBinding
		}
		return c, uint64(revision), nil
	default:
		if !activate || c.Device != "" {
			return Card{}, 0, errSecureBinding
		}
		if err := tx.QueryRowContext(ctx, "UPDATE chezhi_secure_bindings SET public_key=$2,revision=revision+1 WHERE card_id=$1 RETURNING revision", c.ID, encoded).Scan(&revision); err != nil {
			return Card{}, 0, errDatabase
		}
	}

	// Preserve the exact historical activation timestamp and expiry on rebind.
	if c.Activated == nil {
		if now.Before(c.Created) {
			return Card{}, 0, errSecureBinding
		}
		c.Activated = &now
		if c.Days != 0 {
			expires := now.AddDate(0, 0, c.Days)
			c.Expires = &expires
		}
	}
	c.Device = device
	if err := dbExec(ctx, tx, "UPDATE chezhi_cards SET activated=$2,expires=$3,device=$4 WHERE id=$1",
		c.ID, sqlOptionalTime(c.Activated), sqlOptionalTime(c.Expires), c.Device); err != nil {
		return Card{}, 0, err
	}
	if err := appendAudit(ctx, tx, Audit{At: now, Action: "bind", CardID: c.ID, Actor: "user"}); err != nil {
		return Card{}, 0, err
	}
	return c, uint64(revision), nil
}

func verifySecureBindings(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT b.public_key,b.revision,c.device,c.revoked,c.activated IS NOT NULL
		FROM chezhi_secure_bindings b JOIN chezhi_cards c ON c.id=b.card_id`)
	if err != nil {
		return errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var key, device string
		var revision int64
		var revoked, activated bool
		if rows.Scan(&key, &revision, &device, &revoked, &activated) != nil || revision <= 0 {
			return errDatabase
		}
		if key == "" {
			if device != "" && !revoked {
				return errDatabase
			}
			continue
		}
		raw, err := hex.DecodeString(key)
		if err != nil {
			return errDatabase
		}
		_, fp, err := proof.DevicePublicKey(raw)
		if err != nil || !activated || device != hex.EncodeToString(fp[:]) {
			return errDatabase
		}
	}
	if rows.Err() != nil {
		return errDatabase
	}
	return nil
}

func denySecureLegacyBackup(ctx context.Context, tx *sql.Tx) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM chezhi_secure_bindings)").Scan(&exists); err != nil {
		return errDatabase
	}
	if exists {
		return errSecureBackup
	}
	return nil
}
