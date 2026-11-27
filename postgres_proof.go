package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"chezhi.local/licenseprototype/internal/proof"
)

const challengeCapacity = 4096
const challengeIssueLock int64 = 39184272004

var errChallengeCapacity = errors.New("challenge capacity reached")
var errChallengeInvalid = errors.New("challenge invalid or unavailable")

func databaseProofTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var seconds int64
	if err := tx.QueryRowContext(ctx, "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").Scan(&seconds); err != nil {
		return time.Time{}, errDatabase
	}
	return time.Unix(seconds, 0).UTC(), nil
}

// issueProofChallenge creates only server-owned, bounded-lived state. The
// transport must apply the shared licensing rate budget before calling it.
func (p *postgresStore) issueProofChallenge(ctx context.Context, scope proof.Scope, op proof.Operation, card proof.Digest, public []byte) (proof.Challenge, error) {
	var challenge proof.Challenge
	err := p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Serializes capacity checks across all instances, not verification.
		if err := dbExec(ctx, tx, "SELECT pg_advisory_xact_lock($1)", challengeIssueLock); err != nil {
			return err
		}
		now, err := databaseProofTime(ctx, tx)
		if err != nil {
			return err
		}
		if err := dbExec(ctx, tx, "DELETE FROM chezhi_challenges WHERE expires<=$1", now.Unix()); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_challenges").Scan(&count); err != nil {
			return errDatabase
		}
		if count >= challengeCapacity {
			return errChallengeCapacity
		}
		epoch, err := lockCardEpoch(ctx, tx, card)
		if err != nil { return err }
		// Refresh after waiting for the card row.
		now, err = databaseProofTime(ctx, tx)
		if err != nil { return err }
		challenge, err = proof.NewChallenge(scope, op, card, public, epoch, now)
		if err != nil {
			return errChallengeInvalid
		}
		payload, err := json.Marshal(challenge)
		if err != nil {
			return errDatabase
		}
		return dbExec(ctx, tx, "INSERT INTO chezhi_challenges(nonce,payload,expires) VALUES ($1,$2,$3)",
			hex.EncodeToString(challenge.Nonce[:]), payload, challenge.ExpiresAt)
	})
	if err != nil {
		return proof.Challenge{}, err
	}
	return challenge, nil
}

func decodeStoredChallenge(nonce string, payload []byte, expires int64) (proof.Challenge, error) {
	var c proof.Challenge
	if len(payload) == 0 || len(payload) > 4096 || json.Unmarshal(payload, &c) != nil ||
		hex.EncodeToString(c.Nonce[:]) != nonce || c.ExpiresAt != expires {
		return proof.Challenge{}, errDatabase
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, payload) {
		return proof.Challenge{}, errDatabase
	}
	if _, err := c.Transcript(); err != nil {
		return proof.Challenge{}, errDatabase
	}
	return c, nil
}

// consumeProofChallenge deletes the challenge and runs the authorization
// mutation on ONE transaction. The callback MUST use only the supplied tx;
// it must not return credentials to the network or make external side effects.
// Any proof or callback failure rolls back the delete and the business writes.
// On ambiguous commit, do not deliver credentials; reconcile with a fresh
// challenge. A concurrent successful consumer makes subsequent attempts fail.
func (p *postgresStore) consumeProofChallenge(ctx context.Context, nonce proof.Digest, scope proof.Scope, op proof.Operation,
	card proof.Digest, public, signature []byte, apply func(context.Context, *sql.Tx, proof.Challenge) error) error {
	if apply == nil || nonce == (proof.Digest{}) || len(public) != 65 || len(signature) != 64 {
		return errChallengeInvalid
	}
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var payload []byte
		var expires int64
		id := hex.EncodeToString(nonce[:])
		err := tx.QueryRowContext(ctx, `DELETE FROM chezhi_challenges WHERE nonce=$1
			AND expires>floor(extract(epoch FROM clock_timestamp()))::bigint RETURNING payload,expires`, id).Scan(&payload, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return errChallengeInvalid
		}
		if err != nil {
			return errDatabase
		}
		c, err := decodeStoredChallenge(id, payload, expires)
		if err != nil {
			return err
		}
		// Sample time AFTER acquiring the row lock; a waiting consumer
		// cannot use a challenge that expired during its wait.
		now, err := databaseProofTime(ctx, tx)
		if err != nil {
			return err
		}
		if proof.VerifyChallenge(c, scope, op, card, public, signature, now) != nil {
			return errChallengeInvalid
		}
		epoch, err := lockCardEpoch(ctx, tx, card)
		if err != nil { return err }
		if epoch != c.Epoch { return errChallengeInvalid }
		// The card lock may have blocked beyond the challenge lifetime.
		now, err = databaseProofTime(ctx, tx)
		if err != nil { return err }
		if now.Unix() < c.IssuedAt || now.Unix() >= c.ExpiresAt { return errChallengeInvalid }
		return apply(ctx, tx, c)
	})
}

func verifyStoredChallenges(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT nonce,payload,expires FROM chezhi_challenges LIMIT 4097")
	if err != nil {
		return errDatabase
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var nonce string
		var payload []byte
		var expires int64
		count++
		if count > challengeCapacity || rows.Scan(&nonce, &payload, &expires) != nil {
			return errDatabase
		}
		if _, err := decodeStoredChallenge(nonce, payload, expires); err != nil {
			return err
		}
	}
	if rows.Err() != nil {
		return errDatabase
	}
	return nil
}

// Lock ordering: challenge row first, then card row. Administrative changes
// lock cards only; they never delete challenges while holding a card lock.
func lockCardEpoch(ctx context.Context, tx *sql.Tx, hash proof.Digest) (uint64, error) {
	var epoch int64
	err := tx.QueryRowContext(ctx, "SELECT auth_epoch FROM chezhi_cards WHERE hash=$1 FOR UPDATE", hex.EncodeToString(hash[:])).Scan(&epoch)
	if errors.Is(err, sql.ErrNoRows) { return 0, errChallengeInvalid }
	if err != nil || epoch <= 0 { return 0, errDatabase }
	return uint64(epoch), nil
}
