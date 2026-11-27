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
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"chezhi.local/licenseprototype/internal/proof"
)

func signTestChallenge(t *testing.T, c proof.Challenge, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	data, err := c.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	half := new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(key.Params().N, s)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature
}

func TestPostgresProofChallenge(t *testing.T) {
	s, dsn := postgresFixture(t)
	pgInitialize(t, s)
	ctx := context.Background()
	peer, err := openPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.db.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public := elliptic.Marshal(key.Curve, key.X, key.Y)
	scope := proof.Scope{Deployment: sha256.Sum256([]byte("fixture deployment")), Product: "chezhi"}
	card := sha256.Sum256([]byte("fixture card hash"))
	issue := func() proof.Challenge {
		t.Helper()
		c, err := s.pg.issueProofChallenge(ctx, scope, proof.Activate, card, public)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := issue()
	sig := signTestChallenge(t, c, key)
	noop := func(context.Context, *sql.Tx, proof.Challenge) error { return nil }
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	if err := peer.consumeProofChallenge(ctx, c.Nonce, scope, proof.Activate, card, public, bad, noop); !errors.Is(err, errChallengeInvalid) {
		t.Fatal("invalid signature", err)
	}
	if err := peer.consumeProofChallenge(ctx, c.Nonce, scope, proof.Validate, card, public, sig, noop); !errors.Is(err, errChallengeInvalid) {
		t.Fatal("cross-operation proof", err)
	}
	abort := errors.New("fixture rollback")
	if err := peer.consumeProofChallenge(ctx, c.Nonce, scope, proof.Activate, card, public, sig, func(ctx context.Context, tx *sql.Tx, _ proof.Challenge) error {
		if err := dbExec(ctx, tx, "UPDATE chezhi_config SET qq='123456789' WHERE singleton"); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal("expected rollback", err)
	}
	if got := pgSnapshot(t, s).QQ; got != "----------" {
		t.Fatal("callback write escaped rollback")
	}

	// Two independent pools, same proof and nonce: exactly one commit.
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		store := s.pg
		if i%2 != 0 {
			store = peer
		}
		wg.Add(1)
		go func(p *postgresStore) {
			defer wg.Done()
			<-start
			err := p.consumeProofChallenge(ctx, c.Nonce, scope, proof.Activate, card, public, sig,
				func(ctx context.Context, tx *sql.Tx, _ proof.Challenge) error {
					return dbExec(ctx, tx, "UPDATE chezhi_config SET qq='987654321' WHERE singleton")
				})
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, errChallengeInvalid) {
				failures <- err
			}
		}(store)
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error("unexpected concurrent error", err)
	}
	if winners.Load() != 1 || pgSnapshot(t, s).QQ != "987654321" {
		t.Fatal("proof consumption was not atomic")
	}
	if err := s.pg.consumeProofChallenge(ctx, c.Nonce, scope, proof.Activate, card, public, sig, noop); !errors.Is(err, errChallengeInvalid) {
		t.Fatal("consumed proof replay", err)
	}

	expired := issue()
	expiredSig := signTestChallenge(t, expired, key)
	pgExec(t, s, "UPDATE chezhi_challenges SET expires=1 WHERE nonce=$1", hex.EncodeToString(expired.Nonce[:]))
	if err := s.pg.consumeProofChallenge(ctx, expired.Nonce, scope, proof.Activate, card, public, expiredSig, noop); !errors.Is(err, errChallengeInvalid) {
		t.Fatal("expired challenge accepted", err)
	}
	if err := s.pg.cleanShared(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.pg.db.QueryRow("SELECT count(*) FROM chezhi_challenges").Scan(&count); err != nil || count != 0 {
		t.Fatal("expired challenge cleanup", err)
	}

	// Artificial rows exercise the storage ceiling without issuing thousands
	// of challenges. These are explicitly corrupt test fixtures, not accepted
	// proof payloads. The independent checker must reject them.
	pgExec(t, s, `INSERT INTO chezhi_challenges(nonce,payload,expires)
		SELECT lpad(to_hex(i),64,'0'),decode('00','hex'),floor(extract(epoch FROM clock_timestamp()))::bigint+120
		FROM generate_series(1,$1) i`, challengeCapacity)
	if _, err := s.pg.issueProofChallenge(ctx, scope, proof.Activate, card, public); !errors.Is(err, errChallengeCapacity) {
		t.Fatal("challenge capacity not enforced", err)
	}
	if err := s.pg.transaction(ctx, &sql.TxOptions{ReadOnly:true}, verifyStoredChallenges); err == nil {
		t.Fatal("corrupt stored challenges accepted")
	}
	pgExec(t, s, "DELETE FROM chezhi_challenges")
	c = issue()
	if err := s.pg.verifyDatabase(ctx, "--migrator"); err != nil {
		t.Fatal("V5 deep check", err)
	}
	var name string
	if err := s.pg.db.QueryRow("SELECT current_database()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if err := s.pg.offlineSecurity(ctx, name, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.pg.consumeProofChallenge(ctx, c.Nonce, scope, proof.Activate, card, public, signTestChallenge(t,c,key), noop); !errors.Is(err, errChallengeInvalid) {
		t.Fatal("pre-transition challenge survived", err)
	}
}
