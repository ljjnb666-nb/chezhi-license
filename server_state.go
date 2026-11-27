package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"
)

var errSessionCapacity = errors.New("session capacity reached")
var errSessionInvalid = errors.New("session no longer authorized")
var errRateLimited = errors.New("request rate exceeded")

type sharedSessionKey struct{}

func (p *postgresStore) sharedSession(ctx context.Context, token string) (adminSession, error) {
	var s adminSession
	err := p.db.QueryRowContext(ctx, `SELECT principal,role,revision,expires FROM chezhi_sessions
        WHERE token_digest=$1 AND expires>clock_timestamp()`, digestSecret(token)).
		Scan(&s.name, &s.role, &s.revision, &s.expiry)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return s, errSessionInvalid
	case err != nil:
		return s, errDatabase
	default:
		s.csrf = digestSecret("csrf:" + token)
		return s, nil
	}
}

func (p *postgresStore) createSharedSession(ctx context.Context, oldToken, token, name, role string, revision int64) error {
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		// Serialize the global capacity check and all account/session mutations.
		if _, err := lockAccountRevision(ctx, tx, true); err != nil {
			return err
		}
		if err := dbExec(ctx, tx, "DELETE FROM chezhi_sessions WHERE expires<=clock_timestamp() OR token_digest=$1", digestSecret(oldToken)); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_sessions").Scan(&count); err != nil {
			return errDatabase
		}
		if count >= 32 {
			return errSessionCapacity
		}
		if err := dbExec(ctx, tx, `INSERT INTO chezhi_sessions(token_digest,principal,role,revision,expires)
            VALUES ($1,$2,$3,$4,clock_timestamp()+interval '8 hours')`, digestSecret(token), name, role, revision); err != nil {
			return err
		}
		return appendAudit(ctx, tx, Audit{At: time.Now().UTC(), Action: "login_success", Actor: name})
	})
}

func (p *postgresStore) revokeSharedSession(ctx context.Context, token, name string, all bool) error {
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := lockAccountRevision(ctx, tx, true); err != nil {
			return err
		}
		query, argument, action := "DELETE FROM chezhi_sessions WHERE token_digest=$1", digestSecret(token), "logout"
		if all {
			query, argument, action = "DELETE FROM chezhi_sessions WHERE principal=$1", name, "logout_all"
		}
		if err := dbExec(ctx, tx, query, argument); err != nil {
			return err
		}
		return appendAudit(ctx, tx, Audit{At: time.Now().UTC(), Action: action, Actor: name})
	})
}

func sessionCookieFor(r *http.Request, value string, age int) *http.Cookie {
	settings, _ := r.Context().Value(serverRequestKey{}).(serverRequest)
	name := sessionCookie
	if settings.secure {
		name = "__Host-" + name
	}
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: settings.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: age}
}

func (p *postgresStore) allowShared(ctx context.Context, scope, source string, global, individual int) (bool, error) {
	err := p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		var window int64
		if tx.QueryRowContext(ctx, "SELECT floor(extract(epoch FROM clock_timestamp()) / 60)::bigint").Scan(&window) != nil {
			return errDatabase
		}
		for _, bucket := range []struct {
			key   string
			limit int
		}{{"*", global}, {source, individual}} {
			var used int
			err := tx.QueryRowContext(ctx, `INSERT INTO chezhi_rate_limits AS limits(scope,source,window_start,used)
                VALUES ($1,$2,$3,1)
                ON CONFLICT(scope,source,window_start) DO UPDATE SET used=limits.used+1 WHERE limits.used<$4
                RETURNING used`, scope, bucket.key, window, bucket.limit).Scan(&used)
			if errors.Is(err, sql.ErrNoRows) {
				return errRateLimited
			}
			if err != nil {
				return errDatabase
			}
		}
		return nil
	})
	if errors.Is(err, errRateLimited) {
		return false, nil
	}
	return err == nil, err
}

func (p *postgresStore) cleanShared(ctx context.Context) error {
	return p.transaction(ctx, nil, func(ctx context.Context, tx *sql.Tx) error {
		if err := dbExec(ctx, tx, `DELETE FROM chezhi_sessions WHERE expires<=clock_timestamp()`); err != nil {
			return err
		}
		return dbExec(ctx, tx, `DELETE FROM chezhi_rate_limits WHERE (scope,source,window_start) IN (
            SELECT scope,source,window_start FROM chezhi_rate_limits
            WHERE window_start<floor(extract(epoch FROM clock_timestamp()) / 60)::bigint-1
            ORDER BY window_start LIMIT 4096 FOR UPDATE SKIP LOCKED
        )`)
	})
}
