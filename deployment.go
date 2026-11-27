package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const deploymentLock int64 = 39184272003

type deploymentBinding struct {
	mode       string
	generation int64
}

const selectDeployment = `SELECT mode,generation,database_name=current_database() AND database_oid=(
    SELECT oid FROM pg_database WHERE datname=current_database())
    AND cluster_id=(SELECT system_identifier FROM pg_control_system())
    FROM chezhi_deployment WHERE singleton`

var errDeployment = errors.New("PostgreSQL mode or deployment identity changed")

func deploymentState(ctx context.Context, query rowQueryer) (deploymentBinding, bool, error) {
	var binding deploymentBinding
	var current bool
	if err := query.QueryRowContext(ctx, selectDeployment).Scan(&binding.mode, &binding.generation, &current); err != nil {
		return binding, false, errDatabase
	}
	return binding, current, nil
}

type deploymentLease struct {
	binding deploymentBinding
	pid     atomic.Int64
}

func closeDeploymentConnection(connection *sql.Conn) {
	// Discard the physical backend so the advisory locks never return to the pool.
	_ = connection.Raw(func(any) error { return driver.ErrBadConn })
	_ = connection.Close()
}

func acquireDeployment(ctx context.Context, pool *sql.DB, mode string) (*sql.Conn, deploymentBinding, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := pool.Conn(ctx)
	if err != nil {
		return nil, deploymentBinding{}, 0, errDatabase
	}
	var acquired bool
	var pid int64
	if connection.QueryRowContext(ctx, "SELECT pg_try_advisory_lock_shared($1),pg_backend_pid()", deploymentLock).Scan(&acquired, &pid) != nil || !acquired {
		closeDeploymentConnection(connection)
		return nil, deploymentBinding{}, 0, errors.New("PostgreSQL deployment in use by an offline process")
	}
	if mode == "local" {
		if connection.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", deploymentLock+1).Scan(&acquired) != nil || !acquired {
			closeDeploymentConnection(connection)
			return nil, deploymentBinding{}, 0, errors.New("PostgreSQL local deployment already has an instance")
		}
	}
	binding, current, err := deploymentState(ctx, connection)
	if err != nil || !current || binding.mode != mode {
		closeDeploymentConnection(connection)
		return nil, deploymentBinding{}, 0, errors.New("PostgreSQL deployment has a different mode or requires recovery; follow the offline runbook")
	}
	return connection, binding, pid, nil
}

func (p *postgresStore) attachDeployment(ctx context.Context, mode string) (func(), error) {
	connection, binding, pid, err := acquireDeployment(ctx, p.db, mode)
	if err != nil {
		return nil, err
	}
	lease := &deploymentLease{binding: binding}
	lease.pid.Store(pid)
	p.deployment = lease
	lifetime, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if connection != nil {
				closeDeploymentConnection(connection)
			}
		}()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-timer.C:
				if connection != nil {
					probe, cancel := context.WithTimeout(lifetime, time.Second)
					err := connection.PingContext(probe)
					cancel()
					if err == nil {
						continue
					}
					lease.pid.Store(0)
					closeDeploymentConnection(connection)
					connection = nil
				}
				next, current, pid, err := acquireDeployment(lifetime, p.db, mode)
				if err != nil {
					continue
				}
				if current != binding {
					closeDeploymentConnection(next)
					return
				}
				connection = next
				lease.pid.Store(pid)
			}
		}
	}()
	return func() { stop(); <-done }, nil
}

func (p *postgresStore) checkDeployment(ctx context.Context, q rowQueryer) error {
	lease := p.deployment
	if lease == nil {
		return nil
	}
	pid := lease.pid.Load()
	if pid == 0 {
		return errDeployment
	}
	var mode string
	var generation int64
	var matched, active bool
	if err := q.QueryRowContext(ctx, `SELECT mode,generation,database_name=current_database() AND database_oid=(
        SELECT oid FROM pg_database WHERE datname=current_database())
        AND cluster_id=(SELECT system_identifier FROM pg_control_system()),
        EXISTS(SELECT FROM pg_locks WHERE locktype='advisory' AND pid=$1 AND granted AND objsubid=1
            AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
            AND classid=($2::bigint >> 32)::oid AND objid=($2::bigint & 4294967295)::oid)
        FROM chezhi_deployment WHERE singleton`, pid, deploymentLock).Scan(&mode, &generation, &matched, &active); err != nil {
		return errDatabase
	}
	if !active || !matched || (deploymentBinding{mode: mode, generation: generation}) != lease.binding {
		return errDeployment
	}
	return nil
}

func (p *postgresStore) offlineSecurity(ctx context.Context, name, nextMode string) error {
	var sessions, rates int
	mode := nextMode
	err := p.transaction(ctx, &sql.TxOptions{}, func(ctx context.Context, tx *sql.Tx) error {
		var acquired bool
		if tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", deploymentLock).Scan(&acquired) != nil {
			return errDatabase
		}
		if !acquired {
			return errors.New("PostgreSQL deployment is online; stop every instance first")
		}
		if err := verifyMigratorRole(ctx, tx); err != nil {
			return err
		}
		var nameMatches bool
		if tx.QueryRowContext(ctx, "SELECT current_database()=$1", name).Scan(&nameMatches) != nil {
			return errDatabase
		}
		if !nameMatches {
			return errors.New("confirmation does not match connected database name")
		}
		state, matched, err := deploymentState(ctx, tx)
		if err != nil {
			return err
		}
		action := "runtime_mode_changed"
		switch {
		case nextMode == "":
			if matched {
				return errors.New("recovery requires a newly created restore database with a different identity")
			}
			mode, action = state.mode, "security_recovered"
		case !matched:
			return errors.New("restore security must be reset before changing modes")
		case state.mode == nextMode:
			return errors.New("requested PostgreSQL mode is already active")
		}
		if tx.QueryRowContext(ctx, `WITH removed AS (DELETE FROM chezhi_sessions RETURNING 1)
            SELECT count(*) FROM removed`).Scan(&sessions) != nil {
			return errDatabase
		}
		if tx.QueryRowContext(ctx, `WITH removed AS (DELETE FROM chezhi_rate_limits RETURNING 1)
            SELECT count(*) FROM removed`).Scan(&rates) != nil {
			return errDatabase
		}
		if err := dbExec(ctx, tx, `UPDATE chezhi_deployment SET mode=$1,generation=generation+1,
            database_name=current_database(), database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()),
            cluster_id=(SELECT system_identifier FROM pg_control_system())
            WHERE singleton`, mode); err != nil {
			return err
		}
		if err := appendAudit(ctx, tx, Audit{At: time.Now().UTC(), Action: action, Actor: "admin"}); err != nil {
			return err
		}
		return nil
	})
	if err == nil {
		fmt.Printf("Security state reset: mode=%s sessions=%d rate_buckets=%d\n", mode, sessions, rates)
	}
	return err
}
