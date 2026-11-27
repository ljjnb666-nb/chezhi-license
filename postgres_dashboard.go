package main

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strings"
	"time"
)

const cardStatusSQL = `CASE WHEN c.revoked THEN '已吊销'
    WHEN c.expires<=$1::numeric THEN '已过期'
    WHEN c.activated IS NULL THEN '未激活'
    WHEN c.device='' THEN '已解绑' ELSE '已激活' END`

// dashboardPage reads at most one page of rows, within the same transaction as
// its counts. SQL fragments are fixed by the section and user values are bound.
func (p *postgresStore) dashboardPage(ctx context.Context, v *View, q url.Values) error {
	return p.transaction(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(ctx context.Context, tx *sql.Tx) error {
		d, o := dashboardFilters("", q), operationsFilters(q)
		var err error
		switch v.Section {
		case "overview":
			err = readOverview(ctx, tx, v.Now, &d, &o)
		case "cards":
			err = readCardsPage(ctx, tx, v.Now, &d, q)
		case "orders":
			err = readOrdersPage(ctx, tx, &o, q)
		case "devices":
			err = readDevicesPage(ctx, tx, v.Now, &o, q)
		case "audit":
			err = readAuditPage(ctx, tx, &d, q)
		case "settings":
			if tx.QueryRowContext(ctx, "SELECT qq FROM chezhi_config WHERE singleton").Scan(&d.QQ) != nil {
				err = errDatabase
			}
		case "issue", "plans":
			v.Plans, err = readPlans(ctx, tx)
		}
		if err != nil {
			return err
		}
		v.Dashboard, v.Operations = d, o
		return nil
	})
}

func readOverview(ctx context.Context, tx *sql.Tx, now time.Time, d *Dashboard, o *Operations) error {
	if err := tx.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE state='已激活'),
        count(*) FILTER(WHERE state='未激活'),count(*) FILTER(WHERE state='已过期'),
        count(*) FILTER(WHERE state='已吊销'),count(*) FILTER(WHERE state='已解绑'),
        count(DISTINCT ref) FILTER(WHERE channel<>'test'),coalesce(sum(cents) FILTER(WHERE channel<>'test'),0)
        FROM (SELECT c.ref,o.channel,o.cents,`+cardStatusSQL+` AS state
            FROM chezhi_cards c JOIN chezhi_orders o USING(ref)) s`, sqlTime(now)).
		Scan(&d.Stats.Total, &d.Stats.Active, &d.Stats.Unused, &d.Stats.Expired, &d.Stats.Revoked, &d.Stats.Unbound,
			&d.Stats.Orders, &d.Stats.ManualCents); err != nil {
		return errDatabase
	}

	t := now.In(beijing)
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, beijing)
	from := midnight.AddDate(0, 0, -6)
	o.Trend = emptyTrend(now)
	rows, err := tx.QueryContext(ctx, `SELECT floor((o.created-$1::numeric)/86400)::int,count(*),count(DISTINCT o.ref),sum(o.cents)
        FROM chezhi_orders o JOIN chezhi_cards c USING(ref)
        WHERE o.channel<>'test' AND o.created>=$1::numeric AND o.created<$2::numeric GROUP BY 1`,
		sqlTime(from), sqlTime(midnight.AddDate(0, 0, 1)))
	if err != nil {
		return errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var day, cards, orders int
		var cents int64
		if rows.Scan(&day, &cards, &orders, &cents) != nil || day < 0 || day >= len(o.Trend) {
			return errDatabase
		}
		row := &o.Trend[day]
		row.Cards, row.Orders, row.Cents = cards, orders, cents
	}
	if rows.Err() != nil {
		return errDatabase
	}
	o.scaleTrend()
	return nil
}

const cardSearchSQL = ` AND ($3='' OR strpos(lower(c.prefix COLLATE "pg_c_utf8"),$3)>0
    OR strpos(lower(c.ref COLLATE "pg_c_utf8"),$3)>0)`

func readCardsPage(ctx context.Context, tx *sql.Tx, now time.Time, d *Dashboard, q url.Values) error {
	const from = ` FROM chezhi_cards c JOIN chezhi_orders o USING(ref)`
	const filter = ` WHERE ($2='' OR ` + cardStatusSQL + `=$2)` + cardSearchSQL + ` AND ($4='' OR o.channel=$4)`
	args := []any{sqlTime(now), d.Status, strings.ToLower(d.Q), d.Channel}
	if tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM chezhi_cards),count(*)"+from+filter, args...).Scan(&d.Stats.Total, &d.Count) != nil {
		return errDatabase
	}
	d.Page, d.Pages = pageNum(q.Get("page"), d.Count)
	var err error
	d.Cards, err = queryCards(ctx, tx, filter+" ORDER BY c.position DESC LIMIT 20 OFFSET $5", append(args, (d.Page-1)*20)...)
	d.addLinks()
	return err
}

func readDevicesPage(ctx context.Context, tx *sql.Tx, now time.Time, o *Operations, q url.Values) error {
	const filter = ` WHERE c.device<>'' AND ($2='' OR ` + cardStatusSQL + `=$2)` + cardSearchSQL
	args := []any{sqlTime(now), o.State, strings.ToLower(o.Q)}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_cards c"+filter, args...).Scan(&o.Count) != nil {
		return errDatabase
	}
	o.Page, o.Pages = pageNum(q.Get("op"), o.Count)
	cards, err := queryCards(ctx, tx, filter+" ORDER BY c.position DESC LIMIT 20 OFFSET $4", append(args, (o.Page-1)*20)...)
	if err != nil {
		return err
	}
	for _, c := range cards {
		o.Devices = append(o.Devices, DeviceRow{Card: c, State: cardStatus(c, now)})
	}
	o.addLinks("devices")
	return nil
}

func readOrdersPage(ctx context.Context, tx *sql.Tx, o *Operations, q url.Values) error {
	const filter = ` WHERE ($1='' OR o.channel=$1) AND ($2='' OR strpos(lower(o.ref COLLATE "pg_c_utf8"),$2)>0)`
	args := []any{o.Channel, strings.ToLower(o.Q)}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_orders o"+filter+
		" AND EXISTS (SELECT 1 FROM chezhi_cards c WHERE c.ref=o.ref)", args...).Scan(&o.Count) != nil {
		return errDatabase
	}
	o.Page, o.Pages = pageNum(q.Get("op"), o.Count)
	rows, err := tx.QueryContext(ctx, `SELECT o.ref,o.channel,o.created,o.days,count(*),
        count(*) FILTER (WHERE c.activated IS NOT NULL),count(*) FILTER (WHERE c.revoked),sum(o.cents)
        FROM chezhi_orders o JOIN chezhi_cards c USING(ref)`+filter+
		" GROUP BY o.ref ORDER BY max(c.position) DESC LIMIT 20 OFFSET $3", append(args, (o.Page-1)*20)...)
	if err != nil {
		return errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var order OrderRow
		var created string
		if rows.Scan(&order.Ref, &order.Channel, &created, &order.Days, &order.Count, &order.Activated, &order.Revoked, &order.Cents) != nil {
			return errDatabase
		}
		order.Created, err = parseSQLTime(created)
		if err != nil {
			return err
		}
		o.Orders = append(o.Orders, order)
	}
	if rows.Err() != nil {
		return errDatabase
	}
	o.addLinks("orders")
	return nil
}

func readAuditPage(ctx context.Context, tx *sql.Tx, d *Dashboard, q url.Values) error {
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_audit").Scan(&d.AuditCount) != nil {
		return errDatabase
	}
	d.AuditPage, d.AuditPages = pageNum(q.Get("ap"), d.AuditCount)
	var err error
	d.Audits, err = queryAudit(ctx, tx, " ORDER BY position DESC LIMIT 20 OFFSET $1", (d.AuditPage-1)*20)
	d.addLinks()
	return err
}

var errExportLimit = errors.New("server export exceeds interactive limit")

func (p *postgresStore) readServerExport(ctx context.Context, archive bool) (State, []Plan, error) {
	var state State
	var plans []Plan
	err := p.transaction(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead}, func(ctx context.Context, tx *sql.Tx) error {
		var tooMany bool
		if tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM chezhi_cards OFFSET 20000 LIMIT 1)
            OR ($1 AND EXISTS(SELECT FROM chezhi_audit OFFSET 100000 LIMIT 1))`, archive).Scan(&tooMany) != nil {
			return errDatabase
		}
		if tooMany {
			return errExportLimit
		}
		var err error
		if archive {
			state, err = readState(ctx, tx, true)
			if err != nil {
				return err
			}
			plans, err = readPlans(ctx, tx)
			return err
		}
		state.Cards, err = queryCards(ctx, tx, " ORDER BY c.position")
		return err
	})
	return state, plans, err
}
