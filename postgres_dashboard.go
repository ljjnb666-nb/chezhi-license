package main

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"strconv"
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

// Aggregate each card exactly once into its order. The FK ensures every
// card belongs to an order. Status totals include test orders; revenue
// and trend explicitly exclude them. GROUPING distinguishes total rows
// from the NULL day bucket for orders outside the seven-day window.
const overviewCombinedSQL = `WITH quantities AS (
    SELECT c.ref,count(*) AS cards,
        count(*) FILTER (WHERE c.revoked) AS revoked,
        count(*) FILTER (WHERE NOT c.revoked AND c.expires<=$1::numeric) AS expired,
        count(*) FILTER (WHERE NOT c.revoked AND c.activated IS NULL) AS unused,
        count(*) FILTER (WHERE NOT c.revoked AND c.activated IS NOT NULL AND c.device='' AND (c.expires<=$1::numeric) IS NOT TRUE) AS unbound
    FROM chezhi_cards c GROUP BY c.ref
), sales AS (
    SELECT CASE WHEN o.channel<>'test' AND o.created>=$2::numeric AND o.created<$3::numeric
        THEN floor((o.created-$2::numeric)/86400)::int END AS day,
        q.*,o.channel<>'test' AS paid,q.cards::numeric*o.cents AS cents
    FROM quantities q JOIN chezhi_orders o USING(ref)
)
SELECT grouping(day),day,coalesce(sum(cards) FILTER (WHERE paid),0),
    count(*) FILTER (WHERE paid),coalesce(sum(cents) FILTER (WHERE paid),0),
    coalesce(sum(cards),0),coalesce(sum(revoked),0),coalesce(sum(expired),0),
    coalesce(sum(unused),0),coalesce(sum(unbound),0)
FROM sales GROUP BY GROUPING SETS ((day),())`

func readOverview(ctx context.Context, tx *sql.Tx, now time.Time, d *Dashboard, o *Operations) error {
	t := now.In(beijing)
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, beijing)
	o.Trend = emptyTrend(now)
	rows, err := tx.QueryContext(ctx, overviewCombinedSQL, sqlTime(now),
		sqlTime(midnight.AddDate(0, 0, -6)), sqlTime(midnight.AddDate(0, 0, 1)))
	if err != nil {
		return errDatabase
	}
	defer rows.Close()
	for rows.Next() {
		var summary, cards, orders, total, revoked, expired, unused, unbound int
		var day sql.NullInt32
		var cents int64
		if rows.Scan(&summary, &day, &cards, &orders, &cents, &total, &revoked,
			&expired, &unused, &unbound) != nil {
			return errDatabase
		}
		if summary == 1 {
			d.Stats.Orders, d.Stats.ManualCents = orders, cents
			d.Stats.Total, d.Stats.Revoked, d.Stats.Expired = total, revoked, expired
			// The schema guarantees unactivated cards have NULL expiry.
			// The five status buckets are disjoint and exhaustive.
			if revoked+expired+unused+unbound > total { return errDatabase }
			d.Stats.Unused, d.Stats.Unbound = unused, unbound
			d.Stats.Active = total - revoked - expired - unused - unbound
			continue
		}
		if day.Valid {
			if day.Int32 < 0 || int(day.Int32) >= len(o.Trend) {
				return errDatabase
			}
			o.Trend[day.Int32].Cards, o.Trend[day.Int32].Orders, o.Trend[day.Int32].Cents = cards, orders, cents
		}
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
	if d.Status == "" && d.Q == "" && d.Channel == "" {
		if tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_cards").Scan(&d.Count) != nil {
			return errDatabase
		}
		d.Stats.Total = d.Count
	} else if tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM chezhi_cards),count(*)"+from+filter, args...).Scan(&d.Stats.Total, &d.Count) != nil {
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

const orderFilterSQL = ` WHERE ($1='' OR o.channel=$1) AND ($2='' OR strpos(lower(o.ref COLLATE "pg_c_utf8"),$2)>0)`
const ordersPageSQL = `WITH page AS (
    SELECT o.ref,o.channel,o.created,o.days,o.cents,last_card.position
    FROM chezhi_orders o
    JOIN LATERAL (SELECT c.position FROM chezhi_cards c WHERE c.ref=o.ref ORDER BY c.position DESC LIMIT 1) last_card ON true
    ` + orderFilterSQL + ` ORDER BY last_card.position DESC LIMIT 20 OFFSET $3
)
SELECT p.ref,p.channel,p.created,p.days,q.cards,q.activated,q.revoked,q.cards::numeric*p.cents
FROM page p CROSS JOIN LATERAL (
    SELECT count(*) AS cards,count(*) FILTER (WHERE c.activated IS NOT NULL) AS activated,
        count(*) FILTER (WHERE c.revoked) AS revoked FROM chezhi_cards c WHERE c.ref=p.ref
) q ORDER BY p.position DESC`

// Share the exact grouped order keys between count and page. A single
// sentinel row carries the count for an empty database. Clamp the requested
// page before OFFSET, retaining last-card position ordering.
const ordersUnfilteredPageSQL = `WITH keys AS MATERIALIZED (
    SELECT ref,max(position) AS position FROM chezhi_cards GROUP BY ref
), totals AS (
    SELECT count(*) AS n FROM keys
), page AS (
    SELECT ref,position FROM keys ORDER BY position DESC LIMIT 20
    OFFSET (SELECT (least($1::bigint,greatest(1,(n+19)/20))-1)*20 FROM totals)
), details AS (
    SELECT p.position,o.ref,o.channel,o.created,o.days,q.cards,q.activated,q.revoked,q.cards::numeric*o.cents AS cents
    FROM page p JOIN chezhi_orders o USING(ref) CROSS JOIN LATERAL (
        SELECT count(*) AS cards,count(*) FILTER (WHERE c.activated IS NOT NULL) AS activated,
            count(*) FILTER (WHERE c.revoked) AS revoked FROM chezhi_cards c WHERE c.ref=p.ref
    ) q
)
SELECT t.n,d.ref IS NOT NULL,coalesce(d.ref,''),coalesce(d.channel,''),coalesce(d.created::text,''),
    coalesce(d.days,0),coalesce(d.cards,0),coalesce(d.activated,0),coalesce(d.revoked,0),coalesce(d.cents,0)
FROM totals t LEFT JOIN details d ON true ORDER BY d.position DESC`

func readUnfilteredOrdersPage(ctx context.Context, tx *sql.Tx, o *Operations, q url.Values) error {
	requested, err := strconv.Atoi(q.Get("op"))
	if err != nil || requested < 1 { requested = 1 }
	rows, err := tx.QueryContext(ctx, ordersUnfilteredPageSQL, requested)
	if err != nil { return errDatabase }
	defer rows.Close()
	seen := false
	for rows.Next() {
		var order OrderRow
		var count int
		var present bool
		var created string
		if rows.Scan(&count, &present, &order.Ref, &order.Channel, &created, &order.Days,
			&order.Count, &order.Activated, &order.Revoked, &order.Cents) != nil { return errDatabase }
		if seen && count != o.Count { return errDatabase }
		seen, o.Count = true, count
		if !present {
			if count != 0 { return errDatabase }
			continue
		}
		order.Created, err = parseSQLTime(created)
		if err != nil { return err }
		o.Orders = append(o.Orders, order)
	}
	if rows.Err() != nil || !seen { return errDatabase }
	o.Page, o.Pages = pageNum(q.Get("op"), o.Count)
	o.addLinks("orders")
	return nil
}

func readOrdersPage(ctx context.Context, tx *sql.Tx, o *Operations, q url.Values) error {
	if o.Channel == "" && o.Q == "" { return readUnfilteredOrdersPage(ctx, tx, o, q) }
	args := []any{o.Channel, strings.ToLower(o.Q)}
	if tx.QueryRowContext(ctx, "SELECT count(*) FROM chezhi_orders o"+orderFilterSQL+
		" AND EXISTS (SELECT 1 FROM chezhi_cards c WHERE c.ref=o.ref)", args...).Scan(&o.Count) != nil {
		return errDatabase
	}
	o.Page, o.Pages = pageNum(q.Get("op"), o.Count)
	rows, err := tx.QueryContext(ctx, ordersPageSQL, append(args, (o.Page-1)*20)...)
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
			if err := denySecureLegacyBackup(ctx, tx); err != nil { return err }
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
