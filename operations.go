package main

import (
	"net/url"
	"strconv"
	"strings"
	"time"
)

type OrderRow struct {
	Ref, Channel                    string
	Created                         time.Time
	Days, Count, Activated, Revoked int
	Cents                           int64
}
type DeviceRow struct {
	Card  Card
	State string
}
type TrendDay struct {
	Label         string
	Cards, Orders int
	Cents         int64
	Height        int
}
type Operations struct {
	Orders             []OrderRow
	Devices            []DeviceRow
	Trend              []TrendDay
	Q, Channel, State  string
	Count, Page, Pages int
	Prev, Next         string
}

// Read-only projections of the existing authoritative card records; no new state.
func buildOperations(s State, now time.Time, section string, q url.Values) Operations {
	o := Operations{Q: strings.TrimSpace(q.Get("oq")), Channel: q.Get("oc"), State: q.Get("ds")}
	if len(o.Q) > 80 {
		o.Q = ""
	}
	if o.Channel != "test" && o.Channel != "wechat" && o.Channel != "alipay" {
		o.Channel = ""
	}
	if o.State != "已激活" && o.State != "已过期" && o.State != "已吊销" {
		o.State = ""
	}
	match := func(v string) bool { return strings.Contains(strings.ToLower(v), strings.ToLower(o.Q)) }
	days := map[string]int{}
	dayOrders := make([]map[string]bool, 7)
	for i := 0; i < 7; i++ {
		d := now.In(beijing).AddDate(0, 0, i-6)
		days[d.Format("2006-01-02")] = i
		o.Trend = append(o.Trend, TrendDay{Label: d.Format("01/02")})
		dayOrders[i] = map[string]bool{}
	}
	orderIndex := map[string]int{}
	for i := len(s.Cards) - 1; i >= 0; i-- {
		c := s.Cards[i]
		if j, ok := days[c.Created.In(beijing).Format("2006-01-02")]; ok && c.Channel != "test" {
			o.Trend[j].Cards++
			o.Trend[j].Cents += int64(c.AmountCents)
			dayOrders[j][c.SaleRef] = true
		}
		if section == "orders" && (o.Channel == "" || c.Channel == o.Channel) && match(c.SaleRef) {
			j, ok := orderIndex[c.SaleRef]
			if !ok {
				j = len(o.Orders)
				orderIndex[c.SaleRef] = j
				o.Orders = append(o.Orders, OrderRow{Ref: c.SaleRef, Channel: c.Channel, Created: c.Created, Days: c.Days})
			}
			v := &o.Orders[j]
			v.Count++
			v.Cents += int64(c.AmountCents)
			if c.Activated != nil {
				v.Activated++
			}
			if c.Revoked {
				v.Revoked++
			}
		}
		if section == "devices" && c.Device != "" && (o.State == "" || cardStatus(c, now) == o.State) && (match(c.Prefix) || match(c.SaleRef)) {
			o.Devices = append(o.Devices, DeviceRow{Card: c, State: cardStatus(c, now)})
		}
	}
	peak := 0
	for i := range o.Trend {
		o.Trend[i].Orders = len(dayOrders[i])
		peak = max(peak, o.Trend[i].Cards)
	}
	if peak > 0 {
		for i := range o.Trend {
			if o.Trend[i].Cards > 0 {
				o.Trend[i].Height = max(5, 100*o.Trend[i].Cards/peak)
			}
		}
	}
	if section == "orders" {
		o.Count = len(o.Orders)
	} else if section == "devices" {
		o.Count = len(o.Devices)
	} else {
		return o
	}
	o.Page, o.Pages = pageNum(q.Get("op"), o.Count)
	start := (o.Page - 1) * 20
	end := min(start+20, o.Count)
	if section == "orders" {
		o.Orders = o.Orders[start:end]
	} else {
		o.Devices = o.Devices[start:end]
	}
	link := func(n int) string {
		return "/?" + url.Values{"view": {section}, "oq": {o.Q}, "oc": {o.Channel}, "ds": {o.State}, "op": {strconv.Itoa(n)}}.Encode()
	}
	if o.Page > 1 {
		o.Prev = link(o.Page - 1)
	}
	if o.Page < o.Pages {
		o.Next = link(o.Page + 1)
	}
	return o
}
