package main

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOperationsProjection(t *testing.T) {
	now := time.Date(2026, 11, 27, 1, 0, 0, 0, time.UTC)
	prev := now.Add(-24 * time.Hour)
	s := State{Cards: []Card{{SaleRef: "O-1", Channel: "wechat", Days: 30, AmountCents: 990, Created: now, Device: "private-device-hash", Activated: &prev, Prefix: "AAAAA"}, {SaleRef: "O-1", Channel: "wechat", Days: 30, AmountCents: 990, Created: now, Revoked: true}, {SaleRef: "O-2", Channel: "test", Created: now, AmountCents: 100}, {SaleRef: "old", Channel: "alipay", Created: now.AddDate(0, 0, -7), AmountCents: 100}}}
	o := buildOperations(s, now, "orders", url.Values{"oc": {"wechat"}})
	if o.Count != 1 || o.Orders[0].Count != 2 || o.Orders[0].Cents != 1980 || o.Orders[0].Activated != 1 || o.Orders[0].Revoked != 1 {
		t.Fatal(o)
	}
	if o.Trend[6].Cents != 1980 || o.Trend[6].Orders != 1 || o.Trend[6].Cards != 2 || o.Trend[6].Height != 100 || o.Trend[0].Cards != 0 {
		t.Fatal(o.Trend)
	}
	d := buildOperations(s, now, "devices", url.Values{"oq": {"aaaa"}})
	if d.Count != 1 || d.Devices[0].State != "已激活" {
		t.Fatal(d)
	}
	if d = buildOperations(s, now, "devices", url.Values{"ds": {"已过期"}}); d.Count != 0 {
		t.Fatal(d)
	}
	for i := 0; i < 25; i++ {
		s.Cards = append(s.Cards, Card{SaleRef: fmt.Sprintf("p-%02d", i), Channel: "wechat", Created: now})
	}
	o = buildOperations(s, now, "orders", url.Values{"oq": {"p-"}, "op": {"999"}})
	if o.Count != 25 || o.Page != 2 || len(o.Orders) != 5 || o.Prev == "" || o.Next != "" {
		t.Fatal(o)
	}
}
func TestOperationsPagesPrivacyAndNavigation(t *testing.T) {
	s := testStore(t)
	keys, e := s.issue(30, 2, 990, "wechat", "sample-01")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.validate(keys[0], "device-A"); e != nil {
		t.Fatal(e)
	}
	state := s.snapshot()
	w := Web{s, "secret", "csrf", "127.0.0.1:12345"}
	for _, v := range []string{"overview", "orders", "devices"} {
		for _, auth := range []bool{false, true} {
			r := httptest.NewRequest("GET", "http://"+w.host+"/?view="+v, nil)
			if auth {
				r.SetBasicAuth("admin", "secret")
			}
			rr := httptest.NewRecorder()
			w.ServeHTTP(rr, r)
			if !auth {
				if rr.Code != 401 {
					t.Fatal(v, rr.Code)
				}
				continue
			}
			b := rr.Body.String()
			if rr.Code != 200 || strings.Count(b, `aria-current="page"`) != 1 || strings.Contains(b, keys[0]) || strings.Contains(b, state.Cards[0].Hash) || strings.Contains(b, state.Cards[0].Device) {
				t.Fatal(v, "privacy/navigation")
			}
			switch v {
			case "overview":
				if !strings.Contains(b, "近 7 日发卡趋势") {
					t.Fatal(v)
				}
			case "orders":
				if !strings.Contains(b, "¥19.80") || !strings.Contains(b, "sample-01") {
					t.Fatal(v)
				}
			case "devices":
				if !strings.Contains(b, "sample-01") || !strings.Contains(b, "已激活") {
					t.Fatal(v)
				}
			}
		}
	}
}
