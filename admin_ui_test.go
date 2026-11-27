package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAdminSectionsAndIssuedKeyIsolation(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "admin-csrf", "127.0.0.1:12345"}
	call := func(method, path string, fields url.Values, auth bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+w.host+path, strings.NewReader(fields.Encode()))
		if auth {
			r.SetBasicAuth("admin", "secret")
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://"+w.host)
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		return rr
	}
	for view, heading := range map[string]string{"overview": "概览", "issue": "人工发卡", "cards": "卡密管理", "audit": "操作日志", "settings": "客服设置"} {
		path := "/?view=" + view
		if call("GET", path, nil, false).Code != 401 {
			t.Fatal("unauthenticated", view)
		}
		rr := call("GET", path, nil, true)
		b := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(b, "<h1>"+heading+"</h1>") || strings.Count(b, "aria-current=\"page\"") != 1 || strings.Contains(b, "北京时间") || strings.Contains(b, "UTC+8") {
			t.Fatal("navigation", view)
		}
		if strings.Contains(b, `id="preset"`) != (view == "issue") || strings.Contains(b, `id="batch"`) != (view == "cards") || strings.Contains(b, `id="qq"`) != (view == "settings") || strings.Contains(b, `id="issue-result"`) {
			t.Fatal("section content", view)
		}
	}
	fields := url.Values{"action": {"issue"}, "preset": {"30"}, "quantity": {"2"}, "amount_yuan": {"9.90"}, "channel": {"test"}, "sale_ref": {"new-ui"}, "csrf": {w.csrf}, "confirmed": {"yes"}}
	rr := call("POST", "/?view=issue", fields, true)
	b := rr.Body.String()
	form := strings.Index(b, `id="preset"`)
	result := strings.Index(b, `id="issue-result"`)
	if rr.Code != 200 || form < 0 || result < form || !strings.Contains(b, "复制全部") || !strings.Contains(b, "本次生成的卡密（2 张）") || len(s.snapshot().Cards) != 2 || s.snapshot().Cards[0].AmountCents != 990 {
		t.Fatal("issue result")
	}
	if strings.Contains(call("GET", "/?view=issue", nil, true).Body.String(), `id="issue-result"`) || strings.Contains(call("GET", "/", nil, true).Body.String(), `id="issue-result"`) {
		t.Fatal("result persists")
	}
	if rr := call("POST", "/?view=issue", fields, true); !strings.Contains(rr.Body.String(), "该订单已生成卡密") || len(s.snapshot().Cards) != 2 {
		t.Fatal("duplicate")
	}
	if call("GET", "/admin-ui.js", nil, false).Code != 401 || call("POST", "/admin-ui.js", nil, true).Code != 405 {
		t.Fatal("script access")
	}
	js := call("GET", "/admin-ui.js", nil, true)
	if js.Code != 200 || !strings.Contains(js.Body.String(), "navigator.clipboard") {
		t.Fatal("script missing")
	}
	if !strings.Contains(call("GET", "/?view=audit", nil, true).Body.String(), ">生成卡密</td>") {
		t.Fatal("audit label")
	}
	if !strings.Contains(call("GET", "/?q=new-ui", nil, true).Body.String(), "匹配 2 条") {
		t.Fatal("legacy filter")
	}
}

func TestIssueAmountDecimal(t *testing.T) {
	for raw, want := range map[string]int{"0": 0, "0.01": 1, "9.9": 990, "9.90": 990, "1000000.00": 100000000} {
		got, err := parseIssueAmount(url.Values{"amount_yuan": {raw}})
		if err != nil || got != want {
			t.Fatal(raw, got, err)
		}
	}
	for _, raw := range []string{"", "-1", "1e2", "1.001", "1000000.01", "1.", ".5", "10000000", "1,2"} {
		if _, err := parseIssueAmount(url.Values{"amount_yuan": {raw}}); err == nil {
			t.Fatal("invalid amount", raw)
		}
	}
	if _, err := parseIssueAmount(url.Values{"amount_yuan": {"1", "2"}}); err == nil {
		t.Fatal("duplicate")
	}
	if _, err := parseIssueAmount(url.Values{"amount_yuan": {"1"}, "amount": {"1"}}); err == nil {
		t.Fatal("ambiguous amount")
	}
	if got, err := parseIssueAmount(url.Values{"amount": {"990"}}); got != 990 || err != nil {
		t.Fatal("legacy amount", got, err)
	}
}
