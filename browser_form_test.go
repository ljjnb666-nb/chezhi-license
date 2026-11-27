package main

import (
	stdhtml "html"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestBrowserFormPolicyAndActions(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "test-form-token", "127.0.0.1:34567"}
	base := "http://" + w.host
	call := func(method string, form url.Values, origins ...string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, base+"/?view=issue", strings.NewReader(form.Encode()))
		r.SetBasicAuth("admin", "secret")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, o := range origins {
			r.Header.Add("Origin", o)
		}
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		return rr
	}
	get := call("GET", nil)
	if get.Code != 200 || get.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser referrer policy regression")
	}
	if !strings.Contains(get.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Fatal("form CSP missing")
	}
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(get.Body.String())
	if len(m) != 2 {
		t.Fatal("missing rendered token")
	}
	csrf := stdhtml.UnescapeString(m[1])
	issue := url.Values{"csrf": {csrf}, "action": {"issue"}, "days": {"30"}, "quantity": {"1"}, "amount": {"0"}, "channel": {"test"}, "sale_ref": {"browser-order"}, "confirmed": {"yes"}}
	for _, origin := range []string{"null", "http://evil.test", "http://127.0.0.1:34568", "https://" + w.host, base + "/"} {
		if got := call("POST", issue, origin); got.Code != 403 {
			t.Fatalf("invalid origin %q accepted: %d", origin, got.Code)
		}
	}
	issue.Set("csrf", "wrong")
	if got := call("POST", issue, base); got.Code != 403 {
		t.Fatal("wrong token accepted")
	}
	issue.Set("csrf", csrf)
	if len(s.snapshot().Cards) != 0 {
		t.Fatal("rejected request mutated state")
	}
	rr := call("POST", issue, base)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "已生成") {
		t.Fatalf("issue failed %d", rr.Code)
	}
	match := regexp.MustCompile(`(?s)<textarea readonly aria-label="生成卡密">(.*?)</textarea>`).FindStringSubmatch(rr.Body.String())
	if len(match) != 2 {
		t.Fatal("missing generated key")
	}
	key := strings.TrimSpace(stdhtml.UnescapeString(match[1]))
	post := func(v url.Values, want string) {
		t.Helper()
		v.Set("csrf", csrf)
		res := call("POST", v, base)
		if res.Code != 200 || !strings.Contains(res.Body.String(), want) {
			t.Fatalf("action %s failed: %d", v.Get("action"), res.Code)
		}
	}
	activate := func(v url.Values, want string) {
		t.Helper()
		v.Set("csrf", w.activationCSRF())
		r := httptest.NewRequest("POST", base+"/activate", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", base)
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		if rr.Code != 200 || !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("activation failed: %d", rr.Code)
		}
	}
	activate(url.Values{"action": {"validate"}, "key": {key}, "device": {"A"}}, "授权验证成功")
	activate(url.Values{"action": {"validate"}, "key": {key}, "device": {"B"}}, "device_mismatch")
	post(url.Values{"action": {"qq"}, "qq": {"123456789"}}, "客服配置已保存")
	id := s.snapshot().Cards[0].ID
	post(url.Values{"action": {"unbind"}, "id": {id}}, "操作完成")
	activate(url.Values{"action": {"validate"}, "key": {key}, "device": {"B"}}, "授权验证成功")
	post(url.Values{"action": {"revoke"}, "id": {id}}, "操作完成")
	activate(url.Values{"action": {"validate"}, "key": {key}, "device": {"B"}}, "revoked")
	if len(s.snapshot().Cards) != 1 {
		t.Fatal("unexpected card count")
	}
}
