package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPurchaseIsolation(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "admin-token", "127.0.0.1:12345"}
	_ = s.setQQ("123456789")
	_ = issueOne(t, s, 30)
	for _, method := range []string{"GET", "POST"} {
		r := httptest.NewRequest(method, "http://"+w.host+"/purchase", nil)
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		if method == "POST" {
			if rr.Code != 405 {
				t.Fatal(rr.Code)
			}
			continue
		}
		b := rr.Body.String()
		if rr.Code != 200 || !strings.Contains(b, "123456789") || !strings.Contains(b, "30 <small>天") || strings.Contains(b, w.csrf) || strings.Contains(b, "test-1") || strings.Contains(b, "卡密记录") {
			t.Fatal("purchase data boundary")
		}
	}
}
func TestNativeDemoEndpoint(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "admin-token", "127.0.0.1:12345"}
	key := issueOne(t, s, 30)
	call := func(method, body, ct string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+w.host+"/api/demo/activate", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		w.ServeHTTP(rr, r)
		return rr
	}
	payload := func(device string) string { b, _ := json.Marshal(demoRequest{key, device}); return string(b) }
	for _, tc := range []struct {
		method, body, ct string
		headers          map[string]string
		code             int
	}{{"GET", "", "", nil, 405}, {"POST", payload("A"), "text/plain", nil, 415}, {"POST", payload("A"), "application/json", map[string]string{"Origin": "null"}, 403}, {"POST", payload("A"), "application/json", map[string]string{"Origin": "http://evil.test"}, 403}, {"POST", payload("A"), "application/json", map[string]string{"Sec-Fetch-Site": "same-origin"}, 403}, {"POST", payload("A"), "application/json", map[string]string{"Referer": "http://evil.test"}, 403}, {"POST", payload("A") + " {}", "application/json", nil, 400}, {"POST", `{"key":"x","device":"y","admin":true}`, "application/json", nil, 400}, {"POST", strings.Repeat("x", 5000), "application/json", nil, 400}} {
		if r := call(tc.method, tc.body, tc.ct, tc.headers); r.Code != tc.code {
			t.Fatalf("want %d got %d", tc.code, r.Code)
		}
	}
	if s.snapshot().Cards[0].Activated != nil {
		t.Fatal("rejected request activated")
	}
	checkResult := func(device string, valid bool, reason string) {
		t.Helper()
		r := call("POST", payload(device), "application/json", nil)
		var d demoResponse
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &d) != nil || d.Valid != valid || (!valid && d.Reason != reason) || valid && d.Expiry == "" || strings.Contains(r.Body.String(), key) {
			t.Fatalf("unexpected response %d %s", r.Code, r.Body.String())
		}
	}
	checkResult("A", true, "")
	checkResult("B", false, "device_mismatch")
	if err := s.change(s.snapshot().Cards[0].ID, "revoke"); err != nil {
		t.Fatal(err)
	}
	checkResult("A", false, "revoked")
	for i := 0; i < 57; i++ {
		if r := call("POST", payload("A"), "application/json", nil); r.Code != 200 {
			t.Fatal("premature limit")
		}
	}
	r := httptest.NewRequest("POST", "http://"+w.host+"/activate", strings.NewReader("csrf="+w.activationCSRF()+"&key=x&device=A"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	w.ServeHTTP(rr, r)
	if rr.Code != 429 {
		t.Fatal("rate budget not shared", rr.Code)
	}
}
