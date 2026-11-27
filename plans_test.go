package main

import (
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCatalogPersistenceAndHistory(t *testing.T) {
	s := testStore(t)
	issueOne(t, s, 30)
	before, _ := os.ReadFile(s.path)
	f := url.Values{}
	for _, p := range defaultPlans() {
		k := strconv.Itoa(p.Days)
		f.Set("price_"+k, "")
		f.Set("visible_"+k, "yes")
	}
	f.Set("price_30", "9.90")
	f.Set("price_1", "0")
	f.Del("visible_365")
	if e := s.savePlans(f); e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(s.path)
	if string(before) != string(after) {
		t.Fatal("historical state mutated")
	}
	reopened, e := openStore(s.path)
	if e != nil {
		t.Fatal(e)
	}
	p := reopened.catalog()
	if p[2].Price() != "9.90" || p[0].Price() != "0.00" || p[4].Visible {
		t.Fatal("catalog persistence")
	}
	w := Web{reopened, "secret", "csrf", "127.0.0.1:1"}
	r := httptest.NewRequest("GET", "http://"+w.host+"/purchase", nil)
	rr := httptest.NewRecorder()
	w.ServeHTTP(rr, r)
	b := rr.Body.String()
	if !strings.Contains(b, "¥9.90") || !strings.Contains(b, "¥0.00") || strings.Contains(b, "年卡") || strings.Contains(b, "csrf") {
		t.Fatal("catalog rendering")
	}
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(s.path), "plans.json"))
	f.Set("price_30", "9.999")
	if s.savePlans(f) == nil {
		t.Fatal("invalid price")
	}
	raw2, _ := os.ReadFile(filepath.Join(filepath.Dir(s.path), "plans.json"))
	if string(raw) != string(raw2) {
		t.Fatal("partial save")
	}
}
