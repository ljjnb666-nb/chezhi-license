package main

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartupIntegrity(t *testing.T) {
	s := testStore(t)
	k := issueOne(t, s, 30)
	check(t, s, k, "device", true, "")
	raw, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(State) State{
		"duplicate card": func(x State) State { x.Cards = append(x.Cards, x.Cards[0]); return x },
		"invalid expiry": func(x State) State { x.Cards[0].Expires = nil; return x },
		"orphan audit":   func(x State) State { x.Audit[0].CardID = "missing"; return x },
		"invalid qq":     func(x State) State { x.QQ = ""; return x },
		"invalid hash":   func(x State) State { x.Cards[0].Hash = "broken"; return x },
		"invalid order":  func(x State) State { x.Cards[0].SaleRef = "a\x00b"; return x },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			var x State
			if json.Unmarshal(raw, &x) != nil {
				t.Fatal("fixture")
			}
			b, _ := json.Marshal(mut(x))
			if os.WriteFile(s.path, b, 0600) != nil {
				t.Fatal("write")
			}
			if _, e := openStore(s.path); e == nil {
				t.Fatal("invalid state accepted")
			}
			after, _ := os.ReadFile(s.path)
			if string(after) != string(b) {
				t.Fatal("state changed")
			}
		})
	}
	for _, bad := range []string{`null`, `{}`, `{"QQ":"----------","Cards":null,"Audit":null,"QQ":"12345"}`, `{"QQ":"----------","Cards":null,"Audit":null,"qq":"12345"}`} {
		if _, e := decodeState([]byte(bad)); e == nil {
			t.Fatal("accepted malformed state")
		}
	}
	if e := os.WriteFile(s.path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := openStore(s.path); e != nil {
		t.Fatal(e)
	}
}
func TestConcurrentDuplicateOrder(t *testing.T) {
	s := testStore(t)
	var n atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.issue(30, 2, 0, "test", "same-order"); e == nil {
				n.Add(1)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 || len(s.snapshot().Cards) != 2 || len(s.snapshot().Audit) != 2 {
		t.Fatal("duplicate issue")
	}
}
func TestClockRollbackBeforeActivation(t *testing.T) {
	s := testStore(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	k := issueOne(t, s, 30)
	now = now.Add(-time.Hour)
	if _, e := s.validate(k, "A"); e == nil || s.snapshot().Cards[0].Activated != nil {
		t.Fatal("accepted backward clock")
	}
}
func TestDuplicateScalarFields(t *testing.T) {
	s := testStore(t)
	w := Web{s, "secret", "csrf", "127.0.0.1:12345"}
	v := url.Values{"csrf": {"csrf"}, "action": {"qq", "issue"}, "qq": {"123456"}}
	r := httptest.NewRequest("POST", "http://"+w.host+"/", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	w.ServeHTTP(rr, r)
	if rr.Code != 400 || s.snapshot().QQ != "----------" {
		t.Fatal("ambiguous request accepted")
	}
}
