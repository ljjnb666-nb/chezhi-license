package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// Catalog prices are reference prices; historical sales remain independent.
type Plan struct {
	Days       int
	Name       string
	PriceCents *int
	Visible    bool
}

func defaultPlans() []Plan {
	out := []Plan{}
	for _, d := range []int{1, 7, 30, 90, 365, 0} {
		name := plan(d)
		if d == 0 {
			name = "永久卡"
		}
		out = append(out, Plan{Days: d, Name: name, Visible: true})
	}
	return out
}
func (p Plan) Price() string {
	if p.PriceCents == nil {
		return ""
	}
	return money(int64(*p.PriceCents))
}
func (s *Store) catalog() []Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Plan(nil), s.plans...)
}
func (s *Store) loadPlans() error {
	s.plans = defaultPlans()
	b, e := os.ReadFile(filepath.Join(filepath.Dir(s.path), "plans.json"))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var saved []Plan
	if e = uniqueJSON(b); e != nil {
		return e
	}
	if e = json.Unmarshal(b, &saved); e != nil {
		return e
	}
	if len(saved) != len(s.plans) {
		return errors.New("invalid catalog")
	}
	for i, p := range saved {
		if p.Days != s.plans[i].Days || p.Name != s.plans[i].Name || p.PriceCents != nil && (*p.PriceCents < 0 || *p.PriceCents > 100000000) {
			return errors.New("invalid catalog")
		}
	}
	s.plans = saved
	return nil
}
func (s *Store) savePlans(f url.Values) error {
	return s.savePlansContext(context.Background(), f, "")
}
func (s *Store) savePlansContext(ctx context.Context, f url.Values, actor string) error {
	next := defaultPlans()
	for i := range next {
		p := &next[i]
		k := strconv.Itoa(p.Days)
		if len(f["price_"+k]) != 1 || len(f["visible_"+k]) > 1 {
			return errors.New("请检查套餐配置")
		}
		raw := f.Get("price_" + k)
		if raw != "" {
			n, e := parseIssueAmount(url.Values{"amount_yuan": {raw}})
			if e != nil {
				return fmt.Errorf("%s：请输入有效价格", p.Name)
			}
			p.PriceCents = &n
		}
		vis := f.Get("visible_" + k)
		if vis != "" && vis != "yes" {
			return errors.New("请检查套餐配置")
		}
		p.Visible = vis == "yes"
	}
	if s.pg != nil {
		return s.pg.savePlans(ctx, next, Audit{At: s.now().UTC(), Action: "plans_config", Actor: actor})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, e := json.MarshalIndent(next, "", "  ")
	if e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(s.path), ".plans-*")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	if _, e = file.Write(b); e != nil {
		file.Close()
		return e
	}
	if e = file.Sync(); e != nil {
		file.Close()
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	if e = os.Rename(file.Name(), filepath.Join(filepath.Dir(s.path), "plans.json")); e != nil {
		return e
	}
	s.plans = next
	return nil
}
