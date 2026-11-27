package main

import (
	"chezhi.local/licenseprototype/internal/license"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Card struct {
	ID          string     `json:"id"`
	Hash        string     `json:"hash"`
	Prefix      string     `json:"prefix"`
	Days        int        `json:"days"`
	SaleRef     string     `json:"sale_ref"`
	Channel     string     `json:"channel"`
	AmountCents int        `json:"amount_cents"`
	Created     time.Time  `json:"created"`
	Activated   *time.Time `json:"activated,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Device      string     `json:"device_hash,omitempty"`
	Revoked     bool       `json:"revoked"`
}
type Audit struct {
	At     time.Time
	Action string
	CardID string
	Actor  string `json:"Actor,omitempty"`
	Target string `json:"Target,omitempty"`
}
type State struct {
	QQ    string
	Cards []Card
	Audit []Audit
}
type Store struct {
	pg        *postgresStore
	mu        sync.Mutex
	path      string
	state     State
	plans     []Plan
	now       func() time.Time
	rateMu    sync.Mutex
	rateStart time.Time
	rateCount int
}

func openStore(path string) (*Store, error) {
	s := &Store{path: path, now: time.Now, state: State{QQ: "----------"}}
	if e := s.loadPlans(); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return nil, e
	}
	if s.state, e = decodeState(b); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Store) snapshot() State { s.mu.Lock(); defer s.mu.Unlock(); return clone(s.state) }
func clone(x State) State {
	x.Cards = append([]Card(nil), x.Cards...)
	x.Audit = append([]Audit(nil), x.Audit...)
	return x
}
func (s *Store) commit(x State) error {
	b, e := json.MarshalIndent(x, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), s.path); e != nil {
		return e
	}
	s.state = x
	return nil
}
func (s *Store) issue(days, n, amount int, channel, ref string, actors ...string) ([]string, error) {
	return s.issueContext(context.Background(), days, n, amount, channel, ref, actors...)
}
func (s *Store) issueContext(ctx context.Context, days, n, amount int, channel, ref string, actors ...string) ([]string, error) {
	if days < 0 || days > 3650 || n < 1 || n > 100 || amount < 0 || amount > 100000000 {
		return nil, errors.New("invalid plan, count or amount")
	}
	if channel != "wechat" && channel != "alipay" && channel != "test" {
		return nil, errors.New("invalid payment channel")
	}
	ref = strings.TrimSpace(ref)
	if !validOrderRef(ref) {
		return nil, errors.New("sale reference required (max 80 bytes)")
	}
	keys := make([]string, 0, n)
	err := s.mutate(ctx, mutationScope{order: ref}, func(x *State) error {
		for _, c := range x.Cards {
			if c.SaleRef == ref {
				return errOrderExists
			}
		}
		now := s.now().UTC()
		for i := 0; i < n; i++ {
			raw, h, p, e := license.GenerateKey()
			if e != nil {
				return e
			}
			for _, c := range x.Cards {
				if c.Hash == h || c.ID == h[:24] {
					return errors.New("key collision; retry")
				}
			}
			id := h[:24]
			x.Cards = append(x.Cards, Card{ID: id, Hash: h, Prefix: p, Days: days, SaleRef: ref, Channel: channel, AmountCents: amount, Created: now})
			x.Audit = append(x.Audit, Audit{At: now, Action: "issue", CardID: id, Actor: auditActor(actors)})
			keys = append(keys, raw)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}
func (s *Store) validate(raw, device string) (license.ValidationResult, error) {
	return s.validateContext(context.Background(), raw, device)
}
func (s *Store) validateContext(ctx context.Context, raw, device string) (license.ValidationResult, error) {
	return s.checkLicense(ctx, raw, device, true)
}
func (s *Store) checkLicense(ctx context.Context, raw, device string, bind bool) (license.ValidationResult, error) {
	if len(raw) > 100 || len(device) > 200 || strings.TrimSpace(device) == "" {
		return license.ValidationResult{Reason: "invalid_input"}, nil
	}
	h := license.HashKey(raw)
	dh := sha256.Sum256([]byte(strings.TrimSpace(device)))
	d := hex.EncodeToString(dh[:])
	var result license.ValidationResult
	err := s.mutate(ctx, mutationScope{hash: h, readOnly: !bind}, func(x *State) error {
		now := s.now().UTC()
		for i := range x.Cards {
			c := &x.Cards[i]
			if c.Hash != h {
				continue
			}
			r := license.Validate(c.Expires, 0, c.Revoked, "demo", "demo", now)
			if c.Expires != nil && !now.Before(*c.Expires) && !c.Revoked {
				r.Valid = false
				r.Reason = "expired"
			}
			if !r.Valid {
				result = r
				return nil
			}
			if c.Device != "" && c.Device != d {
				result.Reason = "device_mismatch"
				return nil
			}
			if !bind && (c.Activated == nil || c.Device == "") {
				result.Reason = "activation_required"
				return nil
			}
			changed := false
			if c.Activated == nil {
				if now.Before(c.Created) {
					return errors.New("system clock precedes issuance")
				}
				c.Activated = &now
				if c.Days != 0 {
					c.Expires = license.ComputeExpiry(&c.Days, now)
				}
				changed = true
			}
			if c.Device == "" {
				c.Device = d
				changed = true
			}
			if changed {
				x.Audit = append(x.Audit, Audit{At: now, Action: "bind", CardID: c.ID, Actor: "user"})
			}
			result = license.Validate(c.Expires, 0, false, "demo", "demo", now)
			return nil
		}
		result.Reason = "not_found"
		return nil
	})
	if errors.Is(err, errSecureProtocolRequired) {
		return license.ValidationResult{Reason: "secure_protocol_required"}, nil
	}
	if err != nil {
		return license.ValidationResult{}, err
	}
	return result, nil
}
func (s *Store) change(id, action string, actors ...string) error {
	return s.changeBatch([]string{id}, action, actors...)
}

// All selected records must exist; publish the whole batch or none.
func (s *Store) changeBatch(ids []string, action string, actors ...string) error {
	return s.changeContext(context.Background(), ids, action, actors...)
}
func (s *Store) changeContext(ctx context.Context, ids []string, action string, actors ...string) error {
	if len(ids) == 0 || len(ids) > 100 || (action != "revoke" && action != "unbind") {
		return errors.New("请选择 1–100 张卡密及有效操作")
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if selected[id] || len(id) != 24 {
			return errors.New("无效或重复的卡密 ID")
		}
		selected[id] = true
	}
	return s.mutate(ctx, mutationScope{ids: ids}, func(x *State) error {
		found := 0
		now := s.now().UTC()
		for i := range x.Cards {
			c := &x.Cards[i]
			if !selected[c.ID] {
				continue
			}
			found++
			if c.Revoked {
				return errors.New("已吊销卡密不能再次操作")
			}
			if action == "unbind" {
				if c.Device == "" {
					return errors.New("所选卡密存在未绑定设备")
				}
				c.Device = ""
			} else {
				c.Revoked = true
			}
			x.Audit = append(x.Audit, Audit{At: now, Action: action, CardID: c.ID, Actor: auditActor(actors)})
		}
		if found != len(ids) {
			return errors.New("部分卡密不存在，未执行任何操作")
		}
		return nil
	})
}

// This global budget is sufficient for a single local test instance only.
func (s *Store) allowActivation() bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	if s.rateStart.IsZero() || now.Sub(s.rateStart) >= time.Minute {
		s.rateStart = now
		s.rateCount = 0
	}
	if s.rateCount >= 60 {
		return false
	}
	s.rateCount++
	return true
}
func (s *Store) setQQ(q string, actors ...string) error {
	return s.setQQContext(context.Background(), q, actors...)
}
func (s *Store) setQQContext(ctx context.Context, q string, actors ...string) error {
	q = strings.TrimSpace(q)
	if q != "----------" {
		if len(q) < 5 || len(q) > 12 {
			return errors.New("QQ must be 5–12 digits")
		}
		for _, c := range q {
			if c < '0' || c > '9' {
				return errors.New("QQ must be numeric")
			}
		}
	}
	return s.mutate(ctx, mutationScope{support: true}, func(x *State) error {
		x.QQ = q
		x.Audit = append(x.Audit, Audit{At: s.now().UTC(), Action: "support_config", Actor: auditActor(actors)})
		return nil
	})
}
func cardStatus(c Card, now time.Time) string {
	if c.Revoked {
		return "已吊销"
	}
	if c.Expires != nil && !now.Before(*c.Expires) {
		return "已过期"
	}
	if c.Activated == nil {
		return "未激活"
	}
	if c.Device == "" {
		return "已解绑"
	}
	return "已激活"
}
func plan(days int) string {
	if days == 0 {
		return "永久"
	}
	switch days {
	case 1:
		return "日卡 · 1 天"
	case 7:
		return "周卡 · 7 天"
	case 30:
		return "月卡 · 30 天"
	case 90:
		return "季卡 · 90 天"
	case 365:
		return "年卡 · 365 天"
	}
	return fmt.Sprintf("%d 天", days)
}

func auditActor(actors []string) string {
	if len(actors) > 0 {
		return actors[0]
	}
	return ""
}

// Separate metadata files cannot share the state.json transaction. Callers must
// report a failed audit append rather than claim atomic success across files.
func (s *Store) recordAudit(actor, action, target string) error {
	return s.auditContext(context.Background(), actor, action, target)
}
func (s *Store) auditContext(ctx context.Context, actor, action, target string) error {
	return s.mutate(ctx, mutationScope{}, func(x *State) error {
		x.Audit = append(x.Audit, Audit{At: s.now().UTC(), Action: action, Actor: actor, Target: target})
		return nil
	})
}

func (s *Store) mutate(ctx context.Context, scope mutationScope, apply func(*State) error) error {
	if s.pg != nil {
		return s.pg.mutate(ctx, scope, apply)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if err := apply(&next); err != nil {
		return err
	}
	if next.QQ == s.state.QQ && len(next.Audit) == len(s.state.Audit) {
		return nil
	}
	return s.commit(next)
}

func (s *Store) readView(ctx context.Context, full bool) (State, []Plan, error) {
	if s.pg != nil {
		return s.pg.readView(ctx, full)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := State{QQ: s.state.QQ}
	if full {
		state = clone(s.state)
	}
	return state, append([]Plan(nil), s.plans...), nil
}
