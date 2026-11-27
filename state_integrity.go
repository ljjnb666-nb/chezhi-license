package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var stateHex = regexp.MustCompile(`^[0-9a-f]+$`)
var statePrefix = regexp.MustCompile(`^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}$`)
var stateQQ = regexp.MustCompile(`^([0-9]{5,12}|----------)$`)

// Reject duplicate properties (including case aliases accepted by encoding/json).
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting limit exceeded")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid property")
				}
				key = strings.ToLower(key)
				if seen[key] {
					return errors.New("duplicate JSON property")
				}
				seen[key] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return nil
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}
func decodeState(raw []byte) (State, error) {
	var s State
	if err := uniqueJSON(raw); err != nil {
		return s, err
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil || len(shape) != 3 || shape["QQ"] == nil || shape["Cards"] == nil || shape["Audit"] == nil {
		return s, errors.New("invalid state structure")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, err
	}
	if err := validateState(s); err != nil {
		return s, err
	}
	return s, nil
}
func validateState(s State) error {
	if !stateQQ.MatchString(s.QQ) {
		return errors.New("invalid QQ configuration")
	}
	ids := map[string]bool{}
	orders := map[string]Card{}
	for i, c := range s.Cards {
		invalid := func() error { return fmt.Errorf("invalid card record %d", i+1) }
		if len(c.Hash) != 64 || !stateHex.MatchString(c.Hash) || c.ID != c.Hash[:24] || ids[c.ID] || !statePrefix.MatchString(c.Prefix) {
			return invalid()
		}
		if c.Days < 0 || c.Days > 3650 || c.AmountCents < 0 || c.AmountCents > 100000000 || !validOrderRef(c.SaleRef) || c.Created.IsZero() || (c.Channel != "test" && c.Channel != "wechat" && c.Channel != "alipay") {
			return invalid()
		}
		if old, ok := orders[c.SaleRef]; ok && (old.Days != c.Days || old.Channel != c.Channel || old.AmountCents != c.AmountCents || !old.Created.Equal(c.Created)) {
			return invalid()
		}
		if c.Device != "" && (len(c.Device) != 64 || !stateHex.MatchString(c.Device)) {
			return invalid()
		}
		if c.Activated == nil {
			if c.Expires != nil || c.Device != "" {
				return invalid()
			}
		} else {
			if c.Activated.Before(c.Created) {
				return invalid()
			}
			if c.Days == 0 {
				if c.Expires != nil {
					return invalid()
				}
			} else if c.Expires == nil || !c.Expires.Equal(c.Activated.Add(time.Duration(c.Days)*24*time.Hour)) {
				return invalid()
			}
		}
		ids[c.ID] = true
		orders[c.SaleRef] = c
	}
	for i, a := range s.Audit {
		invalid := func() error { return fmt.Errorf("invalid audit record %d", i+1) }
		if a.At.IsZero() || (a.Actor != "" && !memberName.MatchString(a.Actor)) {
			return invalid()
		}
		switch a.Action {
		case "issue", "bind", "unbind", "revoke":
			if !ids[a.CardID] || a.Target != "" {
				return invalid()
			}
		case "member-create", "member-reset", "member-role", "member-disable", "member-enable":
			if a.CardID != "" || !memberName.MatchString(a.Target) {
				return invalid()
			}
		case "support_config", "plans_config", "login_success", "login_failed", "logout", "logout_all", "password_changed", "password_failed":
			if a.CardID != "" || a.Target != "" {
				return invalid()
			}
		default:
			return invalid()
		}
	}
	return nil
}
func validOrderRef(s string) bool {
	return len(s) > 0 && len(s) <= 80 && strings.TrimSpace(s) == s && !strings.ContainsRune(s, 0)
}
