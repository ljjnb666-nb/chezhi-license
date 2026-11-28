package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Fixed-schema local monitoring only. HTTP 200 is not proof of licensing
// success, QUIET is not readiness, and counters are process-local.
type statusSnapshot struct {
	Version int `json:"version"`
	StartedUTC string `json:"started_utc"`
	ObservedUTC string `json:"observed_utc"`
	Lifecycle string `json:"lifecycle"`
	Total uint64 `json:"total"`
	HTTP200 uint64 `json:"http_200"`
	Denied uint64 `json:"denied"`
	Limited uint64 `json:"limited"`
	Unavailable uint64 `json:"unavailable"`
	Other uint64 `json:"other"`
	Active int64 `json:"active"`
	Alert5xxOpen bool `json:"alert_5xx_open"`
	Alert429Open bool `json:"alert_429_open"`
}

func snapshot(m *gatewayMetrics, a *gatewayAlerts, started, now time.Time, lifecycle string) statusSnapshot {
	return statusSnapshot{Version:1, StartedUTC:started.UTC().Format(time.RFC3339Nano),
		ObservedUTC:now.UTC().Format(time.RFC3339Nano), Lifecycle:lifecycle,
		Total:m.total.Load(), HTTP200:m.success.Load(), Denied:m.denied.Load(),
		Limited:m.limited.Load(), Unavailable:m.unavailable.Load(), Other:m.other.Load(),
		Active:m.active.Load(), Alert5xxOpen:a.unavailable.open, Alert429Open:a.limited.open}
}

// Only a pre-provisioned private directory; no creation of arbitrary parent
// directories. Publish one fixed name by atomic rename. Not a same-UID
// security boundary; the supervisor owns the directory and its ancestors.
func validateStatusDir(dir string) error {
	if !filepath.IsAbs(dir) { return errors.New("status directory must be absolute") }
	info,err:=os.Lstat(dir)
	if err!=nil || !info.IsDir() || info.Mode().Perm()!=0700 {
		return errors.New("status directory must be private")
	}
	return nil
}

func writeStatus(dir string, s statusSnapshot) error {
	if err:=validateStatusDir(dir); err!=nil {return err}
	target:=filepath.Join(dir,"status.json")
	if info,err:=os.Lstat(target); err==nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()!=0600 {return errors.New("invalid existing status file")}
	} else if !os.IsNotExist(err) { return errors.New("status file unavailable") }
	f,err:=os.CreateTemp(dir,".status-")
	if err!=nil {return err}
	defer os.Remove(f.Name())
	if err=json.NewEncoder(f).Encode(s); err!=nil {f.Close();return err}
	if err=f.Sync(); err!=nil {f.Close();return err}
	if err=f.Close(); err!=nil {return err}
	if err=os.Rename(f.Name(),target);err!=nil {return err}
	d,err:=os.Open(dir)
	if err!=nil {return err}
	defer d.Close()
	return d.Sync()
}
