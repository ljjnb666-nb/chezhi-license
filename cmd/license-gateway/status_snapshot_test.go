package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLocalStatusSnapshot(t *testing.T) {
	if runtime.GOOS=="windows" {t.Skip("private POSIX file modes")}
	dir:=t.TempDir()
	if err:=os.Chmod(dir,0700);err!=nil {t.Fatal(err)}
	m:=&gatewayMetrics{}
	a:=&gatewayAlerts{}
	started:=time.Date(2026,11,28,0,0,0,0,time.UTC)
	m.total.Store(6);m.unavailable.Store(6)
	m.limited.Store(20)
	a.sample(m,func(string,string){})
	m.unavailable.Add(3);m.limited.Add(10);m.total.Add(13)
	a.sample(m,func(string,string){})
	s:=snapshot(m,a,started,started.Add(time.Minute),"OBSERVING")
	if !s.Alert5xxOpen || !s.Alert429Open || s.Unavailable!=9 || s.Limited!=30 {t.Fatal("wrong state")}
	if err:=writeStatus(dir,s);err!=nil {t.Fatal(err)}
	target:=filepath.Join(dir,"status.json")
	raw,err:=os.ReadFile(target)
	if err!=nil {t.Fatal(err)}
	var actual statusSnapshot
	if err=json.Unmarshal(raw,&actual);err!=nil || actual!=s {t.Fatal("wrong status content",err)}
	if strings.Contains(string(raw),"secret") || strings.Contains(string(raw),"address") {t.Fatal("unexpected field")}
	info,err:=os.Stat(target)
	if err!=nil || info.Mode().Perm()!=0600 {t.Fatal("status mode",err)}
	s.Lifecycle="STOPPING"
	if err=writeStatus(dir,s);err!=nil {t.Fatal(err)}
	entries,err:=os.ReadDir(dir)
	if err!=nil || len(entries)!=1 {t.Fatal("unexpected files",err)}
	if err=os.Remove(target);err!=nil {t.Fatal(err)}
	outside:=filepath.Join(t.TempDir(),"protected")
	if err=os.WriteFile(outside,[]byte("preserve"),0600);err!=nil {t.Fatal(err)}
	if err=os.Symlink(outside,target);err!=nil {t.Fatal(err)}
	if err=writeStatus(dir,s);err==nil {t.Fatal("symlink accepted")}
	got,err:=os.ReadFile(outside)
	if err!=nil || string(got)!="preserve" {t.Fatal("target changed",err)}
	if err=os.Remove(target);err!=nil {t.Fatal(err)}
	if err=os.Chmod(dir,0755);err!=nil {t.Fatal(err)}
	if err=writeStatus(dir,s);err==nil {t.Fatal("nonprivate directory accepted")}
	if err=os.Chmod(dir,0700);err!=nil {t.Fatal(err)}
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	done:=make(chan struct{})
	go func(){m.monitorStatus(ctx,log.New(io.Discard,"",0),time.Hour,dir);close(done)}()
	select {case <-done:case <-time.After(5*time.Second):t.Fatal("monitor did not finish")}
	raw,err=os.ReadFile(target)
	if err!=nil || json.Unmarshal(raw,&actual)!=nil || actual.Lifecycle!="STOPPING" {t.Fatal("missing stopping snapshot",err)}
}
