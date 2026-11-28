package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetBurstRefillAndRollback(t *testing.T) {
	start:=time.Unix(1000,0)
	b:=newBudget(start)
	for i:=0;i<gatewayBurst;i++ {
		if ok,_:=b.allow(start); !ok {t.Fatal("initial burst denied")}
	}
	if ok,retry:=b.allow(start); ok || retry!=2 {t.Fatal("budget not exhausted",ok,retry)}
	if ok,_:=b.allow(start.Add(-time.Hour)); ok {t.Fatal("rollback replenished budget")}
	if ok,_:=b.allow(start.Add(time.Second)); ok {t.Fatal("refilled too soon")}
	if ok,_:=b.allow(start.Add(1250*time.Millisecond)); !ok {t.Fatal("refill missing")}
	if ok,_:=b.allow(start.Add(1250*time.Millisecond)); ok {t.Fatal("extra token")}
	// One full minute replenishes at most the bounded burst.
	later:=start.Add(time.Minute)
	for i:=0;i<gatewayBurst;i++ {
		if ok,_:=b.allow(later); !ok {t.Fatal("refill failed")}
	}
	if ok,_:=b.allow(later); ok {t.Fatal("unbounded accumulation")}
}

func TestBudgetConcurrentAdmission(t *testing.T) {
	now:=time.Unix(1000,0)
	b:=newBudget(now)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i:=0;i<128;i++ {
		wg.Add(1)
		go func(){defer wg.Done(); if ok,_:=b.allow(now);ok {accepted.Add(1)}}()
	}
	wg.Wait()
	if accepted.Load()!=gatewayBurst {t.Fatalf("admitted %d",accepted.Load())}
}
