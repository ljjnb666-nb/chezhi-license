package main

import (
	"strings"
	"testing"
)

func TestAlertTransitions(t *testing.T) {
	m:=&gatewayMetrics{}
	a:=&gatewayAlerts{}
	var events []string
	emit:=func(category,state string){events=append(events,category+":"+state)}
	for i:=0;i<5;i++ {
		m.unavailable.Add(3)
		m.limited.Add(10)
		a.sample(m,emit)
	}
	// Lower, nonzero rates must not close an open alert.
	m.unavailable.Add(1)
	m.limited.Add(1)
	a.sample(m,emit)
	a.sample(m,emit)
	if len(events)!=2 {t.Fatal(events)}
	a.sample(m,emit)
	a.sample(m,emit)
	if strings.Join(events,",")!="http_5xx:OPEN,http_429:OPEN,http_5xx:QUIET,http_429:QUIET" {t.Fatal(events)}
	m.unavailable.Store(0)
	m.limited.Store(0)
	a.sample(m,emit)
	if len(events)!=4 {t.Fatal("reset emitted alert",events)}
	m.unavailable.Add(3)
	a.sample(m,emit)
	if len(events)!=4 {t.Fatal("single burst emitted alert")}
	m.unavailable.Add(3)
	a.sample(m,emit)
	if len(events)!=5 || events[4]!="http_5xx:OPEN" {t.Fatal(events)}
}
