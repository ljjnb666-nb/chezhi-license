package main

import (
	"sync"
	"time"
)

// One bounded, process-local budget for all callers. Never infer a client
// identity from caller-controlled headers. The existing origin remains the
// authoritative persistent quota. This budget intentionally leaves room
// within the default 60/minute origin source budget.
const gatewayBurst = 12
const gatewayPerMinute = 48

type requestBudget struct {
	mu sync.Mutex
	last time.Time
	tokens float64
}

func newBudget(now time.Time) *requestBudget {
	return &requestBudget{last:now,tokens:gatewayBurst}
}

// allow returns a positive rounded-up retry delay only when denied.
// A backwards clock cannot replenish tokens or move the watermark backwards.
func (b *requestBudget) allow(now time.Time) (bool,int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds()*gatewayPerMinute/60
		if b.tokens>gatewayBurst {b.tokens=gatewayBurst}
		b.last=now
	}
	if b.tokens>=1 {
		b.tokens--
		return true,0
	}
	delay:=time.Duration((1-b.tokens)*float64(time.Minute)/gatewayPerMinute)
	if now.Before(b.last) {delay+=b.last.Sub(now)}
	if delay>time.Hour {delay=time.Hour}
	seconds:=int((delay+time.Second-1)/time.Second)
	if seconds<1 {seconds=1}
	return false,seconds
}
