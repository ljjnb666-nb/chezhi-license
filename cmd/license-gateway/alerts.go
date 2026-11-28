package main

// Alert on changes in fixed counters, not caller identity or request contents.
// Thresholds are conservative local defaults, not a measured production SLO.
type alertTracker struct {
	last uint64
	bad,quiet int
	open bool
}

func (a *alertTracker) observe(value,threshold uint64) string {
	// A reset must not underflow into a false burst.
	if value<a.last {
		*a=alertTracker{last:value}
		return ""
	}
	delta:=value-a.last
	a.last=value
	if delta>=threshold {
		a.quiet=0
		if a.bad<2 {a.bad++}
		if a.bad==2 && !a.open {a.open=true;return "OPEN"}
	} else {
		a.bad=0
		// A low but nonzero error rate is not evidence of recovery.
		if delta!=0 {a.quiet=0;return ""}
		if a.quiet<2 {a.quiet++}
		if a.quiet==2 && a.open {a.open=false;return "QUIET"}
	}
	return ""
}

type gatewayAlerts struct {
	unavailable,limited alertTracker
}

func (a *gatewayAlerts) sample(m *gatewayMetrics, emit func(string,string)) {
	if event:=a.unavailable.observe(m.unavailable.Load(),3);event!="" {
		emit("http_5xx",event)
	}
	if event:=a.limited.observe(m.limited.Load(),10);event!="" {
		emit("http_429",event)
	}
}
