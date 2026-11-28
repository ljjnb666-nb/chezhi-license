package main

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// Fixed-cardinality counters only. No paths, credentials, request bodies,
// client addresses or arbitrary headers enter the monitoring output.
type gatewayMetrics struct {
	total atomic.Uint64
	success atomic.Uint64
	denied atomic.Uint64
	limited atomic.Uint64
	unavailable atomic.Uint64
	other atomic.Uint64
	active atomic.Int64
}

type measuredResponse struct {
	http.ResponseWriter
	status int
}

func (w *measuredResponse) WriteHeader(status int) {
	if w.status!=0 {return}
	w.status=status
	w.ResponseWriter.WriteHeader(status)
}
func (w *measuredResponse) Write(b []byte)(int,error) {
	if w.status==0 {w.WriteHeader(http.StatusOK)}
	return w.ResponseWriter.Write(b)
}
func (w *measuredResponse) Unwrap() http.ResponseWriter {return w.ResponseWriter}

func (m *gatewayMetrics) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		m.active.Add(1)
		defer m.active.Add(-1)
		out:=&measuredResponse{ResponseWriter:w}
		defer func(){
			switch {
			case out.status==200:m.success.Add(1)
			case out.status==429:m.limited.Add(1)
			case out.status>=400 && out.status<500:m.denied.Add(1)
			case out.status>=500:m.unavailable.Add(1)
			default:m.other.Add(1)
			}
			m.total.Add(1)
		}()
		next.ServeHTTP(out,r)
	})
}

func (m *gatewayMetrics) report(logger *log.Logger) {
	logger.Printf("gateway_metrics total=%d success=%d denied=%d limited=%d unavailable=%d other=%d active=%d",
		m.total.Load(),m.success.Load(),m.denied.Load(),m.limited.Load(),m.unavailable.Load(),m.other.Load(),m.active.Load())
}

// No health listener or external notification. A fixed cadence bounds log
// volume even under a flood. The supervisor/operator must collect the log.
func (m *gatewayMetrics) monitor(ctx context.Context,logger *log.Logger,interval time.Duration) {
	m.monitorStatus(ctx,logger,interval,"")
}

func (m *gatewayMetrics) monitorStatus(ctx context.Context,logger *log.Logger,interval time.Duration,dir string) {
	ticker:=time.NewTicker(interval)
	defer ticker.Stop()
	alerts:=&gatewayAlerts{}
	started:=time.Now()
	publish:=func(lifecycle string){
		if dir!="" {
			if err:=writeStatus(dir,snapshot(m,alerts,started,time.Now(),lifecycle));err!=nil {
				logger.Print("gateway_status_write_failed")
			}
		}
	}
	publish("OBSERVING")
	for {
		select {
		case <-ctx.Done():
			// Signal receipt is not proof that shutdown has completed.
			publish("STOPPING")
			return
		case <-ticker.C:
			m.report(logger)
			alerts.sample(m,func(category,event string){
				logger.Printf("gateway_alert category=%s state=%s",category,event)
			})
			publish("OBSERVING")
		}
	}
}
