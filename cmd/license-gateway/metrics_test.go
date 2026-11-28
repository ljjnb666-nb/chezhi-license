package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsCountsAndRedaction(t *testing.T) {
	m:=&gatewayMetrics{}
	for _,status:=range []int{200,400,403,404,429,503,500} {
		h:=m.wrap(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
			w.WriteHeader(status)
			w.WriteHeader(200)
			_,_=w.Write([]byte("fixture"))
		}))
		req:=httptest.NewRequest("POST","/private-fixture",strings.NewReader("secret-fixture"))
		req.Header.Set("Authorization","sensitive-fixture")
		w:=httptest.NewRecorder()
		h.ServeHTTP(w,req)
		if w.Code!=status {t.Fatal("metrics changed status")}
	}
	var b bytes.Buffer
	m.report(log.New(&b,"",0))
	want:="gateway_metrics total=7 success=1 denied=3 limited=1 unavailable=2 other=0 active=0"
	if strings.TrimSpace(b.String())!=want {t.Fatalf("wrong or unsanitized metrics: %q",b.String())}
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	done:=make(chan struct{})
	go func(){m.monitor(ctx,log.New(&b,"",0),time.Hour);close(done)}()
	select {case <-done:case <-time.After(time.Second):t.Fatal("monitor did not stop")}
}
