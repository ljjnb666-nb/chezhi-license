package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"log"
	"time"
)

// Read-only check: no HTTP request, listener, database change, or key rotation.
func tlsStatus(target string, roots *x509.CertPool, local *x509.Certificate) error {
	if local==nil || roots==nil {return errors.New("missing TLS configuration")}
	conn,err:=tls.DialWithDialer(&net.Dialer{Timeout:5*time.Second},"tcp",target,
		&tls.Config{RootCAs:roots,ServerName:"127.0.0.1",MinVersion:tls.VersionTLS12})
	if err!=nil {return errors.New("origin TLS verification failed")}
	defer conn.Close()
	state:=conn.ConnectionState()
	if len(state.VerifiedChains)==0 || len(state.VerifiedChains[0])==0 {return errors.New("origin chain unavailable")}
	expiry:=state.VerifiedChains[0][0].NotAfter
	for _,cert:=range state.VerifiedChains[0] {
		if cert.NotAfter.Before(expiry) {expiry=cert.NotAfter}
	}
	now:=time.Now()
	fmt.Printf("gateway_leaf_expires_utc=%s\norigin_chain_expires_utc=%s\n",local.NotAfter.UTC().Format(time.RFC3339),expiry.UTC().Format(time.RFC3339))
	if !local.NotAfter.After(now.Add(7*24*time.Hour)) || !expiry.After(now.Add(7*24*time.Hour)) {
		return errors.New("TLS renewal required within seven days; no automatic replacement")
	}
	fmt.Println("TLS_STATUS_OK")
	return nil
}

// Inspect local origin trust at a fixed cadence. This cannot start or restart
// the origin, alter keys, or send HTTP traffic. Errors are local alerts only.
// The 5-second dial bound also limits shutdown overlap.
func monitorTLS(ctx context.Context,logger *log.Logger,interval time.Duration,target string,roots *x509.CertPool,local *x509.Certificate) {
	ticker:=time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err()!=nil {return}
		if err:=tlsStatus(target,roots,local);err!=nil {
			logger.Printf("gateway_tls_warning: %s",err)
		}
		select {
		case <-ctx.Done():return
		case <-ticker.C:
		}
	}
}
