package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	r "example.invalid/tesla-connector/restricted"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "", "Owner-private service configuration path")
	check := flag.Bool("check", false, "Validate local configuration/TLS only; no listener or car operation")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Local signing service configuration refused")
		os.Exit(1)
	}
	handler, c, err := r.LoadMockService(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Local signing service unavailable; private details withheld")
		os.Exit(1)
	}
	if _, err = tls.LoadX509KeyPair(c.TLSCertificateFile, c.TLSPrivateFile); err != nil {
		fmt.Fprintln(os.Stderr, "Local signing service TLS pair invalid; private details withheld")
		os.Exit(1)
	}
	if *check {
		fmt.Println(`{"configuration_valid":true,"tls_pair_valid":true,"existing_key_matches_public":true,"execution_enabled":false,"infotainment_diagnostic_enabled":false,"listener_started":false}`)
		return
	}
	server := &http.Server{Addr: r.LocalSignerAddress, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", r.LocalSignerAddress)
	if err != nil {
		category := "local-bind-refused"
		if errors.Is(err, syscall.EADDRINUSE) {
			category = "local-port-in-use"
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			category = "local-bind-permission"
		}
		fmt.Fprintln(os.Stderr, "Local signing service stopped: "+category+"; private details withheld")
		os.Exit(1)
	}
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-done
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	fmt.Println(`{"service":"local-signing","mode":"sdk-mock-only","execution_enabled":false,"infotainment_diagnostic_enabled":false,"fleet_network_enabled":false}`)
	if err = server.ServeTLS(listener, c.TLSCertificateFile, c.TLSPrivateFile); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "Local signing service stopped: tls-serve-refused; private details withheld")
		os.Exit(1)
	}
}
