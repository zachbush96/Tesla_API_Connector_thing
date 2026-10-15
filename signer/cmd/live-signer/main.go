package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	r "example.invalid/tesla-connector/restricted"
)

func main() {
	path := flag.String("config", "", "Owner-private existing signing configuration")
	verify := flag.Bool("enable-pairing-verification", false, "Explicit owner-approved handshake-only diagnostic gate")
	infotainment := flag.Bool("enable-infotainment-diagnostic", false, "Explicit separately approved one-handshake INFOTAINMENT diagnostic gate")
	execute := flag.Bool("enable-physical-execution", false, "Explicit owner-approved physical command gate")
	check := flag.Bool("check", false, "Check local configuration only; no listener or Fleet request")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Local signing configuration refused")
		os.Exit(1)
	}
	var handler http.Handler
	var config r.ServiceConfig
	var err error
	if *verify || *execute || *infotainment {
		handler, config, err = r.LoadLiveService(*path, *verify, *execute, *infotainment)
	} else {
		// The default retains the existing physically/network-disabled mock daemon.
		handler, config, err = r.LoadMockService(*path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Local signing configuration unavailable; private details withheld")
		os.Exit(1)
	}
	if _, err = tls.LoadX509KeyPair(config.TLSCertificateFile, config.TLSPrivateFile); err != nil {
		fmt.Fprintln(os.Stderr, "Local signing TLS pair invalid; private details withheld")
		os.Exit(1)
	}
	if *check {
		fmt.Printf("{\"configuration_valid\":true,\"tls_pair_valid\":true,\"execution_enabled\":%t,\"pairing_verification_enabled\":%t,\"infotainment_diagnostic_enabled\":%t,\"listener_started\":false,\"fleet_network_requests\":0}\n", *execute, *verify, *infotainment)
		return
	}
	server := &http.Server{Addr: r.LocalSignerAddress, Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: r.LiveTLSWriteTimeout, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, ErrorLog: log.New(io.Discard, "", 0)}
	listener, err := net.Listen("tcp", r.LocalSignerAddress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Local signing listener refused; private details withheld")
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
	fmt.Printf("{\"service\":\"local-signing\",\"execution_enabled\":%t,\"pairing_verification_enabled\":%t,\"infotainment_diagnostic_enabled\":%t}\n", *execute, *verify, *infotainment)
	if err = server.ServeTLS(listener, config.TLSCertificateFile, config.TLSPrivateFile); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "Local signing TLS service stopped; private details withheld")
		os.Exit(1)
	}
}
