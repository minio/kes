package main

import (
	"crypto/tls"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func serverAddr() string {
	if addr, ok := os.LookupEnv("KEY_SERVER"); ok {
		return addr
	}
	return "https://127.0.0.1:7373"
}

func loadClientCertificates() []tls.Certificate {
	certPath := os.Getenv("KEY_CLIENT_TLS_CERT_FILE")
	keyPath := os.Getenv("KEY_CLIENT_TLS_KEY_FILE")
	if certPath != "" || keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			failf(os.Stderr, "Cannot load TLS key or cert for client auth: %s", err.Error())
		}
		return []tls.Certificate{cert}
	}
	return nil
}

func isTerm(f *os.File) bool { return terminal.IsTerminal(int(f.Fd())) }
