// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

//go:build ignore
// +build ignore

// go run server.go --endpoint <endpoint> --key <path> --cert <path>

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/minio/kes"
	xhttp "github.com/minio/kes/internal/http"
)

func main() {
	log.SetFlags(0)
	var (
		address  string
		certPath string
		keyPath  string
	)
	flag.StringVar(&address, "addr", "0.0.0.0:7001", "")
	flag.StringVar(&certPath, "cert", "", "")
	flag.StringVar(&keyPath, "key", "", "")

	mux := http.NewServeMux()
	mux.Handle("/v1/key/", &KeyStore{})

	server := http.Server{
		Addr:    address,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	serveChan := make(chan error, 1)
	go func() {
		host, port, err := net.SplitHostPort(server.Addr)
		if err != nil {
			log.Fatalf("Error: invalid server address: %q", server.Addr)
		}
		if host == "" {
			host = "0.0.0.0"
		}
		ip := net.ParseIP(host)
		if ip == nil {
			log.Fatalf("Error: invalid server address: %q", server.Addr)
		}
		if ip.IsUnspecified() {
			ip = net.IPv4(127, 0, 0, 1)
		}
		if certPath == "" && keyPath == "" {
			log.Printf("Starting server listening on http://%s:%s ...", ip.String(), port)
			serveChan <- server.ListenAndServe()
		} else {
			log.Printf("Starting server listening on https://%s:%s ...", ip.String(), port)
			serveChan <- server.ListenAndServeTLS(certPath, keyPath)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	select {
	case <-ctx.Done():
		timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
		defer timeoutCancel()

		log.Println("\nStopping server... ")
		if err := server.Shutdown(timeoutCtx); err != nil {
			log.Fatalf("Error: Failed to shutdown server gracefully: %v", err)
		}
	case err := <-serveChan:
		if err != nil {
			log.Fatalf("Error: Failed to serve requests: %v", err)
		}
	}
}

func (s *KeyStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = "/" + r.URL.Path
	}

	switch r.Method {
	case http.MethodPost:
		s.CreateKey(w, r)
	case http.MethodDelete:
		s.DeleteKey(w, r)
	case http.MethodGet:
		if r.URL.Path == "/v1/key" || r.URL.Path == "/v1/key/" {
			s.ListKey(w, r)
		} else {
			s.GetKey(w, r)
		}
	default:
		w.Header().Add("Allow", http.MethodPost)
		w.Header().Add("Allow", http.MethodGet)
		w.Header().Add("Allow", http.MethodDelete)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

type KeyStore struct {
	lock  sync.RWMutex
	store map[string][]byte
}

func (s *KeyStore) CreateKey(w http.ResponseWriter, r *http.Request) {
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	const MaxSize = 1 * mem.MiB
	var request Request
	if err := json.NewDecoder(mem.LimitReader(r.Body, MaxSize)).Decode(&request); err != nil {
		xhttp.Error(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.store == nil {
		s.store = map[string][]byte{}
	}
	key := strings.TrimPrefix(r.URL.Path, "/v1/key/")
	if _, ok := s.store[key]; ok {
		xhttp.Error(w, kes.ErrKeyExists)
		return
	}
	s.store[key] = request.Bytes
	w.WriteHeader(http.StatusCreated)
}

func (s *KeyStore) DeleteKey(w http.ResponseWriter, r *http.Request) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.store == nil {
		s.store = map[string][]byte{}
	}
	key := strings.TrimPrefix(r.URL.Path, "/v1/key/")
	delete(s.store, key)
	w.WriteHeader(http.StatusOK)
}

func (s *KeyStore) GetKey(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Bytes []byte `json:"bytes"`
	}
	s.lock.RLock()
	defer s.lock.RUnlock()

	key := strings.TrimPrefix(r.URL.Path, "/v1/key/")
	v, ok := s.store[key]
	if !ok {
		xhttp.Error(w, kes.ErrKeyNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{
		Bytes: v,
	})
}

func (s *KeyStore) ListKey(w http.ResponseWriter, r *http.Request) {
	type Response struct {
		Name string `json:"name"`
		Last bool   `json:"last,omitempty"`
	}
	s.lock.RLock()
	defer s.lock.RUnlock()

	var (
		encoder = json.NewEncoder(w)
		i       int
	)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	for key := range s.store {
		encoder.Encode(Response{
			Name: key,
			Last: i == len(s.store)-1,
		})
	}
}
