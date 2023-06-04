// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseAddr parses s as an Addr of the form "host:port",
// "https://host:port", "[host]:port" or "https://[host]:port".
//
// A literal IPv6 address must be enclosed in square brackets,
// as in "[::1]:443".
func ParseAddr(s string) (Addr, error) {
	s = strings.TrimPrefix(s, "https://")

	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, fmt.Errorf("kes: invalid addr: %v", err)
	}
	if host == "" {
		return Addr{}, errors.New("kes: invalid addr: host is empty")
	}

	return Addr{
		host: host,
		port: port,
	}, err
}

// Addr represents a KES server address of the form "host:port".
type Addr struct {
	host, port string
}

// Network returns the Addr network, like TCP.
func (Addr) Network() string { return "tcp" }

// String returns the Addr's string representation.
func (a Addr) String() string { return net.JoinHostPort(a.host, a.port) }

// Host returns the Addr's hostname.
func (a Addr) Host() string { return a.host }

// URL returns a URL with the provided path elements joined to the address.
func (a Addr) URL(elem ...string) *url.URL {
	u, _ := url.Parse("https://" + a.String())
	if len(elem) == 0 {
		return u
	}
	return u.JoinPath(elem...)
}

// Equal reports whether a is equal to addr.
func (a Addr) Equal(addr Addr) bool {
	if a.port == addr.port {
		if a.host == addr.host {
			return true
		}
		return a.isLoopback() && addr.isLoopback()
	}
	return false
}

func (n Addr) isLoopback() bool {
	if n.host == "localhost" {
		return true
	}

	ip := net.ParseIP(n.host)
	return ip != nil && ip.IsLoopback()
}
