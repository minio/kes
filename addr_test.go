// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"net"
	"testing"
)

func TestParseAddr(t *testing.T) {
	for i, test := range parseAddrTests {
		addr, err := ParseAddr(test.Addr)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to parse addr '%v': %v", i, test.Addr, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: parsed addr '%v' but should have failed", i, test.Addr)
		}
		if err == nil && addr.Host() != test.Host {
			t.Fatalf("Test %d: invalid host: got '%s' - want '%s'", i, addr.Host(), test.Host)
		}
		if err == nil && addr.port != test.Port {
			t.Fatalf("Test %d: invalid port: got '%s' - want '%s'", i, addr.port, test.Port)
		}
		if err == nil && !addr.Equal(Addr{host: test.Host, port: test.Port}) {
			t.Fatalf("Test %d: invalid port: addrs not equal", i)
		}
	}
}

func TestAddr_isLoopback(t *testing.T) {
	for i, test := range isLoopbackNodeAddrTests {
		addr, err := ParseAddr(test.Addr)
		if err != nil {
			t.Fatalf("Test %d: failed to parse addr '%v': %v", i, test.Addr, err)
		}
		isLoopBack := addr.isLoopback()
		if isLoopBack && !test.IsLoopback {
			t.Fatalf("Test %d: '%s' is considered as loopback addr but shouldn't be", i, addr)
		}
		if !isLoopBack && test.IsLoopback {
			t.Fatalf("Test %d: '%s' is not considered as loopback addr but should be", i, addr)
		}
	}
}

var parseAddrTests = []struct {
	Addr       string
	Host       string
	Port       string
	ShouldFail bool
}{
	{Addr: "localhost:7373", Host: "localhost", Port: "7373"},                                       // 0
	{Addr: "https://localhost:7373", Host: "localhost", Port: "7373"},                               // 1
	{Addr: "127.0.0.1:7373", Host: "127.0.0.1", Port: "7373"},                                       // 2
	{Addr: "localhost:443", Host: "localhost", Port: "443"},                                         // 3
	{Addr: "https://[fe80::21:a317:f548:eef1]:7000", Host: "fe80::21:a317:f548:eef1", Port: "7000"}, // 4
	{Addr: "[fe80::21:a317:f548:eef1]:7373", Host: "fe80::21:a317:f548:eef1", Port: "7373"},         // 5
	{Addr: "kes-0.local:7373", Host: "kes-0.local", Port: "7373"},                                   // 6

	{Addr: "127.0.0.1", ShouldFail: true},                    // 7
	{Addr: ":7373", ShouldFail: true},                        // 8
	{Addr: "https:127.0.0.1:7373", ShouldFail: true},         // 9
	{Addr: "http://127.0.0.1:7373", ShouldFail: true},        // 10
	{Addr: "fe80::21:a317:f548:eef1:7373", ShouldFail: true}, // 11
	{Addr: "kes.local", ShouldFail: true},                    // 12
}

var isLoopbackNodeAddrTests = []struct {
	Addr       string
	IsLoopback bool
}{
	{Addr: "localhost:7373", IsLoopback: true},                                // 0
	{Addr: "127.0.0.1:7373", IsLoopback: true},                                // 1
	{Addr: "127.0.53.53:7000", IsLoopback: true},                              // 2
	{Addr: "[" + net.IPv6loopback.String() + "]" + ":7373", IsLoopback: true}, // 3

	{Addr: "kes0.local:6363"},   // 4
	{Addr: "10.1.2.3:7373"},     // 5
	{Addr: "192.168.1.77:7373"}, // 6
}
