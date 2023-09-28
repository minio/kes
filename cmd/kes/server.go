// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const serverCmdUsage = `Usage:
    kes server [options]

Options:
    --addr <IP:PORT>         The address of the server (default: 0.0.0.0:7373)
    --config <PATH>          Path to the server configuration file

    --key <PATH>             Path to the TLS private key. It takes precedence over
                             the config file
    --cert <PATH>            Path to the TLS certificate. It takes precedence over
                             the config file

    --auth {on|off}          Controls how the server handles mTLS authentication.
                             By default, the server requires a client certificate
                             and verifies that certificate has been issued by a
                             trusted CA.
                             Valid options are:
                                Require and verify      : --auth=on (default)
                                Require but don't verify: --auth=off

    -h, --help               Show list of command-line options

Starts a KES server. The server address can be specified in the config file but
may be overwritten by the --addr flag. If omitted the IP defaults to 0.0.0.0 and
the PORT to 7373.

The client TLS verification can be disabled by setting --auth=off. The server then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ kes server --config config.yml --auth =off
`

func serverCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addrFlag     string
		configFlag   string
		tlsKeyFlag   string
		tlsCertFlag  string
		mtlsAuthFlag string
	)
	cmd.StringVar(&addrFlag, "addr", "", "The address of the server")
	cmd.StringVar(&configFlag, "config", "", "Path to the server configuration file")
	cmd.StringVar(&tlsKeyFlag, "key", "", "Path to the TLS private key")
	cmd.StringVar(&tlsCertFlag, "cert", "", "Path to the TLS certificate")
	cmd.StringVar(&mtlsAuthFlag, "auth", "", "Controls how the server handles mTLS authentication")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes server --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		os.Exit(2)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}

	startGateway(gatewayConfig{
		Address:     addrFlag,
		ConfigFile:  configFlag,
		PrivateKey:  tlsKeyFlag,
		Certificate: tlsCertFlag,
		TLSAuth:     mtlsAuthFlag,
	})
}

// listeningOnV4 returns a list of the system IPv4 interface
// addresses an TCP/IP listener with the given IP is listening
// on.
//
// In particular, a TCP/IP listener listening on the pseudo
// address 0.0.0.0 listens on all network interfaces while
// a listener on a specific IP only listens on the network
// interface with that IP address.
func listeningOnV4(ip net.IP) []net.IP {
	if !ip.IsUnspecified() {
		return []net.IP{ip}
	}
	// We listen on the pseudo-address: 0.0.0.0
	// The TCP/IP listener is listening on all available
	// network interfaces.
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return []net.IP{}
	}

	var ip4Addr []net.IP
	for _, iface := range interfaces {
		var ip net.IP
		switch addr := iface.(type) {
		case *net.IPNet:
			ip = addr.IP.To4()
		case *net.IPAddr:
			ip = addr.IP.To4()
		}
		if ip != nil {
			ip4Addr = append(ip4Addr, ip)
		}
	}
	return ip4Addr
}

// serverAddr takes an address string <IP>:<port> and
// splits it into an IP address and port number.
//
// If addr does not contain an IP (":<port>") then ip will be
// 0.0.0.0.
func serverAddr(addr string) (ip net.IP, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		cli.Fatalf("invalid server address: %q", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}

	ip = net.ParseIP(host)
	if ip == nil {
		cli.Fatalf("invalid server address: %q", addr)
	}
	return ip, port
}
