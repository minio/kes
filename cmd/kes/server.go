// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/minio/kes"
	kesconf "github.com/minio/kes/cluster"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/mtls"
	flag "github.com/spf13/pflag"
)

const serverCmdUsage = `Usage:
    kes server [options] <DIR>

Options:
    --addr <[ip]:port>       The network interface the KES server will listen on.
                             The default is '0.0.0.0:7373', causing KES to listen
                             on all available network interfaces.
	
    --host <host:port>       The public IP or FQDN and port of this KES server.
                             Defaults to the first unicast IP address and the port
                             specified by '--addr'. For example, '10.1.2.3:7373'
                             or '192.168.1.73:443'.
                             If no unicast IP address is available, defaults to
                             'localhost' and the port specified by '--addr'.

    --config <file>          An optional config file. If not specified, KES will
                             use the configuration from the KES config directory,
                             '$USER/.kes' on unix systems and '$USERPROFILE/.kes'
                             on windows systems.
                             
    -h, --help               Show list of command-line options


KES is a cloud-native distributed key management and encryption server.
It can either run as stateless edge node in front of a central KMS or
as stateful high performance KMS cluster.
	
    Quick Start: https://github.com/minio/kes#quick-start
    Docs:        https://github.com/minio/kes/wiki

KES leverages hardware security modules (HSMs) to seal and unseal its encrypted
state on disk. The HSM is responsible for en/decrypting the cluster root key.
The $KES_HSM_KEY env. variable can be used to emulate such an HSM in software.
The same $KES_HSM_KEY must be present on all KES servers within a KES cluster.
You must generate your own $KES_HSM_KEY and keep it secure:
	
     $ kes --soft-hsm

Examples:
  1. Start a single node KES cluster accessible at 'localhost:7373'
     $ export KES_HSM_KEY=kes:v1:aes256:H2BFEgK48Mr4KfuBkxUFJJJNn8f+J0ugpn43ZYJfw30= # Use your own
     $ kes server /tmp/kes0

  2. Start a single node KES cluster accessible at 'kes-0.local:7373'
     $ export KES_HSM_KEY=kes:v1:chacha20:OYmWIhY6iZAMOqNt610dqit5j/NuZNZc71+XreVdwug= # Use your own
     $ kes server --host kes-0.local:7373 ~/kes0

  3. Start a single node KES cluster accessible at '10.1.2.3:443'
     $ export KES_HSM_KEY=kes:v1:aes256:OBwNvb9qloQi235KindURBuSqArJzWN6JaYKUZHIyPY= # Use your own
     $ kes server --addr :443 --host 10.1.2.3:443 ~/kes0

License:
   Copyright:  MinIO, Inc.
   GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
`

func serverCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addrFlag   string
		hostFlag   string
		configFlag string
	)
	cmd.StringVar(&addrFlag, "addr", "", "The network interface the KES server listens on. Default: 0.0.0.0:7373")
	cmd.StringVar(&hostFlag, "host", "", "")
	cmd.StringVar(&configFlag, "config", "", "")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes server --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		os.Exit(1)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}

	if hostFlag == "" {
		port := "7373"
		if addrFlag != "" {
			_, p, err := net.SplitHostPort(addrFlag)
			if err != nil {
				cli.Fatalf("invalid '--addr=%s': %v", addrFlag, err)
			}
			port = p
		}

		if ip, err := lookupExternalIP(); err == nil {
			hostFlag = net.JoinHostPort(ip.String(), port)
		} else {
			hostFlag = net.JoinHostPort("localhost", port)
		}
	}

	nodeAddr, err := kes.ParseAddr(hostFlag)
	if err != nil {
		cli.Fatalf("invalid host addr '%s': %v", hostFlag, err)
	}
	startServer(cmd.Arg(0), addrFlag, nodeAddr, configFlag)
}

func startServer(path, addr string, nodeAddr kes.Addr, configFile string) {
	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	hsmKey, ok := os.LookupEnv("KES_HSM_KEY")
	if !ok {
		cli.Fatal("env variable 'KES_HSM_KEY' is not present")
	}
	hsm, err := kes.ParseSoftHSM(hsmKey)
	if err != nil {
		cli.Fatalf("invalid env variable 'KES_HSM_KEY': %v", err)
	}

	var config *kesconf.ServerConfig
	if configFile != "" {
		file, err := os.Open(configFile)
		if err != nil {
			cli.Fatalf("failed to read server config: %v", err)
		}
		config, err = kesconf.ReadServerConfigYAML(file)
		if err != nil {
			file.Close()
			cli.Fatalf("failed to read server config: %v", err)
		}
		if err = file.Close(); err != nil {
			cli.Fatalf("failed to read server config: %v", err)
		}
	} else {
		dir, err := os.UserHomeDir()
		if err != nil {
			cli.Fatalf("failed to detect home directory: %v", err)
		}
		dir = filepath.Join(dir, ".kes")
		os.Mkdir(dir, 0o755)
		os.Mkdir(filepath.Join(dir, "CAs"), 0o755)

		config = &kesconf.ServerConfig{
			Addr:  "0.0.0.0:7373",
			Admin: "",
			TLS: &kesconf.TLSConfig{
				PrivateKey:  filepath.Join(dir, "private.key"),
				Certificate: filepath.Join(dir, "public.crt"),
				CAPath:      filepath.Join(dir, "CAs"),
			},
		}
	}
	if addr == "" && config.Addr != "" {
		addr = config.Addr
	}

	tlsOptions := []mtls.Option{
		mtls.WithServerCertificate(config.TLS.Certificate, config.TLS.PrivateKey, "", nodeAddr.Host()),
		mtls.WithRootCAs(config.TLS.CAPath),
		mtls.WithClientAuth(tls.RequestClientCert),
	}
	tlsConfig := new(tls.Config)
	for _, opt := range tlsOptions {
		if err = opt(tlsConfig); err != nil {
			cli.Fatal(err)
		}
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.CipherSuites = fips.TLSCiphers()
	tlsConfig.CurvePreferences = fips.TLSCurveIDs()
	tlsConfig.RootCAs.AddCert(tlsConfig.Certificates[0].Leaf)

	if err = kes.Init(path, nodeAddr); err != nil {
		cli.Fatal(err)
	}

	node := kes.NewServer(nodeAddr)
	node.Register(kes.SigStart, func() { cli.PrintStartupMessage(node) })
	node.Register(kes.SigJoin, func() {
		cli.Println()
		cli.Println("Node joining the cluster...")
		cli.Println("")
		cli.PrintStartupMessage(node)
	})
	node.Register(kes.SigLeave, func() {
		cli.Println()
		cli.Println("Node leaving the cluster...")
		cli.Println("")
		cli.PrintStartupMessage(node)
	})
	if err := node.Start(ctx, path, &kes.Config{
		Addr:     addr,
		Admin:    config.Admin,
		HSM:      hsm,
		TLS:      tlsConfig,
		ErrorLog: nil,
		AuditLog: nil,
	}); err != nil {
		cli.Fatalf("failed to start server: %v", err)
	}
}

func lookupExternalIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ipv6 net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // interface is down or is loopback
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
				continue
			}

			if ipv4 := ip.To4(); ipv4 != nil { // Prefer IPv4: return first non-nil IPv4
				return ipv4, nil
			}
			if ipv6 == nil && len(ip) == net.IPv6len { // Record first IPv6 - just in case we don't find an IPv4
				ipv6 = ip
			}
		}
	}
	if ipv6 != nil {
		return ipv6, nil
	}
	return nil, errors.New("no IP addrs")
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
