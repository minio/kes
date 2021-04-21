// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	stdlog "log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/secret"
	"golang.org/x/crypto/ssh/terminal"
)

const toolCmdUsage = `Usage:
    kes tool <command>

Commands:
    identity               Identity management tools.
    migrate                Migrate between KMS backends.

Options:
   -h, --help              Show list of command-line options
`

func tool(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, toolCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(1)
	}

	switch args = cli.Args(); args[0] {
	case "identity":
		toolIdentity(args)
	case "migrate":
		migrate(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes tool command. See 'kes tool --help'", args[0])
	}
}

const toolIdentityCmdUsage = `Usage:
    kes tool identity <command>

Commands:
    of                     Compute identities from TLS certificates.
    new                    Create a new identity by creating a TLS
                           private key and certificate.

Options:
    -h, --help             Show list of command-line options
`

func toolIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, toolIdentityCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(1)
	}

	switch args := cli.Args(); args[0] {
	case "of":
		identityOfCmd(args)
	case "new":
		newIdentityCmd(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes tool identity command. See 'kes tool identity --help'", args[0])
	}
}

const newIdentityCmdUsage = `Usage:
    kes tool identity new [options] [<subject>]

Options:
    --key <PATH>           Path to the private key (default: ./private.key)
    --cert <PATH>          Path to the certificate (default: ./public.crt)

    --server               Create a certificate for TLS server instead of a TLS client.
    --ip <IP>              Add <IP> as subject alternative name (SAN). Can be specified more than once. 
    --dns <DOMAIN>         Add <DOMAIN> as subject alternative name (SAN). Can be specified more than once.

    -t, --time <DATE>      Duration until the certificate will expire (default: 720h)
    -f, --force            Overwrite the private key and/or certificate, if it exists
    -h, --help             Show list of command-line options

Creates a new TLS private key and (self-signed) certificate that is valid
for the duration specified by --time. If a subject name is provided the
certificate common name subject will be set to <subject>.

Examples:
    $ kes tool identity new --key=my-app.key --cert=my-app.crt --time 2160h
    $ kes tool identity new --server --ip=127.0.0.1 --dns=localhost --dns=example.com
`

func newIdentityCmd(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, newIdentityCmdUsage) }

	var (
		keyPath    string
		certPath   string
		validFor   time.Duration
		dnsFlag    multiFlag
		ipFlag     multiFlag
		forceFlag  bool
		serverFlag bool
	)
	cli.StringVar(&keyPath, "key", "./private.key", "Path to the private key (default: ./private.key)")
	cli.StringVar(&certPath, "cert", "./public.crt", "Path to the certificate (default: ./public.crt)")
	cli.DurationVar(&validFor, "t", 720*time.Hour, "Duration until the certificate will expire (default: 720h)")
	cli.DurationVar(&validFor, "time", 720*time.Hour, "Duration until the certificate will expire (default: 720h)")
	cli.BoolVar(&forceFlag, "f", false, "Overwrite the private key and/or certificate, if it exists")
	cli.BoolVar(&forceFlag, "force", false, "Overwrite the private key and/or certificate, if it exists")
	cli.BoolVar(&serverFlag, "server", false, "Create a certificate for a TLS server, not a TLS client")
	cli.Var(&dnsFlag, "dns", "Add a domain name as SAN. Can be specified more than once")
	cli.Var(&ipFlag, "ip", "Add an IP as SAN. Can be specified more than once")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}
	var commonName = ""
	if cli.NArg() == 1 {
		commonName = cli.Arg(0)
	}

	var (
		publicKey  crypto.PublicKey
		privateKey crypto.PrivateKey
	)
	if fips.Enabled {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			stdlog.Fatalf("Error: failed to generate private key: %v", err)
		}
		publicKey, privateKey = private.Public(), private
	} else {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			stdlog.Fatalf("Error: failed to generate private key: %v", err)
		}
		publicKey, privateKey = public, private
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		stdlog.Fatalf("Error: failed to create certificate serial number: %v", err)
	}

	var extKeyUsage []x509.ExtKeyUsage
	if serverFlag {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	var ipAddrs = make([]net.IP, 0, len(ipFlag))
	for _, ipAddr := range ipFlag {
		ip := net.ParseIP(ipAddr)
		if ip == nil {
			stdlog.Fatalf("Error: %q is not a valid IP address", ipAddr)
		}
		ipAddrs = append(ipAddrs, ip)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              dnsFlag,
		IPAddresses:           ipAddrs,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		stdlog.Fatalf("Error: failed to create certificate: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		stdlog.Fatalf("Error: failed to create private key: %v", err)
	}

	fileFlags := os.O_CREATE | os.O_WRONLY
	if forceFlag {
		fileFlags |= os.O_TRUNC
	} else {
		fileFlags |= os.O_EXCL
	}

	var (
		keyFile  *os.File
		certFile *os.File
	)
	keyFile, err = os.OpenFile(keyPath, fileFlags, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			stdlog.Fatalf("Error: private key %q already exists: Use --force to overwrite it", keyPath)
		}
		stdlog.Fatalf("Error: failed to create private key %q: %v", keyPath, err)
	}
	defer keyFile.Close()

	certFile, err = os.OpenFile(certPath, fileFlags, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			stdlog.Fatalf("Error: certificate %q already exists: Use --force to overwrite it", certPath)
		}
		stdlog.Fatalf("Error: failed to create certificate %q: %v", certPath, err)
	}
	defer certFile.Close()

	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		os.Remove(certPath)
		stdlog.Fatalf("Error: failed to write certificate to %q: %v", certPath, err)
	}
	if err = certFile.Close(); err != nil {
		os.Remove(certPath)
		stdlog.Fatalf("Error: failed to write certificate to %q: %v", certPath, err)
	}

	if err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		os.Remove(certPath)
		os.Remove(keyPath)
		stdlog.Fatalf("Error: failed to write private key to %q: %v", keyPath, err)
	}
	if err = keyFile.Close(); err != nil {
		os.Remove(certPath)
		os.Remove(keyPath)
		stdlog.Fatalf("Error: failed to write private key to %q: %v", keyPath, err)
	}
}

const identityOfCmdUsage = `Usage:
    kes tool identity of [options] [<certificate>]

Options:
    --hash <HASH>          The hash function used to compute the
                           identity. (SHA-256, SHA-384 or SHA-512)
    -h, --help             Show list of command-line options

Computes the identity of a TLS certificate by calculating the
hash value of its public key. By default, the hash function
SHA-256 is used.

If no certificate is provided then the certificate will be
read from standard input.

Examples:
    $ kes tool identity of root.cert
    $ cat root.cert | kes tool identity of
`

func identityOfCmd(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, identityOfCmdUsage) }

	var hashFunc string
	cli.StringVar(&hashFunc, "hash", "SHA256", "")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}

	var h hash.Hash
	switch strings.ToUpper(hashFunc) {
	case "SHA256", "SHA-256":
		h = crypto.SHA256.New()
	case "SHA384", "SHA-384":
		h = crypto.SHA384.New()
	case "SHA512", "SHA-512":
		h = crypto.SHA512.New()
	default:
		stdlog.Fatalf("Error: invalid --hash: %q", hashFunc)
	}

	var input = os.Stdin
	if cli.NArg() == 1 && cli.Arg(0) != "-" {
		f, err := os.Open(cli.Arg(0))
		if err != nil {
			stdlog.Fatalf("Error: failed to open %q: %v", cli.Arg(0), err)
		}
		defer f.Close()
		input = f
	}

	cert, err := parseCertificate(input)
	if err != nil {
		if input == os.Stdin {
			stdlog.Fatalf("Error: failed to read certificate from standard input: %v", err)
		}
		stdlog.Fatalf("Error: failed to read certificate from %q: %v", input.Name(), err)
	}
	h.Write(cert.RawSubjectPublicKeyInfo)

	if sum := h.Sum(nil); terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("\n  Identity:  %s\n", hex.EncodeToString(sum))
	} else {
		fmt.Print(hex.EncodeToString(sum))
	}
}

const migrateCmdUsage = `Usage:
    kes tool migrate [options] [<pattern>]

Options:
    --from <PATH>          Path to the configuration file of the server that
                           should be migrated
    --to   <PATH>          Path to the configuration file of the server that
                           is the migration target

    -f, --force            Migrate keys even if a key with the same name exists
                           at the target. The existing keys will be deleted

    --merge                Merge the source into the target by only migrating
                           those keys that do not exist at the target

    -q, --quiet            Don't print migration progress and statistics.
    -h, --help             Show list of command-line options

Migrate keys from one KMS to another KMS. The KMS access credentials are
taken from the KES config files specified via the --from and --to flags.

Both, the source and target KMS, must be reachable from the machine 
performing the migration.

Examples:
    $ kes tool migrate --from kes-vault.yml --to kes-aws.yml
`

func migrate(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, migrateCmdUsage) }

	var (
		fromFlag  string
		toFlag    string
		forceFlag bool
		mergeFlag bool
		quietFlag quiet
	)
	cli.StringVar(&fromFlag, "from", "", "Path to the config file of the migration source")
	cli.StringVar(&toFlag, "to", "", "Path to the config file of the migration target")
	cli.BoolVar(&forceFlag, "f", false, "Overwrite existing keys at the migration target")
	cli.BoolVar(&forceFlag, "force", false, "Overwrite existing keys at the migration target")
	cli.BoolVar(&mergeFlag, "merge", false, "Only migrate keys that don't exist at the migration target")
	cli.Var(&quietFlag, "q", "Don't print migration progress and statistics")
	cli.Var(&quietFlag, "quiet", "Don't print migration progress and statistics")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}
	if fromFlag == "" {
		stdlog.Fatal("Error: no migration source specified. Use '--from' to specify a config file")
	}
	if toFlag == "" {
		stdlog.Fatal("Error: no migration target specified. Use '--to' to specify a config file")
	}
	if forceFlag && mergeFlag {
		stdlog.Fatal("Error: -f or --force cannot be used together with --merge. They are mutually exclusive")
	}

	var pattern = cli.Arg(0)
	if pattern == "" {
		pattern = "*"
	}

	sourceConfig, err := loadServerConfig(fromFlag)
	if err != nil {
		stdlog.Fatalf("Error: failed to read config file: %v", err)
	}
	sourceConfig.KeyStore.SetDefaults()
	if err := sourceConfig.KeyStore.Verify(); err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	targetConfig, err := loadServerConfig(toFlag)
	if err != nil {
		stdlog.Fatalf("Error: failed to read config file: %v", err)
	}
	targetConfig.KeyStore.SetDefaults()
	if err := targetConfig.KeyStore.Verify(); err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	src, err := sourceConfig.KeyStore.Connect(quietFlag, nil)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
	dst, err := targetConfig.KeyStore.Connect(quietFlag, nil)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	var (
		n                   uint64
		uiTicker            = time.NewTicker(100 * time.Millisecond)
		listContext, cancel = context.WithCancel(context.Background())
		uiContext, cancelUI = context.WithCancel(listContext)
		signals             = make(chan os.Signal)
	)
	defer cancel()
	defer cancelUI()
	defer uiTicker.Stop()

	// Watch for Ctrl-C and cancel the listing (and the UI).
	signal.Notify(signals, os.Kill, os.Interrupt)
	defer signal.Stop(signals)
	go func() {
		<-signals
		cancel()
	}()

	// Now, we start listing the keys at the source.
	iterator, err := src.List(listContext)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	// Then, we start the UI which prints how many keys have
	// been migrated in fixed time intervals.
	go func() {
		for {
			select {
			case <-uiTicker.C:
				msg := fmt.Sprintf("Migrated keys: %d", atomic.LoadUint64(&n))
				quietFlag.ClearMessage(msg)
				quietFlag.Print(msg)
			case <-uiContext.Done():
				return
			}
		}
	}()

	// Finally, we start the actual migration.
	var (
		red   = color.New(color.FgRed)
		green = color.New(color.FgGreen)
	)
	for iterator.Next() {
		name := iterator.Value()
		if ok, _ := filepath.Match(pattern, name); !ok {
			continue
		}

		key, err := src.Remote.Get(name)
		if err != nil {
			quietFlag.ClearLine()
			stdlog.Printf("Failed to migrate %q: Error: %v\n", name, err)
			stdlog.Fatal(fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + red.Sprint("[ FAIL ]"))
		}

		// We are conservative and only migrate a key if it is well-formed.
		if _, err = secret.ParseSecret(key); err != nil {
			quietFlag.ClearLine()
			stdlog.Printf("Failed to migrate %q: Error: %v\n", name, err)
			stdlog.Fatal(fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + red.Sprint("[ FAIL ]"))
		}

		err = dst.Remote.Create(name, key)
		if err == kes.ErrKeyExists && mergeFlag {
			continue // Do not increment the counter since we skip this key
		}
		if err == kes.ErrKeyExists && forceFlag { // Try to overwrite the key
			if err = dst.Remote.Delete(name); err != nil {
				quietFlag.ClearLine()
				stdlog.Printf("Failed to migrate %q: Error: %v\n", name, err)
				stdlog.Fatal(fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + red.Sprint("[ FAIL ]"))
			}
			err = dst.Remote.Create(name, key)
		}
		if err != nil {
			quietFlag.ClearLine()
			stdlog.Printf("Failed to migrate %q: Error: %v\n", name, err)
			stdlog.Fatal(fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + red.Sprint("[ FAIL ]"))
		}
		atomic.AddUint64(&n, 1)
	}
	if err = iterator.Err(); err != nil {
		quietFlag.ClearLine()
		stdlog.Printf("Error: failed to list keys: %v\n", err)
		stdlog.Fatal(fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + red.Sprint("[ FAIL ]"))
	}
	cancelUI()

	// At the end we show how many keys we have migrated successfully.
	msg := fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n)) + green.Sprint("[ OK ]")
	quietFlag.ClearMessage(msg)
	quietFlag.Println(msg)
}

func parseCertificate(r io.Reader) (*x509.Certificate, error) {
	certPEMBlock, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			return x509.ParseCertificate(certDERBlock.Bytes)
		}
	}
	return nil, errors.New("found no (non-CA) certificate in any PEM block")
}
