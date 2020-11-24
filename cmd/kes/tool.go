// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/ed25519"
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
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

const toolCmdUsage = `Usage:
    kes tool <command>

Commands:
    identity               Identity management tools.

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

    -t, --time <DATE>      Duration until the certificate will expire (default: 720h)
    -f, --force            Overwrite the private key and/or certificate, if it exists
    -h, --help             Show list of command-line options

Creates a new TLS private key and (self-signed) certificate that is valid
for the duration specified by --time. If a subject name is provided the
certificate common name subject will be set to <subject>.

Examples:
    $ kes tool identity new --key=my-app.key --cert=my-app.crt --time 2160h
`

func newIdentityCmd(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, newIdentityCmdUsage) }

	var (
		keyPath  string
		certPath string
		validFor time.Duration
		force    bool
	)
	cli.StringVar(&keyPath, "key", "./private.key", "Path to the private key (default: ./private.key)")
	cli.StringVar(&certPath, "cert", "./public.cert", "Path to the certificate (default: ./public.cert)")
	cli.DurationVar(&validFor, "t", 720*time.Hour, "Duration until the certificate will expire (default: 720h)")
	cli.DurationVar(&validFor, "time", 720*time.Hour, "Duration until the certificate will expire (default: 720h)")
	cli.BoolVar(&force, "f", false, "Overwrite the private key and/or certificate, if it exists")
	cli.BoolVar(&force, "force", false, "Overwrite the private key and/or certificate, if it exists")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}
	var commonName = ""
	if cli.NArg() == 1 {
		commonName = cli.Arg(0)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		stdlog.Fatalf("Error: failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		stdlog.Fatalf("Error: failed to create certificate serial number: %v", err)
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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		stdlog.Fatalf("Error: failed to create certificate: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		stdlog.Fatalf("Error: failed to create private key: %v", err)
	}

	fileFlags := os.O_CREATE | os.O_WRONLY
	if force {
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
	cli.Usage = func() { fmt.Fprintf(os.Stderr, identityOfCmdUsage) }

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
