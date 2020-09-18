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
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

const toolIdentityCmdUsage = `usage: %s <command>

  of                   Compute identities from TLS certificates.
  new                  Create a new identity by creating a TLS
                       private key and certificate.

  -h, --help           Show list of command-line options
`

func toolIdentity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), toolIdentityCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "of":
		return identityOf(args)
	case "new":
		return newIdentity(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}

const newIdentityCmdUsage = `usage: %s [options] <name>

  --key                Path to the private key (default: ./private.key)
  --cert               Path to the certificate (default: ./public.cert)

  -t, --time           Duration until the certificate will expire (default: 720h)

  -f, --force          Overwrite the private key and/or certificate, if it exists

  -h, --help           Show list of command-line options
`

func newIdentity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), newIdentityCmdUsage, cli.Name())
	}

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
	if args = parseCommandFlags(cli, args[1:]); len(args) != 1 {
		cli.Usage()
		os.Exit(2)
	}
	name := args[0]

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate Ed25519 key pair: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to certificate serial number: %v", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return fmt.Errorf("Failed to encode private key: %v", err)
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
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists: Use --force to overwrite the private key", keyPath)
		}
		return fmt.Errorf("Failed to create private key: %v", err)
	}
	defer keyFile.Close()

	certFile, err = os.OpenFile(certPath, fileFlags, 0600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists: Use --force to overwrite the certificate", certPath)
		}
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	defer certFile.Close()

	if err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		os.Remove(certPath)
		return fmt.Errorf("Failed to create certificate: %v", err)
	}
	if err = certFile.Close(); err != nil {
		os.Remove(certPath)
		return fmt.Errorf("Failed to close %s: %v", certPath, err)
	}

	if err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		os.Remove(certPath)
		os.Remove(keyPath)
		return fmt.Errorf("Failed to create private key: %v", err)
	}
	if err = keyFile.Close(); err != nil {
		os.Remove(certPath)
		os.Remove(keyPath)
		return fmt.Errorf("Failed to close %s: %v", keyPath, err)
	}
	return nil
}

const identityOfCmdUsage = `usage: %s [options] <certificate>

  --hash               The hash function used to compute the
                       identity. (SHA-256, SHA-384 or SHA-512)

  -h, --help           Show list of command-line options
`

func identityOf(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), identityOfCmdUsage, cli.Name())
	}

	var hashFunc string
	cli.StringVar(&hashFunc, "hash", "SHA256", "")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 1 {
		cli.Usage()
		os.Exit(2)
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
		return fmt.Errorf("Unsupported hash function: %s", hashFunc)
	}

	file, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("Failed open '%s': %v", args[0], err)
	}
	defer file.Close()

	cert, err := parseCertificate(file)
	if err != nil {
		return fmt.Errorf("Failed to parse certificate: %v", err)
	}
	h.Write(cert.RawSubjectPublicKeyInfo)

	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("\n  Identity:  %s\n", hex.EncodeToString(h.Sum(nil)))
	} else {
		fmt.Print(hex.EncodeToString(h.Sum(nil)))
	}
	return nil
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
