// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

const identifyCmdUsage = `usage: %s [options] <certificate>
   
  --hash               The hash function used to compute the
                       identity. (SHA-256, SHA-384 or SHA-512)

  -h, --help           Show list of command-line options
`

func identify(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), identifyCmdUsage, cli.Name())
	}

	var hashFunc string
	cli.StringVar(&hashFunc, "hash", "SHA256", "")
	cli.Parse(args[1:])

	if args = cli.Args(); len(args) != 1 {
		if len(args) > 0 && !terminal.IsTerminal(int(os.Stdin.Fd())) {
			cli.Usage()
			os.Exit(2)
		}
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
		failf(cli.Output(), "Unsupported hash function: %s", hashFunc)
	}

	var file *os.File
	if len(args) == 1 {
		var err error
		file, err = os.Open(args[0])
		if err != nil {
			failf(cli.Output(), "Failed open '%s': %v", args[0], err)
		}
		defer file.Close()
	} else {
		file = os.Stdin
	}

	cert, err := parseCertificate(file)
	if err != nil {
		failf(cli.Output(), "Failed to parse certificate: %v", err)
	}
	h.Write(cert.RawSubjectPublicKeyInfo)

	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("\n  Identity:  %s\n", hex.EncodeToString(h.Sum(nil)))
	} else {
		fmt.Print(hex.EncodeToString(h.Sum(nil)))
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
