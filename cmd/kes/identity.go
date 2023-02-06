// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/https"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const identityCmdUsage = `Usage:
    kes identity <command>

Commands:
    new                      Create a new KES identity.
    of                       Compute a KES identity from a certificate.
    info                     Get information about a KES identity.
    ls                       List KES identities.
    rm                       Remove a KES identity.

Options:
    -h, --help               Print command line options.
`

func identityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, identityCmdUsage) }

	subCmds := commands{
		"new":  newIdentityCmd,
		"of":   ofIdentityCmd,
		"info": infoIdentityCmd,
		"ls":   lsIdentityCmd,
		"rm":   rmIdentityCmd,
	}

	if len(args) < 2 {
		cmd.Usage()
		os.Exit(2)
	}
	if cmd, ok := subCmds[args[1]]; ok {
		cmd(args[1:])
		return
	}

	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatalf("%q is not an identity command. See 'kes identity --help'", cmd.Arg(0))
	}
	cmd.Usage()
	os.Exit(2)
}

const newIdentityCmdUsage = `Usage:
    kes identity new [options] <subject>

Options:
    --key <PATH>             Path to private key. (default: ./private.key) 
    --cert <PATH>            Path to certificate. (default: ./public.crt)
    -f, --force              Overwrite an existing private key and/or certificate.

    --ip <IP>                Add <IP> as subject alternative name. (SAN)
    --dns <DOMAIN>           Add <DOMAIN> as subject alternative name. (SAN)
    --expiry <DURATION>      Duration until the certificate expires. (default: 720h)
    --encrypt                Encrypt the private key with a password.

    -h, --help               Print command line options.

Examples:
    $ kes identity new Client-1
    $ kes identity new --ip "192.168.0.182" --ip "10.0.0.92" Client-1
    $ kes identity new --key client1.key --cert client1.crt --encrypt Client-1
    $ kes identity new --key client1.key --cert client1.crt --encrypt Client-1 --expiry 8760h
`

func newIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, newIdentityCmdUsage) }

	var (
		keyPath   string
		certPath  string
		forceFlag bool
		IPs       []net.IP
		domains   []string
		expiry    time.Duration
		encrypt   bool
	)
	cmd.StringVar(&keyPath, "key", "private.key", "Path to private key")
	cmd.StringVar(&certPath, "cert", "public.crt", "Path to certificate")
	cmd.BoolVarP(&forceFlag, "force", "f", false, "Overwrite an existing private key and/or certificate")
	cmd.IPSliceVar(&IPs, "ip", []net.IP{}, "Add <IP> as subject alternative name")
	cmd.StringSliceVar(&domains, "dns", []string{}, "Add <DOMAIN> as subject alternative name")
	cmd.DurationVar(&expiry, "expiry", 720*time.Hour, "Duration until the certificate expires")
	cmd.BoolVar(&encrypt, "encrypt", false, "Encrypt the private key with a password")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity new --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no certificate subject specified. See 'kes identity new --help'")
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity new --help'")
	}

	var (
		subject    = cmd.Arg(0)
		publicKey  crypto.PublicKey
		privateKey crypto.PrivateKey
	)
	if fips.Enabled {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			cli.Fatalf("failed to generate private key: %v", err)
		}
		publicKey, privateKey = private.Public(), private
	} else {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			cli.Fatalf("failed to generate private key: %v", err)
		}
		publicKey, privateKey = public, private
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		cli.Fatalf("failed to create certificate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(expiry),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              domains,
		IPAddresses:           IPs,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		cli.Fatalf("failed to create certificate: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		cli.Fatalf("failed to create private key: %v", err)
	}

	if !forceFlag {
		if _, err = os.Stat(keyPath); err == nil {
			cli.Fatal("private key already exists. Use --force to overwrite it")
		}
		if _, err = os.Stat(certPath); err == nil {
			cli.Fatal("certificate already exists. Use --force to overwrite it")
		}
	}

	var keyPem []byte
	if encrypt {
		fmt.Fprint(os.Stderr, "Enter password for private key:")
		p, err := term.ReadPassword(int(os.Stderr.Fd()))
		if err != nil {
			cli.Fatal(err)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, "Confirm password for private key:")
		confirm, err := term.ReadPassword(int(os.Stderr.Fd()))
		if err != nil {
			cli.Fatal(err)
		}
		fmt.Fprintln(os.Stderr)
		if !bytes.Equal(p, confirm) {
			cli.Fatal("passwords don't match")
		}

		block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", privBytes, p, x509.PEMCipherAES256)
		if err != nil {
			cli.Fatalf("failed to encrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(block)
	} else {
		keyPem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	}
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	if err = os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		cli.Fatalf("failed to create private key: %v", err)
	}
	if err = os.WriteFile(certPath, certPem, 0o644); err != nil {
		os.Remove(keyPath)
		cli.Fatalf("failed to create certificate: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\n  Private key:  %s\n", keyPath)
		fmt.Printf("  Certificate:  %s\n", certPath)

		cert, err := x509.ParseCertificate(certBytes)
		if err == nil {
			identity := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			fmt.Printf("  Identity:     %s\n", hex.EncodeToString(identity[:]))
		}
	}
}

const ofIdentityCmdUsage = `Usage:
    kes identity of <certificate>...

Options:
    -h, --help               Print command line options.

Examples:
    $ kes identity of client.crt
    $ kes identity of client1.crt client2.crt
`

func ofIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, ofIdentityCmdUsage) }

	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity of --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no certificate specified. See 'kes identity of --help'")
	}

	identify := func(filename string) (kes.Identity, error) {
		pemBlock, err := os.ReadFile(filename)
		if err != nil {
			return "", err
		}
		pemBlock, err = https.FilterPEM(pemBlock, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate in %q: %v", filename, err)
		}

		next, _ := pem.Decode(pemBlock)
		cert, err := x509.ParseCertificate(next.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse certificate in %q: %v", filename, err)
		}
		identity := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		return kes.Identity(hex.EncodeToString(identity[:])), nil
	}

	switch {
	case cmd.NArg() == 1:
		identity, err := identify(cmd.Arg(0))
		if err != nil {
			cli.Fatal(err)
		}
		if isTerm(os.Stdout) {
			fmt.Printf("\n  Identity:  %s\n", identity)
		} else {
			fmt.Print(identity)
		}
	case isTerm(os.Stdout):
		for _, filename := range cmd.Args() {
			identity, err := identify(filename)
			if err != nil {
				cli.Fatal(err)
			}
			fmt.Printf("%s: %s\n", filename, identity)
		}
	default:
		type Pair struct {
			Name     string       `json:"name"`
			Identity kes.Identity `json:"identity"`
		}
		encoder := json.NewEncoder(os.Stdout)
		for _, filename := range cmd.Args() {
			identity, err := identify(filename)
			if err != nil {
				cli.Fatal(err)
			}
			encoder.Encode(Pair{
				Name:     filename,
				Identity: identity,
			})
		}
	}
}

const infoIdentityCmdUsage = `Usage:
    kes identity info [options] [<identity>]

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print identity information in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes identity info
    $ kes identity info 3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
`

func infoIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, infoIdentityCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print policy information in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity info --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	var faint, identityStyle, policyStyle, dotAllowStyle, dotDenyStyle tui.Style
	if colorFlag.Colorize() {
		const (
			ColorIdentity tui.Color = "#2e42d1"
			ColorPolicy   tui.Color = "#d1bd2e"
			ColorDotAllow tui.Color = "#00d700"
			ColorDotDeny  tui.Color = "#d70000"
		)
		faint = faint.Faint(true).Bold(true)
		identityStyle = identityStyle.Foreground(ColorIdentity)
		policyStyle = policyStyle.Foreground(ColorPolicy)
		dotAllowStyle = dotAllowStyle.Foreground(ColorDotAllow)
		dotDenyStyle = dotDenyStyle.Foreground(ColorDotDeny)
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	if cmd.NArg() == 0 {
		info, policy, err := enclave.DescribeSelf(ctx)
		if err != nil {
			cli.Fatal(err)
		}
		year, month, day := info.CreatedAt.Date()
		hour, min, sec := info.CreatedAt.Clock()

		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Identity")),
			identityStyle.Render(info.Identity.String()),
		)
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created At")),
			fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
		)
		if info.IsAdmin {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Role")), "Admin")
		} else {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Role")), "User")
		}
		if !info.CreatedBy.IsUnknown() {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Created By")), info.CreatedBy)
		}
		if info.Policy != "" {
			year, month, day := policy.Info.CreatedAt.Date()
			hour, min, sec := policy.Info.CreatedAt.Clock()

			fmt.Println()
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Policy")), policyStyle.Render(info.Policy))
			fmt.Println(
				faint.Render(fmt.Sprintf("%-11s", "Created At")),
				fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
			)
			if len(policy.Allow) > 0 {
				fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Allow")))
				for _, allow := range policy.Allow {
					fmt.Println(fmt.Sprintf("%-11s", " "), dotAllowStyle.Render("·"), allow)
				}
			}
			if len(policy.Deny) > 0 {
				fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Deny")))
				for _, deny := range policy.Deny {
					fmt.Println(fmt.Sprintf("%-11s", " "), dotDenyStyle.Render("·"), deny)
				}
			}
		}
	} else {
		info, err := enclave.DescribeIdentity(ctx, kes.Identity(cmd.Arg(0)))
		if err != nil {
			cli.Fatal(err)
		}
		year, month, day := info.CreatedAt.Date()
		hour, min, sec := info.CreatedAt.Clock()

		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Identity")),
			identityStyle.Render(info.Identity.String()),
		)
		if info.Policy != "" {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Policy")), policyStyle.Render(info.Policy))
		}
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created At")),
			fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
		)
		if info.IsAdmin {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Role")), "Admin")
		} else {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Role")), "User")
		}
		if !info.CreatedBy.IsUnknown() {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Created By")), info.CreatedBy)
		}
	}
}

const lsIdentityCmdUsage = `Usage:
    kes identity ls [options] [<pattern>]

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print identities in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes identity ls
    $ kes identity ls 'b804befd*'
`

func lsIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsIdentityCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity ls --help'")
	}

	pattern := "*"
	if cmd.NArg() == 1 {
		pattern = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	identities, err := enclave.ListIdentities(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to list identities: %v", err)
	}
	defer identities.Close()

	if jsonFlag {
		if _, err = identities.WriteTo(os.Stdout); err != nil {
			cli.Fatal(err)
		}
		if err = identities.Close(); err != nil {
			cli.Fatal(err)
		}
	} else {
		sortedInfos, err := identities.Values(0)
		if err != nil {
			cli.Fatalf("failed to list identities: %v", err)
		}
		if len(sortedInfos) > 0 {
			sort.Slice(sortedInfos, func(i, j int) bool {
				return strings.Compare(sortedInfos[i].Policy, sortedInfos[j].Policy) < 0
			})

			headerStyle := tui.NewStyle()
			dateStyle := tui.NewStyle()
			policyStyle := tui.NewStyle()
			if colorFlag.Colorize() {
				const (
					ColorDate   tui.Color = "#5f8700"
					ColorPolicy tui.Color = "#2E42D1"
				)
				headerStyle = headerStyle.Underline(true).Bold(true)
				dateStyle = dateStyle.Foreground(ColorDate)
				policyStyle = policyStyle.Foreground(ColorPolicy)
			}

			fmt.Printf("%s %s %s\n",
				headerStyle.Render(fmt.Sprintf("%-19s", "Date Created")),
				headerStyle.Render(fmt.Sprintf("%-64s", "Identity")),
				headerStyle.Render("Policy"),
			)
			for _, info := range sortedInfos {
				year, month, day := info.CreatedAt.Local().Date()
				hour, min, sec := info.CreatedAt.Local().Clock()

				fmt.Printf("%s %s %s\n",
					dateStyle.Render(fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec)),
					fmt.Sprintf("%-64s", info.Identity.String()),
					policyStyle.Render(fmt.Sprintf("%-15s", info.Policy)),
				)
			}
		}
	}
}

const rmIdentityCmdUsage = `Usage:
    kes identity rm <identity>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes identity rm 736bf58626441e3e134a2daf2e6a8441b40e1abc0eac510878168c8aac9f2b0b
`

func rmIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmIdentityCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no identity specified. See 'kes identity rm --help'")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, identity := range cmd.Args() {
		if err := enclave.DeleteIdentity(ctx, kes.Identity(identity)); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to remove identity %q: %v", identity, err)
		}
	}
}
