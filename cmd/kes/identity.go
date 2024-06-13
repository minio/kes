// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kms-go/kes"
	sdk "github.com/minio/kms-go/kes"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const identityCmdUsage = `Usage:
    kes identity <command>
    kes identity [KEY | FILE]

Commands:
    new                      Create a new KES identity.
    of                       Compute a KES identity from a certificate.
    info                     Get information about a KES identity.
    ls                       List KES identities.

Options:
    -h, --help               Print command line options.
`

func identityCmd(args []string) {
	if len(args) >= 2 {
		subCmds := commands{
			"new":  newIdentityCmd,
			"of":   ofIdentityCmd,
			"info": infoIdentityCmd,
			"ls":   lsIdentityCmd,
		}
		if cmd, ok := subCmds[args[1]]; ok {
			cmd(args[1:])
			return
		}
	}

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, identityCmdUsage) }
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Exit(err)
	}

	if flags.NArg() > 1 {
		cli.Exit("too many arguments")
	}

	if flags.NArg() == 0 {
		key, err := sdk.GenerateAPIKey(nil)
		if err != nil {
			cli.Exitf("failed to generate API key: %v", err)
		}

		if !cli.IsTerminal() {
			fmt.Print(key)
			return
		}

		buf := &strings.Builder{}
		fmt.Fprintln(buf, "Your API key:")
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "  ", tui.NewStyle().Bold(true).Render(key.String()))
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "This is the only time it is shown. Keep it secret and secure!")
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "Your API key's identity:")
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "  ", tui.NewStyle().Bold(true).Render(key.Identity().String()))
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "The identity is not a secret and can be shared securely.")
		fmt.Fprintln(buf, "Peers need your identity in order to verify your API key.")
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "This identity can be re-computed again via:")
		fmt.Fprintln(buf)
		fmt.Fprintf(buf, "  $ minkms identity %s", key.String())
		fmt.Println(tui.NewStyle().Border(tui.HiddenBorder()).Padding(0, 0, 0, 0).Render(buf.String()))
		return
	}

	printIdentity := func(identity sdk.Identity) {
		if !cli.IsTerminal() {
			fmt.Print(identity)
			return
		}

		buf := &strings.Builder{}
		fmt.Fprintln(buf, "Identity:")
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "  ", tui.NewStyle().Bold(true).Render(identity.String()))
		fmt.Fprintln(buf)
		fmt.Fprintln(buf, "An identity is a fingerprint of your API key")
		fmt.Fprint(buf, "or certificate and can be shared securely.")
		fmt.Println(tui.NewStyle().Border(tui.HiddenBorder()).Padding(0, 0, 0, 0).Render(buf.String()))
	}
	if key, err := sdk.ParseAPIKey(flags.Arg(0)); err == nil {
		printIdentity(key.Identity())
		return
	}

	filename := flags.Arg(0)
	raw, err := os.ReadFile(filename)
	if err != nil {
		cli.Exit(err)
	}
	raw = bytes.TrimSpace(raw)

	var block *pem.Block
	for len(raw) > 0 {
		if block, raw = pem.Decode(raw); block == nil {
			cli.Exitf("'%s' contains no valid PEM certificate or private key", filename)
		}

		switch {
		case block.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				cli.Exit(err)
			}
			h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			printIdentity(sdk.Identity(hex.EncodeToString(h[:])))
			return
		case strings.Contains(block.Type, "PRIVATE KEY"): // Type may be PRIVATE KEY, EC PRIVATE KEY, ...
			priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				cli.Exit(err)
			}

			key, ok := priv.(ed25519.PrivateKey)
			if !ok {
				cli.Exitf("'%s' contains unsupported private key. Only ed25519 private keys are supported", filename)
			}
			apiKey := "kes:v1:" + base64.StdEncoding.EncodeToString(append([]byte{0}, key[:ed25519.SeedSize]...))

			if !cli.IsTerminal() {
				fmt.Print(apiKey)
				return
			}
			buf := &strings.Builder{}
			fmt.Fprintln(buf, "Your API key:")
			fmt.Fprintln(buf)
			fmt.Fprintln(buf, "  ", tui.NewStyle().Bold(true).Render(apiKey))
			fmt.Fprintln(buf)
			fmt.Fprintf(buf, "It corresponds to the private key in: %s.\n", filename)
			fmt.Fprint(buf, "Keep it secret and secure!")
			fmt.Println(tui.NewStyle().Border(tui.HiddenBorder()).Padding(0, 0, 0, 0).Render(buf.String()))
			return
		}
	}
	cli.Exitf("'%s' contains no valid PEM certificate or private key", filename)
}

const newIdentityCmdUsage = `Usage:
    kes identity new [options] [<subject>]

Options:
    --key <PATH>             Optional path for the private key. 
    --cert <PATH>            Optional path for the certificate.

    --ip <IP>                Add <IP> as subject alternative name (SAN). Requires
                             the --key and --cert flags. 
    --dns <DOMAIN>           Add <DOMAIN> as subject alternative name (SAN).
                             Requires the --key and --cert flags.
    --expiry <DURATION>      Duration until the certificate expires. (default: 720h)
                             Requires the --key and --cert flags.
    --encrypt                Encrypt the private key with a password. Requires
                             the --key and --cert flags. 
    -f, --force              Overwrite an existing private key and/or certificate.

    -h, --help               Print command line options.

Examples:
    $ kes identity new
    $ kes identity new --ip "192.168.0.182" --ip "10.0.0.92" --key private.key --cert public.crt localhost
    $ kes identity new --key server.key --cert server.crt --encrypt --expiry 8760h kes-server.local
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
	cmd.StringVar(&keyPath, "key", "", "Path to private key")
	cmd.StringVar(&certPath, "cert", "", "Path to certificate")
	cmd.BoolVarP(&forceFlag, "force", "f", false, "Overwrite an existing private key and/or certificate")
	cmd.IPSliceVar(&IPs, "ip", []net.IP{}, "Add <IP> as subject alternative name")
	cmd.StringSliceVar(&domains, "dns", []string{}, "Add <DOMAIN> as subject alternative name")
	cmd.DurationVar(&expiry, "expiry", 0, "Duration until the certificate expires")
	cmd.BoolVar(&encrypt, "encrypt", false, "Encrypt the private key with a password")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity new --help'", err)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity new --help'")
	}
	if keyPath != "" && certPath == "" {
		cli.Fatalf("private key file specified but no certificate file. Set the '--cert' flag")
	}
	if keyPath == "" && certPath != "" {
		cli.Fatalf("certificate file specified but no private key file. Set the '--key' flag")
	}
	if keyPath == "" || certPath == "" {
		if encrypt {
			cli.Fatalf("'--encrypt' requires a private key and certificate file. Set the '--cert' and '--key' flag")
		}
		if forceFlag {
			cli.Fatalf("'--force' requires a private key and certificate file. Set the '--cert' and '--key' flag")
		}
		if expiry > 0 {
			cli.Fatalf("'--expiry' requires a private key and certificate file. Set the '--cert' and '--key' flag")
		}
		if len(IPs) > 0 {
			cli.Fatalf("'--ip' requires a private key and certificate file. Set the '--cert' and '--key' flag")
		}
		if len(domains) > 0 {
			cli.Fatalf("'--dns' requires a private key and certificate file. Set the '--cert' and '--key' flag")
		}
	}

	key, err := kes.GenerateAPIKey(nil)
	if err != nil {
		cli.Fatalf("failed to generate API key: %v", err)
	}

	if keyPath != "" && certPath != "" {
		options := []kes.CertificateOption{
			func(cert *x509.Certificate) { cert.DNSNames = domains },
			func(cert *x509.Certificate) { cert.IPAddresses = IPs },
			func(cert *x509.Certificate) { cert.ExtKeyUsage = append(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) },
		}
		if cmd.NArg() == 1 {
			name := cmd.Arg(0)
			options = append(options, func(cert *x509.Certificate) { cert.Subject.CommonName = name })
		}
		if expiry == 0 {
			expiry = 720 * time.Hour
		}
		options = append(options, func(cert *x509.Certificate) {
			now := time.Now()
			cert.NotBefore, cert.NotAfter = now, now.Add(expiry)
		})
		cert, err := kes.GenerateCertificate(key, options...)
		if err != nil {
			cli.Fatalf("failed to generate certificate: %v", err)
		}

		certBytes := cert.Certificate[0]
		privBytes, err := x509.MarshalPKCS8PrivateKey(key.Private())
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
	}

	bold := tui.NewStyle()
	if cli.IsTerminal() {
		bold = bold.Bold(true)
	}
	var buffer strings.Builder
	fmt.Fprintln(&buffer, "Your API key:")
	fmt.Fprintln(&buffer)
	fmt.Fprintln(&buffer, "   "+bold.Render(key.String())+"\n")
	fmt.Fprintln(&buffer, "This is the only time it is shown. Keep it secret and secure!")
	fmt.Fprintln(&buffer)
	fmt.Fprintln(&buffer, "Your Identity:")
	fmt.Fprintln(&buffer)
	fmt.Fprintln(&buffer, "   "+bold.Render(key.Identity().String())+"\n")
	fmt.Fprintln(&buffer, "The identity is not a secret. It can be shared. Any peer")
	fmt.Fprintln(&buffer, "needs this identity in order to verify your API key.")
	if keyPath != "" && certPath != "" {
		fmt.Fprintln(&buffer)
		fmt.Fprintf(&buffer, "The generated TLS private key is stored at: %s\n", keyPath)
		fmt.Fprintf(&buffer, "The generated TLS certificate is stored at: %s\n", certPath)
	}
	fmt.Fprintln(&buffer)
	fmt.Fprintln(&buffer, "The identity can be computed again via:")
	fmt.Fprintln(&buffer)
	fmt.Fprintf(&buffer, "    kes identity of %s\n", key.String())
	if keyPath != "" && certPath != "" {
		fmt.Fprintf(&buffer, "    kes identity of %s", certPath)
	}
	cli.Println(buffer.String())
}

const ofIdentityCmdUsage = `Usage:
    kes identity of <api-key>
    kes identity of <certificate>

Options:
    -h, --help               Print command line options.

Examples:
    $ kes identity of kes:v1:ACQpoGqx3rHHjT938Hfu5hVVQJHZWSqVI2Xp1KlYxFVw
    $ kes identity of client.crt
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
		cli.Fatal("no API key or certificate specified. See 'kes identity of --help'")
	}

	var identity kes.Identity
	if strings.HasPrefix(cmd.Arg(0), "kes:v1:") {
		key, err := kes.ParseAPIKey(cmd.Arg(0))
		if err != nil {
			cli.Fatal(err)
		}
		identity = key.Identity()
	} else {
		filename := cmd.Arg(0)
		pemBlock, err := os.ReadFile(filename)
		if err != nil {
			cli.Fatal(err)
		}
		pemBlock, err = https.FilterPEM(pemBlock, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
		if err != nil {
			cli.Fatalf("failed to parse certificate in '%s': %v", filename, err)
		}

		next, _ := pem.Decode(pemBlock)
		cert, err := x509.ParseCertificate(next.Bytes)
		if err != nil {
			cli.Fatalf("failed to parse certificate in '%s': %v", filename, err)
		}
		h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		identity = kes.Identity(hex.EncodeToString(h[:]))
	}
	if cli.IsTerminal() {
		var buffer strings.Builder
		fmt.Fprintln(&buffer, "Identity:")
		fmt.Fprintln(&buffer)
		fmt.Fprintln(&buffer, "   "+tui.NewStyle().Bold(true).Render(identity.String()))
		cli.Print(buffer.String())
	} else {
		fmt.Print(identity)
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

    -h, --help               Print command line options.

Examples:
    $ kes identity info
    $ kes identity info 3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
`

func infoIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, infoIdentityCmdUsage) }

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

	client := newClient(config{
		InsecureSkipVerify: insecureSkipVerify,
	})
	if cmd.NArg() == 0 {
		info, policy, err := client.DescribeSelf(ctx)
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
			year, month, day := policy.CreatedAt.Date()
			hour, min, sec := policy.CreatedAt.Clock()

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
		info, err := client.DescribeIdentity(ctx, kes.Identity(cmd.Arg(0)))
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
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity ls --help'")
	}

	var prefix string
	if cmd.NArg() == 1 {
		prefix = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newClient(config{
		InsecureSkipVerify: insecureSkipVerify,
	})
	iter := &kes.ListIter[kes.Identity]{
		NextFunc: enclave.ListIdentities,
	}

	var ids []kes.Identity
	for id, err := iter.SeekTo(ctx, prefix); err != io.EOF; id, err = iter.Next(ctx) {
		if err != nil {
			cli.Fatalf("failed to list identities: %v", err)
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)

	if jsonFlag {
		if err := json.NewEncoder(os.Stdout).Encode(ids); err != nil {
			cli.Fatalf("failed to list identities: %v", err)
		}
	}
	if len(ids) == 0 {
		return
	}

	var (
		style = tui.NewStyle().Underline(colorFlag.Colorize())
		buf   = &strings.Builder{}
	)
	fmt.Fprintln(buf, style.Render("Identity"))
	for _, id := range ids {
		buf.WriteString(id.String())
		buf.WriteByte('\n')
	}
	fmt.Print(buf)
}
