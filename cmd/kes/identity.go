// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/mtls"
	flag "github.com/spf13/pflag"
	"golang.org/x/exp/maps"
	"golang.org/x/term"
)

const identityCmdUsage = `Usage:
    kes identity <command>

Commands:
    new                      Generate a new KES identity
    of                       Re-compute a KES identity

    create                   Create a new KES identity
    info                     Get information about a KES identity
    ls                       List KES identities
    rm                       Remove a KES identity

Options:
    -h, --help               Print command line options
`

func identityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, identityCmdUsage) }

	subCmds := cli.SubCommands{
		"new":    newIdentityCmd,
		"of":     ofIdentityCmd,
		"create": createIdentityCmd,
		"info":   describeIdentityCmd,
		"ls":     lsIdentityCmd,
		"rm":     rmIdentityCmd,
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
    kes identity new [options] [<subject>]

Options:
    --key <path>             Optional path for the private key
    --cert <path>            Optional path for the certificate

    --ip <ip>                Add <IP> as subject alternative name (SAN). Requires '--key' and '--cert'
    --dns <domain>           Add <DOMAIN> as subject alternative name (SAN) Requires '--key' and '--cert'
    --expiry <duration>      Duration until the certificate expires (default: 720h). Requires '--key' and '--cert'
    --encrypt                Encrypt the private key with a password. Requires '--key' and '--cert'
    -f, --force              Overwrite an existing private key and/or certificate

    -h, --help               Print command line options

Examples:
  1. Create a new API key and corresponding identity.
    $ kes identity new

  2. Create a new mTLS client certificate valid for the IPs '192.168.1.182' and '10.1.2.3'. The
     private key gets stored in the 'private.key' and the certificate in the 'public.crt' file.
    $ kes identity new --ip 192.168.0.182 --ip 10.1.2.3 --key private.key --cert public.crt

  3. Create a new mTLS client certificate valid for the FQDNs 'kes0.local' and 'kes1.local'. The
     private key gets stored in the 'private.key' and the certificate in the 'public.crt' file.
    $ kes identity new --dns kes0.local --dns kes1.local --key private.key --cert public.crt
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
	if cmd.NArg() == 1 && certPath == "" {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatalf("a non-empty subject name '%s' requires '--key' and '--cert' flag", cmd.Arg(0))
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
	if isTerm(os.Stdout) {
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
        --json               Print result in JSON format
	
    -h, --help               Print command line options

Examples:
  1. Compute identity of the API key 'kes:v1:ACQpoGqx3rHHjT938Hfu5hVVQJHZWSqVI2Xp1KlYxFVw'
     $ kes identity of kes:v1:ACQpoGqx3rHHjT938Hfu5hVVQJHZWSqVI2Xp1KlYxFVw

  2. Compute identity of the certificate 'public.crt'
     $ kes identity of public.crt
`

func ofIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, ofIdentityCmdUsage) }

	var jsonFlag bool
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity of --help'", err)
	}
	if cmd.NArg() == 0 && isTerm(os.Stdin) {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no API key or certificate file specified")
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity of --help'")
	}

	var identity kes.Identity
	if cmd.NArg() == 1 && strings.HasPrefix(cmd.Arg(0), "kes:v1:") {
		key, err := kes.ParseAPIKey(cmd.Arg(0))
		if err != nil {
			cli.Fatal(err)
		}
		identity = key.Identity()
	} else {
		in := os.Stdin
		if cmd.NArg() == 1 {
			f, err := os.Open(cmd.Arg(0))
			if err != nil {
				cli.Fatal(err)
			}
			defer f.Close()

			in = f
		}
		pemBlock, err := io.ReadAll(in)
		if err != nil {
			cli.Fatal(err)
		}
		pemBlock, err = mtls.FilterPEM(pemBlock, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
		if err != nil {
			cli.Fatalf("failed to parse certificate: %v", err)
		}

		next, _ := pem.Decode(pemBlock)
		cert, err := x509.ParseCertificate(next.Bytes)
		if err != nil {
			cli.Fatalf("failed to parse certificate: %v", err)
		}
		h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		identity = kes.Identity(hex.EncodeToString(h[:]))
	}

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		type JSON struct {
			Identity kes.Identity `json:"identity"`
		}
		if err := encoder.Encode(JSON{Identity: identity}); err != nil {
			cli.Fatalf("failed to encode identity: %v", err)
		}
		return
	}

	identityStyle := tui.NewStyle().Bold(true)

	var buf cli.Buffer
	buf.Sprintln("Your Identity:").Sprintln()
	buf.Styleln(identityStyle, "   ", identity)
	cli.Print(buf.String())
}

const createIdentityCmdUsage = `Usage:
    kes identity create [options] <identity>

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --admin              Assign admin privileges to the identity. No policy must be set
        --policy <name>      Assign a policy to the identity. If not set, the identity has no
                             privileges at all.
        --ttl <duration>     The identity's time-to-live after which it expires. If not set,
                             the identity lives at most as long as its parent identity.

    -h, --help               Print command line options

Examples:
  1. Create an identity without any access permissions within the enclave $KES_ENCLAVE
     $ kes identity create c33d9b1d34ac111391404589541ce17621d916fae7e07cf31d18a0baf5999102

  2. Create an identity within the enclave $KES_ENCLAVE and assign the policy 'minio' to it.
     $ kes identity create --policy minio 2c3dff9d7d008e64fd8e3c07e6ea47f3e9f478f10aa7dcb24084cc72369377cc

  3. Create an identity within the enclave $KES_ENCLAVe that expires after one hour.
     $ kes identity create --ttl 1h 39e38d6e6851d457f4312e1378dbd1dccb80c0fa90bfd79612a69558cee7398e	
`

func createIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createIdentityCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
		policyName         string
		admin              bool
		ttl                time.Duration
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	cmd.StringVar(&policyName, "policy", "", "Assign a policy to the identity")
	cmd.BoolVar(&admin, "admin", false, "Assign admin privileges to the identity. No policy must be set")
	cmd.DurationVar(&ttl, "ttl", 0, "The identity's time-to-live after which it expires")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity of --help'", err)
	}
	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}
	if policyName != "" && admin {
		cli.Fatal("cannot create an identity with admin privileges and a policy")
	}

	identity := kes.Identity(cmd.Arg(0))
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := enclave.CreateIdentity(ctx, identity, &kes.CreateIdentityRequest{
		Policy: policyName,
		Admin:  admin,
		TTL:    ttl,
	}); err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create identity '%s': %v", identity, err)
	}
}

const describeIdentityCmdUsage = `Usage:
    kes identity info [options] [<identity>...]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show metadata about the identity of '$KES_API_KEY' resp. '$KES_CLIENT_CERT'.
     $ kes identity info

  2. Show metadata about the identity '3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22' within the enclave 'tenant-1'
    $ kes identity info --enclave tenant-1 3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
`

func describeIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeIdentityCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity info --help'", err)
	}

	const ColorName tui.Color = "#2283f3"
	nameColor := tui.NewStyle().Foreground(ColorName)

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if cmd.NArg() == 0 {
		info, policy, err := enclave.DescribeSelf(ctx)
		if err != nil {
			cli.Fatalf("failed to fetch identity metadata: %v", err)
		}
		cancel()

		if jsonFlag {
			encoder := json.NewEncoder(os.Stdout)
			if isTerm(os.Stdout) {
				encoder.SetIndent("", "  ")
			}
			if err = encoder.Encode(info); err != nil {
				cli.Fatalf("failed to encode identity metadata: %v", err)
			}
			return
		}

		var buf cli.Buffer
		buf.Stylef(nameColor, "Identity : %s", info.Identity).Sprintln()
		if info.IsAdmin {
			buf.Sprintln("Admin    :", "yes")
		} else {
			buf.Sprintln("Admin    :", "no")
		}
		if !info.CreatedAt.IsZero() {
			year, month, day := info.CreatedAt.Date()
			hour, min, sec := info.CreatedAt.Clock()
			zone, _ := info.CreatedAt.Zone()
			buf.Sprintf("Date     : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		}
		if info.TTL > 0 {
			buf.Sprintln("TTL      :", info.TTL.String())
		}
		if !info.ExpiresAt.IsZero() {
			year, month, day := info.ExpiresAt.Date()
			hour, min, sec := info.ExpiresAt.Clock()
			zone, _ := info.ExpiresAt.Zone()
			buf.Sprintf("Expires  : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		}
		if !info.CreatedBy.IsUnknown() {
			buf.Sprintln("Parent   :", info.CreatedBy)
		}
		if info.Policy != "" {
			buf.Sprintln("Policy   :", info.Policy)
		}
		if policy != nil {
			if allow := maps.Keys(policy.Allow); len(allow) > 0 {
				sort.Strings(allow)
				buf.Sprintln("Allow    {")
				for _, pattern := range allow {
					buf.Sprintf("           \"%s\",", pattern).Sprintln()
				}
				buf.Sprintln("}")
			}
			if deny := maps.Keys(policy.Deny); len(deny) > 0 {
				sort.Strings(deny)
				buf.Sprintln("Deny     {")
				for _, pattern := range deny {
					buf.Sprintf("           \"%s\",", pattern).Sprintln()
				}
				buf.Sprintln("}")
			}
		}
		cli.Print(buf.String())
		return
	}

	identities := make(map[kes.Identity]*kes.IdentityInfo, len(cmd.Args()))
	for _, arg := range cmd.Args() {
		info, err := enclave.DescribeIdentity(ctx, kes.Identity(arg))
		if err != nil {
			cli.Fatalf("failed to fetch identity metadata: %v", err)
		}
		identities[kes.Identity(arg)] = info
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if len(identities) == 1 {
			for _, info := range identities {
				if err := encoder.Encode(info); err != nil {
					cli.Fatalf("failed to encode identity metadata: %v", err)
				}
			}
			return
		}
		if err := encoder.Encode(identities); err != nil {
			cli.Fatalf("failed to encode identity metadata: %v", err)
		}
		return
	}

	var buf cli.Buffer
	for i, arg := range cmd.Args() {
		info := identities[kes.Identity(arg)]

		buf.Stylef(nameColor, "Identity : %s", info.Identity).Sprintln()
		if info.IsAdmin {
			buf.Sprintln("Admin    :", "yes")
		} else {
			buf.Sprintln("Admin    :", "no")
		}
		if !info.CreatedAt.IsZero() {
			year, month, day := info.CreatedAt.Date()
			hour, min, sec := info.CreatedAt.Clock()
			zone, _ := info.CreatedAt.Zone()
			buf.Sprintf("Date     : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		}
		if info.TTL > 0 {
			buf.Sprintln("TTL      :", info.TTL.String())
		}
		if !info.ExpiresAt.IsZero() {
			year, month, day := info.ExpiresAt.Date()
			hour, min, sec := info.ExpiresAt.Clock()
			zone, _ := info.ExpiresAt.Zone()
			buf.Sprintf("Expires  : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		}
		if !info.CreatedBy.IsUnknown() {
			buf.Sprintln("Parent   :", info.CreatedBy)
		}
		if info.Policy != "" {
			buf.Sprintln("Policy   :", info.Policy)
		}
		if i < len(cmd.Args())-1 {
			buf.Sprintln()
		}
	}
	cli.Print(buf.String())
}

const lsIdentityCmdUsage = `Usage:
    kes identity ls [options] [<prefix>]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. List all identites within the enclave $KES_ENCLAVE.
     $ kes identity ls
	
  2. List all identities starting with '2a' within the enclave 'tenant-1'.
    $ kes identity ls --enclave tenant-1 2a
`

func lsIdentityCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsIdentityCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes identity ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes identity ls --help'")
	}

	prefix := ""
	if cmd.NArg() == 1 {
		prefix = cmd.Arg(0)
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	iter := kes.ListIter[kes.Identity]{
		NextFunc: enclave.ListIdentities,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	var ids []kes.Identity
	for id, err := iter.SeekTo(ctx, prefix); err != io.EOF; id, err = iter.Next(ctx) {
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to list identities: %v", err)
		}
		ids = append(ids, id)
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(ids); err != nil {
			cli.Fatalf("failed to list identites: %v", err)
		}
		return
	}

	if len(ids) == 0 {
		return
	}
	var buf cli.Buffer
	if isTerm(os.Stdout) {
		buf.Styleln(tui.NewStyle().Underline(true).Bold(true), "Identities")
	}
	for _, id := range ids {
		buf.Sprintln(id)
	}
	cli.Print(buf.String())
}

const rmIdentityCmdUsage = `Usage:
    kes identity rm <identity>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Delete the identity within the enclave $KES_ENCLAVE.
     $ kes identity rm 736bf58626441e3e134a2daf2e6a8441b40e1abc0eac510878168c8aac9f2b0b

  2. Delete the identities within the enclave 'tenant-1'.
     $ kes identity rm --enclave tenant-1 736bf58626441e3e134a2daf2e6a8441b40e1abc0eac510878168c8aac9f2b0b \
           2da20af736148bbae7fbd3ad191f055ff44056834c22fdcd43ad36f49f187f50
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
