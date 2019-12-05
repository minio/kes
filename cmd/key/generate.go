package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/aead/key"
)

const generateCmdUsage = `usage: %s name [context]

  --tls-skip-verify    Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func generateKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), generateCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "tls-skip-verify", false, "Skip X.509 certificate validation during TLS handshake")

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) != 1 && len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	var (
		name    string = args[0]
		context []byte
	)
	if len(args) == 2 {
		b, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			failf(cli.Output(), "Invalid context: %s", err.Error())
		}
		context = b
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       loadClientCertificates(),
	})
	plaintext, ciphertext, err := client.GenerateDataKey(name, context)
	if err != nil {
		failf(cli.Output(), "Failed to generate data key: %s", err.Error())
	}

	if isTerm(os.Stdout) {
		fmt.Println("{")
		fmt.Printf("  plaintext : %s\n", base64.StdEncoding.EncodeToString(plaintext))
		fmt.Printf("  ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
		fmt.Println("}")
	} else {
		const format = `{"plaintext":"%s","ciphertext":"%s"}`
		fmt.Printf(format, base64.StdEncoding.EncodeToString(plaintext), base64.StdEncoding.EncodeToString(ciphertext))
	}
}
