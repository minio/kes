package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/aead/key"
)

const decryptCmdUsage = `usage: %s <name> <ciphertext> [<context>]

`

func decryptKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), decryptCmdUsage, cli.Name())
	}
	cli.Parse(args[1:])

	if args = cli.Args(); len(args) != 2 && len(args) != 3 {
		cli.Usage()
		os.Exit(2)
	}

	var (
		name       string = args[0]
		ciphertext []byte
		context    []byte
		err        error
	)
	ciphertext, err = base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		failf(cli.Output(), "Invalid ciphertext: %s", err.Error())
	}
	if len(args) == 3 {
		context, err = base64.StdEncoding.DecodeString(args[2])
		if err != nil {
			failf(cli.Output(), "Invalid context: %s", err.Error())
		}
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       loadClientCertificates(),
	})
	plaintext, err := client.DecryptDataKey(name, ciphertext, context)
	if err != nil {
		failf(cli.Output(), "Failed to decrypt data key: %s", err.Error())
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\n  plaintext: %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		fmt.Printf(`{"plaintext":"%s"}`, base64.StdEncoding.EncodeToString(plaintext))
	}
}
