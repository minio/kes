package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `usage: %s <command>

    server               Start a key server.

    create               Create a new master key at a key server.
    delete               Delete a master key from a key server.

    gen                  Generate a new data key from a master key.
    dec                  Decrypt a encrypted data key using a master key.

    identify             Compute the identity of a TLS certificate.
    identity             Assign policies to identities.
    policy               Manage the key server policies.

  -h, --help             Show this list of command line optios.
`

func main() {
	cli := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), usage, cli.Name())
	}
	cli.Parse(os.Args[1:])

	args := cli.Args()
	if len(args) < 1 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "server":
		server(args)
	case "create":
		createKey(args)
	case "delete":
		deleteKey(args)
	case "gen":
		generateKey(args)
	case "dec":
		decryptKey(args)
	case "identify":
		identify(args)
	case "identity":
		identity(args)
	case "policy":
		policy(args)
	default:
		cli.Usage()
		os.Exit(2)
	}
}

func failf(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, format, args...)
	os.Exit(1)
}
