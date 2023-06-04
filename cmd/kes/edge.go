package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const edgeCmdUsage = `Usage:
    kes edge [options] <FILE>

Options:
    --addr <[IP]:PORT>       The network interface the KES edge server will listen on.
                             The default is '0.0.0.0:7373', causing KES to listen on
                             all available network interfaces.
	
    -h, --help               Show list of command-line options


KES is a cloud-native distributed key management and encryption server.
It can either run as stateless edge node in front of a central KMS or
as stateful high performance KMS cluster.
	
    Quick Start: https://github.com/minio/kes#quick-start
    Docs:        https://github.com/minio/kes/wiki
    
Examples:
  1. Start a stateless KES edge server that uses Hashicorp Vault as keystore:
     $ kes edge ~/vault-config.yml

  2. Start a stateless KES edge server that uses AWS SecretsManager as keystore:
     $ kes edge ~/aws-config.yml

License:
   Copyright:  MinIO, Inc.
   GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
`

func edgeCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, edgeCmdUsage) }

	var addrFlag string
	cmd.StringVar(&addrFlag, "addr", "", "The network interface the KES edge server listens on. Default: 0.0.0.0:7373")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes server --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		os.Exit(1)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}
	startEdgeServer(cmd.Arg(0), addrFlag)
}
