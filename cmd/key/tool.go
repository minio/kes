// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
)

const toolCmdUsage = `usage: %s <command>
  
  identity             Identity management tools.

  -h, --help           Show list of command-line options
`

func tool(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), toolCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "identity":
		toolIdentity(args)
	default:
		cli.Usage()
		os.Exit(2)
	}
}
