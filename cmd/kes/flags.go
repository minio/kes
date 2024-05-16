// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

// Use register functions for common flags exposed by
// many commands. Common flags should have common names
// to make command usage consistent.

// flagsInsecureSkipVerify adds a bool flag '-k, --insecure'
// that sets insecureSkipVerify to true if provided on the
// command line.
func flagsInsecureSkipVerify(f *flag.FlagSet, insecureSkipVerify *bool) {
	f.BoolVarP(insecureSkipVerify, "insecure", "k", false, "Skip server certificate verification")
}

func flagsAPIKey(f *flag.FlagSet, apiKey *string) {
	f.StringVarP(apiKey, "api-key", "a", cli.Env(cli.EnvAPIKey), "API key to authenticate to the KES server")
}

func flagsOutputJSON(f *flag.FlagSet, jsonOutput *bool) {
	f.BoolVar(jsonOutput, "json", false, "Print output in JSON format")
}

func flagsServer(f *flag.FlagSet, host *string) {
	f.StringVarP(host, "server", "s", cli.Env(cli.EnvServer), "Use the server HOST[:PORT]")
}
