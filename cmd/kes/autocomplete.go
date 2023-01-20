// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/minio/kes/internal/cli"
)

func complete(cmd string) bool {
	shell, ok := os.LookupEnv("SHELL")
	if !ok {
		return false
	}
	if !strings.HasSuffix(shell, "zsh") && !strings.HasSuffix(shell, "bash") {
		return false
	}
	line, ok := os.LookupEnv("COMP_LINE")
	if !ok {
		return false
	}

	completion := map[string][]string{
		cmd:             {"server", "init", "enclave", "key", "policy", "identity", "log", "status", "metric", "update"},
		cmd + " server": {"--config", "--addr", "--auth"},
		cmd + " init":   {"--config", "--force"},
		cmd + " log":    {"--audit", "--error", "--json", "--insecure"},
		cmd + " status": {"--short", "--api", "--json", "--color", "--insecure"},
		cmd + " metric": {"--rate", "--insecure"},
		cmd + " update": {"--downgrade", "--output", "--os", "--arch", "--minisign-key", "--insecure"},

		cmd + " enclave":        {"create", "info", "rm"},
		cmd + " enclave create": {"--insecure"},
		cmd + " enclave info":   {"--insecure", "--json", "--color"},
		cmd + " enclave rm":     {"--insecure"},

		cmd + " key":         {"create", "import", "info", "ls", "rm", "encrypt", "decrypt", "dek"},
		cmd + " key create":  {"--enclave", "--insecure"},
		cmd + " key import":  {"--enclave", "--insecure"},
		cmd + " key info":    {"--enclave", "--insecure", "--json", "--color"},
		cmd + " key ls":      {"--enclave", "--insecure", "--json", "--color"},
		cmd + " key rm":      {"--enclave", "--insecure"},
		cmd + " key encrypt": {"--enclave", "--insecure"},
		cmd + " key decrypt": {"--enclave", "--insecure"},
		cmd + " key dek":     {"--enclave", "--insecure"},

		cmd + " policy":        {"create", "assign", "info", "ls", "rm", "show"},
		cmd + " policy create": {"--enclave", "--insecure"},
		cmd + " policy assign": {"--enclave", "--insecure"},
		cmd + " policy info":   {"--enclave", "--insecure", "--json", "--color"},
		cmd + " policy ls":     {"--enclave", "--insecure", "--json", "--color"},
		cmd + " policy rm":     {"--enclave", "--insecure"},
		cmd + " policy show":   {"--enclave", "--insecure", "--json"},

		cmd + " identity":      {"new", "of", "info", "ls", "rm"},
		cmd + " identity new":  {"--key", "--cert", "--force", "--ip", "--dns", "--expiry", "--encrypt"},
		cmd + " identity of":   {},
		cmd + " identity info": {"--enclave", "--insecure", "--json", "--color"},
		cmd + " identity ls":   {"--enclave", "--insecure", "--json", "--color"},
		cmd + " identity rm":   {"--enclave", "--insecure"},
	}

	fields := strings.Fields(line)
	cmds := make([]string, 0, len(fields))
	for _, field := range fields {
		if !strings.HasPrefix(field, "-") {
			cmds = append(cmds, field)
		}
	}
	line = strings.Join(cmds, " ")

	var match string
	for key := range completion {
		if strings.HasPrefix(line, key) && len(key) > len(match) {
			match = key
		}
	}
	if candidates, ok := completion[match]; ok {
		line = strings.TrimSpace(strings.TrimPrefix(line, match))
		for _, candidate := range candidates {
			if strings.HasPrefix(candidate, line) {
				fmt.Println(candidate)
			}
		}
	}
	return true
}

func installAutoCompletion() {
	if runtime.GOOS == "windows" {
		cli.Fatal("auto-completion is not available for windows")
	}

	shell, ok := os.LookupEnv("SHELL")
	if !ok {
		cli.Fatal("failed to detect shell. The env variable $SHELL is not defined")
	}

	var filename string
	switch {
	case strings.HasSuffix(shell, "zsh"):
		filename = ".zshrc"
	case strings.HasSuffix(shell, "bash"):
		filename = ".bashrc"
	default:
		cli.Fatalf("auto-completion for '%s' is not available", shell)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		cli.Fatalf("failed to detect home directory: %v")
	}
	if home == "" {
		home = "~"
	}
	filename = filepath.Join(home, filename)

	binaryPath, err := os.Executable()
	if err != nil {
		cli.Fatalf("failed to detect binary path: %v")
	}
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		cli.Fatalf("failed to turn binary path into an absolute path: %v")
	}

	var (
		autoloadCmd = "autoload -U +X bashcompinit && bashcompinit"
		completeCmd = fmt.Sprintf("complete -o default -C %s %s", binaryPath, os.Args[0])
	)
	hasAutoloadLine, hasCompleteLine := isCompletionInstalled(filename, autoloadCmd, completeCmd)
	if hasAutoloadLine && hasCompleteLine {
		cli.Println("Completion is already installed.")
		return
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_SYNC, 0o600)
	if err != nil {
		cli.Fatal(err)
	}
	defer file.Close()

	if !hasAutoloadLine {
		if _, err = file.WriteString(autoloadCmd + "\n"); err != nil {
			cli.Fatalf("failed to add '%s' to '%s': %v", autoloadCmd, filename, err)
		}
	}
	if !hasCompleteLine {
		if _, err = file.WriteString(completeCmd + "\n"); err != nil {
			cli.Fatalf("failed to add '%s' to '%s': %v", completeCmd, filename, err)
		}
	}
	if err = file.Close(); err != nil {
		cli.Fatal(err)
	}

	cli.Printf("Added completion to '%s'\n", filename)
	cli.Println()
	cli.Printf("To uninstall completion remove the following lines from '%s':\n", filename)
	if !hasAutoloadLine {
		cli.Println("  ", autoloadCmd)
	}
	if !hasCompleteLine {
		cli.Println("  ", completeCmd)
	}
}

func isCompletionInstalled(filename, autoloadCmd, completeCmd string) (autoload, complete bool) {
	file, err := os.Open(filename)
	if err != nil {
		cli.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), autoloadCmd) {
			autoload = true
		}
		if strings.HasPrefix(scanner.Text(), completeCmd) {
			complete = true
		}
	}
	if err = scanner.Err(); err != nil {
		cli.Fatalf("failed to read '%s': %v", filename, err)
	}
	if err = file.Close(); err != nil {
		cli.Fatal(err)
	}
	return
}
