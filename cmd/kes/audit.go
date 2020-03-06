package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
)

const auditCmdUsage = `usage: %s <command>

    trace              Trace the audit log output.

  -h, --help           Show list of command-line options.
`

func audit(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), auditCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "trace":
		return auditTrace(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}

const auditTraceCmdUsage = `Trace and print audit log events.

Connects to a KES server as audit log device and print an audit
log event for each request/response pair processed by the server.
It will print the audit log events as readable text representation
when writing to a tty. Otherwise it will print events as
line-separated JSON (nd-json)

usage: %s [flags]

  --json               Print audit log events as JSON.

  -k, --insecure       Skip X.509 certificate validation during TLS handshake.

  -h, --help           Show list of command-line options.
`

func auditTrace(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), auditTraceCmdUsage, cli.Name())
	}

	var jsonOutput bool
	var insecureSkipVerify bool
	cli.BoolVar(&jsonOutput, "json", false, "Print audit log events as JSON")
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 0 {
		cli.Usage()
		os.Exit(2)
	}

	certificates, err := loadClientCertificates()
	if err != nil {
		return err
	}
	client := kes.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       certificates,
	})

	reader, err := client.TraceAuditLog()
	if err != nil {
		return err
	}
	defer reader.Close()

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if err := reader.Close(); err != nil {
			fmt.Fprintln(cli.Output(), err)
		}
	}()

	type AuditEntry struct {
		Time    time.Time `json:"time"`
		Request struct {
			Path     string       `json:"path"`
			Identity kes.Identity `json:"identity"`
		} `json:"request"`
		Response struct {
			Code int           `json:"code"`
			Time time.Duration `json:"time"`
		} `json:"response"`
	}

	isTerminal := isTerm(os.Stdout)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if err = scanner.Err(); err != nil {
			return err
		}
		if isTerminal && !jsonOutput {
			var entry AuditEntry
			if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				return err
			}
			if len(entry.Request.Identity) > 7 { // only show a short identity - similar to git commits
				entry.Request.Identity = entry.Request.Identity[:7]
			}

			var status string
			var identity string
			if runtime.GOOS == "windows" { // don't colorize on windows
				status = fmt.Sprintf("[%d %s]", entry.Response.Code, http.StatusText(entry.Response.Code))
				identity = entry.Request.Identity.String()
			} else {
				if entry.Response.Code == http.StatusOK {
					status = color.GreenString("[%d %s]", entry.Response.Code, http.StatusText(entry.Response.Code))
				} else {
					status = color.RedString("[%d %s]", entry.Response.Code, http.StatusText(entry.Response.Code))
				}
				identity = color.YellowString(entry.Request.Identity.String())
			}

			// Truncate duration values such that we show reasonable
			// time values - like 1.05s or 345.76ms.
			respTime := entry.Response.Time
			switch {
			case respTime >= time.Second:
				respTime = respTime.Truncate(10 * time.Millisecond)
			case respTime >= time.Millisecond:
				respTime = respTime.Truncate(10 * time.Microsecond)
			default:
				respTime = respTime.Truncate(time.Microsecond)
			}

			const format = "%s %s %-25s %10s\n"
			fmt.Printf(format, identity, status, entry.Request.Path, respTime)
		} else {
			fmt.Println(scanner.Text())
		}
	}
	return nil
}
