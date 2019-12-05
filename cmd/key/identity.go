package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/aead/key"
)

const identityCmdUsage = `usage: %s <command>
  
  assign               Assign a policy to an identity such that the policy
                       applies to the identity.
  list                 List all identities present at the key server.
  forget               Forget an identity such that no policy applies to it.

  -h, --help           Show list of command-line options
`

func identity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), identityCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "assign":
		assignIdentity(args)
	case "list":
		listIdentity(args)
	case "forget":
		forgetIdentity(args)
	default:
		cli.Usage()
		os.Exit(2)
	}
}

const assignIdentityCmdUsage = `usage: %s <identity> <policy>

  --tls-skip-verify    Skip X.509 certificate validation during TLS handshake  

  -h, --help           Show list of command-line options
`

func assignIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), assignIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "tls-skip-verify", false, "Skip X.509 certificate validation during TLS handshake")

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       loadClientCertificates(),
	})
	if err := client.AssignIdentity(args[1], key.Identity(args[0])); err != nil {
		failf(cli.Output(), "Failed to assign policy '%s' to '%s': %v", args[1], args[0], err)
	}
}

const listIdentityCmdUsage = `usage: %s [<pattern>]

  --tls-skip-verify    Skip X.509 certificate validation during TLS handshake  

  -h, --help           Show list of command-line options
`

func listIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), listIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "tls-skip-verify", false, "Skip X.509 certificate validation during TLS handshake")

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) > 1 {
		cli.Usage()
		os.Exit(2)
	}
	pattern := "*"
	if len(args) == 1 {
		pattern = args[0]
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       loadClientCertificates(),
	})
	identityRoles, err := client.ListIdentities(pattern)
	if err != nil {
		failf(cli.Output(), "Cannot list identities: %v", err)
	}
	identities := make([]string, 0, len(identityRoles))
	for id := range identityRoles {
		identities = append(identities, id.String())
	}
	sort.Strings(identities)

	if isTerm(os.Stdout) {
		fmt.Println("{")
		for _, id := range identities {
			fmt.Printf("  %s => %s\n", id, identityRoles[key.Identity(id)])
		}
		fmt.Println("}")
	} else {
		fmt.Print("{")
		for i, id := range identities {
			if i < len(identities)-1 {
				fmt.Printf(`"%s":"%s",`, id, identityRoles[key.Identity(id)])
			} else {
				fmt.Printf(`"%s":"%s"`, id, identityRoles[key.Identity(id)])
			}
		}
		fmt.Print("}")
	}
}

const forgetIdentityCmdUsage = `usage: %s <identity>

  --tls-skip-verify    Skip X.509 certificate validation during TLS handshake  
  
  -h, --help           Show list of command-line options
`

func forgetIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), forgetIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "tls-skip-verify", false, "Skip X.509 certificate validation during TLS handshake")

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) != 1 {
		cli.Usage()
		os.Exit(2)
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       loadClientCertificates(),
	})
	if err := client.ForgetIdentity(key.Identity(args[0])); err != nil {
		failf(cli.Output(), "Cannot forget '%s': %v", args[0], err)
	}
}
