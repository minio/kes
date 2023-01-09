// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/go-openapi/loads"
	"github.com/jessevdk/go-flags"
	"github.com/minio/kes/restapi"
	"github.com/minio/kes/restapi/certs"
	"github.com/minio/kes/restapi/operations"
	flag "github.com/spf13/pflag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const uiCmdUsage = `Usage:
    kes ui [options]

Options:
    --host value             Bind to a specific HOST, HOST can be an IP or hostname
    --port value             Bind to specific HTTP port (default: 9090)
    --certs-dir value        Path to certs directory (default: "/Users/<home>/.kes/certs/CAs")
    --tls-port value         Bind to specific HTTPS port (default: 9443)
    --tls-redirect value     Toggle HTTP->HTTPS redirect (default: "on")
    --help, -h               Show help

Starts a KES UI server. The server address can be specified in the config file but
may be overwritten by the --addr flag. If omitted the IP defaults to 0.0.0.0 and
the PORT to 9393.

The client TLS verification can be disabled by setting --auth=off. The server then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ kes server --config config.yml --auth =off
`

// starts the server
func uiCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, uiCmdUsage) }

	var (
		hostFlag        string
		portFlag        int
		tlsHostFlag     string
		certsDirFlag    string
		tlsPortFlag     int
		tlsRedirectFlag string
		tlsCertFlag     string
		tlsKeyFlag      string
		tlsCAFlag       string
	)
	cmd.StringVar(&hostFlag, "host", restapi.GetHostname(), "bind to a specific HOST, HOST can be an IP or hostname")
	cmd.IntVar(&portFlag, "port", restapi.GetPort(), "bind to specific HTTP port")
	cmd.StringVar(&tlsHostFlag, "tls-host", restapi.GetHostname(), "")
	cmd.StringVar(&certsDirFlag, "certs-dir", certs.GlobalCertsCADir.Get(), "path to certs directory")
	cmd.IntVar(&tlsPortFlag, "tls-port", restapi.GetTLSPort(), "bind to specific HTTPS port")
	cmd.StringVar(&tlsRedirectFlag, "tls-redirect", restapi.GetTLSRedirect(), "toggle HTTP->HTTPS redirect")
	cmd.StringVar(&tlsCertFlag, "tls-certificate", "", "path to TLS public certificate")
	cmd.StringVar(&tlsKeyFlag, "tls-key", "", "path to TLS private key")
	cmd.StringVar(&tlsCAFlag, "tls-ca", "", "path to TLS Certificate Authority")

	// Load all certificates
	if err := loadAllCerts(cmd); err != nil {
		// Log this as a warning and continue running console without TLS certificates
		log.Printf("Unable to load certs: %v \n", err)
	}

	var rctx restapi.Context
	if err := rctx.Load(cmd); err != nil {
		restapi.LogError("argument validation failed: %v", err)
		return
	}

	server, err := buildServer()
	if err != nil {
		restapi.LogError("Unable to initialize console server: %v", err)
		return
	}

	server.Host = rctx.Host
	server.Port = rctx.HTTPPort
	// set conservative timesout for uploads
	server.ReadTimeout = 1 * time.Hour
	// no timeouts for response for downloads
	server.WriteTimeout = 0
	restapi.Port = strconv.Itoa(server.Port)
	restapi.Hostname = server.Host

	if len(restapi.GlobalPublicCerts) > 0 {
		// If TLS certificates are provided enforce the HTTPS schema, meaning console will redirect
		// plain HTTP connections to HTTPS server
		server.EnabledListeners = []string{"http", "https"}
		server.TLSPort = rctx.HTTPSPort
		// Need to store tls-port, tls-host un config variables so secure.middleware can read from there
		restapi.TLSPort = strconv.Itoa(server.TLSPort)
		restapi.Hostname = rctx.Host
		restapi.TLSRedirect = rctx.TLSRedirect
	}

	defer server.Shutdown()

	server.Serve()

}

func buildServer() (*restapi.Server, error) {
	swaggerSpec, err := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
	if err != nil {
		return nil, err
	}

	api := operations.NewKesAPI(swaggerSpec)
	api.Logger = restapi.LogInfo
	server := restapi.NewServer(api)

	parser := flags.NewParser(server, flags.Default)
	parser.ShortDescription = "MinIO Console Server"
	parser.LongDescription = swaggerSpec.Spec().Info.Description

	server.ConfigureFlags()

	// register all APIs
	server.ConfigureAPI()

	for _, optsGroup := range api.CommandLineOptionsGroups {
		_, err := parser.AddGroup(optsGroup.ShortDescription, optsGroup.LongDescription, optsGroup.Options)
		if err != nil {
			return nil, err
		}
	}

	if _, err := parser.Parse(); err != nil {
		return nil, err
	}

	return server, nil
}

func loadAllCerts(cmd *flag.FlagSet) error {
	var err error
	// Set all certs and CAs directories path
	certs.GlobalCertsDir, _, err = certs.NewConfigDirFromCtx(cmd, "certs-dir", certs.DefaultCertsDir.Get)
	if err != nil {
		return err
	}

	certs.GlobalCertsCADir = &certs.ConfigDir{Path: filepath.Join(certs.GlobalCertsDir.Get(), certs.CertsCADir)}
	// check if certs and CAs directories exists or can be created
	if err = certs.MkdirAllIgnorePerm(certs.GlobalCertsCADir.Get()); err != nil {
		return fmt.Errorf("unable to create certs CA directory at %s: failed with %w", certs.GlobalCertsCADir.Get(), err)
	}

	// load the certificates and the CAs
	restapi.GlobalRootCAs, restapi.GlobalPublicCerts, restapi.GlobalTLSCertsManager, err = certs.GetAllCertificatesAndCAs()
	if err != nil {
		return fmt.Errorf("unable to load certificates at %s: failed with %w", certs.GlobalCertsDir.Get(), err)
	}

	{
		// TLS flags from swagger server, used to support VMware vsphere operator version.
		swaggerServerCertificate, err := cmd.GetString("tls-certificate")
		if err != nil {
			return err
		}
		swaggerServerCertificateKey, err := cmd.GetString("tls-key")
		if err != nil {
			return err
		}
		swaggerServerCACertificate, err := cmd.GetString("tls-ca")
		if err != nil {
			return err
		}
		// load tls cert and key from swagger server tls-certificate and tls-key flags
		if swaggerServerCertificate != "" && swaggerServerCertificateKey != "" {
			if err = restapi.GlobalTLSCertsManager.AddCertificate(swaggerServerCertificate, swaggerServerCertificateKey); err != nil {
				return err
			}
			x509Certs, err := certs.ParsePublicCertFile(swaggerServerCertificate)
			if err == nil {
				restapi.GlobalPublicCerts = append(restapi.GlobalPublicCerts, x509Certs...)
			}
		}

		// load ca cert from swagger server tls-ca flag
		if swaggerServerCACertificate != "" {
			caCert, caCertErr := ioutil.ReadFile(swaggerServerCACertificate)
			if caCertErr == nil {
				restapi.GlobalRootCAs.AppendCertsFromPEM(caCert)
			}
		}
	}

	if restapi.GlobalTLSCertsManager != nil {
		restapi.GlobalTLSCertsManager.ReloadOnSignal(syscall.SIGHUP)
	}

	return nil
}
