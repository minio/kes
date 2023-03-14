// This file is part of MinIO KES
// Copyright (c) 2023 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package restapi

import (
	"crypto/x509"
	"os"
	"strconv"
	"strings"

	xcerts "github.com/minio/pkg/certs"
)

var (
	// Port console default port
	Port = "9393"

	// Hostname console hostname
	// avoid listening on 0.0.0.0 by default
	// instead listen on all IPv4 and IPv6
	// - Hostname should be empty.
	Hostname = ""

	// TLSPort console tls port
	TLSPort = "9494"

	// TLSRedirect console tls redirect rule
	TLSRedirect = "on"
)

var (
	// GlobalRootCAs is CA root certificates, a nil value means system certs pool will be used
	GlobalRootCAs *x509.CertPool
	// GlobalPublicCerts has certificates Console will use to serve clients
	GlobalPublicCerts []*x509.Certificate
	// GlobalTLSCertsManager custom TLS Manager for SNI support
	GlobalTLSCertsManager *xcerts.Manager
)

func getEnv(env string, fallbackValue string) string {
	val := os.Getenv(env)
	if val == "" {
		return fallbackValue
	}
	return val
}

// GetHostname gets console hostname set on env variable,
// default one or defined on run command
func GetHostname() string {
	return strings.ToLower(getEnv(ConsoleHostname, Hostname))
}

// GetPort gets console por set on env variable
// or default one
func GetPort() int {
	port, err := strconv.Atoi(getEnv(ConsolePort, Port))
	if err != nil {
		port = 9090
	}
	return port
}

// GetTLSPort gets console tls port set on env variable
// or default one
func GetTLSPort() int {
	port, err := strconv.Atoi(getEnv(ConsoleTLSPort, TLSPort))
	if err != nil {
		port = 9443
	}
	return port
}

// GetTLSRedirect if set to true, then only allow HTTPS requests. Default is true.
func GetTLSRedirect() string {
	return strings.ToLower(getEnv(ConsoleSecureTLSRedirect, TLSRedirect))
}
