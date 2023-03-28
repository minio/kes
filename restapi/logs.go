// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
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
//

package restapi

import (
	"errors"
	"log"
	"os"

	flag "github.com/spf13/pflag"
)

var (
	infoLog  = log.New(os.Stdout, "I: ", log.LstdFlags)
	errorLog = log.New(os.Stdout, "E: ", log.LstdFlags)
)

func logInfo(msg string, data ...interface{}) {
	infoLog.Printf(msg+"\n", data...)
}

func logError(msg string, data ...interface{}) {
	errorLog.Printf(msg+"\n", data...)
}

// globally changeable logger styles
var (
	LogInfo  = logInfo
	LogError = logError
)

// Context captures all command line flags values
type Context struct {
	Host                string
	HTTPPort, HTTPSPort int
	TLSRedirect         string
	// Legacy options, TODO: remove in future
	TLSCertificate, TLSKey, TLSca string
}

// Load loads restapi Context from command line context.
func (c *Context) Load(cmd *flag.FlagSet) error {
	host, err := cmd.GetString("host")
	if err != nil {
		return err
	}
	httpPort, err := cmd.GetInt("port")
	if err != nil {
		return err
	}
	httpsPort, err := cmd.GetInt("tls-port")
	if err != nil {
		return err
	}
	tlsRedirect, err := cmd.GetString("tls-redirect")
	if err != nil {
		return err
	}

	*c = Context{
		Host:        host,
		HTTPPort:    httpPort,
		HTTPSPort:   httpsPort,
		TLSRedirect: tlsRedirect,
	}
	if c.HTTPPort > 65535 {
		return errors.New("invalid argument --port out of range - ports can range from 1-65535")
	}
	if c.HTTPSPort > 65535 {
		return errors.New("invalid argument --tls-port out of range - ports can range from 1-65535")
	}
	if c.TLSRedirect != "on" && c.TLSRedirect != "off" {
		return errors.New("invalid argument --tls-redirect only accepts either 'on' or 'off'")
	}
	return nil
}
