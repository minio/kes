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
//

package restapi

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"

	"github.com/go-openapi/runtime/middleware"

	"github.com/minio/kes/models"
	"github.com/minio/kes/restapi/operations"
	"github.com/minio/kes/restapi/operations/auth"
)

//go:generate swagger generate server --target ../../kes --name Kes --spec ../swagger.yaml --principal models.Principal --exclude-main

func configureFlags(api *operations.KesAPI) {
	// api.CommandLineOptionsGroups = []swag.CommandLineOptionsGroup{ ... }
}

func configureAPI(api *operations.KesAPI) http.Handler {
	// configure the api here
	api.ServeError = errors.ServeError

	// Set your custom logger if needed. Default one is log.Printf
	// Expected interface func(string, ...interface{})
	//
	// Example:
	// api.Logger = log.Printf

	api.UseSwaggerUI()
	// To continue using redoc as your UI, uncomment the following line
	// api.UseRedoc()

	api.JSONConsumer = runtime.JSONConsumer()

	api.JSONProducer = runtime.JSONProducer()

	api.KeyAuth = func(token string, scopes []string) (*models.Principal, error) {
		invalidSession := fmt.Errorf("invalid session")
		token = strings.TrimSpace(token)
		data, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			return nil, invalidSession
		}
		content := strings.Split(string(data), "||")
		if len(content) != 3 {
			return nil, invalidSession
		}
		clientCertificate := content[0]
		clientKey := content[1]
		insecure := content[2]
		_, err = tls.X509KeyPair([]byte(clientCertificate), []byte(clientKey))
		if err != nil {
			return nil, invalidSession
		}
		return &models.Principal{
			ClientCertificate: clientCertificate,
			ClientKey:         clientKey,
			Insecure:          insecure == "true",
		}, nil
	}

	// Set your custom authorizer if needed. Default one is security.Authorized()
	// Expected interface runtime.Authorizer
	//
	// Example:
	// api.APIAuthorizer = security.Authorized()

	api.AuthSessionCheckHandler = auth.SessionCheckHandlerFunc(func(params auth.SessionCheckParams, principal *models.Principal) middleware.Responder {
		return auth.NewSessionCheckOK()
	})

	registerLoginHandlers(api)
	registerEncryptionHandlers(api)

	api.PreServerShutdown = func() {}

	api.ServerShutdown = func() {}

	return setupGlobalMiddleware(api.Serve(setupMiddlewares))
}

// The TLS configuration before HTTPS server starts.
func configureTLS(tlsConfig *tls.Config) {
	// Make all necessary changes to the TLS configuration here.
}

// As soon as server is initialized but not run yet, this function will be called.
// If you need to modify a config, store server instance to stop it individually later, this is the place.
// This function can be called multiple times, depending on the number of serving schemes.
// scheme value will be set accordingly: "http", "https" or "unix".
func configureServer(s *http.Server, scheme, addr string) {
}

// The middleware configuration is for the handler executors. These do not apply to the swagger.json document.
// The middleware executes after routing but before authentication, binding and validation.
func setupMiddlewares(handler http.Handler) http.Handler {
	return handler
}

// The middleware configuration happens before anything, this middleware also applies to serving the swagger.json document.
// So this is a good place to plug in a panic handling middleware, logging and metrics.
func setupGlobalMiddleware(handler http.Handler) http.Handler {
	next := AuthenticationMiddleware(handler)
	return next
}

func AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCookie, _ := r.Cookie(CookieName)
		var token string
		if tokenCookie != nil {
			token = tokenCookie.Value
		}
		r.Header.Add("Authorization", fmt.Sprintf("Bearer  %s", token))
		next.ServeHTTP(w, r)
	})
}
