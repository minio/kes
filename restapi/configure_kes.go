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
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"

	"github.com/go-openapi/runtime/middleware"
	webApp "github.com/minio/kes/web-app"
	"github.com/minio/pkg/env"
	"github.com/minio/pkg/mimedb"

	"github.com/minio/kes/models"
	"github.com/minio/kes/restapi/operations"
	"github.com/minio/kes/restapi/operations/auth"
)

const (
	SubPath = "CONSOLE_SUBPATH"
)

var (
	subPath     = "/"
	subPathOnce sync.Once
)

type notFoundRedirectRespWr struct {
	http.ResponseWriter // We embed http.ResponseWriter
	status              int
}

func (w *notFoundRedirectRespWr) WriteHeader(status int) {
	w.status = status // Store the status for our own use
	if status != http.StatusNotFound {
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *notFoundRedirectRespWr) Write(p []byte) (int, error) {
	if w.status != http.StatusNotFound {
		return w.ResponseWriter.Write(p)
	}
	return len(p), nil // Lie that we successfully wrote it
}

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

// FileServerMiddleware serves files from the static folder
func FileServerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "KES Console")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api"):
			next.ServeHTTP(w, r)
		default:
			buildFs, err := fs.Sub(webApp.GetStaticAssets(), "build")
			if err != nil {
				panic(err)
			}
			wrapHandlerSinglePageApplication(requestBounce(http.FileServer(http.FS(buildFs)))).ServeHTTP(w, r)
		}
	})
}

func requestBounce(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func wrapHandlerSinglePageApplication(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			handleSPA(w, r)
			return
		}

		w.Header().Set("Content-Type", mimedb.TypeByExtension(filepath.Ext(r.URL.Path)))
		nfw := &notFoundRedirectRespWr{ResponseWriter: w}
		h.ServeHTTP(nfw, r)
		if nfw.status == http.StatusNotFound {
			handleSPA(w, r)
		}
	}
}

// handleSPA handles the serving of the React Single Page Application
func handleSPA(w http.ResponseWriter, r *http.Request) {
	basePath := "/"
	// For SPA mode we will replace root base with a sub path if configured unless we received cp=y and cpb=/NEW/BASE
	if v := r.URL.Query().Get("cp"); v == "y" {
		if base := r.URL.Query().Get("cpb"); base != "" {
			// make sure the subpath has a trailing slash
			if !strings.HasSuffix(base, "/") {
				base = fmt.Sprintf("%s/", base)
			}
			basePath = base
		}
	}

	indexPage, err := webApp.GetStaticAssets().Open("build/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	indexPageBytes, err := io.ReadAll(indexPage)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// if we have a seeded basePath. This should override CONSOLE_SUBPATH every time, thus the `if else`
	if basePath != "/" {
		indexPageBytes = replaceBaseInIndex(indexPageBytes, basePath)
		// if we have a custom subpath replace it in
	} else if getSubPath() != "/" {
		indexPageBytes = replaceBaseInIndex(indexPageBytes, getSubPath())
	}

	mimeType := mimedb.TypeByExtension(filepath.Ext(r.URL.Path))

	if mimeType == "application/octet-stream" {
		mimeType = "text/html"
	}

	w.Header().Set("Content-Type", mimeType)
	http.ServeContent(w, r, "index.html", time.Now(), bytes.NewReader(indexPageBytes))
}

func replaceBaseInIndex(indexPageBytes []byte, basePath string) []byte {
	if basePath != "" {
		validBasePath := regexp.MustCompile(`^[0-9a-zA-Z\/-]+$`)
		if !validBasePath.MatchString(basePath) {
			return indexPageBytes
		}
		indexPageStr := string(indexPageBytes)
		newBase := fmt.Sprintf("<base href=\"%s\"/>", basePath)
		indexPageStr = strings.Replace(indexPageStr, "<base href=\"/\"/>", newBase, 1)
		indexPageBytes = []byte(indexPageStr)

	}
	return indexPageBytes
}

func getSubPath() string {
	subPathOnce.Do(func() {
		subPath = parseSubPath(env.Get(SubPath, ""))
	})
	return subPath
}

func parseSubPath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return SlashSeparator
	}
	// Replace all unnecessary `\` to `/`
	// also add pro-actively at the end.
	subPath = path.Clean(filepath.ToSlash(v))
	if !strings.HasPrefix(subPath, SlashSeparator) {
		subPath = SlashSeparator + subPath
	}
	if !strings.HasSuffix(subPath, SlashSeparator) {
		subPath += SlashSeparator
	}
	return subPath
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
	next = FileServerMiddleware(next)
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
