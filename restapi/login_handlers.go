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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/models"
	"github.com/minio/kes/restapi/operations"
	authApi "github.com/minio/kes/restapi/operations/auth"
)

func registerLoginHandlers(api *operations.KesAPI) {
	api.AuthLoginDetailHandler = authApi.LoginDetailHandlerFunc(func(params authApi.LoginDetailParams) middleware.Responder {
		loginDetails, err := getLoginDetailsResponse(params)
		if err != nil {
			return authApi.NewLoginDetailDefault(int(err.Code)).WithPayload(err)
		}
		return authApi.NewLoginDetailOK().WithPayload(loginDetails)
	})

	api.AuthLoginHandler = authApi.LoginHandlerFunc(func(params authApi.LoginParams) middleware.Responder {
		loginResponse, err := getLoginResponse(params)
		if err != nil {
			return authApi.NewLoginDefault(int(err.Code)).WithPayload(err)
		}
		return middleware.ResponderFunc(func(w http.ResponseWriter, p runtime.Producer) {
			cookie := newSessionCookieForConsole(loginResponse.SessionID)
			http.SetCookie(w, &cookie)
			authApi.NewLoginNoContent().WriteResponse(w, p)
		})
	})

	api.AuthLogoutHandler = authApi.LogoutHandlerFunc(func(params authApi.LogoutParams, session *models.Principal) middleware.Responder {
		return middleware.ResponderFunc(func(w http.ResponseWriter, p runtime.Producer) {
			cookie := removeSessionCookie()
			http.SetCookie(w, &cookie)
			authApi.NewLogoutOK().WriteResponse(w, p)
		})
	})
}

// getLoginResponse performs login() and serializes it to the handler's output
func getLoginResponse(params authApi.LoginParams) (*models.LoginResponse, *models.Error) {
	insecure := params.HTTPRequest.FormValue("insecure")
	certBuf, err := getCertificateContent(params)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	keyBuf, err := getKeyContent(params)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	_, err = tls.X509KeyPair(certBuf, keyBuf)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	session := fmt.Sprintf("%s||%s||%s", certBuf, keyBuf, insecure)
	session = base64.StdEncoding.EncodeToString([]byte(session))
	loginResponse := &models.LoginResponse{
		SessionID: session,
	}
	return loginResponse, nil
}

func getCertificateContent(params authApi.LoginParams) ([]byte, error) {
	certFile, _, err := params.HTTPRequest.FormFile("cert")
	if err != nil {
		return nil, err
	}
	defer certFile.Close()
	certBuf := make([]byte, 256*1024)
	sc, err := io.ReadFull(certFile, certBuf)
	if err == nil {
		return nil, bytes.ErrTooLarge
	}
	if err != io.ErrUnexpectedEOF {
		return nil, err
	}
	certBuf = certBuf[:sc]
	return https.FilterPEM(certBuf, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
}

func getKeyContent(params authApi.LoginParams) ([]byte, error) {
	password := params.HTTPRequest.FormValue("password")
	keyFile, _, err := params.HTTPRequest.FormFile("key")
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()
	keyBuf := make([]byte, 256*1024)
	sp, err := io.ReadFull(keyFile, keyBuf)
	if err == nil {
		return nil, bytes.ErrTooLarge
	}
	if err != io.ErrUnexpectedEOF {
		return nil, err
	}
	keyBuf = keyBuf[:sp]
	privateKey, err := decodePrivateKey(keyBuf)
	if err != nil {
		return nil, err
	}
	if len(privateKey.Headers) > 0 && x509.IsEncryptedPEMBlock(privateKey) {
		if password == "" {
			return nil, errors.New("private key is encrypted but no password was provided")
		}
		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, []byte(password))
		if err != nil {
			return nil, err
		}
		keyBuf = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}
	return keyBuf, nil
}

func decodePrivateKey(pemBlock []byte) (*pem.Block, error) {
	ErrNoPrivateKey := errors.New("no PEM-encoded private key found")

	for len(pemBlock) > 0 {
		next, rest := pem.Decode(pemBlock)
		if next == nil {
			return nil, ErrNoPrivateKey
		}
		if next.Type == "PRIVATE KEY" || strings.HasSuffix(next.Type, " PRIVATE KEY") {
			return next, nil
		}
		pemBlock = rest
	}
	return nil, ErrNoPrivateKey
}

func getLoginDetailsResponse(params authApi.LoginDetailParams) (*models.LoginDetails, *models.Error) {
	loginStrategy := models.LoginDetailsLoginStrategyForm
	var redirectRules []*models.RedirectRule

	return &models.LoginDetails{
		LoginStrategy: loginStrategy,
		RedirectRules: redirectRules,
	}, nil
}
