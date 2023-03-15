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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/minio/pkg/env"
	"github.com/secure-io/sio-go/sioutil"
	"github.com/xdg-go/pbkdf2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	cookieName         = "kes-ui-token"
	aesGcm             = 0x00
	c20p1305           = 0x01
	KESPBKDFPassphrase = "KES_PBKDF_PASSPHRASE"
	KESPBKDFSalt       = "KES_PBKDF_SALT"
	letters            = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

var (
	defaultPBKDFPassphrase = randomCharString(64)
	defaultPBKDFSalt       = randomCharString(64)
)

func randomCharString(n int) string {
	random := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		panic(err) // Can only happen if we would run out of entropy.
	}

	var s strings.Builder
	for _, v := range random {
		j := v % byte(len(letters))
		s.WriteByte(letters[j])
	}
	return s.String()
}

func getPBKDFPassphrase() string {
	return env.Get(KESPBKDFPassphrase, defaultPBKDFPassphrase)
}

func getPBKDFSalt() string {
	return env.Get(KESPBKDFSalt, defaultPBKDFSalt)
}

var derivedKey = func() []byte {
	return pbkdf2.Key([]byte(getPBKDFPassphrase()), []byte(getPBKDFSalt()), 4096, 32, sha1.New)
}

func newSessionCookieForConsole(token string) http.Cookie {
	// sessionDuration := xjwt.GetConsoleSTSDuration()
	sessionDuration := 24 * time.Hour
	return http.Cookie{
		Path:     "/",
		Name:     cookieName,
		Value:    token,
		MaxAge:   int(sessionDuration.Seconds()), // default 1 hr
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		// if len(GlobalPublicCerts) > 0 is true, that means Console is running with TLS enable and the browser
		// should not leak any cookie if we access the site using HTTP
		Secure: len(GlobalPublicCerts) > 0,
		// read more: https://web.dev/samesite-cookies-explained/
		SameSite: http.SameSiteLaxMode,
	}
}

func removeSessionCookie() http.Cookie {
	return http.Cookie{
		Path:     "/",
		Name:     cookieName,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Now().Add(-100 * time.Hour),
		HttpOnly: true,
		// if len(GlobalPublicCerts) > 0 is true, that means Console is running with TLS enable and the browser
		// should not leak any cookie if we access the site using HTTP
		Secure: len(GlobalPublicCerts) > 0,
		// read more: https://web.dev/samesite-cookies-explained/
		SameSite: http.SameSiteLaxMode,
	}
}

func encrypt(plaintext []byte) ([]byte, error) {
	var associatedData []byte
	iv, err := sioutil.Random(16) // 16 bytes IV
	if err != nil {
		return nil, err
	}
	var algorithm byte
	if sioutil.NativeAES() {
		algorithm = aesGcm
	} else {
		algorithm = c20p1305
	}
	var aead cipher.AEAD
	switch algorithm {
	case aesGcm:
		mac := hmac.New(sha256.New, derivedKey())
		mac.Write(iv)
		sealingKey := mac.Sum(nil)

		var block cipher.Block
		block, err = aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case c20p1305:
		var sealingKey []byte
		sealingKey, err = chacha20.HChaCha20(derivedKey(), iv) // HChaCha20 expects nonce of 16 bytes
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	}
	nonce, err := sioutil.Random(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	sealedBytes := aead.Seal(nil, nonce, plaintext, associatedData)

	// ciphertext = AEAD ID | iv | nonce | sealed bytes

	var buf bytes.Buffer
	buf.WriteByte(algorithm)
	buf.Write(iv)
	buf.Write(nonce)
	buf.Write(sealedBytes)

	return buf.Bytes(), nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	var associatedData []byte
	var (
		algorithm [1]byte
		iv        [16]byte
		nonce     [12]byte // This depends on the AEAD but both used ciphers have the same nonce length.
	)

	r := bytes.NewReader(ciphertext)
	if _, err := io.ReadFull(r, algorithm[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, iv[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		return nil, err
	}

	var aead cipher.AEAD
	switch algorithm[0] {
	case aesGcm:
		mac := hmac.New(sha256.New, derivedKey())
		mac.Write(iv[:])
		sealingKey := mac.Sum(nil)
		block, err := aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case c20p1305:
		sealingKey, err := chacha20.HChaCha20(derivedKey(), iv[:]) // HChaCha20 expects nonce of 16 bytes
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid algorithm: %v", algorithm)
	}

	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size %d, expected %d", len(nonce), aead.NonceSize())
	}

	sealedBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce[:], sealedBytes, associatedData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
