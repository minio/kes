// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
)

// KMS is a Vault KMS client that implements the
// secret.KMS interface.
//
// It can be used to encrypt secrets before storing
// them at a key store resp. decrypt them after
// fetching them from such a store.
type KMS struct {
	// Addr is the HTTP address of the Vault server.
	Addr string

	// AppRole contains the Vault AppRole authentication
	// credentials.
	AppRole AppRole

	// StatusPingAfter is the duration after which
	// the KMS will check the status of the Vault
	// server. Particularly, this status information
	// is used to determine whether the Vault server
	// has been sealed resp. unsealed again.
	StatusPingAfter time.Duration

	// ErrorLog specifies an optional logger for errors
	// when an encryption or decryption request fails.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	// Path to the mTLS client private key to authenticate to
	// the Vault server.
	ClientKeyPath string

	// Path to the mTLS client certificate to authenticate to
	// the Vault server.
	ClientCertPath string

	// Path to the root CA certificate(s) used to verify the
	// TLS certificate of the Vault server. If empty, the
	// host's root CA set is used.
	CAPath string

	// The Vault namespace used to separate and isolate different
	// organizations / tenants at the same Vault instance. If
	// non-empty, the Vault client will send the
	//   X-Vault-Namespace: Namespace
	// HTTP header on each request. For more information see:
	// https://www.vaultproject.io/docs/enterprise/namespaces/index.html
	Namespace string

	client *client
}

var _ secret.KMS = (*KMS)(nil)

// Authenticate tries to establish a connection to
// a Vault server using the approle credentials.
// It returns an error if no connection could be
// established - for instance because of invalid
// authentication credentials.
func (kms *KMS) Authenticate(context context.Context) error {
	tlsConfig := &vaultapi.TLSConfig{
		ClientKey:  kms.ClientKeyPath,
		ClientCert: kms.ClientCertPath,
	}
	if kms.CAPath != "" {
		stat, err := os.Stat(kms.CAPath)
		if err != nil {
			return fmt.Errorf("Failed to open '%s': %v", kms.CAPath, err)
		}
		if stat.IsDir() {
			tlsConfig.CAPath = kms.CAPath
		} else {
			tlsConfig.CACert = kms.CAPath
		}
	}

	config := vaultapi.DefaultConfig()
	config.Address = kms.Addr
	config.ConfigureTLS(tlsConfig)
	vaultClient, err := vaultapi.NewClient(config)
	if err != nil {
		return err
	}
	kms.client = &client{
		Client: vaultClient,
	}
	if kms.Namespace != "" {
		// We must only set the namespace if it is not
		// empty. If namespace == "" the vault client
		// will send an empty namespace HTTP header -
		// which is not what we want.
		kms.client.SetNamespace(kms.Namespace)
	}
	go kms.client.CheckStatus(context, kms.StatusPingAfter)

	token, ttl, err := kms.client.Authenticate(kms.AppRole)
	if err != nil {
		return err
	}
	kms.client.SetToken(token)
	go kms.client.RenewToken(context, kms.AppRole, ttl)
	return nil
}

var errEncryption = kes.NewError(http.StatusServiceUnavailable, "failed to encrypt key")

// Encrypt tries to encrypt the given plaintext with the specified
// key at the Vault KMS instance. It returns the encrypted plaintext
// as ciphertext.
func (kms *KMS) Encrypt(key string, plaintext []byte) ([]byte, error) {
	if kms.client == nil {
		kms.log(errNoConnection)
		return nil, errEncryption
	}
	if kms.client.Sealed() {
		kms.log("vault: server is sealed")
		return nil, errEncryption
	}

	payload := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	secret, err := kms.client.Logical().Write(fmt.Sprintf("/transit/encrypt/%s", key), payload)
	if secret == nil && err == nil {
		// Under certain conditions (e.g. Vault responds with 200 OK but does not send
		// a response body - i.e. when Vault gets sealed) then the Vault SDK returns
		// no secret but also no error.
		kms.log("vault: server returned no ciphertext but also no error")
		return nil, errEncryption
	}
	if err != nil {
		if err, ok := err.(*vaultapi.ResponseError); ok {
			switch {
			case err.StatusCode == http.StatusForbidden:
				kms.logf("vault: insufficient permissions to encrypt with '%s'", key)
			case err.StatusCode == http.StatusNotFound:
				kms.logf("vault: the key '%s' does not exist", key)
			case len(err.Errors) > 0:
				kms.logf("vault: %d %s: %v", err.StatusCode, http.StatusText(err.StatusCode), err.Errors[0])
			default:
				kms.logf("vault: %d %s: server has not sent any error message", err.StatusCode, http.StatusText(err.StatusCode))
			}
		} else {
			kms.logf("vault: %v", err)
		}
		return nil, errEncryption
	}

	// If we receive a response from Vault we check whether
	// it is well-formed.
	v, ok := secret.Data["ciphertext"]
	if !ok {
		kms.log("vault: response does not contain any ciphertext")
		return nil, errEncryption
	}
	ciphertext, ok := v.(string)
	if !ok {
		kms.log("vault: server has sent invalid ciphertext")
		return nil, errEncryption
	}
	return []byte(ciphertext), nil
}

// Decrypt tries to decrypt the given ciphertext with the the given key
// using the AWS-KMS. It returns the decrypted ciphertexts as plaintext
// on success.
func (kms *KMS) Decrypt(key string, ciphertext []byte) ([]byte, error) {
	if kms.client == nil {
		kms.log(errNoConnection)
		return nil, kes.ErrKeySealed
	}
	if kms.client.Sealed() {
		kms.log("vault: server is sealed")
		return nil, kes.ErrKeySealed
	}

	// A vault ciphertext has the form: 'vault:<verion>:<base64-ciphertext>'
	// Therefore, we pass the ciphertext as string directly to Vault.
	payload := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}
	secret, err := kms.client.Logical().Write(fmt.Sprintf("/transit/decrypt/%s", key), payload)
	if secret == nil && err == nil {
		// Under certain conditions (e.g. Vault responds with 200 OK but does not send
		// a response body - i.e. when Vault gets sealed) then the Vault SDK returns
		// no secret but also no error.
		kms.log("vault: server returned no plaintext but also no error")
		return nil, kes.ErrKeySealed
	}
	if err != nil {
		if err, ok := err.(*vaultapi.ResponseError); ok {
			switch {
			case err.StatusCode == http.StatusForbidden:
				kms.logf("vault: insufficient permissions to decrypt with '%s'", key)
			case len(err.Errors) > 0:
				kms.logf("vault: %d %s: %v", err.StatusCode, http.StatusText(err.StatusCode), err.Errors[0])
			default:
				kms.logf("vault: %d %s: server has not sent any error message", err.StatusCode, http.StatusText(err.StatusCode))
			}
		} else {
			kms.logf("vault: %v", err)
		}
		return nil, kes.ErrKeySealed
	}

	// If we receive a response from Vault we check whether
	// it is well-formed.
	v, ok := secret.Data["plaintext"]
	if !ok {
		kms.log("vault: response does not contain any plaintext")
		return nil, kes.ErrKeySealed
	}
	plaintext, ok := v.(string)
	if !ok {
		kms.log("vault: server has sent invalid plaintext")
		return nil, kes.ErrKeySealed
	}
	bytes, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		kms.logf("vault: server has sent invalid plaintext: %v", err)
		return nil, kes.ErrKeySealed
	}
	return bytes, nil
}

func (kms *KMS) log(v ...interface{}) {
	if kms.ErrorLog == nil {
		log.Println(v...)
	} else {
		kms.ErrorLog.Println(v...)
	}
}

func (kms *KMS) logf(format string, v ...interface{}) {
	if kms.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		kms.ErrorLog.Printf(format, v...)
	}
}
