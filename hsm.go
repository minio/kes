// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"golang.org/x/exp/slices"
)

// HSM is a (hardware) security module that provides
// secret key sealing and unsealing.
type HSM interface {
	// Name returns the name of the HSM.
	Name() string

	// Seal seals the given plaintext and returns the
	// corresponding ciphertext.
	Seal(ctx context.Context, plaintext []byte) ([]byte, error)

	// Unseal unseals the given ciphertext and returns the
	// corresponding plaintext.
	Unseal(ctx context.Context, ciphertext []byte) ([]byte, error)

	// APIKey generates a new API key from an optional seed.
	APIKey(ctx context.Context, seed []byte) (kes.APIKey, error)
}

// ParseSoftHSM parses a SoftHSM string.
func ParseSoftHSM(s string) (*SoftHSM, error) {
	const (
		Prefix         = "kes:v1:"
		AES256Prefix   = "aes256:"
		ChaCha20Prefix = "chacha20:"
	)

	s, ok := strings.CutPrefix(s, Prefix)
	if !ok {
		return nil, errors.New("kes: invalid soft HSM: missing '" + Prefix + "' prefix")
	}

	var cipher crypto.SecretKeyCipher
	switch {
	case strings.HasPrefix(s, AES256Prefix):
		s = strings.TrimPrefix(s, AES256Prefix)
		cipher = crypto.AES256
	case strings.HasPrefix(s, ChaCha20Prefix):
		if fips.Mode == fips.ModeStrict {
			return nil, errors.New("kes: invalid soft HSM: cipher not supported by FIPS module")
		}
		s = strings.TrimPrefix(s, ChaCha20Prefix)
		cipher = crypto.ChaCha20
	default:
		return nil, errors.New("kes: invalid soft HSM: cipher not supported")
	}

	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("kes: invalid soft HSM: invalid key length")
	}

	return &SoftHSM{
		cipher: cipher,
		key:    key[:32],
	}, nil
}

// NewSoftHSM returns a new SoftHSM with the given key.
//
// The key must be 32 bytes long and should be generated
// using high entry, e.g. by reading from crypto/rand.Reader.
func NewSoftHSM(key []byte) (*SoftHSM, error) {
	if len(key) != 32 {
		return nil, errors.New("kes: invalid soft HSM: invalid key length")
	}
	return &SoftHSM{
		key:    slices.Clone(key),
		cipher: crypto.AES256,
	}, nil
}

func GenerateSoftHSM(random io.Reader) (*SoftHSM, error) {
	if random == nil {
		random = rand.Reader
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, err
	}
	cipher := crypto.AES256
	if fips.Mode != fips.ModeStrict && !cpu.HasAESGCM() {
		cipher = crypto.ChaCha20
	}
	return &SoftHSM{
		key:    key,
		cipher: cipher,
	}, nil
}

type SoftHSM struct {
	key    []byte
	cipher crypto.SecretKeyCipher
}

// Name returns the SoftHSM model name.
func (*SoftHSM) Name() string { return "kes:v1:hsm:soft" }

// APIKey generates new API key from provided seed.
func (s *SoftHSM) APIKey(_ context.Context, seed []byte) (kes.APIKey, error) {
	if fips.Mode == fips.ModeStrict {
		return nil, errors.New("kes: Ed25519 API keys not supported by FIPS module")
	}

	random := fips.DeriveKey(sha256.New, s.key, 32, []byte("kes:v1:api_key"), seed)
	return kes.GenerateAPIKey(bytes.NewReader(random))
}

// Seal encrypts and authenticates the plaintext.
func (s *SoftHSM) Seal(_ context.Context, plaintext []byte) ([]byte, error) {
	key, err := crypto.NewSecretKey(s.cipher, fips.DeriveKey(sha256.New, s.key, crypto.SecretKeySize, []byte("kes:v1:root_key"), nil))
	if err != nil {
		return nil, err
	}
	return key.Encrypt(plaintext, nil)
}

// Unseal decrypts and authenticates the ciphertext.
func (s *SoftHSM) Unseal(_ context.Context, ciphertext []byte) ([]byte, error) {
	key, err := crypto.NewSecretKey(s.cipher, fips.DeriveKey(sha256.New, s.key, crypto.SecretKeySize, []byte("kes:v1:root_key"), nil))
	if err != nil {
		return nil, err
	}
	return key.Decrypt(ciphertext, nil)
}

// String returns the string representation of the SoftHSM.
func (s *SoftHSM) String() string {
	const (
		Prefix         = "kes:v1:"
		AES256Prefix   = "aes256:"
		ChaCha20Prefix = "chacha20:"
	)

	key := base64.StdEncoding.EncodeToString(s.key)
	switch s.cipher {
	case crypto.AES256:
		return Prefix + AES256Prefix + key
	case crypto.ChaCha20:
		return Prefix + ChaCha20Prefix + key
	default:
		return "%" + strconv.Itoa(int(s.cipher))
	}
}
