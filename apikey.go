// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"
)

// APIKey is an object that can generate a private/public key pair.
type APIKey interface {
	// Public returns the public key that coresponds to
	// the public key.
	Public() crypto.PublicKey

	// Private returns the private key that correspons
	// to the public key.
	Private() crypto.PrivateKey

	// Identity returns the Identity of the public key.
	//
	// The identity is the cryptographic fingerprint of
	// the raw DER-encoded public key as present in a
	// corresponding X509 cerificate.
	Identity() Identity

	// String returns the APIKey's textual representation.
	String() string
}

// GenerateAPIKey generates a new random API key. If rand
// is nil, crypto/rand.Reader is used.
func GenerateAPIKey(rand io.Reader) (APIKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	id, err := ed25519Identity(pub)
	if err != nil {
		return nil, err
	}
	return &apiKey{
		key:      priv,
		identity: id,
	}, nil
}

// ParseAPIKey parses a formatted APIKey and returns the
// value it represents.
func ParseAPIKey(s string) (APIKey, error) {
	const (
		Header      = "kes:v1:"
		Ed25519Type = 0
	)
	if !strings.HasPrefix(s, Header) {
		return nil, errors.New("kes: invalid API key: missing 'kes:v1:' prefix")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, Header))
	if err != nil {
		return nil, err
	}
	if len(b) != 1+ed25519.SeedSize {
		return nil, errors.New("kes: invalid API key: invalid length")
	}
	if b[0] != Ed25519Type {
		return nil, errors.New("kes: invalid API key: unsupported type")
	}
	key := ed25519.NewKeyFromSeed(b[1:])
	id, err := ed25519Identity(key[ed25519.SeedSize:])
	if err != nil {
		return nil, err
	}
	return &apiKey{
		key:      key,
		identity: id,
	}, nil
}

// CertificateOption is a function modifying the passed *x509.Certificate.
type CertificateOption func(*x509.Certificate)

// GenerateCertificate generates a new tls.Certificate from the APIKey's
// private and public key. The certificate can be customized by specifying
// one or multiple CertificateOptions.
//
// By default, the returned certificate is valid for 90 days.
func GenerateCertificate(key APIKey, options ...CertificateOption) (tls.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: key.Identity().String(),
		},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(90 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	for _, option := range options {
		option(&template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key.Private())
	if err != nil {
		return tls.Certificate{}, err
	}
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(key.Private())
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8}),
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return cert, nil
}

// apiKey is an APIKey implementation using Ed25519 public/private keys.
type apiKey struct {
	key      ed25519.PrivateKey
	identity Identity
}

func (ak *apiKey) Public() crypto.PublicKey {
	public := make([]byte, 0, len(ak.key[ed25519.SeedSize:]))
	return ed25519.PublicKey(append(public, ak.key[ed25519.SeedSize:]...))
}

func (ak *apiKey) Private() crypto.PrivateKey {
	private := make([]byte, 0, len(ak.key))
	return ed25519.PrivateKey(append(private, ak.key...))
}

func (ak *apiKey) Identity() Identity { return ak.identity }

func (ak *apiKey) String() string {
	const Ed25519Type = 0
	k := make([]byte, 0, 1+ed25519.SeedSize)
	k = append(k, Ed25519Type)
	k = append(k, ak.key[:ed25519.SeedSize]...)
	return "kes:v1:" + base64.StdEncoding.EncodeToString(k)
}

func ed25519Identity(pubKey []byte) (Identity, error) {
	type publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	derPublicKey, err := asn1.Marshal(publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		},
		PublicKey: asn1.BitString{BitLength: len(pubKey) * 8, Bytes: pubKey},
	})
	if err != nil {
		return "", err
	}
	id := sha256.Sum256(derPublicKey)
	return Identity(hex.EncodeToString(id[:])), nil
}
