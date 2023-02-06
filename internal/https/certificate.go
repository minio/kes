package https

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

// CertificateFromFile reads and parses the PEM-encoded private key from
// the keyFile and the X.509 certificate from the given certFile.
//
// If the private key is an encrypted PEM block, it uses the given password
// to decrypt the private key. However, PEM encryption as specified in RFC
// 1423 is insecure by design. Since it does not authenticate the ciphertext,
// it is vulnerable to padding oracle attacks that can let an attacker recover
// the plaintext.
func CertificateFromFile(certFile, keyFile, password string) (tls.Certificate, error) {
	certBytes, err := readCertificate(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyBytes, err := readPrivateKey(keyFile, password)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if certificate.Leaf == nil {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return tls.Certificate{}, err
		}
	}
	return certificate, nil
}

// FilterPEM applies the filter function on each PEM block
// in pemBlocks and returns an error if at least one PEM
// block does not pass the filter.
func FilterPEM(pemBlocks []byte, filter func(*pem.Block) bool) ([]byte, error) {
	pemBlocks = bytes.TrimSpace(pemBlocks)

	b := pemBlocks
	for len(b) > 0 {
		next, rest := pem.Decode(b)
		if next == nil {
			return nil, errors.New("https: no valid PEM data")
		}
		if !filter(next) {
			return nil, errors.New("https: unsupported PEM data block")
		}
		b = rest
	}
	return pemBlocks, nil
}

// readCertificate reads the TLS certificate from
// the given file path.
func readCertificate(certFile string) ([]byte, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return FilterPEM(data, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
}

// readPrivateKey reads the TLS private key from the
// given file path.
//
// It decrypts the private key using the given password
// if the private key is an encrypted PEM block.
func readPrivateKey(keyFile, password string) ([]byte, error) {
	pemBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pemBlock, err = FilterPEM(pemBlock, func(b *pem.Block) bool {
		return b.Type == "CERTIFICATE" || b.Type == "PRIVATE KEY" || strings.HasSuffix(b.Type, " PRIVATE KEY")
	})
	if err != nil {
		return nil, err
	}

	for len(pemBlock) > 0 {
		next, rest := pem.Decode(pemBlock)
		if next == nil {
			return nil, errors.New("https: no PEM-encoded private key found")
		}
		if next.Type != "PRIVATE KEY" && !strings.HasSuffix(next.Type, " PRIVATE KEY") {
			pemBlock = rest
			continue
		}

		if x509.IsEncryptedPEMBlock(next) {
			if password == "" {
				return nil, errors.New("https: private key is encrypted: password required")
			}
			plaintext, err := x509.DecryptPEMBlock(next, []byte(password))
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: next.Type, Bytes: plaintext}), nil
		}
		return pem.EncodeToMemory(next), nil
	}
	return nil, errors.New("https: no PEM-encoded private key found")
}
