// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/minio/kes-go"
)

var tlsProxyAddTests = []struct {
	Identities []kes.Identity
}{
	{
		Identities: nil,
	},
	{
		Identities: []kes.Identity{
			"57eb2da320a48ebe2750e95c50b3d64240aef4cd5d54c28a4f25155e88c98580",
		},
	},
	{
		Identities: []kes.Identity{
			kes.IdentityUnknown,
			"57eb2da320a48ebe2750e95c50b3d64240aef4cd5d54c28a4f25155e88c98580",
		},
	},
	{
		Identities: []kes.Identity{
			kes.IdentityUnknown,
			"57eb2da320a48ebe2750e95c50b3d64240aef4cd5d54c28a4f25155e88c98580",
			"163d766f3e88f2a02b15a46bc541cc679c4cbb0a060405f298d5fc0d9d876bb3",
		},
	},
}

func TestTLSProxyAdd(t *testing.T) {
	for i, test := range tlsProxyAddTests {
		var proxy TLSProxy
		for j, identity := range test.Identities {
			proxy.Add(identity)
			if !identity.IsUnknown() && !proxy.Is(identity) {
				t.Fatalf("Test %d: %d-th identity '%s' should be a proxy but is not", i, j, identity)
			}
		}
	}
}

var tlsProxyGetClientCertificateTests = []struct {
	Proxy  *TLSProxy
	Header http.Header
	Err    error
}{
	{
		Proxy:  &TLSProxy{},
		Header: http.Header{},
		Err:    kes.NewError(http.StatusBadRequest, "no client certificate is present"),
	},
	{
		Proxy: &TLSProxy{CertHeader: "X-Forwarded-Ssl-Client-Cert"},
		Header: http.Header{
			"X-Forwarded-Ssl-Client-Cert": []string{url.QueryEscape(clientCert)},
		},
		Err: nil,
	},
	{
		Proxy: &TLSProxy{CertHeader: "X-Forwarded-Ssl-Client-Cert"},
		Header: http.Header{
			"X-Forwarded-Ssl-Client-Cert": []string{url.QueryEscape(clientCert), url.QueryEscape(clientCert)},
		},
		Err: kes.NewError(http.StatusBadRequest, "too many client certificates are present"),
	},
	{
		Proxy: &TLSProxy{CertHeader: "X-Forwarded-Ssl-Client-Cert"},
		Header: http.Header{
			"X-Ssl-Cert": []string{url.QueryEscape(clientCert)},
		},
		Err: kes.NewError(http.StatusBadRequest, "no client certificate is present"),
	},
	{
		Proxy: &TLSProxy{CertHeader: "X-Tls-Client-Cert"},
		Header: http.Header{
			"X-Tls-Client-Cert": []string{url.QueryEscape(noPEMTypeClientCert)},
		},
		Err: kes.NewError(http.StatusBadRequest, "invalid client certificate"),
	},
	{
		Proxy: &TLSProxy{CertHeader: "X-Tls-Client-Cert"},
		Header: http.Header{
			"X-Tls-Client-Cert": []string{unescapedClientCert},
		},
		Err: kes.NewError(http.StatusBadRequest, "invalid client certificate"),
	},
}

func TestTLSProxyGetClientCertificate(t *testing.T) {
	for i, test := range tlsProxyGetClientCertificateTests {
		_, err := test.Proxy.getClientCertificate(test.Header)
		if err != test.Err {
			t.Fatalf("Test %d: got error %v - want error %v", i, err, test.Err)
		}
	}
}

const clientCert = `-----BEGIN CERTIFICATE-----
MIIBETCBxKADAgECAhEAwNfpyTO85V8w7ecjWU8CdDAFBgMrZXAwDzENMAsGA1UE
AxMEcm9vdDAeFw0xOTEyMTYyMjQ2NDdaFw0yMDAxMTUyMjQ2NDdaMA8xDTALBgNV
BAMTBHJvb3QwKjAFBgMrZXADIQDNKcY+Mv84QGUEyC/NIvJefLjt9NGGQ9kj5eEX
e2QNGaM1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwBQYDK2VwA0EAqUvabyUgcQYp+dPFZpPBycx9+2sWEwwBsybk
JPbwv+fAB2l3rjHt2u9iWL6a2C9xzLh8ni+o2YIWLCGhMSfqBA==
-----END CERTIFICATE-----`

const noPEMTypeClientCert = `MIIBETCBxKADAgECAhEAwNfpyTO85V8w7ecjWU8CdDAFBgMrZXAwDzENMAsGA1UE
AxMEcm9vdDAeFw0xOTEyMTYyMjQ2NDdaFw0yMDAxMTUyMjQ2NDdaMA8xDTALBgNV
BAMTBHJvb3QwKjAFBgMrZXADIQDNKcY+Mv84QGUEyC/NIvJefLjt9NGGQ9kj5eEX
e2QNGaM1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwBQYDK2VwA0EAqUvabyUgcQYp+dPFZpPBycx9+2sWEwwBsybk
JPbwv+fAB2l3rjHt2u9iWL6a2C9xzLh8ni+o2YIWLCGhMSfqBA==`

const unescapedClientCert = `%A-----BEGIN CERTIFICATE-----
MIIBETCBxKADAgECAhEAwNfpyTO85V8w7ecjWU8CdDAFBgMrZXAwDzENMAsGA1UE
AxMEcm9vdDAeFw0xOTEyMTYyMjQ2NDdaFw0yMDAxMTUyMjQ2NDdaMA8xDTALBgNV
BAMTBHJvb3QwKjAFBgMrZXADIQDNKcY+Mv84QGUEyC/NIvJefLjt9NGGQ9kj5eEX
e2QNGaM1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwBQYDK2VwA0EAqUvabyUgcQYp+dPFZpPBycx9+2sWEwwBsybk
JPbwv+fAB2l3rjHt2u9iWL6a2C9xzLh8ni+o2YIWLCGhMSfqBA==
-----END CERTIFICATE-----`
