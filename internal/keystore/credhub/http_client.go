package credhub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

type httpResponse struct {
	statusCode int
	status     string
	body       io.ReadCloser
	err        error
}

func newHTTPResponseError(err error) httpResponse {
	return httpResponse{statusCode: -1, status: "", body: nil, err: err}
}
func (c *httpResponse) isStatusCode2xx() bool {
	return c.statusCode >= http.StatusOK && c.statusCode < http.StatusMultipleChoices
}

func (c *httpResponse) closeResource() {
	if c.body != nil {
		_ = c.body.Close()
	}
}

type httpClient interface {
	doRequest(ctx context.Context, method, uri string, body io.Reader) httpResponse
}

type httpMTLSClient struct {
	baseURL    string
	httpClient *http.Client
}

func newHTTPMTLSClient(config *Config) (httpClient, error) {
	certs, err := config.Validate()
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.ServerInsecureSkipVerify,
	}
	if !config.ServerInsecureSkipVerify {
		// Setup mutual TLS - server
		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(certs.ServerCaCert)
		tlsConfig.RootCAs = caCertPool
	}
	if config.EnableMutualTLS {
		// Setup mutual TLS - client
		tlsConfig.Certificates = []tls.Certificate{certs.ClientKeyPair}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}
	return &httpMTLSClient{baseURL: config.BaseURL, httpClient: httpClient}, nil
}

func (s *httpMTLSClient) doRequest(ctx context.Context, method, uri string, body io.Reader) httpResponse {
	url := s.baseURL + uri
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return newHTTPResponseError(err)
	}
	req.Header.Set(contentType, applicationJson)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return newHTTPResponseError(err)
	}
	return httpResponse{statusCode: resp.StatusCode, status: resp.Status, body: resp.Body, err: nil}
}
