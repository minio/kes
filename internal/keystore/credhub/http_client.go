package credhub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

type HTTPResponse struct {
	statusCode int
	status     string
	body       io.ReadCloser
	err        error
}

func NewHTTPResponseError(err error) HTTPResponse {
	return HTTPResponse{statusCode: -1, status: "", body: nil, err: err}
}
func (c *HTTPResponse) isStatusCode2xx() bool {
	return c.statusCode >= http.StatusOK && c.statusCode < http.StatusMultipleChoices
}

func (c *HTTPResponse) closeResource() {
	if c.body != nil {
		_ = c.body.Close()
	}
}

type HTTPClient interface {
	doRequest(ctx context.Context, method, uri string, body io.Reader) HTTPResponse
}

type HTTPMTlsClient struct {
	baseUrl    string
	httpClient *http.Client
}

func NewHttpMTlsClient(config *Config) (HTTPClient, error) {
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
	if config.EnableMutualTls {
		// Setup mutual TLS - client
		tlsConfig.Certificates = []tls.Certificate{certs.ClientKeyPair}
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}
	return &HTTPMTlsClient{baseUrl: config.BaseUrl, httpClient: httpClient}, nil
}

func (s *HTTPMTlsClient) doRequest(ctx context.Context, method, uri string, body io.Reader) HTTPResponse {
	url := s.baseUrl + uri
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return NewHTTPResponseError(err)
	}
	req.Header.Set(contentType, applicationJson)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return NewHTTPResponseError(err)
	}
	return HTTPResponse{statusCode: resp.StatusCode, status: resp.Status, body: resp.Body, err: nil}
}
