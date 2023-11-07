package credhub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
)

type HttpResponse struct {
	StatusCode int
	Status     string
	Body       io.ReadCloser
	err        error
}

func NewHttpResponseError(err error) HttpResponse {
	return HttpResponse{StatusCode: -1, Status: "", Body: nil, err: err}
}
func (c *HttpResponse) IsStatusCode2xx() bool {
	return c.StatusCode >= http.StatusOK && c.StatusCode < http.StatusMultipleChoices
}

func (c *HttpResponse) CloseResource() {
	if c.Body != nil {
		_ = c.Body.Close()
	}
}

type HttpClient interface {
	DoRequest(ctx context.Context, method, uri string, body io.Reader) HttpResponse
}

type HttpMTlsClient struct {
	baseUrl    string
	httpClient *http.Client
}

func NewHttpMTlsClient(config *Config) (HttpClient, error) {
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
	return &HttpMTlsClient{baseUrl: config.BaseUrl, httpClient: httpClient}, nil
}

func (s *HttpMTlsClient) DoRequest(ctx context.Context, method, uri string, body io.Reader) HttpResponse {
	url := s.baseUrl + uri
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return NewHttpResponseError(err)
	}
	req.Header.Set(contentType, applicationJson)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return NewHttpResponseError(err)
	} else {
		return HttpResponse{StatusCode: resp.StatusCode, Status: resp.Status, Body: resp.Body, err: nil}
	}
}
