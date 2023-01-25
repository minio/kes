// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// Client is a KES client. Usually, a new client is
// instantiated via the NewClient or NewClientWithConfig
// functions.
//
// In general, a client just requires:
//   - a KES server endpoint
//   - a X.509 certificate for authentication
//
// However, custom transport protocols, timeouts,
// connection pooling, etc. can be specified via
// a custom http.RoundTripper. For example:
//
//	client := &Client{
//	    Endpoints:  []string{"https:127.0.0.1:7373"},
//	    HTTPClient: http.Client{
//	        Transport: &http.Transport{
//	           // specify custom behavior...
//
//	           TLSClientConfig: &tls.Config{
//	               Certificates: []tls.Certificates{clientCert},
//	           },
//	        },
//	    },
//	 }
//
// A custom transport protocol can be used via a
// custom implemention of the http.RoundTripper
// interface.
type Client struct {
	// Endpoints contains one or multiple KES server
	// endpoints. For example: https://127.0.0.1:7373
	//
	// Each endpoint must be a HTTPS endpoint and
	// should point to different KES server replicas
	// with a common configuration.
	//
	// Multiple endpoints should only be specified
	// when multiple KES servers should be used, e.g.
	// for high availability, but no round-robin DNS
	// is used.
	Endpoints []string

	// HTTPClient is the HTTP client.
	//
	// The HTTP client uses its http.RoundTripper
	// to send requests resp. receive responses.
	//
	// It must not be modified concurrently.
	HTTPClient http.Client

	init sync.Once
	lb   *loadBalancer
}

// NewClient returns a new KES client with the given
// KES server endpoint that uses the given TLS certificate
// mTLS authentication.
//
// The TLS certificate must be valid for client authentication.
//
// NewClient uses an http.Transport with reasonable defaults.
func NewClient(endpoint string, cert tls.Certificate) *Client {
	return NewClientWithConfig(endpoint, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
}

// NewClientWithConfig returns a new KES client with the
// given KES server endpoint that uses the given TLS config
// for mTLS authentication.
//
// Therefore, the config.Certificates must contain a TLS
// certificate that is valid for client authentication.
//
// NewClientWithConfig uses an http.Transport with reasonable
// defaults.
func NewClientWithConfig(endpoint string, config *tls.Config) *Client {
	return &Client{
		Endpoints: []string{endpoint},
		HTTPClient: http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       config,
			},
		},
	}
}

// Enclave returns a new Enclave with the given name.
func (c *Client) Enclave(name string) *Enclave {
	return &Enclave{
		Name:       name,
		Endpoints:  append(make([]string, 0, len(c.Endpoints)), c.Endpoints...),
		HTTPClient: c.HTTPClient,
	}
}

// Version tries to fetch the version information from the
// KES server.
func (c *Client) Version(ctx context.Context) (string, error) {
	const (
		APIPath        = "/version"
		Method         = http.MethodGet
		StatusOK       = http.StatusOK
		MaxResponeSize = 1 * mem.KiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return "", parseErrorResponse(resp)
	}

	type Response struct {
		Version string `json:"version"`
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponeSize)).Decode(&response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// Status returns the current state of the KES server.
func (c *Client) Status(ctx context.Context) (State, error) {
	const (
		APIPath         = "/v1/status"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return State{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return State{}, parseErrorResponse(resp)
	}

	type Response struct {
		Version string        `json:"version"`
		OS      string        `json:"os"`
		Arch    string        `json:"arch"`
		UpTime  time.Duration `json:"uptime"`

		CPUs       int    `json:"num_cpu"`
		UsableCPUs int    `json:"num_cpu_used"`
		HeapAlloc  uint64 `json:"mem_heap_used"`
		StackAlloc uint64 `json:"mem_stack_used"`
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return State{}, err
	}
	return State(response), nil
}

// APIs returns a list of all API endpoints supported
// by the KES server.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch the server
// APIs.
func (c *Client) APIs(ctx context.Context) ([]API, error) {
	const (
		APIPath         = "/v1/api"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	type Response struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		MaxBody int64  `json:"max_body"`
		Timeout int64  `json:"timeout"` // Timeout in seconds
	}
	var responses []Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&responses); err != nil {
		return nil, err
	}

	apis := make([]API, 0, len(responses))
	for _, response := range responses {
		apis = append(apis, API{
			Method:  response.Method,
			Path:    response.Path,
			MaxBody: response.MaxBody,
			Timeout: time.Second * time.Duration(response.Timeout),
		})
	}
	return apis, nil
}

// CreateEnclave creates a new enclave with the given
// identity as enclave admin. Only the KES system
// admin can create new enclaves.
//
// It returns ErrEnclaveExists if the enclave already
// exists.
func (c *Client) CreateEnclave(ctx context.Context, name string, admin Identity) error {
	const (
		APIPath  = "/v1/enclave/create"
		Method   = http.MethodPost
		StatusOK = http.StatusOK
	)
	type Request struct {
		Admin Identity `json:"admin"`
	}
	c.init.Do(c.initLoadBalancer)

	body, err := json.Marshal(Request{
		Admin: admin,
	})
	if err != nil {
		return err
	}
	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, join(APIPath, name), bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DescribeEnclave returns an EnclaveInfo describing the
// specified enclave. Only the KES system admin can create
// fetch enclave descriptions.
//
// It returns ErrEnclaveNotFound if the enclave does not
// exists.
func (c *Client) DescribeEnclave(ctx context.Context, name string) (*EnclaveInfo, error) {
	const (
		APIPath         = "/v1/enclave/describe"
		Method          = http.MethodGet
		StatusOK        = http.StatusOK
		MaxResponseSize = 1 * mem.MiB
	)
	type Response struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`
	}
	c.init.Do(c.initLoadBalancer)

	if name == "" {
		name = "default"
	}

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, join(APIPath, name), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, MaxResponseSize)).Decode(&response); err != nil {
		return nil, err
	}
	return &EnclaveInfo{
		Name:      response.Name,
		CreatedAt: response.CreatedAt,
		CreatedBy: response.CreatedBy,
	}, nil
}

// DeleteEnclave delete the specified enclave. Only the
// KES system admin can delete enclaves.
//
// It returns ErrEnclaveNotFound if the enclave does not
// exist.
func (c *Client) DeleteEnclave(ctx context.Context, name string) error {
	const (
		APIPath  = "/v1/enclave/delete"
		Method   = http.MethodDelete
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, join(APIPath, name), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// CreateKey creates a new cryptographic key. The key will
// be generated by the KES server.
//
// It returns ErrKeyExists if a key with the same name already
// exists.
func (c *Client) CreateKey(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.CreateKey(ctx, name)
}

// ImportKey imports the given key into a KES server. It
// returns ErrKeyExists if a key with the same key already
// exists.
func (c *Client) ImportKey(ctx context.Context, name string, key []byte) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ImportKey(ctx, name, key)
}

// DescribeKey returns the KeyInfo for the given key.
// It returns ErrKeyNotFound if no such key exists.
func (c *Client) DescribeKey(ctx context.Context, name string) (*KeyInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeKey(ctx, name)
}

// DeleteKey deletes the key from a KES server. It returns
// ErrKeyNotFound if no such key exists.
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteKey(ctx, name)
}

// GenerateKey returns a new generated data encryption key (DEK).
// A DEK has a plaintext and ciphertext representation.
//
// The former should be used for cryptographic operations, like
// encrypting some data.
//
// The later is the result of encrypting the plaintext with the named
// key at the KES server. It should be stored at a durable location but
// does not need to stay secret. The ciphertext can only be decrypted
// with the named key at the KES server.
//
// The context is cryptographically bound to the ciphertext and the
// same context value must be provided when decrypting the ciphertext
// via Decrypt. Therefore, an application must either remember the
// context or must be able to re-generate it.
//
// GenerateKey returns ErrKeyNotFound if no key with the given name
// exists.
func (c *Client) GenerateKey(ctx context.Context, name string, context []byte) (DEK, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.GenerateKey(ctx, name, context)
}

// Encrypt encrypts the given plaintext with the named key at the
// KES server. The optional context is cryptographically bound to
// the returned ciphertext. The exact same context must be provided
// when decrypting the ciphertext again.
//
// Encrypt returns ErrKeyNotFound if no such key exists at the KES
// server.
func (c *Client) Encrypt(ctx context.Context, name string, plaintext, context []byte) ([]byte, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.Encrypt(ctx, name, plaintext, context)
}

// Decrypt decrypts the ciphertext with the named key at the KES
// server. The exact same context, used during Encrypt, must be
// provided.
//
// Decrypt returns ErrKeyNotFound if no such key exists. It returns
// ErrDecrypt when the ciphertext has been modified or a different
// context value is provided.
func (c *Client) Decrypt(ctx context.Context, name string, ciphertext, context []byte) ([]byte, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.Decrypt(ctx, name, ciphertext, context)
}

// DecryptAll decrypts all ciphertexts with the named key at the
// KES server. It either returns all decrypted plaintexts or the
// first decryption error.
//
// DecryptAll returns ErrKeyNotFound if the specified key does not
// exist. It returns ErrDecrypt if any ciphertext has been modified
// or a different context value was used.
func (c *Client) DecryptAll(ctx context.Context, name string, ciphertexts ...CCP) ([]PCP, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DecryptAll(ctx, name, ciphertexts...)
}

// ListKeys lists all names of cryptographic keys that match the given
// pattern. It returns a KeyIterator that iterates over all matched key
// names.
//
// The pattern matching happens on the server side. If pattern is empty
// the KeyIterator iterates over all key names.
func (c *Client) ListKeys(ctx context.Context, pattern string) (*KeyIterator, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListKeys(ctx, pattern)
}

// CreateSecret creates a new secret with the given name.
//
// It returns ErrSecretExists if a secret with the same name
// already exists.
func (c *Client) CreateSecret(ctx context.Context, name string, value []byte, options *SecretOptions) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.CreateSecret(ctx, name, value, options)
}

// DescribeSecret returns the SecretInfo for the given secret.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) DescribeSecret(ctx context.Context, name string) (*SecretInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeSecret(ctx, name)
}

// ReadSecret returns the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) ReadSecret(ctx context.Context, name string) ([]byte, *SecretInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ReadSecret(ctx, name)
}

// DeleteSecret deletes the secret with the given name.
//
// It returns ErrSecretNotFound if no such secret exists.
func (c *Client) DeleteSecret(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteSecret(ctx, name)
}

// ListSecrets returns a SecretIter that iterates over all secrets
// matching the pattern.
//
// The '*' pattern matches any secret. If pattern is empty the
// SecretIter iterates over all secrets names.
func (c *Client) ListSecrets(ctx context.Context, pattern string) (*SecretIter, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListSecrets(ctx, pattern)
}

// SetPolicy creates the given policy. If a policy with the same
// name already exists, SetPolicy overwrites the existing policy
// with the given one. Any existing identites will be assigned to
// the given policy.
func (c *Client) SetPolicy(ctx context.Context, name string, policy *Policy) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.SetPolicy(ctx, name, policy)
}

// DescribePolicy returns the PolicyInfo for the given policy.
// It returns ErrPolicyNotFound if no such policy exists.
func (c *Client) DescribePolicy(ctx context.Context, name string) (*PolicyInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribePolicy(ctx, name)
}

// GetPolicy returns the policy with the given name.
// It returns ErrPolicyNotFound if no such policy
// exists.
func (c *Client) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.GetPolicy(ctx, name)
}

// DeletePolicy deletes the policy with the given name. Any
// assigned identities will be removed as well.
//
// It returns ErrPolicyNotFound if no such policy exists.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeletePolicy(ctx, name)
}

// ListPolicies lists all policy names that match the given pattern.
// It returns a PolicyIterator that iterates over all matched policies.
//
// The pattern matching happens on the server side. If pattern is empty
// ListPolicies returns all policy names.
func (c *Client) ListPolicies(ctx context.Context, pattern string) (*PolicyIterator, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListPolicies(ctx, pattern)
}

// AssignPolicy assigns the policy to the identity.
// The KES admin identity cannot be assigned to any
// policy.
//
// AssignPolicy returns PolicyNotFound if no such policy exists.
func (c *Client) AssignPolicy(ctx context.Context, policy string, identity Identity) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.AssignPolicy(ctx, policy, identity)
}

// DescribeIdentity returns an IdentityInfo describing the given identity.
func (c *Client) DescribeIdentity(ctx context.Context, identity Identity) (*IdentityInfo, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeIdentity(ctx, identity)
}

// DescribeSelf returns an IdentityInfo describing the identity
// making the API request. It also returns the assigned policy,
// if any.
//
// DescribeSelf allows an application to obtain identity and
// policy information about itself.
func (c *Client) DescribeSelf(ctx context.Context) (*IdentityInfo, *Policy, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DescribeSelf(ctx)
}

// DeleteIdentity removes the identity. Once removed, any
// operation issued by this identity will fail with
// ErrNotAllowed.
//
// The KES admin identity cannot be removed.
func (c *Client) DeleteIdentity(ctx context.Context, identity Identity) error {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.DeleteIdentity(ctx, identity)
}

// ListIdentities lists all identites that match the given pattern.
//
// The pattern matching happens on the server side. If pattern is empty
// ListIdentities returns all identities.
func (c *Client) ListIdentities(ctx context.Context, pattern string) (*IdentityIterator, error) {
	enclave := Enclave{
		Endpoints:  c.Endpoints,
		HTTPClient: c.HTTPClient,
		lb:         c.lb,
	}
	return enclave.ListIdentities(ctx, pattern)
}

// AuditLog returns a stream of audit events produced by the
// KES server. The stream does not contain any events that
// happened in the past.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// audit log.
func (c *Client) AuditLog(ctx context.Context) (*AuditStream, error) {
	const (
		APIPath  = "/v1/log/audit"
		Method   = http.MethodGet
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewAuditStream(resp.Body), nil
}

// ErrorLog returns a stream of error events produced by the
// KES server. The stream does not contain any events that
// happened in the past.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// error log.
func (c *Client) ErrorLog(ctx context.Context) (*ErrorStream, error) {
	const (
		APIPath  = "/v1/log/error"
		Method   = http.MethodGet
		StatusOK = http.StatusOK
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewErrorStream(resp.Body), nil
}

// Metrics returns a KES server metric snapshot.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch server metrics.
func (c *Client) Metrics(ctx context.Context) (Metric, error) {
	const (
		APIPath        = "/v1/metrics"
		Method         = http.MethodGet
		StatusOK       = http.StatusOK
		MaxResponeSize = 1 * mem.MiB
	)
	c.init.Do(c.initLoadBalancer)

	client := retry(c.HTTPClient)
	resp, err := c.lb.Send(ctx, &client, Method, c.Endpoints, APIPath, nil)
	if err != nil {
		return Metric{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != StatusOK {
		return Metric{}, parseErrorResponse(resp)
	}

	const (
		MetricRequestOK         = "kes_http_request_success"
		MetricRequestErr        = "kes_http_request_error"
		MetricRequestFail       = "kes_http_request_failure"
		MetricRequestActive     = "kes_http_request_active"
		MetricAuditEvents       = "kes_log_audit_events"
		MetricErrorEvents       = "kes_log_error_events"
		MetricResponseTime      = "kes_http_response_time"
		MetricSystemUpTme       = "kes_system_up_time"
		MetricSystemCPUs        = "kes_system_num_cpu"
		MetricSystemUsableCPUs  = "kes_system_num_cpu_used"
		MetricSystemThreads     = "kes_system_num_threads"
		MetricSystemHeapUsed    = "kes_system_mem_heap_used"
		MetricSystemHeapObjects = "kes_system_mem_heap_objects"
		MetricSystemStackUsed   = "kes_system_mem_stack_used"
	)

	var (
		metric       Metric
		metricFamily dto.MetricFamily
	)
	decoder := expfmt.NewDecoder(mem.LimitReader(resp.Body, MaxResponeSize), expfmt.ResponseFormat(resp.Header))
	for {
		err := decoder.Decode(&metricFamily)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Metric{}, err
		}

		if len(metricFamily.Metric) == 0 {
			return Metric{}, errors.New("kes: server response contains no metric")
		}
		var (
			name = metricFamily.GetName()
			kind = metricFamily.GetType()
		)
		switch {
		case kind == dto.MetricType_COUNTER && name == MetricRequestOK:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestOK += uint64(m.GetCounter().GetValue())
			}
		case kind == dto.MetricType_COUNTER && name == MetricRequestErr:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestErr += uint64(m.GetCounter().GetValue())
			}
		case kind == dto.MetricType_COUNTER && name == MetricRequestFail:
			for _, m := range metricFamily.GetMetric() {
				metric.RequestFail += uint64(m.GetCounter().GetValue())
			}
		default:
			if len(metricFamily.Metric) != 1 {
				return Metric{}, errors.New("kes: server response contains more than one metric")
			}
			rawMetric := metricFamily.GetMetric()[0] // Safe since we checked length before
			switch {
			case kind == dto.MetricType_GAUGE && name == MetricRequestActive:
				metric.RequestActive = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_COUNTER && name == MetricAuditEvents:
				metric.AuditEvents = uint64(rawMetric.GetCounter().GetValue())
			case kind == dto.MetricType_COUNTER && name == MetricErrorEvents:
				metric.ErrorEvents = uint64(rawMetric.GetCounter().GetValue())
			case kind == dto.MetricType_HISTOGRAM && name == MetricResponseTime:
				metric.LatencyHistogram = map[time.Duration]uint64{}
				for _, bucket := range rawMetric.GetHistogram().GetBucket() {
					if math.IsInf(bucket.GetUpperBound(), 0) { // Ignore the +Inf bucket
						continue
					}

					duration := time.Duration(1000*bucket.GetUpperBound()) * time.Millisecond
					metric.LatencyHistogram[duration] = bucket.GetCumulativeCount()
				}
				delete(metric.LatencyHistogram, 0) // Delete the artificial zero entry
			case kind == dto.MetricType_GAUGE && name == MetricSystemUpTme:
				metric.UpTime = time.Duration(rawMetric.GetGauge().GetValue()) * time.Second
			case kind == dto.MetricType_GAUGE && name == MetricSystemCPUs:
				metric.CPUs = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemUsableCPUs:
				metric.UsableCPUs = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemThreads:
				metric.Threads = int(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemHeapUsed:
				metric.HeapAlloc = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemHeapObjects:
				metric.HeapObjects = uint64(rawMetric.GetGauge().GetValue())
			case kind == dto.MetricType_GAUGE && name == MetricSystemStackUsed:
				metric.StackAlloc = uint64(rawMetric.GetGauge().GetValue())
			}
		}
	}
	return metric, nil
}

func (c *Client) initLoadBalancer() {
	if c.lb == nil {
		c.lb = &loadBalancer{endpoints: map[string]time.Time{}}
	}
}

// Join joins any number of arguments with the API path.
// All arguments are path-escaped before joining.
func join(api string, args ...string) string {
	for _, arg := range args {
		api = path.Join(api, url.PathEscape(arg))
	}
	return api
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   - endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   - endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
//
// Any leading or trailing whitespaces are removed from
// the endpoint before it is concatenated with the path
// elements.
//
// The path elements will not be URL-escaped.
func endpoint(endpoint string, elems ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimSuffix(endpoint, "/")

	if len(elems) > 0 && !strings.HasPrefix(elems[0], "/") {
		endpoint += "/"
	}
	return endpoint + path.Join(elems...)
}
