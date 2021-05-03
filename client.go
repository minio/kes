// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// Client is a KES client. Usually, a new client is
// instantiated via the NewClient or NewClientWithConfig
// functions.
//
// In general, a client just requires:
//   • a KES server endpoint
//   • a X.509 certificate for authentication
//
// However, custom transport protocols, timeouts,
// connection pooling, etc. can be specified via
// a custom http.RoundTripper. For example:
//   client := &Client{
//       Endpoints:  []string{"https:127.0.0.1:7373"},
//       HTTPClient: http.Client{
//           Transport: &http.Transport{
//              // specify custom behavior...
//
//              TLSClientConfig: &tls.Config{
//                  Certificates: []tls.Certificates{clientCert},
//              },
//           },
//       },
//    }
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

// DEK is a data encryption key. It has a plaintext
// and a ciphertext representation.
//
// Applications should use the plaintext for cryptographic
// operations and store the ciphertext at a durable
// location.
//
// If the DEK is used to e.g. encrypt some data then it's
// safe to store the DEK's ciphertext representation next
// to the encrypted data. The ciphertext representation
// does not need to stay secret.
//
// DEK implements binary as well as text marshaling.
// However, only the ciphertext representation gets
// encoded. The plaintext should never be stored
// anywhere.
// Therefore, after un-marshaling there will be no
// plaintext representation. To obtain it the
// ciphertext must be decrypted.
type DEK struct {
	Plaintext  []byte
	Ciphertext []byte
}

var (
	_ encoding.BinaryMarshaler   = (*DEK)(nil)
	_ encoding.TextMarshaler     = (*DEK)(nil)
	_ encoding.BinaryUnmarshaler = (*DEK)(nil)
	_ encoding.TextUnmarshaler   = (*DEK)(nil)
)

// MarshalText encodes the DEK's ciphertext into
// a base64-encoded text and returns the result.
//
// It never returns an error.
func (d DEK) MarshalText() ([]byte, error) {
	ciphertext := make([]byte, base64.StdEncoding.EncodedLen(len(d.Ciphertext)))
	base64.StdEncoding.Encode(ciphertext, d.Ciphertext)
	return ciphertext, nil
}

// UnmarshalText tries to decode a base64-encoded text
// and sets DEK's ciphertext to the decoded data.
//
// It returns an error if text is not base64-encoded.
//
// UnmarshalText sets DEK's plaintext to nil.
func (d *DEK) UnmarshalText(text []byte) (err error) {
	n := base64.StdEncoding.DecodedLen(len(text))
	if len(d.Ciphertext) < n {
		if cap(d.Ciphertext) >= n {
			d.Ciphertext = d.Ciphertext[:n]
		} else {
			d.Ciphertext = make([]byte, n)
		}
	}

	d.Plaintext = nil // Forget any previous plaintext
	n, err = base64.StdEncoding.Decode(d.Ciphertext, text)
	d.Ciphertext = d.Ciphertext[:n]
	return err
}

// MarshalBinary returns DEK's ciphertext representation.
// It never returns an error.
func (d DEK) MarshalBinary() ([]byte, error) { return d.Ciphertext, nil }

// UnmarshalBinary sets DEK's ciphertext to the given data.
// It never returns an error and DEK's plaintext will be nil.
func (d *DEK) UnmarshalBinary(data []byte) error {
	n := len(data)
	if len(d.Ciphertext) < n {
		if cap(d.Ciphertext) >= n {
			d.Ciphertext = d.Ciphertext[:n]
		} else {
			d.Ciphertext = make([]byte, n)
		}
	}

	d.Plaintext = nil // Forget any previous plaintext
	copy(d.Ciphertext, data)
	return nil
}

// KeyIterator iterates over list of KeyDescription objects.
//   for iterator.Next() {
//       _ = iterator.Value() // Use the KeyDescription
//   }
//   if err := iterator.Err(); err != nil {
//   }
//
// Once done with iterating over the list of KeyDescription
// objects, an iterator should be closed using the Close
// method.
//
// In general, a KeyIterator does not provide any guarantees
// about ordering or the when its underlying source is modified
// concurrently.
// Particularly, if a key is created or deleted at the KES a
// KeyIterator may or may not be affected by this change.
type KeyIterator struct {
	response *http.Response
	decoder  *json.Decoder

	last   KeyDescription
	err    error
	closed bool
}

// KeyDescription describes a cryptographic key at a KES server.
type KeyDescription struct {
	// Name is the name of the cryptographic key.
	Name string `json:"name"`
}

// Next returns true if there is another KeyDescription.
// This KeyDescription can be retrieved via the Value method.
//
// It returns false once there is no more KeyDescription
// or if the KeyIterator encountered an error. The error,
// if any, can be retrieved via the Err method.
func (i *KeyIterator) Next() bool {
	if i.closed || i.err != nil {
		return false
	}
	if err := i.decoder.Decode(&i.last); err != nil {
		if err == io.EOF {
			i.err = i.Close()
		} else {
			i.err = err
		}
		return false
	}
	return true
}

// Value returns the current KeyDescription. It returns
// the same KeyDescription until Next is called again.
//
// If KeyIterator has been closed or if Next has not been
// called once resp. once Next returns false then the
// behavior of Value is undefined.
func (i *KeyIterator) Value() KeyDescription { return i.last }

// Err returns the first error encountered by the KeyIterator,
// if any.
func (i *KeyIterator) Err() error { return i.err }

// Close closes the underlying connection to the KES server
// and returns any encountered error, if any.
func (i *KeyIterator) Close() error {
	i.closed = true
	if err := i.response.Body.Close(); err != nil {
		return err
	}
	if err := parseErrorTrailer(i.response.Trailer); err != nil {
		return err
	}
	return nil
}

// Version tries to fetch the version information from the
// KES server.
func (c *Client) Version(ctx context.Context) (string, error) {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, "/version", nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", parseErrorResponse(resp)
	}

	type Response struct {
		Version string `json:"version"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// CreateKey tries to create a new cryptographic key with
// the specified name.
//
// The key will be generated by the server. The client
// application does not have the cryptographic key at
// any point in time.
func (c *Client) CreateKey(ctx context.Context, name string) error {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/key/create", url.PathEscape(name)), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ImportKey tries to import the given key as cryptographic
// key with the specified name.
//
// In contrast to CreateKey, the client specifies, and
// therefore, knows the value of the cryptographic key.
func (c *Client) ImportKey(ctx context.Context, name string, key []byte) error {
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	body, err := json.Marshal(Request{
		Bytes: key,
	})
	if err != nil {
		return err
	}

	client := retry(c.HTTPClient)

	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/key/import", url.PathEscape(name)), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// DeleteKey deletes the given key. Once a key has been deleted
// all data, that has been encrypted with it, cannot be decrypted
// anymore.
func (c *Client) DeleteKey(ctx context.Context, name string) error {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodDelete, c.Endpoints, path.Join("/v1/key/delete", url.PathEscape(name)), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// GenerateKey generates a new data encryption key (DEK).
// The context is cryptographically bound to the DEK.
//
// A DEK has a plaintext and a ciphertext representation.
// The plaintext should be used to perform a cryptographic
// operation - for example: encrypt some data.
//
// The ciphertext is the result of encrypting the plaintext
// with the given key. It should be stored at a durable location
// but does not need to stay secret. The ciphertext can only
// be decrypted with the given key at the server.
//
// Whenever an application needs the DEK's plaintext representation
// it should send the ciphertext to the server via the Decrypt method.
//
// The context is cryptographically bound to the ciphertext and
// the same context value must be provided whenever the
// ciphertext should be decrypted. An application either must
// remember the context or must be able to re-generate it.
//
// If an application does not wish to specify a context
// value it can set it to nil.
func (c *Client) GenerateKey(ctx context.Context, name string, context []byte) (DEK, error) {
	type Request struct {
		Context []byte `json:"context,omitempty"` // A context is optional
	}
	body, err := json.Marshal(Request{
		Context: context,
	})
	if err != nil {
		return DEK{}, err
	}

	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/key/generate", url.PathEscape(name)), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return DEK{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return DEK{}, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return DEK{}, err
	}
	return DEK(response), nil
}

// Encrypt encrypts and authenticates the given plaintext
// with the specified key and returns the corresponding
// ciphertext on success.
//
// An optional context value gets authenticated but is not
// encrypted. Therefore, the same context value must be provided
// for decryption. Clients should remember or be able to
// re-generate the context value.
func (c *Client) Encrypt(ctx context.Context, name string, plaintext, context []byte) ([]byte, error) {
	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context,omitempty"` // A context is optional
	}
	body, err := json.Marshal(Request{
		Plaintext: plaintext,
		Context:   context,
	})
	if err != nil {
		return nil, err
	}

	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/key/encrypt", url.PathEscape(name)), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Ciphertext, nil
}

// Decrypt tries to decrypt the given ciphertext with the
// specified key and returns plaintext on success.
//
// The context value must match the context used when
// the ciphertext was produced. If no context was used
// the context value should be set to nil.
func (c *Client) Decrypt(ctx context.Context, name string, ciphertext, context []byte) ([]byte, error) {
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context,omitempty"` // A context is optional
	}
	body, err := json.Marshal(Request{
		Ciphertext: ciphertext,
		Context:    context,
	})
	if err != nil {
		return nil, err
	}

	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/key/decrypt", url.PathEscape(name)), bytes.NewReader(body), withHeader("Content-Type", "application/json"))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Plaintext, nil
}

// ListKeys returns a new KeyIterator that iterates over all keys
// matching the given glob pattern.
//
// The KeyIterator will stop once the given context.Done() completes,
// an error occurs while iterating or once there are no more
// KeyDescription objects - whatever happens first.
//
// If the pattern is empty it defaults to "*".
func (c *Client) ListKeys(ctx context.Context, pattern string) (*KeyIterator, error) {
	if pattern == "" { // The empty pattern never matches anything
		pattern = "*" // => default to: list all keys
	}

	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, path.Join("/v1/key/list", url.PathEscape(pattern)), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return &KeyIterator{
		response: resp,
		decoder:  json.NewDecoder(resp.Body),
	}, nil
}

// SetPolicy adds the given policy to the set of policies.
// There can be just one policy with one particular name at
// one point in time.
//
// If there is already a policy with the given name then SetPolicy
// overwrites the existing policy with the given one.
//
// If there are identities assigned to an existing policy then
// SetPolicy will not remove those identities before overwriting
// the policy. Instead, it will just updated the policy entry such
// that the given policy automatically applies to those identities.
func (c *Client) SetPolicy(ctx context.Context, name string, policy *Policy) error {
	content, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/policy/write", url.PathEscape(name)), bytes.NewReader(content), withHeader("Content-Type", "application/json"))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// GetPolicy returns the policy with the given name. If no such
// policy exists then GetPolicy returns ErrPolicyNotFound.
func (c *Client) GetPolicy(ctx context.Context, name string) (*Policy, error) {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, path.Join("/v1/policy/read", url.PathEscape(name)), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	const limit = 32 * 1024 * 1024 // A policy might be large
	decoder := json.NewDecoder(io.LimitReader(resp.Body, limit))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err = decoder.Decode(&policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

// ListPolicies returns a list of policies with names that
// match the given glob pattern. For example
//   policies, err := client.ListPolicies("*") // '*' matches any
// returns the names of all existing policies.
//
// If no / an empty pattern is provided then ListPolicies uses
// the pattern '*' as default.
func (c *Client) ListPolicies(ctx context.Context, pattern string) ([]string, error) {
	if pattern == "" { // The empty pattern never matches anything
		pattern = "*" // => default to: list "all" policies
	}
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/policy/list", url.PathEscape(pattern)), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	const limit = 64 * 1024 * 1024 // There might be many policies
	var policies []string
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// DeletePolicy removes the policy with the given name. It will not
// return an error if no policy exists.
//
// If there are identities assigned to the deleted policies then these
// identities will be removed as well.
//
// Therefore, setting an empty policy and deleting a policy have
// slightly different implications. The former will revoke any
// access permission for all identities assigned to the policy.
// The later will remove the policy as well as all identities
// assigned to it.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodDelete, c.Endpoints, path.Join("/v1/policy/delete", url.PathEscape(name)), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) AssignIdentity(ctx context.Context, policy string, id Identity) error {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodPost, c.Endpoints, path.Join("/v1/identity/assign", url.PathEscape(policy), url.PathEscape(id.String())), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) ListIdentities(ctx context.Context, pattern string) (map[Identity]string, error) {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, path.Join("/v1/identity/list", url.PathEscape(pattern)), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	const limit = 64 * 1024 * 1024 // There might be many identities
	response := map[Identity]string{}
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) ForgetIdentity(ctx context.Context, id Identity) error {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodDelete, c.Endpoints, path.Join("/v1/identity/forget", url.PathEscape(id.String())), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// AuditLog returns a stream of audit events produced by the
// KES server. The stream does not contain any events that
// happened in the past.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// audit log.
func (c *Client) AuditLog(ctx context.Context) (*AuditStream, error) {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, "/v1/log/audit/trace", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
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
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, "/v1/log/error/trace", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewErrorStream(resp.Body), nil
}

// Metrics returns a KES server metric snapshot.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to fetch server metrics.
func (c *Client) Metrics(ctx context.Context) (Metric, error) {
	client := retry(c.HTTPClient)
	resp, err := client.Send(ctx, http.MethodGet, c.Endpoints, "/v1/metrics", nil)
	if err != nil {
		return Metric{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Metric{}, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	const (
		MetricRequestOK     = "kes_http_request_success"
		MetricRequestErr    = "kes_http_request_error"
		MetricRequestFail   = "kes_http_request_failure"
		MetricRequestActive = "kes_http_request_active"
		MetricResponseTime  = "kes_http_response_time"
		MetricSystemUpTme   = "kes_system_up_time"
	)

	var (
		metric       Metric
		metricFamily dto.MetricFamily
	)
	decoder := expfmt.NewDecoder(resp.Body, expfmt.ResponseFormat(resp.Header))
	for {
		err := decoder.Decode(&metricFamily)
		if err == io.EOF {
			break
		}
		if err != nil {
			return Metric{}, err
		}

		if len(metricFamily.Metric) != 1 {
			return Metric{}, errors.New("kes: server response contains more than one metric")
		}
		var (
			name      = metricFamily.GetName()
			kind      = metricFamily.GetType()
			rawMetric = metricFamily.GetMetric()[0] // Safe since we checked length before
		)
		switch {
		case kind == dto.MetricType_COUNTER && name == MetricRequestOK:
			metric.RequestOK = uint64(rawMetric.GetCounter().GetValue())
		case kind == dto.MetricType_COUNTER && name == MetricRequestErr:
			metric.RequestErr = uint64(rawMetric.GetCounter().GetValue())
		case kind == dto.MetricType_COUNTER && name == MetricRequestFail:
			metric.RequestFail = uint64(rawMetric.GetCounter().GetValue())
		case kind == dto.MetricType_GAUGE && name == MetricRequestActive:
			metric.RequestActive = uint64(rawMetric.GetGauge().GetValue())
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
		}
	}
	return metric, nil
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   • endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   • endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
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
