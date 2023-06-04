package edge

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge/kv"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/https/header"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
)

func initRoutes(s *serverState, config map[string]APIConfig) {
	s.Routes = map[string]api.API{
		api.PathVersion: {
			Method:  http.MethodGet,
			Path:    api.PathVersion,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.InsecureSkipVerify,
			Handler: api.HandlerFunc(s.handleVersion),
		},
		api.PathReady: {
			Method:  http.MethodGet,
			Path:    api.PathReady,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleReady),
		},
		api.PathListAPIs: {
			Method:  http.MethodGet,
			Path:    api.PathListAPIs,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListRoutes),
		},
		api.PathStatus: {
			Method:  http.MethodGet,
			Path:    api.PathStatus,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleStatus),
		},
		api.PathMetrics: {
			Method:  http.MethodGet,
			Path:    api.PathMetrics,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleMetrics),
		},

		api.PathSecretKeyCreate: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyCreate,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleCreateSecretKey),
		},
		api.PathSecretKeyImport: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyImport,
			MaxBody: int64(1 * mem.KiB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleImportSecretKey),
		},
		api.PathSecretKeyDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathSecretKeyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeSecretKey),
		},
		api.PathSecretKeyList: {
			Method:  http.MethodGet,
			Path:    api.PathSecretKeyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListSecretKeys),
		},
		api.PathSecretKeyDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathSecretKeyDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDeleteSecretKey),
		},
		api.PathSecretKeyGenerate: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyGenerate,
			MaxBody: int64(1 * mem.MiB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleGenerateKey),
		},
		api.PathSecretKeyEncrypt: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyEncrypt,
			MaxBody: int64(1 * mem.MiB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleEncrypt),
		},
		api.PathSecretKeyDecrypt: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyDecrypt,
			MaxBody: int64(1 * mem.MiB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDecrypt),
		},

		api.PathPolicyDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribePolicy),
		},
		api.PathPolicyRead: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyRead,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleReadPolicy),
		},
		api.PathPolicyList: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListPolicies),
		},

		api.PathIdentityDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeIdentity),
		},
		api.PathIdentitySelfDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathIdentitySelfDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleSelfDescribeIdentity),
		},
		api.PathIdentityList: {
			Method:  http.MethodGet,
			Path:    api.PathIdentityList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListIdentities),
		},

		api.PathLogError: {
			Method:  http.MethodGet,
			Path:    api.PathLogError,
			MaxBody: 0,
			Timeout: 0 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleLogError),
		},
		api.PathLogAudit: {
			Method:  http.MethodGet,
			Path:    api.PathLogAudit,
			MaxBody: 0,
			Timeout: 0 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleLogAudit),
		},
	}

	for route, handler := range s.Routes {
		if apiConf, ok := config[route]; ok {
			if apiConf.InsecureSkipAuth {
				handler.Verify = api.InsecureSkipVerify
			}
		}

		s.Mux.Handle(route, handler)
	}
}

type serverState struct {
	Mux *http.ServeMux

	Admin kes.Identity

	StartTime time.Time

	Routes map[string]api.API

	Keys *Cache

	Policies map[string]*auth.Policy

	Identities map[kes.Identity]string

	Metrics *metric.Metrics

	TLS *tls.Config

	ErrorLog *log.Logger

	AuditLog *log.Logger
}

func (s *serverState) verify(r *http.Request) (kes.Identity, error) {
	identity, err := auth.IdentifyRequest(r.TLS)
	if err != nil {
		return identity, err
	}
	if identity == s.Admin {
		return identity, nil
	}

	_, policy, err := s.getIdentity(identity)
	if err != nil {
		if errors.Is(err, kes.ErrIdentityNotFound) {
			return "", kes.ErrNotAllowed
		}
		if errors.Is(err, kes.ErrPolicyNotFound) {
			return "", kes.ErrNotAllowed
		}
		return "", err
	}
	return identity, policy.Verify(r)
}

func (s *serverState) getIdentity(identity kes.Identity) (string, *auth.Policy, error) {
	name, ok := s.Identities[identity]
	if !ok {
		return "", nil, kes.ErrIdentityNotFound
	}
	policy, ok := s.Policies[name]
	if !ok {
		return "", nil, kes.ErrPolicyNotFound
	}
	return name, policy, nil
}

func (*serverState) handleVersion(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.VersionRespose{
		Version: sys.BinaryInfo().Version,
		Commit:  sys.BinaryInfo().CommitID,
	})
}

func (s *serverState) handleReady(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	_, err := s.Keys.Status(r.Context())
	if err != nil {
		if _, ok := kv.IsUnreachable(err); ok {
			api.Failf(w, http.StatusGatewayTimeout, err.Error())
		} else {
			api.Failf(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *serverState) handleStatus(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	response := api.StatusResponse{
		Version: sys.BinaryInfo().Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		UpTime:  time.Since(s.StartTime).Round(time.Second),

		CPUs:       runtime.NumCPU(),
		UsableCPUs: runtime.GOMAXPROCS(0),
		HeapAlloc:  memStats.HeapAlloc,
		StackAlloc: memStats.StackSys,
	}

	state, err := s.Keys.Status(r.Context())
	if err != nil {
		response.KeyStoreUnavailable = true
		_, response.KeyStoreUnreachable = kv.IsUnreachable(err)
	} else {
		latency := state.Latency.Round(time.Millisecond)
		if latency == 0 { // Make sure we actually send a latency even if the key store respond time is < 1ms.
			latency = 1 * time.Millisecond
		}
		response.KeyStoreLatency = latency.Milliseconds()
	}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (s *serverState) handleMetrics(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	contentType := expfmt.Negotiate(r.Header)
	w.Header().Set(header.ContentType, string(contentType))
	w.WriteHeader(http.StatusOK)

	s.Metrics.EncodeTo(expfmt.NewEncoder(w, contentType))
}

func (s *serverState) handleListRoutes(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	responses := make([]api.ListAPIsResponse, 0, len(s.Routes))
	for _, a := range s.Routes {
		responses = append(responses, api.ListAPIsResponse{
			Method:  a.Method,
			Path:    a.Path,
			MaxBody: a.MaxBody,
			Timeout: int64(a.Timeout.Truncate(time.Second).Seconds()),
		})
	}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responses)
}

func (s *serverState) handleCreateSecretKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyCreate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}

	var cipher crypto.SecretKeyCipher
	if fips.Mode > fips.ModeNone || cpu.HasAESGCM() {
		cipher = kes.AES256
	} else {
		cipher = kes.ChaCha20
	}

	key, err := crypto.GenerateSecretKey(cipher, rand.Reader)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if err = s.Keys.Create(r.Context(), name, crypto.SecretKeyVersion{
		Key:       key,
		CreatedAt: time.Now(),
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *serverState) handleImportSecretKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyImport, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}

	var req api.ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, err)
		return
	}

	var cipher crypto.SecretKeyCipher
	const (
		AES256   = "aes256"
		ChaCha20 = "chacha20"
	)
	switch strings.ToLower(req.Cipher) {
	case AES256:
		cipher = crypto.AES256
	case ChaCha20:
		if fips.Mode > fips.ModeNone {
			api.Failf(w, http.StatusBadRequest, "secret key cipher is not supported in FIPS mode")
			return
		}
		cipher = crypto.ChaCha20
	case "":
		api.Failf(w, http.StatusBadRequest, "no secret key cipher specified")
		return
	default:
		api.Failf(w, http.StatusBadRequest, "unknown secret key cipher '%s'", req.Cipher)
		return
	}

	key, err := crypto.NewSecretKey(cipher, req.Key)
	if err != nil {
		api.Failf(w, http.StatusBadRequest, "invalid secret key: %v", err)
		return
	}

	if err = s.Keys.Create(r.Context(), name, crypto.SecretKeyVersion{
		Key:       key,
		CreatedAt: time.Now(),
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *serverState) handleDescribeSecretKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	key, err := s.Keys.Get(r.Context(), name)
	if err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeKeyResponse{
		Version:   0,
		CreatedAt: key.CreatedAt,
		CreatedBy: key.CreatedBy,
	})
}

func (s *serverState) handleListSecretKeys(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathSecretKeyList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	const N = 250
	var names []string
	names, prefix, err = s.Keys.List(r.Context(), prefix, N)
	if err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListKeysResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *serverState) handleDeleteSecretKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	if err = s.Keys.Delete(r.Context(), name); err != nil {
		api.Fail(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *serverState) handleGenerateKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyGenerate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Failf(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := s.Keys.Get(r.Context(), name)
	if err != nil {
		api.Fail(w, err)
		return
	}

	dataKey := make([]byte, crypto.SecretKeySize)
	if _, err = rand.Read(dataKey); err != nil {
		api.Fail(w, err)
		return
	}
	ciphertext, err := key.Key.Encrypt(dataKey, req.Context)
	if err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.GenerateKeyResponse{
		Plaintext:  dataKey,
		Ciphertext: ciphertext,
	})
}

func (s *serverState) handleEncrypt(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyEncrypt, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.EncryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Failf(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := s.Keys.Get(r.Context(), name)
	if err != nil {
		api.Fail(w, err)
		return
	}

	ciphertext, err := key.Key.Encrypt(req.Plaintext, req.Context)
	if err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.EncryptKeyResponse{
		Ciphertext: ciphertext,
	})
}

func (s *serverState) handleDecrypt(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDecrypt, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.DecryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Failf(w, http.StatusBadRequest, err.Error())
		return
	}
	key, err := s.Keys.Get(r.Context(), name)
	if err != nil {
		api.Fail(w, err)
		return
	}

	ciphertext, err := decodeCiphertext(req.Ciphertext)
	if err != nil {
		api.Fail(w, err)
		return
	}
	plaintext, err := key.Key.Decrypt(ciphertext, req.Context)
	if err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DecryptKeyResponse{
		Plaintext: plaintext,
	})
}

func (s *serverState) handleDescribePolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	policy, ok := s.Policies[name]
	if !ok {
		api.Fail(w, kes.ErrPolicyNotFound)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribePolicyResponse{
		CreatedAt: policy.CreatedAt,
		CreatedBy: policy.CreatedBy,
	})
}

func (s *serverState) handleReadPolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyRead, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	policy, ok := s.Policies[name]
	if !ok {
		api.Fail(w, kes.ErrPolicyNotFound)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ReadPolicyResponse{
		Allow:     policy.Allow,
		Deny:      policy.Deny,
		CreatedAt: policy.CreatedAt,
		CreatedBy: policy.CreatedBy,
	})
}

func (s *serverState) handleListPolicies(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathPolicyList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	names := make([]string, 0, len(s.Policies))
	for name := range s.Policies {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListPoliciesResponse{Names: names})
}

func (s *serverState) handleDescribeIdentity(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	id, err := api.CutPath(r.URL, api.PathIdentityDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var name string
	if kes.Identity(id) != s.Admin {
		name, _, err = s.getIdentity(kes.Identity(id))
		if err != nil {
			api.Fail(w, err)
			return
		}
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeIdentityResponse{
		Policy:    name,
		IsAdmin:   kes.Identity(id) == s.Admin,
		CreatedAt: s.StartTime,
		CreatedBy: s.Admin,
	})
}

func (s *serverState) handleSelfDescribeIdentity(w http.ResponseWriter, r *http.Request, _ api.Verifier) {
	identity, err := auth.IdentifyRequest(r.TLS)
	if err != nil {
		api.Fail(w, err)
		return
	}

	var (
		name   string
		policy *auth.Policy
	)
	if identity != s.Admin {
		var ok bool
		name, ok = s.Identities[identity]
		if !ok {
			api.Fail(w, kes.ErrIdentityNotFound)
			return
		}
		policy = s.Policies[name]
	}

	resp := api.SelfDescribeIdentityResponse{
		Identity:  identity,
		IsAdmin:   identity == s.Admin,
		Policy:    name,
		CreatedAt: s.StartTime,
		CreatedBy: s.Admin,
	}
	if policy != nil {
		resp.Allow = policy.Allow
		resp.Deny = policy.Deny
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (s *serverState) handleListIdentities(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathIdentityDescribe, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	identities := make([]kes.Identity, 0, len(s.Identities))
	for id := range s.Identities {
		if strings.HasPrefix(id.String(), prefix) {
			identities = append(identities, id)
		}
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i] < identities[j] })

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListIdentitiesResponse{Identities: identities})
}

func (s *serverState) handleLogError(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSONLines)
	w.WriteHeader(http.StatusOK)

	out := log.NewErrEncoder(https.FlushOnWrite(w))
	s.ErrorLog.Add(out)
	defer s.ErrorLog.Remove(out)

	<-r.Context().Done() // Wait for the client to close the connection
}

func (s *serverState) handleLogAudit(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSONLines)
	w.WriteHeader(http.StatusOK)

	out := https.FlushOnWrite(w)
	s.AuditLog.Add(out)
	defer s.AuditLog.Remove(out)

	<-r.Context().Done() // Wait for the client to close the connection
}
