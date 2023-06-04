package kes

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/https/header"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

func initRoutes(s *Server) (*http.ServeMux, map[string]api.API) {
	routes := map[string]api.API{
		api.PathVersion: {
			Method:  http.MethodGet,
			Path:    api.PathVersion,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.InsecureSkipVerify,
			Handler: api.HandlerFunc(s.handleVersion),
		},
		api.PathStatus: {
			Method:  http.MethodGet,
			Path:    api.PathStatus,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleStatus),
		},
		api.PathMetrics: {
			Method:  http.MethodGet,
			Path:    api.PathMetrics,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleMetrics),
		},
		api.PathListAPIs: {
			Method:  http.MethodGet,
			Path:    api.PathListAPIs,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListRoutes),
		},

		api.PathEnclaveCreate: {
			Method:  http.MethodPut,
			Path:    api.PathEnclaveCreate,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyAdmin),
			Handler: api.HandlerFunc(s.handleCreateEnclave),
		},
		api.PathEnclaveDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathEnclaveDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeEnclave),
		},
		api.PathEnclaveDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathEnclaveDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyAdmin),
			Handler: api.HandlerFunc(s.handleDeleteEnclave),
		},
		api.PathEnclaveList: {
			Method:  http.MethodGet,
			Path:    api.PathEnclaveList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListEnclaves),
		},

		api.PathSecretKeyCreate: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyCreate,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleCreateSecretKeyRing),
		},
		api.PathSecretKeyDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathSecretKeyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeSecretKeyRing),
		},
		api.PathSecretKeyDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathSecretKeyDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDeleteSecretKeyRing),
		},
		api.PathSecretKeyList: {
			Method:  http.MethodGet,
			Path:    api.PathSecretKeyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListSecretKeyRings),
		},
		api.PathSecretKeyGenerate: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyGenerate,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleGenerateKey),
		},
		api.PathSecretKeyEncrypt: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyEncrypt,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleEncrypt),
		},
		api.PathSecretKeyDecrypt: {
			Method:  http.MethodPut,
			Path:    api.PathSecretKeyDecrypt,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDecrypt),
		},

		api.PathSecretCreate: {
			Method:  http.MethodPut,
			Path:    api.PathSecretCreate,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleCreateSecret),
		},
		api.PathSecretDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathSecretDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeSecret),
		},
		api.PathSecretRead: {
			Method:  http.MethodGet,
			Path:    api.PathSecretRead,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleReadSecret),
		},
		api.PathSecretDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathSecretDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDeleteSecret),
		},
		api.PathSecretList: {
			Method:  http.MethodGet,
			Path:    api.PathSecretList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListSecrets),
		},

		api.PathPolicyCreate: {
			Method:  http.MethodPut,
			Path:    api.PathPolicyCreate,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleCreatePolicy),
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
		api.PathPolicyDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathPolicyDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDeletePolicy),
		},
		api.PathPolicyList: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListPolicies),
		},

		api.PathIdentityCreate: {
			Method:  http.MethodPut,
			Path:    api.PathIdentityCreate,
			MaxBody: int64(1 * mem.KB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleCreateIdentity),
		},
		api.PathIdentityDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathIdentityDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeIdentity),
		},
		api.PathIdentityDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathIdentityDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDeleteIdentity),
		},
		api.PathIdentityList: {
			Method:  http.MethodGet,
			Path:    api.PathIdentityList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleListIdentities),
		},
		api.PathIdentitySelfDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathIdentitySelfDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify: api.VerifyFunc(func(r *http.Request) (kes.Identity, error) {
				return auth.IdentifyRequest(r.TLS)
			}),
			Handler: api.HandlerFunc(s.handleSelfDescribeIdentity),
		},

		api.PathClusterExpand: {
			Method:  http.MethodPut,
			Path:    api.PathClusterExpand,
			MaxBody: int64(1 * mem.KB),
			Timeout: 300 * time.Second,
			Verify:  api.VerifyFunc(s.verifyAdmin),
			Handler: api.HandlerFunc(s.handleExpandCluster),
		},
		api.PathClusterDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathClusterDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleDescribeCluster),
		},
		api.PathClusterShrink: {
			Method:  http.MethodDelete,
			Path:    api.PathClusterShrink,
			MaxBody: int64(1 * mem.KB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyAdmin),
			Handler: api.HandlerFunc(s.handleShrinkCluster),
		},
		api.PathClusterBackup: {
			Method:  http.MethodGet,
			Path:    api.PathClusterBackup,
			MaxBody: 0,
			Timeout: 300 * time.Second,
			Verify:  api.VerifyFunc(s.verify),
			Handler: api.HandlerFunc(s.handleSnapshot),
		},
		api.PathClusterRestore: {
			Method:  http.MethodPut,
			Path:    api.PathClusterRestore,
			MaxBody: int64(5 * mem.GB),
			Timeout: 300 * time.Second,
			Verify:  api.VerifyFunc(s.verifyPeer),
			Handler: api.HandlerFunc(s.handleRestore),
		},

		api.PathClusterRPCForward: {
			Method:  http.MethodPut,
			Path:    api.PathClusterRPCForward,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyPeer),
			Handler: api.HandlerFunc(s.handleForwardRPC),
		},
		api.PathClusterRPCReplicate: {
			Method:  http.MethodPut,
			Path:    api.PathClusterRPCReplicate,
			MaxBody: int64(1 * mem.MB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyPeer),
			Handler: api.HandlerFunc(s.handleReplicateRPC),
		},
		api.PathClusterRPCVote: {
			Method:  http.MethodPut,
			Path:    api.PathClusterRPCVote,
			MaxBody: int64(1 * mem.KB),
			Timeout: 15 * time.Second,
			Verify:  api.VerifyFunc(s.verifyPeer),
			Handler: api.HandlerFunc(s.handleVoteRPC),
		},
	}

	mux := http.NewServeMux()
	for p, a := range routes {
		mux.Handle(p, a)
	}
	return mux, routes
}

func (s *Server) verifyAdmin(req *http.Request) (kes.Identity, error) {
	identity, err := auth.IdentifyRequest(req.TLS)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.admin.IsUnknown() {
		if identity == s.apiKey.Identity() {
			return identity, nil
		}
	} else if s.admin == identity {
		return identity, nil
	}
	return "", kes.ErrNotAllowed
}

func (s *Server) verifyPeer(req *http.Request) (kes.Identity, error) {
	identity, err := auth.IdentifyRequest(req.TLS)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if identity == s.apiKey.Identity() {
		return identity, nil
	}
	return "", kes.ErrNotAllowed
}

func (s *Server) verify(req *http.Request) (kes.Identity, error) {
	identity, err := auth.IdentifyRequest(req.TLS)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.admin.IsUnknown() {
		if identity == s.apiKey.Identity() {
			return identity, nil
		}
	} else if s.admin == identity {
		return identity, nil
	}

	enclave := readEnclaveHeader(req.Header)
	if err := s.db.View(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			if errors.Is(err, kes.ErrEnclaveNotFound) {
				return kes.ErrNotAllowed
			}
			return err
		}

		info, err := readIdentity(tx, enc.Key, enclave, identity.String())
		if err != nil {
			if errors.Is(err, kes.ErrEnclaveNotFound) {
				return kes.ErrNotAllowed
			}
			return err
		}
		if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
			return kes.ErrNotAllowed
		}
		if info.IsAdmin {
			return nil
		}

		policy, err := readPolicy(tx, enc.Key, enclave, info.Policy)
		if err != nil {
			if errors.Is(err, kes.ErrPolicyNotFound) {
				return kes.ErrNotAllowed
			}
			return err
		}
		return policy.Verify(req)
	}); err != nil {
		return "", err
	}
	return identity, nil
}

func (s *Server) view(fn func(tx *bolt.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.db.View(fn)
}

func (s *Server) apply(ctx context.Context, cmd command) error {
	binCmd, err := encodeEvent(cmd)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.state.Load() != Leader {
		if s.leaderID == s.id {
			s.mu.Unlock()

			// This might happen when the node is not able to
			// join a cluster, and therefore, fails to receive
			// replication requests from the leader. If the Node's
			// ID (within the cluster) happens to be 0 - which is
			// also the default value on startup - then the node
			// is in Follower state but the leader ID still points to
			// itself.
			// TODO: log this situation
			return kes.NewError(http.StatusInternalServerError, "cluster: cannot accept request: leader is unknown")
		}
		leader, ok := s.cluster[s.leaderID]
		if !ok {
			s.mu.Unlock()

			// TODO: log this situation
			return kes.NewError(http.StatusInternalServerError, "cluster: cannot accept request: no leader")
		}
		self, client := s.id, s.client
		s.mu.Unlock()

		return forward(ctx, client, leader, api.ForwardRPCRequest{
			NodeID:      self,
			CommandType: cmd.Type(),
			Command:     binCmd,
		})
	}
	defer s.mu.Unlock()

	if !s.eventReplicated.Load() {
		var wg errgroup.Group
		for id, addr := range s.cluster {
			if id == s.id {
				continue
			}
			addr := addr

			wg.Go(func() error {
				return replicate(s.ctx, s.client, addr, api.ReplicateRPCRequest{
					NodeID:      s.id,
					Commit:      s.commit.N,
					CommandType: s.commit.Type,
					Command:     s.commit.Command,
				})
			})
		}
		if err := wg.Wait(); err != nil {
			return errors.Join(kes.ErrPartialWrite, err)
		}
	}
	s.eventReplicated.Store(true)
	if s.shutdown.Load() {
		s.stop(s.db.Close())
		return nil
	}

	commit := commit{
		N:       s.commit.N + 1,
		Type:    cmd.Type(),
		Command: binCmd,
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		if err := cmd.Apply(s, tx); err != nil {
			return err
		}
		if err := writeCommit(tx, s.rootKey, commit); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}); err != nil {
		return err
	}
	s.commit = commit
	s.eventReplicated.Store(false)

	var wg errgroup.Group
	for id, addr := range s.cluster {
		if id == s.id {
			continue
		}
		addr := addr

		wg.Go(func() error {
			return replicate(s.ctx, s.client, addr, api.ReplicateRPCRequest{
				NodeID:      s.id,
				Commit:      s.commit.N,
				CommandType: s.commit.Type,
				Command:     s.commit.Command,
			})
		})
	}
	if err := wg.Wait(); err != nil {
		return err
	}
	s.eventReplicated.Store(true)

	if s.shutdown.Load() {
		s.stop(s.db.Close())
		return nil
	}
	return nil
}

func (*Server) handleVersion(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.VersionRespose{
		Version: sys.BinaryInfo().Version,
		Commit:  sys.BinaryInfo().CommitID,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, v api.Verifier) {
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
		UpTime:  time.Since(s.startTime).Round(time.Second),

		CPUs:       runtime.NumCPU(),
		UsableCPUs: runtime.GOMAXPROCS(0),
		HeapAlloc:  memStats.HeapAlloc,
		StackAlloc: memStats.StackSys,
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (*Server) handleMetrics(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	contentType := expfmt.Negotiate(r.Header)
	w.Header().Set(header.ContentType, string(contentType))
	w.WriteHeader(http.StatusOK)

	metric.New().EncodeTo(expfmt.NewEncoder(w, contentType))
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.RLock()
	routes := maps.Clone(s.routes)
	s.mu.RUnlock()

	responses := make([]api.ListAPIsResponse, 0, len(routes))
	for _, a := range routes {
		responses = append(responses, api.ListAPIsResponse{
			Method:  a.Method,
			Path:    a.Path,
			MaxBody: a.MaxBody,
			Timeout: int64(a.Timeout.Truncate(time.Second).Seconds()),
		})
	}
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responses)
}

func (s *Server) handleCreateEnclave(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathEnclaveCreate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}

	key, err := crypto.GenerateSecretKey(crypto.AES256, rand.Reader)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if err = s.apply(r.Context(), &createEnclaveCmd{
		Name:      name,
		Key:       key,
		CreatedAt: time.Now().UTC(),
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribeEnclave(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathEnclaveDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var enclave *Enclave
	if err = s.view(func(tx *bolt.Tx) error {
		enclave, err = readEnclave(tx, s.rootKey, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&api.DescribeEnclaveResponse{
		Name:      name,
		CreatedAt: enclave.CreatedAt,
		CreatedBy: enclave.CreatedBy,
	})
}

func (s *Server) handleListEnclaves(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathEnclaveList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var names []string
	if err = s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			names, prefix = []string{}, ""
			return nil
		}

		const N = 250
		names, prefix = listBuckets(b, prefix, N)
		return nil
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListEnclavesResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *Server) handleDeleteEnclave(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathEnclaveDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	if err := s.apply(r.Context(), &deleteEnclaveCmd{Name: name}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCreateSecretKeyRing(w http.ResponseWriter, r *http.Request, v api.Verifier) {
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

	cipher := crypto.AES256
	if fips.Mode == fips.ModeNone && !cpu.HasAESGCM() {
		cipher = crypto.ChaCha20
	}
	key, err := crypto.GenerateSecretKey(cipher, nil)
	if err != nil {
		api.Fail(w, err)
		return
	}

	if err := s.apply(r.Context(), &createSecretKeyRingCmd{
		Enclave:   readEnclaveHeader(r.Header),
		Name:      name,
		Key:       key,
		CreatedAt: time.Now().UTC(),
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribeSecretKeyRing(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var ring *crypto.SecretKeyRing
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		ring, err = readSecretKeyRing(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	key, version := ring.Latest()
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeKeyResponse{
		Name:      name,
		Version:   version,
		CreatedAt: key.CreatedAt,
		CreatedBy: key.CreatedBy,
	})
}

func (s *Server) handleDeleteSecretKeyRing(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	if err := s.apply(r.Context(), &deleteSecretKeyRingCmd{
		Enclave: enclave,
		Name:    name,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListSecretKeyRings(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathSecretKeyList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var names []string
	if err = s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(enclave))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(dbSecretKeyBucket))
		if b == nil {
			prefix = ""
			return nil
		}

		const N = 250
		names, prefix = listKeys[string](b, prefix, N)
		return nil
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListKeysResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *Server) handleGenerateKey(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyGenerate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.GenerateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	var ring *crypto.SecretKeyRing
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		ring, err = readSecretKeyRing(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	key, version := ring.Latest()
	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		api.Fail(w, err)
		return
	}
	ciphertext, err := key.Key.Encrypt(dataKey, req.Context)
	if err != nil {
		api.Fail(w, err)
		return
	}
	ciphertext = binary.LittleEndian.AppendUint32(ciphertext, version)

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.GenerateKeyResponse{
		Plaintext:  dataKey,
		Ciphertext: ciphertext,
	})
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyEncrypt, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.EncryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	var ring *crypto.SecretKeyRing
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		ring, err = readSecretKeyRing(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	key, version := ring.Latest()
	ciphertext, err := key.Key.Encrypt(req.Plaintext, req.Context)
	if err != nil {
		api.Fail(w, err)
		return
	}
	ciphertext = binary.LittleEndian.AppendUint32(ciphertext, version)

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.EncryptKeyResponse{
		Ciphertext: ciphertext,
	})
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretKeyDecrypt, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.DecryptKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	if len(req.Ciphertext) < 4 {
		api.Fail(w, kes.ErrDecrypt)
		return
	}
	l := len(req.Ciphertext)
	version := binary.LittleEndian.Uint32(req.Ciphertext[l-4:])
	ciphertext := req.Ciphertext[: l-4 : l-4]

	var ring *crypto.SecretKeyRing
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		ring, err = readSecretKeyRing(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	key, ok := ring.Get(version)
	if !ok {
		api.Fail(w, kes.ErrKeyNotFound)
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

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyCreate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.CreatePolicyRequest
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	if err = s.apply(r.Context(), &createPolicyCmd{
		Enclave:   enclave,
		Name:      name,
		Allow:     req.Allow,
		Deny:      req.Deny,
		CreatedAt: time.Now().UTC(),
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribePolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var policy *auth.Policy
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		policy, err = readPolicy(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribePolicyResponse{
		CreatedAt: policy.CreatedAt,
		CreatedBy: policy.CreatedBy,
	})
}

func (s *Server) handleReadPolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyRead, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var policy *auth.Policy
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		policy, err = readPolicy(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
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

func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathPolicyDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	if err = s.apply(r.Context(), &deletePolicyCmd{
		Enclave: enclave,
		Name:    name,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathPolicyList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var names []string
	if err = s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(enclave))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(dbPolicyBucket))
		if b == nil {
			prefix = ""
			return nil
		}

		const N = 250
		names, prefix = listKeys[string](b, prefix, N)
		return nil
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListKeysResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretCreate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
	}

	if err := s.apply(r.Context(), &createSecretCmd{
		Enclave:    enclave,
		Name:       name,
		Secret:     req.Secret,
		SecretType: crypto.SecretTypeGeneric,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribeSecret(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var secret *crypto.Secret
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		secret, err = readSecret(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	key, version := secret.Latest()
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeSecretResponse{
		Version:   version,
		CreatedAt: key.CreatedAt,
		CreatedBy: key.CreatedBy,
	})
}

func (s *Server) handleReadSecret(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretRead, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var secret *crypto.Secret
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		secret, err = readSecret(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	sec, version := secret.Latest()
	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ReadSecretResponse{
		Version:   version,
		Value:     sec.Value,
		CreatedAt: sec.CreatedAt,
		CreatedBy: sec.CreatedBy,
	})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathSecretDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	if err := s.apply(r.Context(), &deleteSecretCmd{
		Enclave: enclave,
		Name:    name,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathSecretList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var names []string
	if err = s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(enclave))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(dbSecretBucket))
		if b == nil {
			prefix = ""
			return nil
		}

		const N = 250
		names, prefix = listKeys[string](b, prefix, N)
		return nil
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListKeysResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *Server) handleCreateIdentity(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathIdentityCreate, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var req api.CreateIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
	}

	var (
		now       = time.Now().UTC()
		ttl       time.Duration
		expiresAt time.Time
	)
	if req.TTL != "" {
		ttl, err = time.ParseDuration(req.TTL)
		if err != nil {
			api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
			return
		}
		if ttl > 0 {
			expiresAt = now.Add(ttl)
		}
	}

	if err := s.apply(r.Context(), &createIdentityCmd{
		Enclave:   enclave,
		Identity:  kes.Identity(name),
		Policy:    req.Policy,
		IsAdmin:   req.IsAdmin,
		TTL:       ttl,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		CreatedBy: identity,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribeIdentity(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathIdentityDescribe, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var info *auth.Identity
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		info, err = readIdentity(tx, enc.Key, enclave, name)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	var ttl string
	if info.TTL > 0 {
		ttl = info.TTL.String()
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeIdentityResponse{
		Policy:    info.Policy,
		IsAdmin:   info.IsAdmin,
		Children:  info.Children.Slice(),
		TTL:       ttl,
		ExpiresAt: info.ExpiresAt.UTC(),
		CreatedAt: info.CreatedAt.UTC(),
		CreatedBy: info.CreatedBy,
	})
}

func (s *Server) handleDeleteIdentity(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	name, err := api.CutPath(r.URL, api.PathIdentityDelete, api.IsValidName)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	if err := s.apply(r.Context(), &deleteIdentityCmd{
		Enclave:  enclave,
		Identity: kes.Identity(name),
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListIdentities(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	prefix, err := api.CutPath(r.URL, api.PathIdentityList, api.IsValidPrefix)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if _, err = v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	enclave := readEnclaveHeader(r.Header)

	var ids []kes.Identity
	if err = s.view(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(dbEnclaveBucket))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(enclave))
		if b == nil {
			return kes.ErrEnclaveNotFound
		}
		b = b.Bucket([]byte(dbIdentityBucket))
		if b == nil {
			prefix = ""
			return nil
		}

		const N = 250
		ids, prefix = listKeys[kes.Identity](b, prefix, N)
		return nil
	}); err != nil {
		api.Fail(w, err)
		return
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.ListIdentitiesResponse{
		Identities: ids,
		ContinueAt: prefix,
	})
}

func (s *Server) handleSelfDescribeIdentity(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	identity, err := v.Verify(r)
	if err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.RLock()
	admin, apiKey := s.admin, s.apiKey
	s.mu.RUnlock()

	if (!admin.IsUnknown() && admin == identity) || apiKey.Identity() == identity {
		w.Header().Set(header.ContentType, header.ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(api.SelfDescribeIdentityResponse{
			Identity: identity,
		})
		return
	}

	var (
		info    *auth.Identity
		policy  *auth.Policy
		enclave = readEnclaveHeader(r.Header)
	)
	if err = s.view(func(tx *bolt.Tx) error {
		enc, err := readEnclave(tx, s.rootKey, enclave)
		if err != nil {
			return err
		}
		info, err = readIdentity(tx, enc.Key, enclave, identity.String())
		if err != nil {
			return err
		}
		if info.IsAdmin || info.Policy == "" {
			return nil
		}

		policy, err = readPolicy(tx, enc.Key, enclave, info.Policy)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}

	var (
		ttl         string
		allow, deny map[string]auth.Rule
	)
	if info.TTL > 0 {
		ttl = info.TTL.String()
	}
	if policy != nil {
		allow, deny = policy.Allow, policy.Deny
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.SelfDescribeIdentityResponse{
		Identity:  info.Identity,
		IsAdmin:   info.IsAdmin,
		Children:  info.Children.Slice(),
		TTL:       ttl,
		ExpiresAt: info.ExpiresAt.UTC(),
		CreatedAt: info.CreatedAt.UTC(),
		CreatedBy: info.CreatedBy,
		Policy:    info.Policy,
		Allow:     allow,
		Deny:      deny,
	})
}

func (s *Server) handleExpandCluster(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.ExpandClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	addr, err := ParseAddr(req.NodeAddr)
	if err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	if err = s.view(func(tx *bolt.Tx) error {
		// TODO(aead): Avoid pipe. One option may be to copy the metadata buffer (2*PageSize)
		// and then open the DB file. (ref Tx.WriteTo implementation). Use io.MultiReader.

		pr, pw := io.Pipe()
		defer pr.Close()

		go func() {
			_, wErr := tx.WriteTo(pw)
			pw.CloseWithError(wErr)
		}()
		client := *s.client
		client.Timeout = 300 * time.Second
		return expandCluster(r.Context(), &client, addr, pr, tx.Size())
	}); err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.RLock()
	cluster := maps.Clone(s.cluster)
	s.mu.RUnlock()

	if _, ok := cluster.Lookup(addr); ok {
		api.Fail(w, kes.NewError(http.StatusConflict, "node is already part of the cluster"))
		return
	}
	if err := s.apply(r.Context(), &joinClusterCmd{
		Cluster: cluster,
		Node:    addr,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleShrinkCluster(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.ShrinkClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}
	addr, err := ParseAddr(req.NodeAddr)
	if err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.RLock()
	cluster := maps.Clone(s.cluster)
	s.mu.RUnlock()

	if _, ok := cluster.Lookup(addr); !ok {
		api.Fail(w, kes.NewError(http.StatusConflict, "node is not part of the cluster"))
		return
	}
	if err = s.apply(r.Context(), &leaveClusterCmd{
		Cluster: cluster,
		Node:    addr,
	}); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDescribeCluster(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.RLock()
	leader, cluster := s.leaderID, maps.Clone(s.cluster)
	s.mu.RUnlock()

	nodes := make(map[uint64]string, len(cluster))
	for id, addr := range cluster {
		nodes[uint64(id)] = addr.String()
	}

	w.Header().Set(header.ContentType, header.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(api.DescribeClusterResponse{
		Nodes:  nodes,
		Leader: uint64(leader),
	})
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.OpenFile(filepath.Join(s.path, "kes.db.new"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_SYNC, 0o644)
	if err != nil {
		api.Fail(w, err)
		return
	}
	defer tmp.Close()

	if _, err = io.Copy(tmp, r.Body); err != nil {
		api.Fail(w, err)
		return
	}
	if err = tmp.Sync(); err != nil {
		api.Fail(w, err)
		return
	}
	if err = tmp.Close(); err != nil {
		api.Fail(w, err)
		return
	}

	if err = s.db.Close(); err != nil {
		api.Fail(w, err)
		return
	}
	if err := os.Rename(filepath.Join(s.path, "kes.db.new"), filepath.Join(s.path, "kes.db")); err != nil {
		api.Fail(w, err)
		return
	}

	s.db, err = bolt.Open(filepath.Join(s.path, "kes.db"), 0o644, &bolt.Options{
		FreelistType: bolt.FreelistMapType,
		Timeout:      3 * time.Second,
	})
	if err != nil {
		api.Fail(w, err)
		return
	}

	rootKey, commit, err := initState(s.ctx, s.db, s.hsm)
	if err != nil {
		api.Fail(w, err)
		return
	}
	s.rootKey, s.commit = rootKey, commit
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	if err := s.view(func(tx *bolt.Tx) error {
		w.Header().Set(header.ContentType, "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(tx.Size(), 10))
		w.WriteHeader(http.StatusOK)

		_, err := tx.WriteTo(w)
		return err
	}); err != nil {
		api.Fail(w, err)
		return
	}
}

func (s *Server) handleReplicateRPC(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.ReplicateRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state.Load() == Leader {
		if len(s.cluster) > 1 {
			api.Failf(w, http.StatusConflict, "replication rejected: not a follower")
			return
		}
	}
	if s.commit.N > req.Commit {
		api.Failf(w, http.StatusConflict, fmt.Sprintf("replication rejected: ahead of commit '%d'", req.Commit))
		return
	}

	s.state.Store(Follower)
	s.leaderID = req.NodeID
	s.heartbeatReceived.Store(true)
	s.eventReplicated.Store(false)

	if s.commit.N == req.Commit {
		w.WriteHeader(http.StatusOK)
		return
	}

	event, err := decodeEvent(req.CommandType, req.Command)
	if err != nil {
		api.Fail(w, err)
		return
	}

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if s.commit.N != req.Commit {
			if err := event.Apply(s, tx); err != nil {
				return err
			}
		}
		return writeCommit(tx, s.rootKey, commit{N: req.Commit, Type: req.CommandType, Command: req.Command})
	}); err != nil {
		api.Fail(w, err)
		return
	}

	s.commit = commit{
		N:       req.Commit,
		Type:    req.CommandType,
		Command: req.Command,
	}
	w.WriteHeader(http.StatusOK)

	if s.shutdown.Load() {
		s.stop(s.db.Close())
	}
}

func (s *Server) handleVoteRPC(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}

	var req api.VoteRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	s.mu.RLock()
	kind, commit, nNodes := s.state.Load(), s.commit.N, len(s.cluster)
	s.mu.RUnlock()

	if kind != Follower && nNodes > 1 {
		api.Fail(w, kes.NewError(http.StatusConflict, "vote not granted: not a follower"))
		return
	}
	if commit > req.Commit {
		api.Fail(w, kes.NewError(http.StatusConflict, fmt.Sprintf("vote not granted: ahead of '%d'", s.commit)))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleForwardRPC(w http.ResponseWriter, r *http.Request, v api.Verifier) {
	if _, err := v.Verify(r); err != nil {
		api.Fail(w, err)
		return
	}
	if s.state.Load() != Leader {
		api.Fail(w, kes.NewError(http.StatusConflict, "not a leader"))
		return
	}

	var req api.ForwardRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Fail(w, kes.NewError(http.StatusBadRequest, err.Error()))
		return
	}

	event, err := decodeEvent(req.CommandType, req.Command)
	if err != nil {
		api.Fail(w, err)
		return
	}
	if err = s.apply(r.Context(), event); err != nil {
		api.Fail(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
