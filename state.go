// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/metric"
)

type serverState struct {
	Addr      net.Addr
	StartTime time.Time

	Admin      kes.Identity
	Keys       *keyCache
	Policies   map[string]*kes.Policy
	Identities map[kes.Identity]identityEntry

	Metrics *metric.Metrics
	Routes  map[string]api.Route

	LogHandler *logHandler
	Log        *slog.Logger
	Audit      *auditLogger
}

type identityEntry struct {
	Name string
	*kes.Policy
}

func initRoutes(s *Server, routeConfig map[string]RouteConfig) (*http.ServeMux, map[string]api.Route) {
	routes := map[string]api.Route{
		api.PathVersion: {
			Method:  http.MethodGet,
			Path:    api.PathVersion,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Auth:    api.InsecureSkipVerify,
			Handler: api.HandlerFunc(s.version),
		},
		api.PathReady: {
			Method:  http.MethodGet,
			Path:    api.PathReady,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.ready),
		},
		api.PathStatus: {
			Method:  http.MethodGet,
			Path:    api.PathStatus,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.status),
		},
		api.PathMetrics: {
			Method:  http.MethodGet,
			Path:    api.PathMetrics,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.metrics),
		},
		api.PathListAPIs: {
			Method:  http.MethodGet,
			Path:    api.PathListAPIs,
			MaxBody: 0,
			Timeout: 10 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.listAPIs),
		},

		api.PathKeyCreate: {
			Method:  http.MethodPut,
			Path:    api.PathKeyCreate,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.createKey),
		},
		api.PathKeyImport: {
			Method:  http.MethodPut,
			Path:    api.PathKeyImport,
			MaxBody: 1 * mem.MB,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.importKey),
		},
		api.PathKeyDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathKeyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.describeKey),
		},
		api.PathKeyList: {
			Method:  http.MethodGet,
			Path:    api.PathKeyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.listKeys),
		},
		api.PathKeyDelete: {
			Method:  http.MethodDelete,
			Path:    api.PathKeyDelete,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.deleteKey),
		},
		api.PathKeyEncrypt: {
			Method:  http.MethodPut,
			Path:    api.PathKeyEncrypt,
			MaxBody: 1 * mem.MB,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.encryptKey),
		},
		api.PathKeyGenerate: {
			Method:  http.MethodPut,
			Path:    api.PathKeyGenerate,
			MaxBody: 1 * mem.MB,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.generateKey),
		},
		api.PathKeyDecrypt: {
			Method:  http.MethodPut,
			Path:    api.PathKeyDecrypt,
			MaxBody: 1 * mem.MB,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.decryptKey),
		},
		api.PathKeyHMAC: {
			Method:  http.MethodPut,
			Path:    api.PathKeyHMAC,
			MaxBody: 1 * mem.MB,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.hmacKey),
		},

		api.PathPolicyDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.describePolicy),
		},
		api.PathPolicyRead: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyRead,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.readPolicy),
		},
		api.PathPolicyList: {
			Method:  http.MethodGet,
			Path:    api.PathPolicyList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.listPolicies),
		},

		api.PathIdentityDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathIdentityDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.describeIdentity),
		},
		api.PathIdentityList: {
			Method:  http.MethodGet,
			Path:    api.PathIdentityList,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.listIdentities),
		},
		api.PathIdentitySelfDescribe: {
			Method:  http.MethodGet,
			Path:    api.PathIdentitySelfDescribe,
			MaxBody: 0,
			Timeout: 15 * time.Second,
			Auth:    insecureIdentifyOnly{}, // Anyone can use the self-describe API as long as a client cert is provided
			Handler: api.HandlerFunc(s.selfDescribeIdentity),
		},

		api.PathLogError: {
			Method:  http.MethodGet,
			Path:    api.PathLogError,
			MaxBody: 0,
			Timeout: 0, // No timeout
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.logError),
		},
		api.PathLogAudit: {
			Method:  http.MethodGet,
			Path:    api.PathLogAudit,
			MaxBody: 0,
			Timeout: 0, // No timeout
			Auth:    (*verifyIdentity)(&s.state),
			Handler: api.HandlerFunc(s.logAudit),
		},
	}

	for path, conf := range routeConfig { // apply API customization
		route, ok := routes[path]
		if !ok {
			continue
		}
		if conf.InsecureSkipAuth {
			route.Auth = insecureIdentifyOnly{}
		}
		if conf.Timeout > 0 {
			route.Timeout = conf.Timeout
		}
		routes[path] = route
	}

	mux := http.NewServeMux()
	for path, route := range routes {
		mux.Handle(path, route)
	}
	return mux, routes
}

func initPolicies(policies map[string]Policy) (map[string]*kes.Policy, map[kes.Identity]identityEntry, error) {
	policySet := make(map[string]*kes.Policy, len(policies))
	identitySet := make(map[kes.Identity]identityEntry, len(policies))
	for name, policy := range policies {
		if !validName(name) {
			return nil, nil, fmt.Errorf("kes: policy name '%s' is empty, too long or contains invalid characters", name)
		}
		p := &kes.Policy{
			Allow: maps.Clone(policy.Allow),
			Deny:  maps.Clone(policy.Deny),
		}

		policySet[name] = p
		for _, id := range policy.Identities {
			if !validName(id.String()) {
				return nil, nil, fmt.Errorf("kes: identity '%s' is empty, too long or contains invalid characters", id)
			}
			if _, ok := identitySet[id]; ok {
				return nil, nil, fmt.Errorf("kes: cannot assign policy '%s' to '%v': identity already has a policy", name, id)
			}
			identitySet[id] = identityEntry{
				Name:   name,
				Policy: p,
			}
		}
	}
	return policySet, identitySet, nil
}
