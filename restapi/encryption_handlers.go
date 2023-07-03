// This file is part of MinIO KES
// Copyright (c) 2023 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

package restapi

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/minio/kes-go"
	"github.com/minio/kes/models"
	"github.com/minio/kes/restapi/operations"
	"github.com/minio/kes/restapi/operations/encryption"
)

func registerEncryptionHandlers(api *operations.KesAPI) {
	registerEncryptionStatusHandlers(api)
	registerEncryptionKeyHandlers(api)
	registerEncryptionPolicyHandlers(api)
	registerEncryptionIdentityHandlers(api)
	registerEncryptionSecretHandlers(api)
}

func registerEncryptionStatusHandlers(api *operations.KesAPI) {
	api.EncryptionMetricsHandler = encryption.MetricsHandlerFunc(func(params encryption.MetricsParams, session *models.Principal) middleware.Responder {
		resp, err := getMetricsResponse(session, params)
		if err != nil {
			return encryption.NewMetricsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewMetricsOK().WithPayload(resp)
	})

	api.EncryptionAPIsHandler = encryption.APIsHandlerFunc(func(params encryption.APIsParams, session *models.Principal) middleware.Responder {
		resp, err := getAPIsResponse(session, params)
		if err != nil {
			return encryption.NewAPIsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAPIsOK().WithPayload(resp)
	})

	api.EncryptionVersionHandler = encryption.VersionHandlerFunc(func(params encryption.VersionParams, session *models.Principal) middleware.Responder {
		resp, err := getVersionResponse(session, params)
		if err != nil {
			return encryption.NewVersionDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewVersionOK().WithPayload(resp)
	})
}

func getMetricsResponse(session *models.Principal, params encryption.MetricsParams) (*models.EncryptionMetricsResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return getMetrics(ctx, KESClient{Client: kesClient})
}

func getMetrics(ctx context.Context, kesClient KESClientI) (*models.EncryptionMetricsResponse, *models.Error) {
	metrics, err := kesClient.metrics(ctx)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	rok := int64(metrics.RequestOK)
	rerr := int64(metrics.RequestErr)
	rf := int64(metrics.RequestFail)
	ra := int64(metrics.RequestActive)
	ae := int64(metrics.AuditEvents)
	ee := int64(metrics.ErrorEvents)
	up := int64(metrics.UpTime)
	cpus := int64(metrics.CPUs)
	ucpus := int64(metrics.UsableCPUs)
	t := int64(metrics.Threads)
	ha := int64(metrics.HeapAlloc)
	ho := int64(metrics.HeapObjects)
	sa := int64(metrics.StackAlloc)
	return &models.EncryptionMetricsResponse{
		RequestOK:        &rok,
		RequestErr:       &rerr,
		RequestFail:      &rf,
		RequestActive:    &ra,
		AuditEvents:      &ae,
		ErrorEvents:      &ee,
		LatencyHistogram: parseHistogram(metrics.LatencyHistogram),
		Uptime:           &up,
		Cpus:             &cpus,
		UsableCPUs:       &ucpus,
		Threads:          &t,
		HeapAlloc:        &ha,
		HeapObjects:      ho,
		StackAlloc:       &sa,
	}, nil
}

func parseHistogram(histogram map[time.Duration]uint64) (records []*models.EncryptionLatencyHistogram) {
	for duration, total := range histogram {
		records = append(records, &models.EncryptionLatencyHistogram{Duration: int64(duration), Total: int64(total)})
	}
	cp := func(i, j int) bool {
		return records[i].Duration < records[j].Duration
	}
	sort.Slice(records, cp)
	return records
}

func getAPIsResponse(session *models.Principal, params encryption.APIsParams) (*models.EncryptionAPIsResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return getAPIs(ctx, KESClient{Client: kesClient})
}

func getAPIs(ctx context.Context, kesClient KESClientI) (*models.EncryptionAPIsResponse, *models.Error) {
	apis, err := kesClient.apis(ctx)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionAPIsResponse{
		Results: parseApis(apis),
	}, nil
}

func parseApis(apis []kes.API) (data []*models.EncryptionAPI) {
	for _, api := range apis {
		data = append(data, &models.EncryptionAPI{
			Method:  api.Method,
			Path:    api.Path,
			MaxBody: api.MaxBody,
			Timeout: int64(api.Timeout),
		})
	}
	return data
}

func getVersionResponse(session *models.Principal, params encryption.VersionParams) (*models.EncryptionVersionResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return getVersion(ctx, KESClient{Client: kesClient})
}

func getVersion(ctx context.Context, kesClient KESClientI) (*models.EncryptionVersionResponse, *models.Error) {
	version, err := kesClient.version(ctx)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionVersionResponse{
		Version: version,
	}, nil
}

func registerEncryptionKeyHandlers(api *operations.KesAPI) {
	api.EncryptionCreateKeyHandler = encryption.CreateKeyHandlerFunc(func(params encryption.CreateKeyParams, session *models.Principal) middleware.Responder {
		err := getCreateKeyResponse(session, params)
		if err != nil {
			return encryption.NewCreateKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewCreateKeyCreated()
	})

	api.EncryptionImportKeyHandler = encryption.ImportKeyHandlerFunc(func(params encryption.ImportKeyParams, session *models.Principal) middleware.Responder {
		err := getImportKeyResponse(session, params)
		if err != nil {
			return encryption.NewImportKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewImportKeyCreated()
	})

	api.EncryptionListKeysHandler = encryption.ListKeysHandlerFunc(func(params encryption.ListKeysParams, session *models.Principal) middleware.Responder {
		resp, err := getListKeysResponse(session, params)
		if err != nil {
			return encryption.NewListKeysDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListKeysOK().WithPayload(resp)
	})

	api.EncryptionDescribeKeyHandler = encryption.DescribeKeyHandlerFunc(func(params encryption.DescribeKeyParams, session *models.Principal) middleware.Responder {
		resp, err := getDescribeKeyResponse(session, params)
		if err != nil {
			return encryption.NewDescribeKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeKeyOK().WithPayload(resp)
	})

	api.EncryptionDeleteKeyHandler = encryption.DeleteKeyHandlerFunc(func(params encryption.DeleteKeyParams, session *models.Principal) middleware.Responder {
		err := getDeleteKeyResponse(session, params)
		if err != nil {
			return encryption.NewDeleteKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteKeyOK()
	})
}

func getCreateKeyResponse(session *models.Principal, params encryption.CreateKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return createKey(ctx, *params.Body.Key, KESClient{Client: kesClient, enclave: params.Enclave})
}

func createKey(ctx context.Context, key string, kesClient KESClientI) *models.Error {
	if err := kesClient.createKey(ctx, key); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func getImportKeyResponse(session *models.Principal, params encryption.ImportKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	bytes, err := json.Marshal(params.Body)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return importKey(ctx, params.Name, bytes, KESClient{Client: kesClient, enclave: params.Enclave})
}

func importKey(ctx context.Context, key string, bytes []byte, kesClient KESClientI) *models.Error {
	if err := kesClient.importKey(ctx, key, bytes); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func getListKeysResponse(session *models.Principal, params encryption.ListKeysParams) (*models.EncryptionListKeysResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listKeys(ctx, pattern, KESClient{Client: kesClient, enclave: params.Enclave})
}

func listKeys(ctx context.Context, pattern string, kesClient KESClientI) (*models.EncryptionListKeysResponse, *models.Error) {
	iterator, err := kesClient.listKeys(ctx, pattern)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}

	keys, err := iterator.Values(0)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	if err = iterator.Close(); err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionListKeysResponse{Results: parseKeys(keys)}, nil
}

func parseKeys(results []kes.KeyInfo) (data []*models.EncryptionKeyInfo) {
	for _, key := range results {
		data = append(data, &models.EncryptionKeyInfo{
			CreatedAt: key.CreatedAt.String(),
			CreatedBy: key.CreatedBy.String(),
			Name:      key.Name,
		})
	}
	return data
}

func getDescribeKeyResponse(session *models.Principal, params encryption.DescribeKeyParams) (*models.EncryptionDescribeKeyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeKey(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func describeKey(ctx context.Context, key string, kesClient KESClientI) (*models.EncryptionDescribeKeyResponse, *models.Error) {
	k, err := kesClient.describeKey(ctx, key)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionDescribeKeyResponse{
		Name:      k.Name,
		ID:        k.ID,
		Algorithm: k.Algorithm.String(),
		CreatedAt: k.CreatedAt.String(),
		CreatedBy: k.CreatedBy.String(),
	}, nil
}

func getDeleteKeyResponse(session *models.Principal, params encryption.DeleteKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deleteKey(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func deleteKey(ctx context.Context, key string, kesClient KESClientI) *models.Error {
	if err := kesClient.deleteKey(ctx, key); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func registerEncryptionPolicyHandlers(api *operations.KesAPI) {
	api.EncryptionSetPolicyHandler = encryption.SetPolicyHandlerFunc(func(params encryption.SetPolicyParams, session *models.Principal) middleware.Responder {
		err := getSetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewSetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewSetPolicyOK()
	})

	api.EncryptionAssignPolicyHandler = encryption.AssignPolicyHandlerFunc(func(params encryption.AssignPolicyParams, session *models.Principal) middleware.Responder {
		err := getAssignPolicyResponse(session, params)
		if err != nil {
			return encryption.NewAssignPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAssignPolicyOK()
	})

	api.EncryptionDescribePolicyHandler = encryption.DescribePolicyHandlerFunc(func(params encryption.DescribePolicyParams, session *models.Principal) middleware.Responder {
		resp, err := getDescribePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDescribePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribePolicyOK().WithPayload(resp)
	})

	api.EncryptionGetPolicyHandler = encryption.GetPolicyHandlerFunc(func(params encryption.GetPolicyParams, session *models.Principal) middleware.Responder {
		resp, err := getGetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewGetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewGetPolicyOK().WithPayload(resp)
	})

	api.EncryptionListPoliciesHandler = encryption.ListPoliciesHandlerFunc(func(params encryption.ListPoliciesParams, session *models.Principal) middleware.Responder {
		resp, err := getListPoliciesResponse(session, params)
		if err != nil {
			return encryption.NewListPoliciesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListPoliciesOK().WithPayload(resp)
	})

	api.EncryptionDeletePolicyHandler = encryption.DeletePolicyHandlerFunc(func(params encryption.DeletePolicyParams, session *models.Principal) middleware.Responder {
		err := getDeletePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDeletePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeletePolicyOK()
	})
}

func getSetPolicyResponse(session *models.Principal, params encryption.SetPolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	bytes, err := json.Marshal(params.Body)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return setPolicy(ctx, *params.Body.Policy, bytes, KESClient{Client: kesClient, enclave: params.Enclave})
}

func setPolicy(ctx context.Context, name string, content []byte, kesClient KESClientI) *models.Error {
	var policy kes.Policy
	if err := json.Unmarshal(content, &policy); err != nil {
		newDefaultAPIError(err)
	}
	if err := kesClient.setPolicy(ctx, name, &policy); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func getAssignPolicyResponse(session *models.Principal, params encryption.AssignPolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return assignPolicy(ctx, params.Name, params.Body.Identity, KESClient{Client: kesClient, enclave: params.Enclave})
}

func assignPolicy(ctx context.Context, policy, identity string, kesClient KESClientI) *models.Error {
	if err := kesClient.assignPolicy(ctx, policy, identity); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func getDescribePolicyResponse(session *models.Principal, params encryption.DescribePolicyParams) (*models.EncryptionDescribePolicyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describePolicy(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func describePolicy(ctx context.Context, policy string, kesClient KESClientI) (*models.EncryptionDescribePolicyResponse, *models.Error) {
	dp, err := kesClient.describePolicy(ctx, policy)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionDescribePolicyResponse{
		Name:      dp.Name,
		CreatedAt: dp.CreatedAt.String(),
		CreatedBy: dp.CreatedBy.String(),
	}, nil
}

func getGetPolicyResponse(session *models.Principal, params encryption.GetPolicyParams) (*models.EncryptionGetPolicyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return getPolicy(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func getPolicy(ctx context.Context, policy string, kesClient KESClientI) (*models.EncryptionGetPolicyResponse, *models.Error) {
	p, err := kesClient.getPolicy(ctx, policy)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionGetPolicyResponse{
		Allow: p.Allow,
		Deny:  p.Deny,
	}, nil
}

func getListPoliciesResponse(session *models.Principal, params encryption.ListPoliciesParams) (*models.EncryptionListPoliciesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listPolicies(ctx, pattern, KESClient{Client: kesClient, enclave: params.Enclave})
}

func listPolicies(ctx context.Context, pattern string, kesClient KESClientI) (*models.EncryptionListPoliciesResponse, *models.Error) {
	iterator, err := kesClient.listPolicies(ctx, pattern)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}

	policies, err := iterator.Values(0)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	if err = iterator.Close(); err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionListPoliciesResponse{Results: parsePolicies(policies)}, nil
}

func parsePolicies(results []kes.PolicyInfo) (data []*models.EncryptionPolicyInfo) {
	for _, policy := range results {
		data = append(data, &models.EncryptionPolicyInfo{
			CreatedAt: policy.CreatedAt.String(),
			CreatedBy: policy.CreatedBy.String(),
			Name:      policy.Name,
		})
	}
	return data
}

func getDeletePolicyResponse(session *models.Principal, params encryption.DeletePolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deletePolicy(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func deletePolicy(ctx context.Context, policy string, kesClient KESClientI) *models.Error {
	if err := kesClient.deletePolicy(ctx, policy); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func registerEncryptionIdentityHandlers(api *operations.KesAPI) {
	api.EncryptionDescribeIdentityHandler = encryption.DescribeIdentityHandlerFunc(func(params encryption.DescribeIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := getDescribeIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeIdentityOK().WithPayload(resp)
	})

	api.EncryptionDescribeSelfIdentityHandler = encryption.DescribeSelfIdentityHandlerFunc(func(params encryption.DescribeSelfIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := getDescribeSelfIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeSelfIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeSelfIdentityOK().WithPayload(resp)
	})

	api.EncryptionListIdentitiesHandler = encryption.ListIdentitiesHandlerFunc(func(params encryption.ListIdentitiesParams, session *models.Principal) middleware.Responder {
		resp, err := getListIdentitiesResponse(session, params)
		if err != nil {
			return encryption.NewListIdentitiesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListIdentitiesOK().WithPayload(resp)
	})
	api.EncryptionDeleteIdentityHandler = encryption.DeleteIdentityHandlerFunc(func(params encryption.DeleteIdentityParams, session *models.Principal) middleware.Responder {
		err := getDeleteIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDeleteIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteIdentityOK()
	})
}

func getDescribeIdentityResponse(session *models.Principal, params encryption.DescribeIdentityParams) (*models.EncryptionDescribeIdentityResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeIdentity(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func describeIdentity(ctx context.Context, identity string, kesClient KESClientI) (*models.EncryptionDescribeIdentityResponse, *models.Error) {
	i, err := kesClient.describeIdentity(ctx, identity)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionDescribeIdentityResponse{
		Policy:    i.Policy,
		Admin:     i.IsAdmin,
		Identity:  i.Identity.String(),
		CreatedAt: i.CreatedAt.String(),
		CreatedBy: i.CreatedBy.String(),
	}, nil
}

func getDescribeSelfIdentityResponse(session *models.Principal, params encryption.DescribeSelfIdentityParams) (*models.EncryptionDescribeSelfIdentityResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeSelfIdentity(ctx, KESClient{Client: kesClient, enclave: params.Enclave})
}

func describeSelfIdentity(ctx context.Context, kesClient KESClientI) (*models.EncryptionDescribeSelfIdentityResponse, *models.Error) {
	i, p, err := kesClient.describeSelfIdentity(ctx)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionDescribeSelfIdentityResponse{
		Policy: &models.EncryptionGetPolicyResponse{
			Allow: p.Allow,
			Deny:  p.Deny,
		},
		Identity:  i.Identity.String(),
		Admin:     i.IsAdmin,
		CreatedAt: i.CreatedAt.String(),
		CreatedBy: i.CreatedBy.String(),
	}, nil
}

func getListIdentitiesResponse(session *models.Principal, params encryption.ListIdentitiesParams) (*models.EncryptionListIdentitiesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listIdentities(ctx, pattern, KESClient{Client: kesClient, enclave: params.Enclave})
}

func listIdentities(ctx context.Context, pattern string, kesClient KESClientI) (*models.EncryptionListIdentitiesResponse, *models.Error) {
	iterator, err := kesClient.listIdentities(ctx, pattern)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}

	identities, err := iterator.Values(0)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	if err = iterator.Close(); err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionListIdentitiesResponse{Results: parseIdentities(identities)}, nil
}

func parseIdentities(results []kes.IdentityInfo) (data []*models.EncryptionIdentityInfo) {
	for _, identity := range results {
		data = append(data, &models.EncryptionIdentityInfo{
			CreatedAt: identity.CreatedAt.String(),
			CreatedBy: identity.CreatedBy.String(),
			Identity:  identity.Identity.String(),
			Policy:    identity.Policy,
			IsAdmin:   identity.IsAdmin,
		})
	}
	return data
}

func getDeleteIdentityResponse(session *models.Principal, params encryption.DeleteIdentityParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deleteIdentity(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func deleteIdentity(ctx context.Context, identity string, kesClient KESClientI) *models.Error {
	if err := kesClient.deleteIdentity(ctx, identity); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func registerEncryptionSecretHandlers(api *operations.KesAPI) {
	api.EncryptionCreateSecretHandler = encryption.CreateSecretHandlerFunc(func(params encryption.CreateSecretParams, session *models.Principal) middleware.Responder {
		err := getCreateSecretResponse(session, params)
		if err != nil {
			return encryption.NewCreateSecretDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewCreateSecretCreated()
	})

	api.EncryptionListSecretsHandler = encryption.ListSecretsHandlerFunc(func(params encryption.ListSecretsParams, session *models.Principal) middleware.Responder {
		resp, err := getListSecretsResponse(session, params)
		if err != nil {
			return encryption.NewListSecretsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListSecretsOK().WithPayload(resp)
	})

	api.EncryptionDescribeSecretHandler = encryption.DescribeSecretHandlerFunc(func(params encryption.DescribeSecretParams, session *models.Principal) middleware.Responder {
		resp, err := getDescribeSecretResponse(session, params)
		if err != nil {
			return encryption.NewDescribeSecretDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeSecretOK().WithPayload(resp)
	})

	api.EncryptionDeleteSecretHandler = encryption.DeleteSecretHandlerFunc(func(params encryption.DeleteSecretParams, session *models.Principal) middleware.Responder {
		err := getDeleteSecretResponse(session, params)
		if err != nil {
			return encryption.NewDeleteSecretDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteSecretOK()
	})
}

func getCreateSecretResponse(session *models.Principal, params encryption.CreateSecretParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return createSecret(ctx, *params.Body.Secret, *params.Body.Value, KESClient{Client: kesClient, enclave: params.Enclave})
}

func createSecret(ctx context.Context, secret, value string, kesClient KESClientI) *models.Error {
	if err := kesClient.createSecret(ctx, secret, value); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func getListSecretsResponse(session *models.Principal, params encryption.ListSecretsParams) (*models.EncryptionListSecretsResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listSecrets(ctx, pattern, KESClient{Client: kesClient, enclave: params.Enclave})
}

func listSecrets(ctx context.Context, pattern string, kesClient KESClientI) (*models.EncryptionListSecretsResponse, *models.Error) {
	iterator, err := kesClient.listSecrets(ctx, pattern)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}

	secrets, err := iterator.Values(0)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	if err = iterator.Close(); err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionListSecretsResponse{Results: parseSecrets(secrets)}, nil
}

func parseSecrets(results []kes.SecretInfo) (data []*models.EncryptionSecretInfo) {
	for _, secret := range results {
		data = append(data, &models.EncryptionSecretInfo{
			CreatedAt:  secret.CreatedAt.String(),
			UpdatedAt:  secret.ModTime.String(),
			CreatedBy:  secret.CreatedBy.String(),
			Name:       secret.Name,
			SecretType: secret.Type.String(),
		})
	}
	return data
}

func getDescribeSecretResponse(session *models.Principal, params encryption.DescribeSecretParams) (*models.EncryptionSecretInfo, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeSecret(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func describeSecret(ctx context.Context, secret string, kesClient KESClientI) (*models.EncryptionSecretInfo, *models.Error) {
	s, err := kesClient.describeSecret(ctx, secret)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return &models.EncryptionSecretInfo{
		CreatedAt:  s.CreatedAt.String(),
		UpdatedAt:  s.ModTime.String(),
		CreatedBy:  s.CreatedBy.String(),
		Name:       s.Name,
		SecretType: s.Type.String(),
	}, nil
}

func getDeleteSecretResponse(session *models.Principal, params encryption.DeleteSecretParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := newKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deleteSecret(ctx, params.Name, KESClient{Client: kesClient, enclave: params.Enclave})
}

func deleteSecret(ctx context.Context, secret string, kesClient KESClientI) *models.Error {
	if err := kesClient.deleteSecret(ctx, secret); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}
