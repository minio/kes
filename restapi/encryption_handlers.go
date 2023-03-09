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
	"github.com/minio/kes"
	"github.com/minio/kes/models"
	"github.com/minio/kes/restapi/operations"
	"github.com/minio/kes/restapi/operations/encryption"
)

func registerEncryptionHandlers(api *operations.KesAPI) {
	registerEncryptionStatusHandlers(api)
	registerEncryptionKeyHandlers(api)
	registerEncryptionPolicyHandlers(api)
	registerEncryptionIdentityHandlers(api)
}

func registerEncryptionStatusHandlers(api *operations.KesAPI) {
	api.EncryptionStatusHandler = encryption.StatusHandlerFunc(func(params encryption.StatusParams, session *models.Principal) middleware.Responder {
		resp, err := GetStatusResponse(session, params)
		if err != nil {
			return encryption.NewStatusDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewStatusOK().WithPayload(resp)
	})

	api.EncryptionMetricsHandler = encryption.MetricsHandlerFunc(func(params encryption.MetricsParams, session *models.Principal) middleware.Responder {
		resp, err := GetMetricsResponse(session, params)
		if err != nil {
			return encryption.NewMetricsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewMetricsOK().WithPayload(resp)
	})

	api.EncryptionAPIsHandler = encryption.APIsHandlerFunc(func(params encryption.APIsParams, session *models.Principal) middleware.Responder {
		resp, err := GetAPIsResponse(session, params)
		if err != nil {
			return encryption.NewAPIsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAPIsOK().WithPayload(resp)
	})

	api.EncryptionVersionHandler = encryption.VersionHandlerFunc(func(params encryption.VersionParams, session *models.Principal) middleware.Responder {
		resp, err := GetVersionResponse(session, params)
		if err != nil {
			return encryption.NewVersionDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewVersionOK().WithPayload(resp)
	})
}

func GetStatusResponse(session *models.Principal, params encryption.StatusParams) (*models.EncryptionStatusResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return encryptionStatus(ctx, KESClient{Client: kesClient})
}

func encryptionStatus(ctx context.Context, kesClient KESClientI) (*models.EncryptionStatusResponse, *models.Error) {
	// st, err := kesClient.Status(ctx)
	// if err != nil {
	// 	return nil, newDefaultAPIError(err)
	// }
	// return &models.EncryptionStatusResponse{
	// 	DefaultKeyID: st.DefaultKeyID,
	// 	Name:         st.Name,
	// 	Endpoints:    parseStatusEndpoints(st.Endpoints),
	// }, nil
	return nil, nil
}

// func parseStatusEndpoints(endpoints map[string]madmin.ItemState) (kmsEndpoints []*models.Endpoint) {
// 	for key, value := range endpoints {
// 		kmsEndpoints = append(kmsEndpoints, &models.Endpoint{URL: key, Status: string(value)})
// 	}
// 	return kmsEndpoints
// }

func GetMetricsResponse(session *models.Principal, params encryption.MetricsParams) (*models.EncryptionMetricsResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
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

func GetAPIsResponse(session *models.Principal, params encryption.APIsParams) (*models.EncryptionAPIsResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
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

func GetVersionResponse(session *models.Principal, params encryption.VersionParams) (*models.EncryptionVersionResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
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
		err := GetCreateKeyResponse(session, params)
		if err != nil {
			return encryption.NewCreateKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewCreateKeyCreated()
	})

	api.EncryptionImportKeyHandler = encryption.ImportKeyHandlerFunc(func(params encryption.ImportKeyParams, session *models.Principal) middleware.Responder {
		err := GetImportKeyResponse(session, params)
		if err != nil {
			return encryption.NewImportKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewImportKeyCreated()
	})

	api.EncryptionListKeysHandler = encryption.ListKeysHandlerFunc(func(params encryption.ListKeysParams, session *models.Principal) middleware.Responder {
		resp, err := GetListKeysResponse(session, params)
		if err != nil {
			return encryption.NewListKeysDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListKeysOK().WithPayload(resp)
	})

	api.EncryptionDescribeKeyHandler = encryption.DescribeKeyHandlerFunc(func(params encryption.DescribeKeyParams, session *models.Principal) middleware.Responder {
		resp, err := GetDescribeKeyResponse(session, params)
		if err != nil {
			return encryption.NewDescribeKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeKeyOK().WithPayload(resp)
	})

	api.EncryptionDeleteKeyHandler = encryption.DeleteKeyHandlerFunc(func(params encryption.DeleteKeyParams, session *models.Principal) middleware.Responder {
		err := GetDeleteKeyResponse(session, params)
		if err != nil {
			return encryption.NewDeleteKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteKeyOK()
	})
}

func GetCreateKeyResponse(session *models.Principal, params encryption.CreateKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return createKey(ctx, *params.Body.Key, KESClient{Client: kesClient})
}

func createKey(ctx context.Context, key string, kesClient KESClientI) *models.Error {
	if err := kesClient.createKey(ctx, key); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func GetImportKeyResponse(session *models.Principal, params encryption.ImportKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	bytes, err := json.Marshal(params.Body)
	if err != nil {
		return newDefaultAPIError(err)
	}

	return importKey(ctx, params.Name, bytes, KESClient{Client: kesClient})
}

func importKey(ctx context.Context, key string, bytes []byte, kesClient KESClientI) *models.Error {
	if err := kesClient.importKey(ctx, key, bytes); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func GetListKeysResponse(session *models.Principal, params encryption.ListKeysParams) (*models.EncryptionListKeysResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listKeys(ctx, pattern, KESClient{Client: kesClient})
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

func GetDescribeKeyResponse(session *models.Principal, params encryption.DescribeKeyParams) (*models.EncryptionDescribeKeyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeKey(ctx, params.Name, KESClient{Client: kesClient})
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

func GetDeleteKeyResponse(session *models.Principal, params encryption.DeleteKeyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deleteKey(ctx, params.Name, KESClient{Client: kesClient})
}

func deleteKey(ctx context.Context, key string, kesClient KESClientI) *models.Error {
	if err := kesClient.deleteKey(ctx, key); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func registerEncryptionPolicyHandlers(api *operations.KesAPI) {
	api.EncryptionSetPolicyHandler = encryption.SetPolicyHandlerFunc(func(params encryption.SetPolicyParams, session *models.Principal) middleware.Responder {
		err := GetSetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewSetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewSetPolicyOK()
	})

	api.EncryptionAssignPolicyHandler = encryption.AssignPolicyHandlerFunc(func(params encryption.AssignPolicyParams, session *models.Principal) middleware.Responder {
		err := GetAssignPolicyResponse(session, params)
		if err != nil {
			return encryption.NewAssignPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAssignPolicyOK()
	})

	api.EncryptionDescribePolicyHandler = encryption.DescribePolicyHandlerFunc(func(params encryption.DescribePolicyParams, session *models.Principal) middleware.Responder {
		resp, err := GetDescribePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDescribePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribePolicyOK().WithPayload(resp)
	})

	api.EncryptionGetPolicyHandler = encryption.GetPolicyHandlerFunc(func(params encryption.GetPolicyParams, session *models.Principal) middleware.Responder {
		resp, err := GetGetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewGetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewGetPolicyOK().WithPayload(resp)
	})

	api.EncryptionListPoliciesHandler = encryption.ListPoliciesHandlerFunc(func(params encryption.ListPoliciesParams, session *models.Principal) middleware.Responder {
		resp, err := GetListPoliciesResponse(session, params)
		if err != nil {
			return encryption.NewListPoliciesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListPoliciesOK().WithPayload(resp)
	})

	api.EncryptionDeletePolicyHandler = encryption.DeletePolicyHandlerFunc(func(params encryption.DeletePolicyParams, session *models.Principal) middleware.Responder {
		err := GetDeletePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDeletePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeletePolicyOK()
	})
}

func GetSetPolicyResponse(session *models.Principal, params encryption.SetPolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	bytes, err := json.Marshal(params.Body)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return setPolicy(ctx, *params.Body.Policy, bytes, KESClient{Client: kesClient})
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

func GetAssignPolicyResponse(session *models.Principal, params encryption.AssignPolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return assignPolicy(ctx, params.Name, params.Body.Identity, KESClient{Client: kesClient})
}

func assignPolicy(ctx context.Context, policy, identity string, kesClient KESClientI) *models.Error {
	if err := kesClient.assignPolicy(ctx, policy, identity); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func GetDescribePolicyResponse(session *models.Principal, params encryption.DescribePolicyParams) (*models.EncryptionDescribePolicyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describePolicy(ctx, params.Name, KESClient{Client: kesClient})
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

func GetGetPolicyResponse(session *models.Principal, params encryption.GetPolicyParams) (*models.EncryptionGetPolicyResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return getPolicy(ctx, params.Name, KESClient{Client: kesClient})
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

func GetListPoliciesResponse(session *models.Principal, params encryption.ListPoliciesParams) (*models.EncryptionListPoliciesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listPolicies(ctx, pattern, KESClient{Client: kesClient})
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

func GetDeletePolicyResponse(session *models.Principal, params encryption.DeletePolicyParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deletePolicy(ctx, params.Name, KESClient{Client: kesClient})
}

func deletePolicy(ctx context.Context, policy string, kesClient KESClientI) *models.Error {
	if err := kesClient.deletePolicy(ctx, policy); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}

func registerEncryptionIdentityHandlers(api *operations.KesAPI) {
	api.EncryptionDescribeIdentityHandler = encryption.DescribeIdentityHandlerFunc(func(params encryption.DescribeIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := GetDescribeIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeIdentityOK().WithPayload(resp)
	})

	api.EncryptionDescribeSelfIdentityHandler = encryption.DescribeSelfIdentityHandlerFunc(func(params encryption.DescribeSelfIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := GetDescribeSelfIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeSelfIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeSelfIdentityOK().WithPayload(resp)
	})

	api.EncryptionListIdentitiesHandler = encryption.ListIdentitiesHandlerFunc(func(params encryption.ListIdentitiesParams, session *models.Principal) middleware.Responder {
		resp, err := GetListIdentitiesResponse(session, params)
		if err != nil {
			return encryption.NewListIdentitiesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListIdentitiesOK().WithPayload(resp)
	})
	api.EncryptionDeleteIdentityHandler = encryption.DeleteIdentityHandlerFunc(func(params encryption.DeleteIdentityParams, session *models.Principal) middleware.Responder {
		err := GetDeleteIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDeleteIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteIdentityOK()
	})
}

func GetDescribeIdentityResponse(session *models.Principal, params encryption.DescribeIdentityParams) (*models.EncryptionDescribeIdentityResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeIdentity(ctx, params.Name, KESClient{Client: kesClient})
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

func GetDescribeSelfIdentityResponse(session *models.Principal, params encryption.DescribeSelfIdentityParams) (*models.EncryptionDescribeSelfIdentityResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	return describeSelfIdentity(ctx, KESClient{Client: kesClient})
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

func GetListIdentitiesResponse(session *models.Principal, params encryption.ListIdentitiesParams) (*models.EncryptionListIdentitiesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listIdentities(ctx, pattern, KESClient{Client: kesClient})
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

func GetDeleteIdentityResponse(session *models.Principal, params encryption.DeleteIdentityParams) *models.Error {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient(session)
	if err != nil {
		return newDefaultAPIError(err)
	}
	return deleteIdentity(ctx, params.Name, KESClient{Client: kesClient})
}

func deleteIdentity(ctx context.Context, identity string, kesClient KESClientI) *models.Error {
	if err := kesClient.deleteIdentity(ctx, identity); err != nil {
		return newDefaultAPIError(err)
	}
	return nil
}
