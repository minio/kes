// This file is part of MinIO KES
// Copyright (c) 2022 MinIO, Inc.
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
		resp, err := GetKMSStatusResponse(session, params)
		if err != nil {
			return encryption.NewStatusDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewStatusOK().WithPayload(resp)
	})

	api.EncryptionMetricsHandler = encryption.MetricsHandlerFunc(func(params encryption.MetricsParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSMetricsResponse(session, params)
		if err != nil {
			return encryption.NewMetricsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewMetricsOK().WithPayload(resp)
	})

	api.EncryptionAPIsHandler = encryption.APIsHandlerFunc(func(params encryption.APIsParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSAPIsResponse(session, params)
		if err != nil {
			return encryption.NewAPIsDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAPIsOK().WithPayload(resp)
	})

	api.EncryptionVersionHandler = encryption.VersionHandlerFunc(func(params encryption.VersionParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSVersionResponse(session, params)
		if err != nil {
			return encryption.NewVersionDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewVersionOK().WithPayload(resp)
	})
}

func GetKMSStatusResponse(session *models.Principal, params encryption.StatusParams) (*models.EncryptionStatusResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return kmsStatus(ctx, AdminClient{Client: mAdmin})
}

// func kmsStatus(ctx context.Context, minioClient MinioAdmin) (*models.StatusResponse, *models.Error) {
// 	st, err := minioClient.Status(ctx)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.StatusResponse{
// 		DefaultKeyID: st.DefaultKeyID,
// 		Name:         st.Name,
// 		Endpoints:    parseStatusEndpoints(st.Endpoints),
// 	}, nil
// }

// func parseStatusEndpoints(endpoints map[string]madmin.ItemState) (kmsEndpoints []*models.Endpoint) {
// 	for key, value := range endpoints {
// 		kmsEndpoints = append(kmsEndpoints, &models.Endpoint{URL: key, Status: string(value)})
// 	}
// 	return kmsEndpoints
// }

func GetKMSMetricsResponse(session *models.Principal, params encryption.MetricsParams) (*models.EncryptionMetricsResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return kmsMetrics(ctx, AdminClient{Client: mAdmin})
}

// func kmsMetrics(ctx context.Context, minioClient MinioAdmin) (*models.MetricsResponse, *models.Error) {
// 	metrics, err := minioClient.Metrics(ctx)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.MetricsResponse{
// 		RequestOK:        &metrics.RequestOK,
// 		RequestErr:       &metrics.RequestErr,
// 		RequestFail:      &metrics.RequestFail,
// 		RequestActive:    &metrics.RequestActive,
// 		AuditEvents:      &metrics.AuditEvents,
// 		ErrorEvents:      &metrics.ErrorEvents,
// 		LatencyHistogram: parseHistogram(metrics.LatencyHistogram),
// 		Uptime:           &metrics.UpTime,
// 		Cpus:             &metrics.CPUs,
// 		UsableCPUs:       &metrics.UsableCPUs,
// 		Threads:          &metrics.Threads,
// 		HeapAlloc:        &metrics.HeapAlloc,
// 		HeapObjects:      metrics.HeapObjects,
// 		StackAlloc:       &metrics.StackAlloc,
// 	}, nil
// }

// func parseHistogram(histogram map[int64]int64) (records []*models.LatencyHistogram) {
// 	for duration, total := range histogram {
// 		records = append(records, &models.LatencyHistogram{Duration: duration, Total: total})
// 	}
// 	cp := func(i, j int) bool {
// 		return records[i].Duration < records[j].Duration
// 	}
// 	sort.Slice(records, cp)
// 	return records
// }

func GetKMSAPIsResponse(session *models.Principal, params encryption.APIsParams) (*models.EncryptionAPIsResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return kmsAPIs(ctx, AdminClient{Client: mAdmin})
}

// func kmsAPIs(ctx context.Context, minioClient MinioAdmin) (*models.APIsResponse, *models.Error) {
// 	apis, err := minioClient.APIs(ctx)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.APIsResponse{
// 		Results: parseApis(apis),
// 	}, nil
// }

// func parseApis(apis []madmin.API) (data []*models.API) {
// 	for _, api := range apis {
// 		data = append(data, &models.API{
// 			Method:  api.Method,
// 			Path:    api.Path,
// 			MaxBody: api.MaxBody,
// 			Timeout: api.Timeout,
// 		})
// 	}
// 	return data
// }

func GetKMSVersionResponse(session *models.Principal, params encryption.VersionParams) (*models.EncryptionVersionResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return kmsVersion(ctx, AdminClient{Client: mAdmin})
}

// func kmsVersion(ctx context.Context, minioClient MinioAdmin) (*models.VersionResponse, *models.Error) {
// 	version, err := minioClient.Version(ctx)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.VersionResponse{
// 		Version: version.Version,
// 	}, nil
// }

func registerEncryptionKeyHandlers(api *operations.KesAPI) {
	api.EncryptionCreateKeyHandler = encryption.CreateKeyHandlerFunc(func(params encryption.CreateKeyParams, session *models.Principal) middleware.Responder {
		err := GetKMSCreateKeyResponse(session, params)
		if err != nil {
			return encryption.NewCreateKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewCreateKeyCreated()
	})

	api.EncryptionImportKeyHandler = encryption.ImportKeyHandlerFunc(func(params encryption.ImportKeyParams, session *models.Principal) middleware.Responder {
		err := GetKMSImportKeyResponse(session, params)
		if err != nil {
			return encryption.NewImportKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewImportKeyCreated()
	})

	api.EncryptionListKeysHandler = encryption.ListKeysHandlerFunc(func(params encryption.ListKeysParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSListKeysResponse(session, params)
		if err != nil {
			return encryption.NewListKeysDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListKeysOK().WithPayload(resp)
	})

	api.EncryptionKeyStatusHandler = encryption.KeyStatusHandlerFunc(func(params encryption.KeyStatusParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSKeyStatusResponse(session, params)
		if err != nil {
			return encryption.NewKeyStatusDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewKeyStatusOK().WithPayload(resp)
	})

	api.EncryptionDeleteKeyHandler = encryption.DeleteKeyHandlerFunc(func(params encryption.DeleteKeyParams, session *models.Principal) middleware.Responder {
		err := GetKMSDeleteKeyResponse(session, params)
		if err != nil {
			return encryption.NewDeleteKeyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteKeyOK()
	})
}

func GetKMSCreateKeyResponse(session *models.Principal, params encryption.CreateKeyParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return createKey(ctx, *params.Body.Key, AdminClient{Client: mAdmin})
}

// func createKey(ctx context.Context, key string, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.createKey(ctx, key); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func GetKMSImportKeyResponse(session *models.Principal, params encryption.ImportKeyParams) *models.Error {
	return nil
	//	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	//	defer cancel()
	//	mAdmin, err := NewMinioAdminClient(session)
	//	if err != nil {
	//		return ErrorWithContext(ctx, err)
	//	}
	//	bytes, err := json.Marshal(params.Body)
	//	if err != nil {
	//		return ErrorWithContext(ctx, err)
	//	}
	//
	// return importKey(ctx, params.Name, bytes, AdminClient{Client: mAdmin})
}

// func importKey(ctx context.Context, key string, bytes []byte, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.importKey(ctx, key, bytes); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func GetKMSListKeysResponse(session *models.Principal, params encryption.ListKeysParams) (*models.EncryptionListKeysResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient()
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

func GetKMSKeyStatusResponse(session *models.Principal, params encryption.KeyStatusParams) (*models.EncryptionKeyStatusResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return keyStatus(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func keyStatus(ctx context.Context, key string, minioClient MinioAdmin) (*models.KeyStatusResponse, *models.Error) {
// 	ks, err := minioClient.keyStatus(ctx, key)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.KeyStatusResponse{
// 		KeyID:         ks.KeyID,
// 		EncryptionErr: ks.EncryptionErr,
// 		DecryptionErr: ks.DecryptionErr,
// 	}, nil
// }

func GetKMSDeleteKeyResponse(session *models.Principal, params encryption.DeleteKeyParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return deleteKey(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func deleteKey(ctx context.Context, key string, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.deleteKey(ctx, key); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func registerEncryptionPolicyHandlers(api *operations.KesAPI) {
	api.EncryptionSetPolicyHandler = encryption.SetPolicyHandlerFunc(func(params encryption.SetPolicyParams, session *models.Principal) middleware.Responder {
		err := GetKMSSetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewSetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewSetPolicyOK()
	})

	api.EncryptionAssignPolicyHandler = encryption.AssignPolicyHandlerFunc(func(params encryption.AssignPolicyParams, session *models.Principal) middleware.Responder {
		err := GetKMSAssignPolicyResponse(session, params)
		if err != nil {
			return encryption.NewAssignPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewAssignPolicyOK()
	})

	api.EncryptionDescribePolicyHandler = encryption.DescribePolicyHandlerFunc(func(params encryption.DescribePolicyParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSDescribePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDescribePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribePolicyOK().WithPayload(resp)
	})

	api.EncryptionGetPolicyHandler = encryption.GetPolicyHandlerFunc(func(params encryption.GetPolicyParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSGetPolicyResponse(session, params)
		if err != nil {
			return encryption.NewGetPolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewGetPolicyOK().WithPayload(resp)
	})

	api.EncryptionListPoliciesHandler = encryption.ListPoliciesHandlerFunc(func(params encryption.ListPoliciesParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSListPoliciesResponse(session, params)
		if err != nil {
			return encryption.NewListPoliciesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListPoliciesOK().WithPayload(resp)
	})

	api.EncryptionDeletePolicyHandler = encryption.DeletePolicyHandlerFunc(func(params encryption.DeletePolicyParams, session *models.Principal) middleware.Responder {
		err := GetKMSDeletePolicyResponse(session, params)
		if err != nil {
			return encryption.NewDeletePolicyDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeletePolicyOK()
	})
}

func GetKMSSetPolicyResponse(session *models.Principal, params encryption.SetPolicyParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// bytes, err := json.Marshal(params.Body)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return setPolicy(ctx, *params.Body.Policy, bytes, AdminClient{Client: mAdmin})
}

// func setPolicy(ctx context.Context, policy string, content []byte, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.setKMSPolicy(ctx, policy, content); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func GetKMSAssignPolicyResponse(session *models.Principal, params encryption.AssignPolicyParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// bytes, err := json.Marshal(params.Body)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return assignPolicy(ctx, params.Name, bytes, AdminClient{Client: mAdmin})
}

// func assignPolicy(ctx context.Context, policy string, content []byte, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.assignPolicy(ctx, policy, content); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func GetKMSDescribePolicyResponse(session *models.Principal, params encryption.DescribePolicyParams) (*models.EncryptionDescribePolicyResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return describePolicy(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func describePolicy(ctx context.Context, policy string, minioClient MinioAdmin) (*models.DescribePolicyResponse, *models.Error) {
// 	dp, err := minioClient.describePolicy(ctx, policy)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.DescribePolicyResponse{
// 		Name:      dp.Name,
// 		CreatedAt: dp.CreatedAt,
// 		CreatedBy: dp.CreatedBy,
// 	}, nil
// }

func GetKMSGetPolicyResponse(session *models.Principal, params encryption.GetPolicyParams) (*models.EncryptionGetPolicyResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return getPolicy(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func getPolicy(ctx context.Context, policy string, minioClient MinioAdmin) (*models.GetPolicyResponse, *models.Error) {
// 	p, err := minioClient.getKMSPolicy(ctx, policy)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.GetPolicyResponse{
// 		Allow: p.Allow,
// 		Deny:  p.Deny,
// 	}, nil
// }

func GetKMSListPoliciesResponse(session *models.Principal, params encryption.ListPoliciesParams) (*models.EncryptionListPoliciesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient()
	if err != nil {
		return nil, newDefaultAPIError(err)
	}
	pattern := ""
	if params.Pattern != nil {
		pattern = *params.Pattern
	}
	return listKMSPolicies(ctx, pattern, KESClient{Client: kesClient})
}

func listKMSPolicies(ctx context.Context, pattern string, kesClient KESClientI) (*models.EncryptionListPoliciesResponse, *models.Error) {
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

func GetKMSDeletePolicyResponse(session *models.Principal, params encryption.DeletePolicyParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return deletePolicy(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func deletePolicy(ctx context.Context, policy string, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.deletePolicy(ctx, policy); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }

func registerEncryptionIdentityHandlers(api *operations.KesAPI) {
	api.EncryptionDescribeIdentityHandler = encryption.DescribeIdentityHandlerFunc(func(params encryption.DescribeIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSDescribeIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeIdentityOK().WithPayload(resp)
	})

	api.EncryptionDescribeSelfIdentityHandler = encryption.DescribeSelfIdentityHandlerFunc(func(params encryption.DescribeSelfIdentityParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSDescribeSelfIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDescribeSelfIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDescribeSelfIdentityOK().WithPayload(resp)
	})

	api.EncryptionListIdentitiesHandler = encryption.ListIdentitiesHandlerFunc(func(params encryption.ListIdentitiesParams, session *models.Principal) middleware.Responder {
		resp, err := GetKMSListIdentitiesResponse(session, params)
		if err != nil {
			return encryption.NewListIdentitiesDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewListIdentitiesOK().WithPayload(resp)
	})
	api.EncryptionDeleteIdentityHandler = encryption.DeleteIdentityHandlerFunc(func(params encryption.DeleteIdentityParams, session *models.Principal) middleware.Responder {
		err := GetKMSDeleteIdentityResponse(session, params)
		if err != nil {
			return encryption.NewDeleteIdentityDefault(int(err.Code)).WithPayload(err)
		}
		return encryption.NewDeleteIdentityOK()
	})
}

func GetKMSDescribeIdentityResponse(session *models.Principal, params encryption.DescribeIdentityParams) (*models.EncryptionDescribeIdentityResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return describeIdentity(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func describeIdentity(ctx context.Context, identity string, minioClient MinioAdmin) (*models.DescribeIdentityResponse, *models.Error) {
// 	i, err := minioClient.describeIdentity(ctx, identity)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.DescribeIdentityResponse{
// 		Policy:    i.Policy,
// 		Admin:     i.IsAdmin,
// 		Identity:  i.Identity,
// 		CreatedAt: i.CreatedAt,
// 		CreatedBy: i.CreatedBy,
// 	}, nil
// }

func GetKMSDescribeSelfIdentityResponse(session *models.Principal, params encryption.DescribeSelfIdentityParams) (*models.EncryptionDescribeSelfIdentityResponse, *models.Error) {
	return nil, nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return nil, ErrorWithContext(ctx, err)
	// }
	// return describeSelfIdentity(ctx, AdminClient{Client: mAdmin})
}

// func describeSelfIdentity(ctx context.Context, minioClient MinioAdmin) (*models.DescribeSelfIdentityResponse, *models.Error) {
// 	i, err := minioClient.describeSelfIdentity(ctx)
// 	if err != nil {
// 		return nil, ErrorWithContext(ctx, err)
// 	}
// 	return &models.DescribeSelfIdentityResponse{
// 		Policy: &models.GetPolicyResponse{
// 			Allow: i.Policy.Allow,
// 			Deny:  i.Policy.Deny,
// 		},
// 		Identity:  i.Identity,
// 		Admin:     i.IsAdmin,
// 		CreatedAt: i.CreatedAt,
// 		CreatedBy: i.CreatedBy,
// 	}, nil
// }

func GetKMSListIdentitiesResponse(session *models.Principal, params encryption.ListIdentitiesParams) (*models.EncryptionListIdentitiesResponse, *models.Error) {
	ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	defer cancel()
	kesClient, err := NewKESClient()
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

func GetKMSDeleteIdentityResponse(session *models.Principal, params encryption.DeleteIdentityParams) *models.Error {
	return nil
	// ctx, cancel := context.WithCancel(params.HTTPRequest.Context())
	// defer cancel()
	// mAdmin, err := NewMinioAdminClient(session)
	// if err != nil {
	// 	return ErrorWithContext(ctx, err)
	// }
	// return deleteIdentity(ctx, params.Name, AdminClient{Client: mAdmin})
}

// func deleteIdentity(ctx context.Context, identity string, minioClient MinioAdmin) *models.Error {
// 	if err := minioClient.deleteIdentity(ctx, identity); err != nil {
// 		return ErrorWithContext(ctx, err)
// 	}
// 	return nil
// }
