/* eslint-disable */
/* tslint:disable */
/*
 * ---------------------------------------------------------------
 * ## THIS FILE WAS GENERATED VIA SWAGGER-TYPESCRIPT-API        ##
 * ##                                                           ##
 * ## AUTHOR: acacode                                           ##
 * ## SOURCE: https://github.com/acacode/swagger-typescript-api ##
 * ---------------------------------------------------------------
 */

export interface Principal {
  clientCertificate?: string;
  clientKey?: string;
  apiKey?: string;
  insecure?: boolean;
}

export interface Error {
  /** @format int32 */
  code?: number;
  message: string;
  detailedMessage: string;
}

export interface LoginDetails {
  loginStrategy?: "form";
  redirectRules?: RedirectRule[];
}

export interface LoginResponse {
  sessionId?: string;
  IDPRefreshToken?: string;
}

export interface LogoutRequest {
  state?: string;
}

export interface SessionResponse {
  status?: "ok";
}

export interface RedirectRule {
  redirect?: string;
  displayName?: string;
}

export interface EncryptionStatusResponse {
  name?: string;
  defaultKeyID?: string;
  endpoints?: EncryptionEndpoint[];
}

export interface EncryptionEndpoint {
  url?: string;
  status?: string;
}

export interface EncryptionDescribeKeyResponse {
  name?: string;
  ID?: string;
  algorithm?: string;
  createdAt?: string;
  createdBy?: string;
}

export interface EncryptionCreateKeyRequest {
  key: string;
}

export interface EncryptionImportKeyRequest {
  bytes: string;
}

export interface EncryptionListKeysResponse {
  results?: EncryptionKeyInfo[];
}

export interface EncryptionKeyInfo {
  name?: string;
  createdAt?: string;
  createdBy?: string;
}

export interface EncryptionGetPolicyResponse {
  allow?: string[];
  deny?: string[];
}

export interface EncryptionSetPolicyRequest {
  policy: string;
  allow?: string[];
  deny?: string[];
}

export interface EncryptionDescribePolicyResponse {
  createdAt?: string;
  createdBy?: string;
  name?: string;
}

export interface EncryptionAssignPolicyRequest {
  identity?: string;
}

export interface EncryptionListPoliciesResponse {
  results?: EncryptionPolicyInfo[];
}

export interface EncryptionPolicyInfo {
  name?: string;
  createdAt?: string;
  createdBy?: string;
}

export interface EncryptionDescribeIdentityResponse {
  policy?: string;
  identity?: string;
  admin?: boolean;
  createdAt?: string;
  createdBy?: string;
}

export interface EncryptionDescribeSelfIdentityResponse {
  identity?: string;
  policyName?: string;
  admin?: boolean;
  createdAt?: string;
  createdBy?: string;
  policy?: EncryptionGetPolicyResponse;
}

export interface EncryptionListIdentitiesResponse {
  results?: EncryptionIdentityInfo[];
}

export interface EncryptionIdentityInfo {
  identity?: string;
  policy?: string;
  error?: string;
  createdAt?: string;
  createdBy?: string;
  isAdmin?: boolean;
}

export interface EncryptionMetricsResponse {
  requestOK: number;
  requestErr: number;
  requestFail: number;
  requestActive: number;
  auditEvents: number;
  errorEvents: number;
  latencyHistogram: EncryptionLatencyHistogram[];
  uptime: number;
  cpus: number;
  usableCPUs: number;
  threads: number;
  heapAlloc: number;
  heapObjects?: number;
  stackAlloc: number;
}

export interface EncryptionLatencyHistogram {
  duration?: number;
  total?: number;
}

export interface EncryptionAPIsResponse {
  results?: EncryptionAPI[];
}

export interface EncryptionAPI {
  method?: string;
  path?: string;
  maxBody?: number;
  timeout?: number;
}

export interface EncryptionVersionResponse {
  version?: string;
}

export interface EncryptionCreateSecretRequest {
  secret: string;
  value: string;
}

export interface EncryptionListSecretsResponse {
  results?: EncryptionSecretInfo[];
}

export interface EncryptionSecretInfo {
  name?: string;
  secretType?: string;
  createdAt?: string;
  updatedAt?: string;
  createdBy?: string;
}

export type QueryParamsType = Record<string | number, any>;
export type ResponseFormat = keyof Omit<Body, "body" | "bodyUsed">;

export interface FullRequestParams extends Omit<RequestInit, "body"> {
  /** set parameter to `true` for call `securityWorker` for this request */
  secure?: boolean;
  /** request path */
  path: string;
  /** content type of request body */
  type?: ContentType;
  /** query params */
  query?: QueryParamsType;
  /** format of response (i.e. response.json() -> format: "json") */
  format?: ResponseFormat;
  /** request body */
  body?: unknown;
  /** base url */
  baseUrl?: string;
  /** request cancellation token */
  cancelToken?: CancelToken;
}

export type RequestParams = Omit<
  FullRequestParams,
  "body" | "method" | "query" | "path"
>;

export interface ApiConfig<SecurityDataType = unknown> {
  baseUrl?: string;
  baseApiParams?: Omit<RequestParams, "baseUrl" | "cancelToken" | "signal">;
  securityWorker?: (
    securityData: SecurityDataType | null
  ) => Promise<RequestParams | void> | RequestParams | void;
  customFetch?: typeof fetch;
}

export interface HttpResponse<D extends unknown, E extends unknown = unknown>
  extends Response {
  data: D;
  error: E;
}

type CancelToken = Symbol | string | number;

export enum ContentType {
  Json = "application/json",
  FormData = "multipart/form-data",
  UrlEncoded = "application/x-www-form-urlencoded",
  Text = "text/plain",
}

export class HttpClient<SecurityDataType = unknown> {
  public baseUrl: string = "/api/v1";
  private securityData: SecurityDataType | null = null;
  private securityWorker?: ApiConfig<SecurityDataType>["securityWorker"];
  private abortControllers = new Map<CancelToken, AbortController>();
  private customFetch = (...fetchParams: Parameters<typeof fetch>) =>
    fetch(...fetchParams);

  private baseApiParams: RequestParams = {
    credentials: "same-origin",
    headers: {},
    redirect: "follow",
    referrerPolicy: "no-referrer",
  };

  constructor(apiConfig: ApiConfig<SecurityDataType> = {}) {
    Object.assign(this, apiConfig);
  }

  public setSecurityData = (data: SecurityDataType | null) => {
    this.securityData = data;
  };

  protected encodeQueryParam(key: string, value: any) {
    const encodedKey = encodeURIComponent(key);
    return `${encodedKey}=${encodeURIComponent(
      typeof value === "number" ? value : `${value}`
    )}`;
  }

  protected addQueryParam(query: QueryParamsType, key: string) {
    return this.encodeQueryParam(key, query[key]);
  }

  protected addArrayQueryParam(query: QueryParamsType, key: string) {
    const value = query[key];
    return value.map((v: any) => this.encodeQueryParam(key, v)).join("&");
  }

  protected toQueryString(rawQuery?: QueryParamsType): string {
    const query = rawQuery || {};
    const keys = Object.keys(query).filter(
      (key) => "undefined" !== typeof query[key]
    );
    return keys
      .map((key) =>
        Array.isArray(query[key])
          ? this.addArrayQueryParam(query, key)
          : this.addQueryParam(query, key)
      )
      .join("&");
  }

  protected addQueryParams(rawQuery?: QueryParamsType): string {
    const queryString = this.toQueryString(rawQuery);
    return queryString ? `?${queryString}` : "";
  }

  private contentFormatters: Record<ContentType, (input: any) => any> = {
    [ContentType.Json]: (input: any) =>
      input !== null && (typeof input === "object" || typeof input === "string")
        ? JSON.stringify(input)
        : input,
    [ContentType.Text]: (input: any) =>
      input !== null && typeof input !== "string"
        ? JSON.stringify(input)
        : input,
    [ContentType.FormData]: (input: any) =>
      Object.keys(input || {}).reduce((formData, key) => {
        const property = input[key];
        formData.append(
          key,
          property instanceof Blob
            ? property
            : typeof property === "object" && property !== null
            ? JSON.stringify(property)
            : `${property}`
        );
        return formData;
      }, new FormData()),
    [ContentType.UrlEncoded]: (input: any) => this.toQueryString(input),
  };

  protected mergeRequestParams(
    params1: RequestParams,
    params2?: RequestParams
  ): RequestParams {
    return {
      ...this.baseApiParams,
      ...params1,
      ...(params2 || {}),
      headers: {
        ...(this.baseApiParams.headers || {}),
        ...(params1.headers || {}),
        ...((params2 && params2.headers) || {}),
      },
    };
  }

  protected createAbortSignal = (
    cancelToken: CancelToken
  ): AbortSignal | undefined => {
    if (this.abortControllers.has(cancelToken)) {
      const abortController = this.abortControllers.get(cancelToken);
      if (abortController) {
        return abortController.signal;
      }
      return void 0;
    }

    const abortController = new AbortController();
    this.abortControllers.set(cancelToken, abortController);
    return abortController.signal;
  };

  public abortRequest = (cancelToken: CancelToken) => {
    const abortController = this.abortControllers.get(cancelToken);

    if (abortController) {
      abortController.abort();
      this.abortControllers.delete(cancelToken);
    }
  };

  public request = async <T = any, E = any>({
    body,
    secure,
    path,
    type,
    query,
    format,
    baseUrl,
    cancelToken,
    ...params
  }: FullRequestParams): Promise<HttpResponse<T, E>> => {
    const secureParams =
      ((typeof secure === "boolean" ? secure : this.baseApiParams.secure) &&
        this.securityWorker &&
        (await this.securityWorker(this.securityData))) ||
      {};
    const requestParams = this.mergeRequestParams(params, secureParams);
    const queryString = query && this.toQueryString(query);
    const payloadFormatter = this.contentFormatters[type || ContentType.Json];
    const responseFormat = format || requestParams.format;

    return this.customFetch(
      `${baseUrl || this.baseUrl || ""}${path}${
        queryString ? `?${queryString}` : ""
      }`,
      {
        ...requestParams,
        headers: {
          ...(requestParams.headers || {}),
          ...(type && type !== ContentType.FormData
            ? { "Content-Type": type }
            : {}),
        },
        signal: cancelToken
          ? this.createAbortSignal(cancelToken)
          : requestParams.signal,
        body:
          typeof body === "undefined" || body === null
            ? null
            : payloadFormatter(body),
      }
    ).then(async (response) => {
      const r = response as HttpResponse<T, E>;
      r.data = null as unknown as T;
      r.error = null as unknown as E;

      const data = !responseFormat
        ? r
        : await response[responseFormat]()
            .then((data) => {
              if (r.ok) {
                r.data = data;
              } else {
                r.error = data;
              }
              return r;
            })
            .catch((e) => {
              r.error = e;
              return r;
            });

      if (cancelToken) {
        this.abortControllers.delete(cancelToken);
      }

      if (!response.ok) throw data;
      return data;
    });
  };
}

/**
 * @title MinIO KES
 * @version 0.1.0
 * @baseUrl /api/v1
 */
export class Api<
  SecurityDataType extends unknown
> extends HttpClient<SecurityDataType> {
  login = {
    /**
     * No description
     *
     * @tags Auth
     * @name LoginDetail
     * @summary Returns login strategy, form or sso.
     * @request GET:/login
     */
    loginDetail: (params: RequestParams = {}) =>
      this.request<LoginDetails, Error>({
        path: `/login`,
        method: "GET",
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Auth
     * @name Login
     * @summary Login to Console
     * @request POST:/login
     */
    login: (
      data: {
        password?: string;
        apiKey?: string;
        insecure?: string;
        /** @format binary */
        cert?: File;
        /** @format binary */
        key?: File;
      },
      params: RequestParams = {}
    ) =>
      this.request<void, Error>({
        path: `/login`,
        method: "POST",
        body: data,
        type: ContentType.FormData,
        ...params,
      }),
  };
  logout = {
    /**
     * No description
     *
     * @tags Auth
     * @name Logout
     * @summary Logout from Console.
     * @request POST:/logout
     * @secure
     */
    logout: (params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/logout`,
        method: "POST",
        secure: true,
        ...params,
      }),
  };
  session = {
    /**
     * No description
     *
     * @tags Auth
     * @name SessionCheck
     * @summary Endpoint to check if your session is still valid
     * @request GET:/session
     * @secure
     */
    sessionCheck: (params: RequestParams = {}) =>
      this.request<SessionResponse, Error>({
        path: `/session`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),
  };
  encryption = {
    /**
     * No description
     *
     * @tags Encryption
     * @name Status
     * @summary Encryption status
     * @request GET:/encryption/status
     * @secure
     */
    status: (params: RequestParams = {}) =>
      this.request<EncryptionStatusResponse, Error>({
        path: `/encryption/status`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name Metrics
     * @summary Encryption metrics
     * @request GET:/encryption/metrics
     * @secure
     */
    metrics: (params: RequestParams = {}) =>
      this.request<EncryptionMetricsResponse, Error>({
        path: `/encryption/metrics`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ApIs
     * @summary Encryption apis
     * @request GET:/encryption/apis
     * @secure
     */
    apIs: (params: RequestParams = {}) =>
      this.request<EncryptionAPIsResponse, Error>({
        path: `/encryption/apis`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name Version
     * @summary Encryption version
     * @request GET:/encryption/version
     * @secure
     */
    version: (params: RequestParams = {}) =>
      this.request<EncryptionVersionResponse, Error>({
        path: `/encryption/version`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name CreateKey
     * @summary Encryption create key
     * @request POST:/encryption/keys
     * @secure
     */
    createKey: (body: EncryptionCreateKeyRequest, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/keys`,
        method: "POST",
        body: body,
        secure: true,
        type: ContentType.Json,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ListKeys
     * @summary Encryption list keys
     * @request GET:/encryption/keys
     * @secure
     */
    listKeys: (
      query?: {
        /** pattern to retrieve keys */
        pattern?: string;
      },
      params: RequestParams = {}
    ) =>
      this.request<EncryptionListKeysResponse, Error>({
        path: `/encryption/keys`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DescribeKey
     * @summary Encryption describe key
     * @request GET:/encryption/keys/{name}
     * @secure
     */
    describeKey: (name: string, params: RequestParams = {}) =>
      this.request<EncryptionDescribeKeyResponse, Error>({
        path: `/encryption/keys/${name}`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DeleteKey
     * @summary Encryption delete key
     * @request DELETE:/encryption/keys/{name}
     * @secure
     */
    deleteKey: (name: string, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/keys/${name}`,
        method: "DELETE",
        secure: true,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ImportKey
     * @summary Encryption import key
     * @request POST:/encryption/keys/{name}/import
     * @secure
     */
    importKey: (
      name: string,
      body: EncryptionImportKeyRequest,
      params: RequestParams = {}
    ) =>
      this.request<void, Error>({
        path: `/encryption/keys/${name}/import`,
        method: "POST",
        body: body,
        secure: true,
        type: ContentType.Json,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name SetPolicy
     * @summary Encryption set policy
     * @request POST:/encryption/policies
     * @secure
     */
    setPolicy: (body: EncryptionSetPolicyRequest, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/policies`,
        method: "POST",
        body: body,
        secure: true,
        type: ContentType.Json,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ListPolicies
     * @summary Encryption list policies
     * @request GET:/encryption/policies
     * @secure
     */
    listPolicies: (
      query?: {
        /** pattern to retrieve policies */
        pattern?: string;
      },
      params: RequestParams = {}
    ) =>
      this.request<EncryptionListPoliciesResponse, Error>({
        path: `/encryption/policies`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name GetPolicy
     * @summary Encryption get policy
     * @request GET:/encryption/policies/{name}
     * @secure
     */
    getPolicy: (name: string, params: RequestParams = {}) =>
      this.request<EncryptionGetPolicyResponse, Error>({
        path: `/encryption/policies/${name}`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DeletePolicy
     * @summary Encryption delete policy
     * @request DELETE:/encryption/policies/{name}
     * @secure
     */
    deletePolicy: (name: string, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/policies/${name}`,
        method: "DELETE",
        secure: true,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name AssignPolicy
     * @summary Encryption assign policy
     * @request POST:/encryption/policies/{name}/assign
     * @secure
     */
    assignPolicy: (
      name: string,
      body: EncryptionAssignPolicyRequest,
      params: RequestParams = {}
    ) =>
      this.request<void, Error>({
        path: `/encryption/policies/${name}/assign`,
        method: "POST",
        body: body,
        secure: true,
        type: ContentType.Json,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DescribePolicy
     * @summary Encryption describe policy
     * @request GET:/encryption/policies/{name}/describe
     * @secure
     */
    describePolicy: (name: string, params: RequestParams = {}) =>
      this.request<EncryptionDescribePolicyResponse, Error>({
        path: `/encryption/policies/${name}/describe`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DeleteIdentity
     * @summary Encryption delete identity
     * @request DELETE:/encryption/identities/{name}
     * @secure
     */
    deleteIdentity: (name: string, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/identities/${name}`,
        method: "DELETE",
        secure: true,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DescribeIdentity
     * @summary Encryption describe identity
     * @request GET:/encryption/identities/{name}/describe
     * @secure
     */
    describeIdentity: (name: string, params: RequestParams = {}) =>
      this.request<EncryptionDescribeIdentityResponse, Error>({
        path: `/encryption/identities/${name}/describe`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DescribeSelfIdentity
     * @summary Encryption describe self identity
     * @request GET:/encryption/describe-self/identity
     * @secure
     */
    describeSelfIdentity: (params: RequestParams = {}) =>
      this.request<EncryptionDescribeSelfIdentityResponse, Error>({
        path: `/encryption/describe-self/identity`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ListIdentities
     * @summary Encryption list identities
     * @request GET:/encryption/identities
     * @secure
     */
    listIdentities: (
      query?: {
        /** pattern to retrieve identities */
        pattern?: string;
      },
      params: RequestParams = {}
    ) =>
      this.request<EncryptionListIdentitiesResponse, Error>({
        path: `/encryption/identities`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name CreateSecret
     * @summary Encryption create secret
     * @request POST:/encryption/secrets
     * @secure
     */
    createSecret: (
      body: EncryptionCreateSecretRequest,
      params: RequestParams = {}
    ) =>
      this.request<void, Error>({
        path: `/encryption/secrets`,
        method: "POST",
        body: body,
        secure: true,
        type: ContentType.Json,
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name ListSecrets
     * @summary Encryption list secrets
     * @request GET:/encryption/secrets
     * @secure
     */
    listSecrets: (
      query?: {
        /** pattern to retrieve secrets */
        pattern?: string;
      },
      params: RequestParams = {}
    ) =>
      this.request<EncryptionListSecretsResponse, Error>({
        path: `/encryption/secrets`,
        method: "GET",
        query: query,
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DescribeSecret
     * @summary Encryption describe secret
     * @request GET:/encryption/secrets/{name}
     * @secure
     */
    describeSecret: (name: string, params: RequestParams = {}) =>
      this.request<EncryptionSecretInfo, Error>({
        path: `/encryption/secrets/${name}`,
        method: "GET",
        secure: true,
        format: "json",
        ...params,
      }),

    /**
     * No description
     *
     * @tags Encryption
     * @name DeleteSecret
     * @summary Encryption delete secret
     * @request DELETE:/encryption/secrets/{name}
     * @secure
     */
    deleteSecret: (name: string, params: RequestParams = {}) =>
      this.request<void, Error>({
        path: `/encryption/secrets/${name}`,
        method: "DELETE",
        secure: true,
        ...params,
      }),
  };
}
