## KES KeyStore Plugin Specification 

### Introduction

KES supports various KMS / KeyStore implementations. However, some KMS / KeyStore
implementations cannot or should not be supported directly for multiple reasons. For example,
the KMS / KeyStore may be a proprietary custom solution. Adding a direct integration would
disclose IP or confidential information about the KMS / KeyStore implementation or about the
underlying infrastructure. Usually, those details must not be disclosed due to compliance rules
or even by law.

Therefore, KES provides a plugin interface. The plugin interface defines an REST API that has
to be implemented by a KES KeyStore plugin. The KES server can then create, access, list and
delete keys indirectly at the KeyStore by talking to the plugin service.

```    
                          ┌────────────────────────────────────────────────────┐
┌────────────┐   REST API │ ┌─────────────────────┐             ┌───────────┐  │
│ KES Server ├────────────┼─┤ KES KeyStore Plugin ├─────────────┤ Key Store │  │
└────────────┘            │ └─────────────────────┘             └───────────┘  │
                          └────────────────────────────────────────────────────┘ 
                                          internal/proprietary
```

Hence, the KES plugin interface enables integrations of arbitrary KMS / KeyStore implementations.

### KeyStore Plugin

A `v1` compatible key store plugin implements and exposes four HTTP API endpoints
for creating, accessing, listing and deleting keys. 

#### 1. CreateKey

The `CreateKey` API endpoint creates a new key if and only if no key with the same
name exists. It MUST be exposed as:
```
POST {HTTP | HTTPS}://{HOSTNAME}/v1/key/{KEY_NAME}
```
The `{KEY_NAME}` MUST be a valid URL path segment.

A key creation request MUST contain the key value as JSON object in the request body:
```
{
  "bytes":"eyJieXRlcyI6Ilg4RUEwU3dkbUQzOXB4YzdUa293c0theWw1bC9sc0tJK1B6Zko1NDBCeW89In0K",
}
```

If the key creation succeeded `CreateKey` MUST respond with HTTP status code `201`
to the client.

When a request tries to create a key but an entry with this key name already exists then
the `CreateKey` API endpoint MUST return the HTTP status code `400` with the following
JSON object as response body:
```
{
  "message":"key already exists", 
}
```

`CreateKey` MUST be implemented as atomic operation that only succeeds if and only if
no key with the same name exists. If multiple requests try to create a key with the same
name concurrently then only one MAY succeed and all other requests MUST fail.

**Example:**

```
POST https://127.0.0.1:7373/v1/key/my-key
{
  "bytes":"eyJieXRlcyI6Ilg4RUEwU3dkbUQzOXB4YzdUa293c0theWw1bC9sc0tJK1B6Zko1NDBCeW89In0K",
}


HTTP/1.1 201 Created
```

#### 2. GetKey

The `GetKey` API endpoint returns the value for a given key, if it exists. It MUST be
exposed as:
```
GET {HTTP | HTTPS}://{HOSTNAME}/v1/key/{KEY_NAME}
```

The `{KEY_NAME}` MUST be a valid URL path segment.

If a key with the requested key name exists then `GetKey` MUST respond with HTTP status
code `200` and a respond body that contains the value of the key:
```
{
  "bytes":{KEY_VALUE},
}
```

When a request tries to access a key that does not exist resp. no entry could be found then
the `GetKey` API endpoint MUST return the HTTP status code `404` with the following
error message as response body:
```
{
  "message":"key does not exist", 
}
```
 
**Example:**

```
GET https://127.0.0.1:7337/v1/key/my-key


HTTP/1.1 200 OK
{
  "bytes":"eyJieXRlcyI6Ilg4RUEwU3dkbUQzOXB4YzdUa293c0theWw1bC9sc0tJK1B6Zko1NDBCeW89In0K",
}
```

#### 3. DeleteKey

The `DeleteKey` API endpoint deletes the key with the given key, if it exists. It MUST be
exposed as:
```
DELETE {HTTP | HTTPS}://{HOSTNAME}/v1/key/{KEY_NAME}
```

The `{KEY_NAME}` MUST be a valid URL path segment.

If a key has been deleted successfully the `DeleteKey` endpoint MUST respond with the HTTP
status code `200`. It MAY also respond with the HTTP status code `200` if the requested key
does not exist.

**Example:**

```
DELETE https://127.0.0.1:7373/v1/key/my-key


HTTP/1.1 200 OK
```

#### 4. ListKeys

The `ListKeys` API endpoint lists all key names. It MUST be exposed as:
```
GET {HTTP | HTTPS}://{HOSTNAME}/v1/key
```

The `ListKeys` API endpoint returns a stream of JSON objects as `nd-json`:
```
{
  "name":{KEY_NAME},
  "last":[true | false],
}
```
Each JSON object MAY contain an additional `last` field. It MUST always be
set to `false`, if present, unless the JSON object is the last element of
the `nd-json` stream. The last JSON object MUST contain the `last` field
and it MUST be set to `true`. Multiple JSON objects MUST be separated by the
new-line character (`\n`).

The response SHOULD set the HTTP header `Content-Type` to `application/x-ndjson`.

**Example:**

```
GET https://127.0.0.1:7373/v1/key

HTTP/1.1 200 OK
{"name":"my-key"}
{"name":"some-key"}
{"name":"another-key","last":true}
```

### Errors

Whenever a `v1` compatible plugin encounters an error while processing a client request
it SHOULD respond with an appropriate HTTP status code and error message. All returned
errors MUST be JSON objects of the following format:
```
{
  "message":{ERROR_MESSAGE},
}
```

A plugin SHOULD only send a HTTP status code `5xx` if appropriate and no HTTP status code `4xx`
describes the error situation adequately. A error response MUST always contain an HTTP status code
`4xx` or `5xx`.

### Security Considerations

A KES KeyStore plugin implementation SHOULD only accept TLS/HTTPS request. The usage of plaintext
HTTP will leak cryptographic key material exchanged between the KES server and the plugin. Therefore,
it SHOULD NOT accept plaintext HTTP connection attempts except during development or for testing purposes.

If a plugin implementation accepts TLS/HTTPS connections it MUST support at least TLS 1.2. If it only supports
TLS 1.2 then it MUST support at least one of the following TLS 1.2 cipher suites:
 - `ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
 - `ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
 - `ECDHE_RSA_WITH_AES_128_GCM_SHA256`
 - `ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
 - `ECDHE_RSA_WITH_AES_256_GCM_SHA384`
 - `ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

The KES server and the KeyStore plugin SHOULD mutually authenticate via X.509 certificates (mTLS). Therefore,
the KES server will verify the X.509 certificate of the plugin and the plugin SHOULD verify the X.509 client
certificate of the KES server.

Additionally, the plugin MAY verify that the cryptographic hash of the public key within the KES server client
certificate matches an expected value (TLS HPKP). This cryptographic hash should be computed as SHA-256 of the
raw subject public key of the X.509 certificate.
