<p align="center">
  <img src='.github/logo.svg?sanitize=true' width='55%'>
</p>

***

**KES is a cloud-native distributed key management and encryption server designed to secure modern applications at scale.**

 - [What is KES?](#what-is-kes)
 - [Installation](#install)
 - [Quick Start](#quick-start)
 - [Documentation](#docs)
 
## What is KES?

KES is a distributed key management server that scales horizontally. It can either be run as edge server close to the applications
reducing latency to and load on a central key management system (KMS) or as central key management server. Edge servers are
self-contained stateless nodes close to the application that can be scaled up/down automatically. Central KES servers or clusters
are stateful systems that store and manage cryptographic keys and secrets securely.

## Install

The KES server and CLI is available as a single binary, container image or can be build from source.

<details open="true"><summary><b><a name="binary-releases">Binary Releases</a></b></summary>

| OS       | ARCH    | Binary                                                                                       |
|:--------:|:-------:|:--------------------------------------------------------------------------------------------:|
| Linux    | amd64   | [linux-amd64](https://github.com/minio/kes/releases/latest/download/kes-linux-amd64)         |
| Linux    | arm64   | [linux-arm64](https://github.com/minio/kes/releases/latest/download/kes-linux-arm64)         |
| Linux    | ppc64le | [linux-ppc64le](https://github.com/minio/kes/releases/latest/download/kes-linux-ppc64le)     |
| Linux    | s390x   | [linux-s390x](https://github.com/minio/kes/releases/latest/download/kes-linux-s390x)         |
| Apple M1 | arm64   | [darwin-arm64](https://github.com/minio/kes/releases/latest/download/kes-darwin-arm64)       |
| Apple    | amd64   | [darwin-amd64](https://github.com/minio/kes/releases/latest/download/kes-darwin-amd64)       |
| Windows  | amd64   | [windows-amd64](https://github.com/minio/kes/releases/latest/download/kes-windows-amd64.exe) |

You can also verify the binary with [minisign](https://jedisct1.github.io/minisign/) by downloading the corresponding [`.minisig`](https://github.com/minio/kes/releases/latest) signature file. Then run:
```
minisign -Vm kes-<OS>-<ARCH> -P RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav
```
</details>   
   
<details><summary><b><a name="docker">Docker</a></b></summary>

Pull the latest release via:
```
docker pull minio/kes
```
</details>
   
<details><summary><b><a name="build-from-source">Build from source</a></b></summary>

Download and install the binary via your Go toolchain:

```sh
go install github.com/minio/kes/cmd/kes@latest
```

</details>
   
## Quick Start
   
We run a public KES instance at `https://play.min.io:7373` for you to experiment with.
You can interact with our play instance either via the KES CLI or cURL. Alternatively, you can
get started by setting up your own KES server in less than five minutes.
   
<details><summary><b>CLI</b></summary>

#### 1. Configure CLI
We point the KES CLI to the KES server at `https://play.min.io:7373` and use the following API key:
```sh
export KES_SERVER=https://play.min.io:7373
export KES_API_KEY=kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc
```

#### 3. Create a Key
Next, we can create a new root encryption key - e.g. `my-key`.
```
kes key create my-key
```
> Note that creating a new key will fail with `key already exist` if it already exist.

#### 4. Generate a DEK
Now, you can use that key to derive a new data encryption keys (DEK).
```sh
kes key dek my-key
```
The plaintext part of the DEK would be used by an application to encrypt some data.
The ciphertext part of the DEK would be stored alongside the encrypted data for future
decryption.
   
</details>   
   
<details><summary><b>Server</b></summary>

For a quickstart setup take a look at our [FS guide](https://github.com/minio/kes/wiki/Filesystem-Keystore).
For further references checkout our list of key store [guides](https://github.com/minio/kes/wiki#guides).
   
</details>
   
<details><summary><b>cURL</b></summary>

#### 1. Fetch Admin Credentials

As an initial step, you will need to download the private key and certificate
to authenticate to the KES server as the admin.
```sh
curl -sSL --tlsv1.2 \
   -O 'https://raw.githubusercontent.com/minio/kes/master/root.key' \
   -O 'https://raw.githubusercontent.com/minio/kes/master/root.cert'
```
   
#### 2. Create a Key   
Next, we can create a new root encryption key - e.g. `my-key`.
```sh
curl -sSL --tlsv1.3 \
    --key root.key \
    --cert root.cert \
    -X POST 'https://play.min.io:7373/v1/key/create/my-key'
```
> Note that creating a new key will fail with `key already exist` if it already exist.

#### 3. Generate a DEK
Now, you can use that key to derive a new data encryption keys (DEK).
```sh
curl -sSL --tlsv1.3 \
    --key root.key \
    --cert root.cert \
    --data '{}' \
    -X POST 'https://play.min.io:7373/v1/key/generate/my-key'
```
The plaintext part of the DEK would be used by an application to encrypt some data.
The ciphertext part of the DEK would be stored alongside the encrypted data for future
decryption.

#### 4. Further References
   
For a comprehensive list of REST API endpoints refer to the KES [API overview](https://github.com/minio/kes/wiki/Server-API).
   
</details>

## Docs

If you want to learn more about KES checkout our [documentation](https://github.com/minio/kes/wiki).
 - [Integration Guides](https://github.com/minio/kes/wiki#supported-kms-targets)
 - [Server API](https://github.com/minio/kes/wiki/Server-API)
 - [Go SDK](https://pkg.go.dev/github.com/minio/kes-go)

## FAQs

<details><summary><b>I have received an <code>insufficient permissions</code> error</b></summary>
   
This means that you are using a KES identity that is not allowed to perform a specific operation, like creating or listing keys.

The KES [admin identity](https://github.com/minio/kes/blob/6452cdc079dfae54e4a46102cb4622c80b99776f/server-config.yaml#L8)
can perform any general purpose API operation. You should never experience a `not authorized: insufficient permissions`
error when performing general purpose API operations using the admin identity.

In addition to the admin identity, KES supports a [policy-based](https://github.com/minio/kes/blob/6452cdc079dfae54e4a46102cb4622c80b99776f/server-config.yaml#L77) access control model.
You will receive a `not authorized: insufficient permissions` error in the following two cases:
1. **You are using a KES identity that is not assigned to any policy. KES rejects requests issued by unknown identities.**
   
   This can be fixed by assigning a policy to the identity. Checkout the [examples](https://github.com/minio/kes/blob/6452cdc079dfae54e4a46102cb4622c80b99776f/server-config.yaml#L79-L88).
2. **You are using a KES identity that is assigned to a policy but the policy either not allows or even denies the API call.**
   
   In this case, you have to grant the API permission in the policy assigned to the identity. Checkout the [list of APIs](https://github.com/minio/kes/wiki/Server-API#api-overview).
   For example, when you want to create a key you should allow the `/v1/key/create/<key-name>`. The `<key-name>` can either be a
   specific key name, like `my-key-1` or a pattern allowing arbitrary key names, like `my-key*`.
   
   Also note that deny rules take precedence over allow rules. Hence, you have to make sure that any deny pattern does not
   accidentally matches your API request.

</details>   
   
***

## License
Use of `KES` is governed by the AGPLv3 license that can be found in the [LICENSE](./LICENSE) file.
