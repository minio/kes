# KES
[![Go Reference](https://pkg.go.dev/badge/github.com/minio/kes.svg)](https://pkg.go.dev/github.com/minio/kes) ![build](https://github.com/minio/kes/workflows/Go/badge.svg) ![license](https://img.shields.io/badge/license-AGPL%20V3-blue) [![latest](https://badgen.net/github/tag/minio/kes)](https://github.com/minio/kes/releases/latest)

KES is a stateless and distributed key-management system for high-performance applications. We built KES as the bridge between modern applications - running as containers on [Kubernetes](https://kubernetes.io) - and centralized KMS solutions. Therefore, KES has been designed to be simple, scalable and secure by default. It has just a few knobs to tweak instead of a complex configuration and does not require a deep understanding of secure key-management or cryptography.

## Architecture
[![KES](https://raw.githubusercontent.com/minio/kes/master/.github/arch.png)](https://min.io/product/enterprise-object-storage-encryption)

## Install

### Binary Releases

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

### Docker

Pull the latest release via:
```
docker pull minio/kes
```

### Build from source

```
GO111MODULE=on go get github.com/minio/kes/cmd/kes
```
> You will need a working Go environment. Therefore, please follow [How to install Go](https://golang.org/doc/install).
> Minimum version required is go1.14

## Getting Started

We run a public KES server instance at `https://play.min.io:7373` for you to experiment with.
Just follow the steps below to get a first impression of how easy it is to use KES as a client.
All you need is `cURL`.

If you instead want to run a KES server locally as your first steps then checkout our
[Getting Started Guide](https://github.com/minio/kes/wiki/Getting-Started).

#### 1. Fetch the root identity

As an initial step, you will need to download the "private" key and certificate
to authenticate to the KES server as the root identity.
```sh
curl -sSL --tlsv1.2 \
   -O 'https://raw.githubusercontent.com/minio/kes/master/root.key' \
   -O 'https://raw.githubusercontent.com/minio/kes/master/root.cert'
```

#### 2. Create a new master key

Then, you can create a new master key named e.g. `my-key`.
```sh
curl -sSL --tlsv1.3 --http2 \
    --key root.key \
    --cert root.cert \
    -X POST 'https://play.min.io:7373/v1/key/create/my-key'
```
> Note that creating a new key will fail with `key does already exist` if it already exist.

#### 3. Generate a new data encryption key (DEK)

Now, you can use that master key to derive a new data encryption key.
```sh
curl -sSL --tlsv1.3 --http2 \
    --key root.key \
    --cert root.cert \
    --data '{}' \
    -X POST 'https://play.min.io:7373/v1/key/generate/my-key'
```
You will get a plaintext and a ciphertext data key. The ciphertext data
key is the encrypted version of the plaintext key. Your application would
use the plaintext key to e.g. encrypt some application data but only remember
the ciphertext key version.

#### 4. Use the KES CLI client

For more sophisticated tasks, like managing policies or audit log tracing, you
may want to use the KES CLI. Therefore, point your CLI to our KES instance:
```sh
export KES_SERVER=https://play.min.io:7373
export KES_CLIENT_KEY=root.key
export KES_CLIENT_CERT=root.cert
```

Then run a KES CLI command. For example:
```
kes key list
```

***

If you want to learn more about KES checkout our [documentation](https://github.com/minio/kes/wiki).

## License
Use of `KES` is governed by the AGPLv3 license that can be found in the [LICENSE](./LICENSE) file.
