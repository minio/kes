# Kes
Kes is a tool for managing and distributing secret keys at scale. In particular, it decouples a traditional key-management-system (KMS) - like AWS-KMS or Hashicorp Vault from large-scale and high-performance applications.

## Architecture
[![KES](https://raw.githubusercontent.com/minio/kes/master/.github/arch.png)](https://min.io)

## Install 

### Binary Releases

| OS      | ARCH  | Binary            |
|:-------:|:-----:|:-----------------:|
| Linux   | amd64 | [linux-amd64](https://github.com/minio/kes/releases/latest/download/linux-amd64.zip)
| Linux   | arm   | [linux-arm](https://github.com/minio/kes/releases/latest/download/linux-arm.zip)
| Apple   | amd64 | [darwin-amd64](https://github.com/minio/kes/releases/latest/download/darwin-amd64.zip)
| Windows | amd64 | [windows-amd64](https://github.com/minio/kes/releases/latest/download/windows-amd64.zip)

You can also verify the binary with [minisign](https://jedisct1.github.io/minisign/) by downloading the corresponding [`.minisign`](https://github.com/minio/kes/releases/latest) signature file. Then run:
```
minisign -Vm <OS-ARCH>.zip -P RWRcOzQ19UrKLp4rkfssIwwWiWagluGJ8fpUBh/BeH+bZV3keFcdIJTF
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
> Minimum version required is go1.13

## Getting Started
For your first steps checkout our [Getting Started](https://github.com/minio/kes/wiki/Getting-Started) guide.

## License
Use of `kes` is governed by the AGPLv3 license that can be found in the [LICENSE](./LICENSE) file.
