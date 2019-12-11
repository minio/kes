> This project is under active development and not ready for production use yet.

## Keys
Keys is a tool for managing and distributing secret keys at scale. In particular, it decouples a traditional key-management-system (KMS) - like AWS-KMS or Hashicorp Vault from large-scale and high-performance applications.

Almost every large-scale system deals with sensitive information that must be protected from unauthorized access. Therefore, applications encrypt network traffic and data at rest. However, someone has to provide the encryption keys to those applications at some point in time. An on-prem or cloud KMS can distribute unique encryption keys to those applications and also allows tight control over which encryption key is accessed by whom at which point in time.

## Prerequisites
If you do not have a working Golang environment, please follow [How to install Golang](https://golang.org/doc/install). Minimum version required is [go1.13](https://golang.org/dl/#stable)

### Getting Started

#### Generate self-signed certs
Create a TLS private key and certificate for the key server
```
openssl ecparam -genkey -name prime256v1 | openssl ec -out server.key
openssl req -new -x509 -days 365 -key server.key -out server.cert -subj "/C=/ST=/L=/O=/CN=localhost"
```

#### Install keys
```
GO111MODULE=on go get github.com/minio/keys/cmd/key
```

#### Create new identity
Create a new identity (e.g. `root`)
```
key tool identity new --key="./root.key" --cert="root.cert" root
```

#### Start key server
Switch to a new terminal window
```
key server --mtls-auth=ignore --tls-key="./server.key" --tls-cert="./server.cert" --root $(key tool identity of root.cert)
```

#### Set key client TLS certs
Switch back to the previous terminal window to set following ENVs
```
export KEY_CLIENT_TLS_KEY_FILE=./root.key
```

```
export KEY_CLIENT_TLS_CERT_FILE=./root.cert
```

Now, can you talk to the server and e.g. create a new master key (named my-key)

```
key create my-key -k
```

This key can now be used to derive unique encryption keys for your applications
```
key derive my-key -k
```

```
{
  plaintext : ...
  ciphertext: ...
}
```

The *plaintext* is a base64-encoded 256 bit key. The *ciphertext* is the plaintext key encrypted with the `my-key` at the server. You can decrypt the ciphertext again by passing it to: `key decrypt my-key -k <base64-ciphertext>`

**Note:** You just started a key server with a non-persistent in-memory key store. Therefore, by restarting the server all keys created in between will be destroyed. For durable key stores take a look at the [toml](https://github.com/minio/keys/blob/master/server-config.toml) or [yaml](https://github.com/minio/keys/blob/master/server-config.yaml) config file.
