> This project is under active development and not ready for production use yet.

## Keys
Keys is a tool for managing and distributing secret keys at scale. In particular, it decouples a traditional key-management-system (KMS) - like AWS-KMS or Hashicorp Vault from large-scale and high-performance applications.

Almost every large-scale system deals with sensitive information that must be protected from unauthorized access. Therefore, applications encrypt network traffic and data at rest. However, someone has to provide the encryption keys to those applications at some point in time. An on-prem or cloud KMS can distribute unique encryption keys to those applications and also allows tight control over which encryption key is accessed by whom at which point in time.

### Getting Started

For your first steps checkout our [Getting Started](https://github.com/minio/kes/wiki/Getting-Started) guide.
