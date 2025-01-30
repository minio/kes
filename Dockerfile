FROM registry.access.redhat.com/ubi9/ubi-minimal:9.5 as build

RUN microdnf update -y --nodocs && microdnf install ca-certificates --nodocs

FROM registry.access.redhat.com/ubi9/ubi-micro:9.5

ARG TAG

LABEL name="MinIO" \
      vendor="MinIO Inc <dev@min.io>" \
      maintainer="MinIO Inc <dev@min.io>" \
      version="${TAG}" \
      release="${TAG}" \
      summary="KES is a cloud-native distributed key management and encryption server designed to build zero-trust infrastructures at scale."

# On RHEL the certificate bundle is located at:
# - /etc/pki/tls/certs/ca-bundle.crt (RHEL 6)
# - /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem (RHEL 7)
COPY --from=build /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/

COPY LICENSE /LICENSE
COPY CREDITS /CREDITS
COPY kes /kes

EXPOSE 7373

ENTRYPOINT ["/kes"]
CMD ["kes"]
