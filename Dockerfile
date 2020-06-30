FROM golang:1.14-alpine

LABEL maintainer="MinIO Inc <dev@min.io>"

ENV GOPATH /go
ENV CGO_ENABLED 0
ENV GO111MODULE on

RUN  \
     apk add --no-cache git && \
     go install -v -ldflags "-s -w" github.com/minio/kes/cmd/release && \
     GOPROXY=$(go env GOPROXY) go install -v -ldflags "-s -w -X main.version=$(release)" github.com/minio/kes/cmd/kes

FROM alpine:3.12

EXPOSE 7373

COPY --from=0 /go/bin/kes /usr/bin/kes

RUN  \
     apk add --no-cache ca-certificates 'curl>7.61.0' 'su-exec>=0.2' && \
     echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf

ENTRYPOINT ["kes"]
