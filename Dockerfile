FROM golang:1.13-alpine

LABEL maintainer="MinIO Inc <dev@min.io>"

ENV GOPATH /go
ENV CGO_ENABLED 0
ENV GO111MODULE on
ENV GOPROXY https://proxy.golang.org

RUN  \
     apk add --no-cache git && \
     go install -v -ldflags "-s -w" github.com/minio/kes/cmd/release && \
     go install -v -ldflags "-s -w -X main.version=$(release)" github.com/minio/kes/cmd/kes

FROM alpine:3.10

EXPOSE 7373

COPY --from=0 /go/bin/kes /usr/bin/kes

RUN  \
     apk add --no-cache ca-certificates 'curl>7.61.0' 'su-exec>=0.2' && \
     echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf

ENTRYPOINT ["kes"]
