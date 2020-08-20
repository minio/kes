FROM golang:1.14-alpine as build

LABEL maintainer="MinIO Inc <dev@min.io>"

ENV GOPATH /go
ENV CGO_ENABLED 0
ENV GO111MODULE on

RUN  \
     apk add --no-cache git && \
     git clone https://github.com/minio/kes && cd kes && \
     GOPROXY=$(go env GOPROXY) go install -v -ldflags "-s -w" ./cmd/kes

FROM alpine:latest as alpine
RUN apk add -U --no-cache ca-certificates

FROM scratch

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/kes /kes

EXPOSE 7373

ENTRYPOINT ["/kes"]
