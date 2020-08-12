FROM alpine:latest as alpine
RUN apk add -U --no-cache ca-certificates

FROM scratch
MAINTAINER MinIO Development "dev@min.io"

COPY --from=alpine /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY kes /kes

EXPOSE 7373

ENTRYPOINT ["/kes"]
