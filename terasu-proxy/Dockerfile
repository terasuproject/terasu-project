ARG GO_VERSION=1.24

FROM golang:${GO_VERSION} AS builder
WORKDIR /src

# cache deps
COPY terasu-proxy/go.mod ./
COPY terasu-proxy/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY terasu-proxy/ ./
RUN --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -ldflags="-s -w -checklinkname=0" -o /out/terasu-proxy ./cmd/terasu-proxy

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/terasu-proxy /usr/local/bin/terasu-proxy
COPY terasu-proxy/config.example.yaml /etc/terasu-proxy/config.yaml

ENV TERASU_PROXY_METRICS_ADDR=0.0.0.0:9090

VOLUME ["/data"]
EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/terasu-proxy"]
CMD ["-config","/etc/terasu-proxy/config.yaml"]




