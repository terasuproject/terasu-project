ARG DOTNET_SDK_TAG=9.0
ARG GO_VERSION=1.24

FROM golang:${GO_VERSION} AS proxy_builder
WORKDIR /src
COPY terasu-proxy/go.mod terasu-proxy/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY terasu-proxy/ ./
RUN --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 go build -ldflags="-s -w -checklinkname=0" -o /out/terasu-proxy ./cmd/terasu-proxy

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_SDK_TAG} AS ctl_builder
RUN apt-get update && apt-get install -y --no-install-recommends clang binutils && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY terasu-controller/ ./terasu-controller/
RUN dotnet publish terasu-controller/terasu-controller-CLI/terasu-controller-CLI.csproj -c Release -r linux-arm64 -p:PublishAot=true --self-contained true -o /out/linux-arm64

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=proxy_builder /out/terasu-proxy /usr/local/bin/terasu-proxy
COPY --from=ctl_builder /out/linux-arm64/terasu-controller-CLI /usr/local/bin/terasu-ctl
ENV TERASU_PROXY_BIN=/usr/local/bin/terasu-proxy
EXPOSE 8080 9090
ENTRYPOINT ["/bin/sh","-c"]
CMD ["/usr/local/bin/terasu-ctl set-listen 0.0.0.0:8080; /usr/local/bin/terasu-ctl set-metrics-addr 0.0.0.0:9090; /usr/local/bin/terasu-ctl install-ca || true; /usr/local/bin/terasu-ctl show-ca; /usr/local/bin/terasu-ctl set-mode all; /usr/local/bin/terasu-ctl start; tail -f /dev/null"]


