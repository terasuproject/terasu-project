# terasu-proxy

## 概述

以 MITM 方式实现的显式 HTTP 代理（支持 HTTP/1.1 与 HTTP/2），出站统一使用 `github.com/fumiama/terasu` 的 HTTP/HTTP2 客户端（自带 DoH/DoT 与定制 TLS 握手）以提升直连成功率并规避审查。

- **拦截模式**: `all`（全量拦截）或 `list`（按名单拦截，支持后缀匹配）
- **证书**: 首次运行自动生成根 CA 并写入到 `/data/ca.pem`、`/data/ca.key`；MITM 需在客户端/系统信任该 CA
- **入站**: 与客户端建立 TLS（`NextProtos=[h2,http/1.1]`），内部使用内嵌 `http.Server` 转发
- **出站**: 复用 `terasu/http.DefaultClient.Transport`（DoH/DoT + 定制握手 + HTTP/2 优先，失败回退）
- **可选**: Basic Auth、最大并发限制、健康检查 `/healthz`

参考与致谢：[`fumiama/terasu`](https://github.com/fumiama/terasu)

## 快速开始（Docker）

```bash
# 构建镜像（在仓库根目录）
docker build -t terasu-proxy:dev -f terasu-proxy/Dockerfile .

# 启动（默认 list 模式，CA 保存到 ./data）
mkdir -p ./data
docker run -d --name terasu-proxy \
  -p 8080:8080 -p 9090:9090 \
  -v "$PWD/data:/data" \
  terasu-proxy:dev

# 健康检查
curl -sS http://127.0.0.1:9090/healthz
```

使用系统 DNS 且禁用 IPv6（某些网络环境更稳定）：

```bash
docker run -d --name terasu-proxy \
  -e TERASU_PROXY_DNS_MODE=system -e GODEBUG=ipv6=0 \
  -p 8080:8080 -p 9090:9090 \
  -v "$PWD/data:/data" \
  terasu-proxy:dev
```

## 客户端示例（容器内验证）

不改宿主系统证书，直接在容器中使用本地 CA：

```bash
# macOS 使用 host.docker.internal 访问宿主代理
docker run --rm \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -v "$PWD/data/ca.pem:/ca.pem:ro" \
  curlimages/curl:8.8.0 -sSI https://registry-1.docker.io/v2/ --cacert /ca.pem

docker run --rm \
  -e HTTPS_PROXY=http://host.docker.internal:8080 \
  -v "$PWD/data/ca.pem:/ca.pem:ro" \
  curlimages/curl:8.8.0 -sSI https://github.com --cacert /ca.pem
```

期望：`registry-1.docker.io/v2/` 返回 401（未携带 token），`github.com` 返回 200/301。

## Docker 守护进程代理（可选）

- **代理**：
  - macOS（Docker Desktop）：Settings → Resources → Proxies 设置 `http://host.docker.internal:8080`
  - Linux（systemd）：`/etc/systemd/system/docker.service.d/http-proxy.conf` 设置 HTTP(S)_PROXY 后重启 docker
- **信任 CA**：
  - macOS：`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./data/ca.pem`
  - Linux（仅对 docker hub 域名）：

    ```bash
    sudo mkdir -p /etc/docker/certs.d/registry-1.docker.io
    sudo cp ./data/ca.pem /etc/docker/certs.d/registry-1.docker.io/ca.crt
    sudo systemctl restart docker
    ```

## 配置

容器默认读取 `/etc/terasu-proxy/config.yaml`；示例见 `terasu-proxy/config.example.yaml`。常用键：

- **listen**: 监听地址，默认 `0.0.0.0:8080`
- **mode**: `all` | `list`
- **intercept_list**: 名单模式的域名/后缀（如 `docker.io`, `github.com`）
- **ca.cert_file / ca.key_file / ca.auto_generate**: 根证书路径与自动生成
- **logging.level**: `info`/`debug`...
- **metrics.addr**: 健康检查/指标监听地址（默认 `0.0.0.0:9090`）
- **dns.mode**: `auto` | `terasu` | `system`

环境变量覆盖（部分）：

- `TERASU_PROXY_LISTEN`
- `TERASU_PROXY_MODE`
- `TERASU_PROXY_INTERCEPT_LIST`（逗号分隔）
- `TERASU_PROXY_CA_CERT_FILE` / `TERASU_PROXY_CA_KEY_FILE` / `TERASU_PROXY_CA_AUTO_GENERATE`
- `TERASU_PROXY_LOG_LEVEL`
- `TERASU_PROXY_METRICS_ADDR`
- `TERASU_PROXY_DNS_MODE`
- `TERASU_PROXY_LIMITS_MAX_CONNS` / `TERASU_PROXY_LIMITS_READ_TIMEOUT` / `TERASU_PROXY_LIMITS_WRITE_TIMEOUT`
- `TERASU_PROXY_BASIC_AUTH_ENABLED` / `TERASU_PROXY_BASIC_AUTH_USERNAME` / `TERASU_PROXY_BASIC_AUTH_PASSWORD`

## 拦截模式

- **all**: 拦截所有 CONNECT 流量
- **list**: 仅拦截名单内域名（后缀匹配：`example.com` 覆盖 `a.example.com`）

建议名单（示例）：`docker.io`, `registry-1.docker.io`, `auth.docker.io`, `github.com`, `ghcr.io`。

## 常见问题

- **x509: certificate signed by unknown authority**：未信任 `ca.pem`。在请求中显式 `--cacert /ca.pem` 或将 CA 导入系统/容器/守护进程信任库。
- **502 或握手失败**：尝试 `TERASU_PROXY_DNS_MODE=system` 与 `GODEBUG=ipv6=0`；或切换网络再试。
- **名单未生效**：`mode=list` 时需确保域名在 `intercept_list` 中，或临时改为 `mode=all` 排查。

## 许可与注意

- 本项目出站依赖 `github.com/fumiama/terasu`（AGPL-3.0），使用/分发需遵守相应条款
- 最低 TLS 1.2；不支持 QUIC/HTTP3（对 Docker Hub 不构成实际影响）
