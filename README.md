# frp-otp

基于动态验证码的 FRP 临时 IP 授权插件。一个密钥、一份全局授权表，默认拒绝未授权且不在信任网段内的访客；授权后当前 IP 默认可在四小时内新建连接。

不需要域名，不内置 HTTPS，不分渠道，无账号管理、分渠道规则或通知。授权存在内存中，重启后清空。授权到期不主动断开已有连接；同一个公网 IP 后的设备共享授权。默认对 `10.0.0.0/8`、`192.168.0.0/16` 访客免验证放通，可通过 `trust_networks` 配置替换或关闭。

## 可执行文件下载

从 [Releases](https://github.com/gaolujie1989/frp-otp/releases) 下载对应系统和架构的压缩包。解压后运行 `./frp-otp -e key`，填写 `frp.otp.json` 的密钥，再运行 `./frp-otp -e web -c ./frp.otp.json`；Windows 使用 `frp-otp.exe`。下载包附带 `SHA256SUMS` 校验文件。

## 运行

依赖：Go **1.27.3**；FRP **v0.71.1**；OTP 库 **v1.5.0**。

```bash
make build
./bin/frp-otp -e key
```

把输出的 Secret 填入 `frp.otp.json`，在支持 SHA-512 的认证器中导入完整 `otpauth://` URI，或手动配置：6 位、30 秒、SHA-512。密钥生成不会修改配置文件，不再生成二维码文件。

```json
{
  "BindAddress": "127.0.0.1:9000",
  "secret": "填入刚生成的密钥",
  "grant_duration": "4h",
  "trust_networks": ["10.0.0.0/8", "192.168.0.0/16"]
}
```

```bash
./bin/frp-otp -e web -c ./frp.otp.json
./bin/frp-otp -v
```

没有 `start` 子命令。`-e web` 是默认入口。配置错误和端口占用会以非零状态退出。未知配置字段会报错，旧配置需要替换。

访问 `http://服务器地址:9000/` 或 `/knock`，提交动态验证码授权当前 IP。GET 请求只显示表单，授权只接受 POST。

每个来源 IP 在一分钟内最多允许五次失败验证，达到上限后必须等窗口结束；一次失败后立即输入正确验证码仍可授权。授权时长由 `grant_duration` 配置，默认四小时。验证码在有效时间步内可以重复验证；这不是严格的单次令牌系统。

## 授权时长和信任网段

- `grant_duration`：正数时长字符串，例如 `4h`、`30m`、`1h30m`；省略或空字符串时默认 `4h`。不接受零、负数或无效时长。
- `trust_networks`：免验证码放通的访客 CIDR 列表，支持 IPv4 和 IPv6。省略或为 `null` 时默认 `["10.0.0.0/8", "192.168.0.0/16"]`；显式设置列表会替换默认网段，设置 `[]` 关闭全部免验证放通。
- 网段必须使用完整 CIDR，例如 `10.0.0.0/8`，不能简写为 `10.0/8`。无效网段会使启动失败。
- `172.16.0.0/12`、回环及 IPv6 私网默认不免验证；需要时自行添加到 `trust_networks`。
- 修改配置后重启生效。旧配置省略新字段时会使用上述默认值。

免验证放通匹配 frps `NewUserConn.remote_addr` 中的访客 IP，不依据插件回调的来源 IP 或 XFF。`trust_networks` 不改变可信代理的 XFF 解析规则，也不放开 `/handler` 的回调来源限制。授权页面及成功提示显示实际配置时长。

## FRP 配置

将以下配置添加到 `frps.toml`，完整示例见 [examples/frps.toml](examples/frps.toml)：

```toml
[[httpPlugins]]
name = "frp-otp"
addr = "127.0.0.1:9000"
path = "/handler"
ops = ["NewProxy", "NewUserConn"]
```

代理注册时不要求访问者先授权；访客新建连接时检查全局 IP 授权表，与代理名称无关。frps 的 token/OIDC 认证继续独立配置。插件不可用或返回错误时，所订阅的代理注册和新连接会失败。

支持 TCP、HTTPS、STCP、TCPMUX。HTTP、UDP、SUDP、XTCP 不具备这里需要的完整访客 IP 准入语义，因此拒绝它们的代理注册，防止误以为已经受保护。STCP 匹配的是 visitor 连接到 frps 的出口 IP，而非 visitor 后面的终端 IP。无需为了这个插件修改 frpc。

## 真实 IP 与可信代理

先检查 HTTP 连接的直接来源地址：只有 RFC1918 私网（`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`）、IPv6 ULA 和回环来源，才信任 `X-Forwarded-For`。使用 IP 地址解析，不按字符串前缀判断。这里的可信代理规则独立于 `trust_networks` 访客免验证网段配置。

- 公网直接来源：忽略 XFF，使用连接来源 IP。
- 私网直接来源：从右向左跳过可信代理，取最近的非可信 IP；全部为内网时取最左端 IP。
- 没有 XFF：使用直接来源 IP。
- 可信来源的 XFF 含无效项：拒绝授权，不退回代理 IP。
- IPv4、IPv6、IPv4-mapped IPv6 会规范化，避免同一 IP 匹配失败。

例如 `X-Forwarded-For: 伪造IP, 用户IP, 内网代理IP`，识别到的是用户 IP。

WAF/反代应覆盖或按标准追加真实连接来源地址，并限制回源入口只有可信代理可达。特别注意 Docker/SNAT 可能让公网请求在应用看来都来自私网网关，此时仅靠私网来源判断无法区分是否真正经过 WAF。

`/handler` 只接受来自私网或回环连接的 POST 回调；公网 WAF 只需暴露 `/` 和 `/knock`。不要把整个 `/handler` 路径代理到公网。

授权网页识别的 IP 必须与 frps `NewUserConn.remote_addr` 中的 IP 一致。FRP 数据入口若被额外 SNAT 或代理，需要确保不会把所有访客变成同一个网关 IP。

## Docker

已提供 GHCR 镜像（Linux amd64/arm64），可使用固定版本或 latest：

```bash
docker pull ghcr.io/gaolujie1989/frp-otp:v0.1.1
docker run --rm ghcr.io/gaolujie1989/frp-otp:v0.1.1 -v
```

填好配置后启动：

```bash
docker run -d --name frp-otp --restart unless-stopped \
  -p 127.0.0.1:9000:9000 \
  -v "$(pwd)/frp.otp.json:/etc/frp-otp.json:ro" \
  ghcr.io/gaolujie1989/frp-otp:v0.1.1
```

配置中的 BindAddress 需为 `0.0.0.0:9000`，密钥需先生成。配置文件需要能被容器 UID 65532 读取。镜像的版本标签对应同名 Git tag 的源代码，latest 指向最近发布的版本。

### 本地构建

先填好 `frp.otp.json` 的密钥，`BindAddress` 设置为 `0.0.0.0:9000`。配置文件需要能被容器 UID 65532 读取，避免给无关用户读取密钥的权限。

```bash
docker compose up -d --build
```

默认只将端口映射到宿主机 `127.0.0.1:9000`，供宿主机 frps 和 WAF/反代回源。跨容器调用应使用共享私网和服务名 `frp-otp:9000`。

生成密钥也可以使用构建后的镜像，无需配置文件：

```bash
docker compose build
docker compose run --rm frp-otp -e key
```

容器以非 root 身份运行，只提供 HTTP。TLS 和公网域名由外部入口自行处理。

## 验证

```bash
make test
make vet
```

本项目 fork 自 [csg2008/frp-otp](https://github.com/csg2008/frp-otp)，保留 Apache-2.0 许可证。

## 发布维护

`VERSION` 保存发布版本号（例如 `v0.1.0`）。更新它并提交到 main 后，Release 工作流会测试、构建六个平台压缩包、生成 SHA256SUMS，再发布 GitHub Release。也可手动运行 Release 工作流。已发布版本不可覆盖，重新发布应使用新版本号，并添加 `docs/releases/版本号.md` 发布说明。

本地构建发布包：`./scripts/build-release.sh`。输出目录为 `release/版本号/`，打包时总是生成空密钥配置，不包含本地运行密钥。

发布 Release 后会继续发布对应的 GHCR 镜像（`v版本号` 和 `latest`）。首次安装或修改 Docker 发布工作流时也会构建当前 VERSION 指定的已发布版本；也可手动运行 Publish Docker image 工作流。镜像始终从对应 Git tag 构建业务代码，并使用当前 Dockerfile 打包。
