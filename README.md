# 云资源鉴权中转服务

独立的 Python 3.11+ 中转服务，监控通过 `http://中转IP:18443` 访问，无需域名或证书。为七牛云、汇付斗拱、爱签和微信小程序提供厂商鉴权与只读请求转发。厂商 AK/SK、RSA 私钥和业务 token 由可信中转端保管；`cloud-resource-monitor` 使用受限中转令牌请求允许的官方接口，收到厂商原始 JSON 后，在监控端完成解析、分页、金额/额度计算、指标存储和告警。

**中转只负责鉴权和转发，所有监控与告警都在 `cloud-resource-monitor`。** 本服务不生成 Metric，不计算阈值或套餐余量，不汇总分页，不保存 MySQL 数据，也不调度监控或发送通知。一个中转 HTTP 请求对应一次厂商查询。

两项目分别部署和运行，通过 HTTP 通信，不导入、挂载对方源码。HTTP 会明文传输中转 token 和返回数据，仅用于可信内网或 VPN，限制访问来源为监控主机。中转到厂商仍使用经过证书校验的 HTTPS。当前示例提供 15 个只读操作模板、4 个客户端和 4 个厂商账号，默认全部关闭。当前项目已脱敏：正式配置和示例配置中的厂商账号标识及凭据已置空，现有密钥文件内容已清空；正式配置的授权关系和启用状态保留。启动前须重新填写凭据并准备有效的密钥、令牌文件。本地联调使用临时凭据和模拟厂商响应，不代表生产账号已联通。

## 目录

```text
cloud-resource-relay/
  cloud_resource_relay/       # HTTP 服务、客户端授权、只读接口校验和厂商鉴权
  config/
    config.yaml              # 已脱敏的正式配置，保留授权关系和启用状态
    config.example.yaml      # 账号凭据为空、默认关闭的示例
    secrets/                 # 厂商密钥、业务 token 和中转令牌
    tls/                     # 可选 HTTPS 模式证书；HTTP 不使用
  scripts/                   # 本地 HTTP / HTTPS 联调工具
  tests/
  pyproject.toml
  Dockerfile
  docker-compose.yml
```

`config` 整个目录不进入 Docker 镜像；正式配置、秘密目录及 TLS 文件被 Git 忽略。不要输出完整配置、环境变量、令牌、私钥或原始厂商响应。当前 `CHANGE_ME_*` 值及示例订单日期均不是业务数据。

## 职责与授权

| 内容 | 所在项目 |
| --- | --- |
| 厂商密钥、业务 token、请求签名、汇付响应验签 | 中转 |
| 客户端令牌、操作授权、资源访问范围、只读端点校验 | 中转 |
| 查询目标、时间窗口、分页、子账户筛选、订单监控清单 | 监控 |
| 金额换算、预算、额度、套餐有效期、指标和数据新鲜度 | 监控 |
| MySQL、Prometheus、Grafana、规则、恢复判定、通知 | 监控 |
| 爱签本地台账、SDK 历史结果、汇付公开 X.509 证书检查 | 监控本地，不经过中转 |

请求须同时满足：客户端启用且令牌有效、操作在该客户端的显式授权列表内、操作及厂商账号已启用、`provider + account + operation + kind` 与服务端映射完全一致。授权列表不支持通配符。随后按内置只读官方接口目录校验请求方法、完整官方 HTTPS URL、字段、参数类型及资源范围，最后由中转注入真实厂商鉴权。

中转不接受自定义请求头或厂商凭据，不允许任意域名、重定向或业务写操作。已有的支付、退款、出金、创建/签署合同、修改设置或令牌刷新等接口不在转发目录内。客户端改变 URL、方法或正文不能扩大授权范围。

`operations[].account` 是中转内部厂商账号 ID，例如 `qiniu-primary`；`monitor_account` 是监控配置账号 ID，例如 `qiniu-example`。中转账号的公开应用/商户标识须与监控端声明匹配，但密钥和业务 token 只在中转保存。

## 正式配置

在 [config/config.yaml](config/config.yaml) 中维护正式配置。当前交付文件已清空账号凭据，使用前须重新填写；文件路径和内部账号引用保留，不代表凭据已经可用。[config/config.example.yaml](config/config.example.yaml) 用作参考，示例默认关闭。完成部署后的日常升级应保留自行填写的正式配置和秘密文件。

脱敏 ZIP 包含源码、文档、测试、部署文件和脱敏配置，不包含 Git 历史、本地虚拟环境、缓存、临时文件、日志及已有压缩包。测试中的合成凭据仅用于离线验证。

| 配置 | 用途 |
| --- | --- |
| `version: 1` | 本地配置版本；线上请求协议版本为 2 |
| `api` | HTTP 监听 IP、端口、工作线程和读取请求超时；可选 HTTPS |
| `clients` | 中转令牌文件、显式操作授权、每分钟请求上限 |
| `accounts` | 厂商身份和鉴权凭据；只在中转端加载 |
| `operations` | 内部账号与监控账号映射、kind、资源访问范围、每请求超时 |

`clients[].requests_per_minute` 默认 60，范围为 1 至 600，按 HTTP 转发请求计数。分页、多个域名或多笔订单会产生多次请求，应按实际扇出评估配额。`operations[].minimum_interval_seconds` 默认 0，允许监控连续翻页；配置正间隔会限制同一操作的连续查询，需要与监控调用方式相容。

每操作 `timeout_seconds` 默认 20 秒，最大 120 秒，限制一次上游 HTTP 请求等待时间。`api.request_timeout_seconds` 控制读取客户端请求的超时。监控的 `relay.timeout_seconds` 应比实际单次上游超时留有网络余量。本服务没有业务来源年龄、分页上限或多请求计算预算配置；这些属于监控端 `options.collector`。

上游连接及响应头/正文读取受绝对超时限制；DNS 解析仍遵循操作系统解析器的超时设置，因此该参数不是包含 DNS 在内的整次请求截止保证。服务没有为 DNS 创建额外的无界解析线程，部署时应维护可靠的 DNS 配置。

配置支持 `${ENVIRONMENT_VARIABLE}` 替换，但 Compose 不自动传入所有宿主机环境变量。优先使用秘密文件；需要环境变量时在服务 `environment` 中逐项显式声明。示例路径均为容器内的 `/app/config/...`；直接运行 Python 时改为当前主机实际路径。

## 资源范围

`operations[].scope` 只限制允许读取的资源，不配置指标口径、阈值、分页或 SLA。

| 操作 | scope |
| --- | --- |
| `qiniu-kodo-standard` | `buckets: [允许的 Bucket]` |
| `qiniu-cdn-usage`, `qiniu-cdn-status` | `domains: [允许的域名]` |
| `asign-company-verification` | `company_selectors: [{account: 精确企业标识}]`，每项只选 account/creditCode/companyName 之一 |
| `wechat-api-quota` | `cgi_paths: [允许的 CGI 路径]` |
| `wechat-charge-packages` | `spu_ids: [允许的 SPU]` |
| `huifu-settlements` | `orders: [{org_req_date: "YYYYMMDD", org_req_seq_id: 精确原流水}]` |
| 其余已支持的在线 kind | `{}`，范围是当前配置的厂商账号/应用及固定只读接口 |

七牛财务/资源包列表及汇付余额等官方接口返回账号或商户级原始数据，中转不筛选响应中的包或子账户。启用这些操作意味着授权客户端读取该接口返回的账号范围数据；在监控配置选几个包或子账户不会把中转授权收窄到这些记录。资源范围无法进一步收紧时，使用专门的厂商账号或接受明确的账号级只读授权。

汇付出金的 `scope.orders` 是允许查询的交易身份，需随业务授权更新。它不是监控告警清单：待处理跟踪、清单时效和 SLA 仍在监控端 `huifu-orders.json` 中处理。移除中转授权会使后续查询被拒绝，不等于恢复监控告警。

## 操作模板

| 平台/监控账号 | 转发操作 |
| --- | --- |
| 七牛 `qiniu-example` | `qiniu-balance`, `qiniu-billing-snapshot`, `qiniu-packages-month`, `qiniu-package-expiry`, `qiniu-kodo-standard`, `qiniu-cdn-usage`, `qiniu-cdn-status` |
| 汇付 `huifu-example` | `huifu-balance`, `huifu-settlements` |
| 爱签 OpenAPI `asign-openapi-example` | `asign-company-verification` |
| 微信 `wechat-example` | `wechat-api-quota`, `wechat-charge-packages`, `wechat-annual-review`, `wechat-js-errors`, `wechat-performance` |

汇付公开证书检查没有中转操作，文件位于监控的 `config/integrations/huifu-certificate.pem`，不能包含私钥。爱签本地台账和历史 SDK 结果也继续由监控本地读取。

七牛使用中转端 AK/SK 生成官方 Qiniu/QBox 签名。汇付使用商户私钥签名并以平台公钥验签，商户标识必须绑定本服务配置；通过验签不表示交易成功，余额/交易业务字段仍由监控校验。爱签仅接入 OpenAPI，账号配置 `api_mode: openapi`，使用中转端私钥签名，向 `https://oapi.asign.cn` 转发已授权的企业认证查询。

微信业务服务统一维护中转端 token 缓存，中转不自行获取或刷新。缓存含真实 AppID、失效 Unix 秒及 `access_token`，第三方代调用则用 `authorizer_access_token`。年审须具备第三方授权和权限集 30；其他第三方接口的权限条件按官方要求验证。监控端可配置公开 AppID 和授权方式声明，但没有业务 token 文件。

## 安装与离线验证

在本目录执行：

```sh
python -m venv .venv
# 按当前操作系统激活虚拟环境。
python -m pip install -e ".[test]"
python -m cloud_resource_relay --config config/config.yaml check
python -m pytest -q
python -m ruff check .
python scripts/integration_check.py --monitor-project ../cloud-resource-monitor
```

`check` 只检查 YAML 结构、身份和资源授权范围，不调用厂商、不读取真实秘密；`check --live` 进一步校验已启用账号/操作及客户端的本地凭据，仍不访问上游。全部关闭的占位配置可以先进行离线检查。

集成脚本默认使用本地 IP + HTTP，无需证书：中转签名/注入鉴权并转发模拟厂商响应，监控原有适配器负责解析和计算。使用临时客户端令牌和模拟厂商凭据，不修改正式配置，不调用真实厂商、MySQL、通知或监控调度。加 `--scheme https` 可回归验证可选 TLS 模式，证书临时生成，不安装全局 CA。同级源码只作为联调参与方，不是中转运行依赖。

## 令牌与配置更新

```sh
python -m cloud_resource_relay issue-token --output config/secrets/qiniu-example.token
```

命令无需配置文件，将随机令牌写入指定文件，不向终端输出内容，目标已存在则拒绝覆盖。POSIX 文件以 `0600` 创建，Windows 需配合目录/文件 ACL。部署时确保 UID 10001 可读取所需文件。将仅此中转令牌通过可信渠道配置到监控 `config/relay/qiniu-example.token`，不要复制中转秘密目录或厂商 token。

客户端、账号、操作和资源范围在每次请求重新加载，令牌文件也每次重读。先离线检查待发布配置，再用原子替换发布。调整 `api` 配置后重启。轮换中转令牌时协调两端切换；启用客户端令牌文件缺失、格式错误或重复会使认证校验失败，应修复文件而不是关闭认证。

## IP 端口与 Docker

在 `config/config.yaml` 填写账号、客户端和资源授权，按需启用。监听配置已准备好，无需任何中转证书：

```yaml
api:
  scheme: http
  host: "0.0.0.0"
  port: 8443
```

```sh
docker compose build
docker compose run --rm --no-deps collection-relay --config /app/config/config.yaml check --live
docker compose up -d
docker compose logs --tail=100 collection-relay
```

最后两条是实际服务部署，开发验证不执行。服务没有后台厂商采集调度，但收到授权查询时会调用真实厂商。全部账号、操作和客户端关闭时仍可启动，没有客户端能转发查询。

Compose 以 UID/GID 10001 运行，只读挂载配置和秘密目录，根文件系统只读。默认发布 `0.0.0.0:18443` 到容器的 8443，可设置 `RELAY_BIND_IP` 仅绑定内网 IP，并用防火墙仅放行监控主机。监控填写 `http://中转主机IP:18443/v1/monitor/collect`；监控在 Docker 中时，不能用 `127.0.0.1` 代表另一容器或主机。直接运行 Python 则使用 `api.port`，默认 8443。

健康检查执行 CLI `health`，通过本地 HTTP 请求 `GET /healthz`，无需证书。健康状态表明中转与本地配置可用，不代表厂商账号已联通。挂载、环境或端口修改后使用 `docker compose up -d` 重建容器。

仍兼容可选 HTTPS：显式设 `api.scheme: https` 并配置 `cert_file`、`key_file`，自行挂载证书目录；证书加载失败会拒绝启动。健康检查用 `health_server_name` 校验名称，`health_ca_file` 指定可信 CA，未填时使用 `cert_file`。旧配置未写 `scheme` 但有证书字段时继续使用 HTTPS；无证书字段时默认 HTTP。HTTPS 客户端仍严格校验证书，不自动降级。

## 监控接入

监控保留公开的应用/商户标识与查询参数，厂商秘密全部移到中转。例如微信账号可有 `appid`、`token_type`、`permission_sets`，爱签可有 `app_id`；这些须与中转配置一致。

```yaml
# 监控端账号
id: qiniu-example
provider: qiniu
enabled: false
relay:
  url: http://192.0.2.10:18443/v1/monitor/collect
  token_file: /app/config/relay/qiniu-example.token
  timeout_seconds: 30
```

将示例 IP `192.0.2.10` 换成监控可达的中转主机 IP。HTTP 地址只允许字面 IP、显式端口和上述固定路径。两端令牌文件内容相同；其他厂商凭据不复制到监控端。

监控在线任务使用 `options.operation`、可选 `source_max_age_seconds` 和 `collector`；原有目标、预算、换算、分页、时间窗口等全部位于 `collector`。监控决定何时查询和如何从响应生成指标，中转只检查请求的授权并转发。

```yaml
options:
  operation: qiniu-kodo-standard
  source_max_age_seconds: 1800
  collector:
    buckets: [CHANGE_ME_BUCKET]
    max_source_age_seconds: 1800
```

中转 `qiniu-kodo-standard.scope.buckets` 必须包含这些 Bucket。授权范围与监控选择可以不同：中转范围规定最多能访问什么，监控选择规定当前查什么、如何计算和告警。配置完成后按需启用两端对应项。实际 `diagnose` 会通过中转调用厂商，仅在准备真实只读联调时执行。

## V2 请求协议

入口保留 `POST /v1/monitor/collect` 路径，JSON 协议版本为整数 `2`。使用 `Authorization: Bearer <中转令牌>`，请求身份必须逐项匹配授权。一次请求只允许一个经内置目录验证的官方 HTTP 请求，不接受额外 headers：

```json
{
  "version": 2,
  "request_id": "00112233445566778899aabbccddeeff",
  "provider": "wechat",
  "account": "wechat-example",
  "operation": "wechat-api-quota",
  "kind": "api_quota",
  "request": {
    "method": "POST",
    "url": "https://api.weixin.qq.com/cgi-bin/openapi/quota/get",
    "body": {"cgi_path": "/cgi-bin/message/subscribe/send"}
  }
}
```

`request_id` 是每次请求新生成的 32 位小写十六进制 UUID。URL 必须是内置只读目录允许的无凭据官方 HTTPS 地址，body 只能为对象或 null，具体字段严格按接口验证。客户端不得传递厂商 token、签名或任意鉴权字段。

成功响应回显六个身份字段，另有 `status: "ok"`、`signature_verified` 和 `response`。后者是厂商原始 JSON，没有 `metrics` 或 `query_performed`；汇付已验签时 `signature_verified=true`，其余为 null。监控按原厂商适配器检查业务码、身份、分页完整性及数据时间，然后生成指标。

失败只回显身份并附加 `status: "error"` 和受限 `reason`，不包含厂商秘密、错误页面或堆栈。认证或 HTTP 格式错误可直接返回拒绝状态。中转不将原始业务失败改写为正常指标；业务判断仍由监控负责。两端完整接口约定见监控项目 `docs/collection-relay.md`，它只用于协作文档，不是本服务运行依赖。
