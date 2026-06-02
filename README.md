# CF Auto Check（Python 版）

Cloudflare IP / 域名延迟和速度测试服务，使用 Python 重写并集成 [CloudflareSpeedTest (CFST)](https://github.com/XIU2/CloudflareSpeedTest)。

## 功能特性

- **CFST 集成**：调用 CloudflareSpeedTest 二进制进行精准的延迟与速度测试。
- **两阶段智能测试**：先用 CFST 测全部 IP 的延迟，再对延迟最优的 IP 做下载测速。443 端口取前 `SPEED_TEST_COUNT_443` 个，非 443 端口共享前 `SPEED_TEST_COUNT` 个。
- **自动下载二进制**：根据系统平台自动下载并解压对应版本的 CFST。
- **多端口并行**：按端口对 IP 分组，多个端口在同一阶段内并行测试。
- **定时调度**：支持 cron 表达式定期执行。
- **自动更新备注**：API 备注格式 `IP 区域|延迟|速度MB/s`。
- **启用 CFIP 稳定性维护**：`SYNC_TO_CF_CRON` 周期性对处于 `enabled` 状态的 CFIP 重新测速并更新数据，然后把符合 `SYNC_TO_CF_FILTER_PORT` 的最优结果同步到 Cloudflare DNS。
- **Telegram 机器人**：内置长轮询，支持 `/cfst`、`/cfst_maint`、`/cfst_blacklist_current`、`/cfst_status`、`/cfst_health`、`/cf_sync <IP>` 等命令。
- **Telegram 独立代理**：通过 `TG_PROXY` 仅为 Telegram API 配置代理。
- **手动 Cloudflare 同步**：用 `/cf_sync <IP>` 强制覆盖目标 IP。
- **双黑名单类型**：`DNS` 黑名单仅影响 Cloudflare DNS 同步候选顺延；`节点` 黑名单用于在查询 CFIP 列表时过滤待测节点。
- **当前 CF 同步 IP DNS 拉黑**：读取当前 Cloudflare DNS A 记录，将其匹配的 CFIP 加入 DNS 黑名单后立即重新触发启用维护。
- **回退测试**：CFST 失败时回退到手工 ping 测试。

## 运行环境

- Python 3.9+
- `ping` 命令（用于回退测试）
- 联网（首次启动需要下载 CFST）

## 安装

1. 克隆仓库
2. 创建并激活虚拟环境：
   ```bash
   python -m venv venv

   # macOS / Linux
   source venv/bin/activate

   # Windows
   .\venv\Scripts\activate
   ```
3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```

## 配置

复制 `.env.example` 为 `.env` 并按需修改：

```ini
# ── API ───────────────────────────────
API_URL=https://your-worker.pages.dev
API_KEY=your-api-key-here

# API 客户端
API_MAX_RETRIES=3
API_RETRY_DELAY=2000          # 毫秒
API_USE_SESSION_TOKEN=true

# ── 调度 ──────────────────────────────
ENABLE_CRON_SCHEDULER=true
CHECK_CRON=0 * * * *          # 每小时整点

# ── CFST 测试 ─────────────────────────
LATENCY_THREADS=200           # 两阶段共用的线程数（CFST -n）
SPEED_TEST_COUNT=20           # Phase 2 非 443 端口共享的测速数量
SPEED_TEST_COUNT_443=20       # Phase 2 443 端口测速数量
SPEED_ENABLE_COUNT=50         # 非 443 端口共享启用数量
SPEED_ENABLE_COUNT_443=50     # 443 端口启用数量
SPEED_TEST_URL=https://speed.cloudflare.com/__down?bytes=200000000
MAX_LATENCY=9999              # 平均延迟上限（ms）
MAX_LOSS=1.0                  # 丢包率上限（0.0–1.0）
RESULT_CACHE_HOURS=8          # 结果缓存有效期（小时）

# 选优策略：lowest_latency / highest_speed / lowest_latency_nonzero
SELECT_MODE=highest_speed

# ── 测试模式 ──────────────────────────
TEST_MODE=cfip                # cfip / proxyip / outbound / all
ENABLE_AUTO_UPDATE=true

# ── 启用维护 + Cloudflare 同步 ────────
SYNC_TO_CF=true
CF_API_TOKEN=your-cloudflare-api-token
CF_ZONE_ID=your-zone-id
CF_RECORD_NAME=cf.example.com
SYNC_TO_CF_FILTER_PORT=443    # 0 表示不限端口
SYNC_TO_CF_CRON=*/30 * * * *  # 启用维护 cron，留空禁用

# 启动时是否立即跑一次启用维护，默认 false（仅按 cron 触发）
RUN_MAINTENANCE_ON_STARTUP=false

# ── 本地 GET 触发 API（可选） ─────────
ENABLE_API_TRIGGER=true
API_TRIGGER_KEY=your-trigger-key
API_TRIGGER_PORT=8080

# ── Telegram 通知（可选） ─────────────
TG_ENABLED=true
TG_BOT_TOKEN=your-bot-token
TG_CHAT_ID=your-chat-id
TG_PROXY=                     # 仅 Telegram 走代理
TG_BOT_COMMANDS_ENABLED=true  # 启用内置 Bot 命令

# ── CFIP 导入 API（可选） ─────────────
CFIP_IMPORT_API_URL=
CFIP_IMPORT_API_KEY=
TG_IMPORT_NOTIFY_CHANNEL_ID=  # 例：-1003460092123，把导入结果同步推到频道
```

### 启用维护与 Cloudflare 同步

`SYNC_TO_CF_CRON` 会启动一个独立的维护循环，专门针对当前已 `enabled` 的 CFIP：重新测延迟和下载速度、回写最新指标和状态，再把命中 `SYNC_TO_CF_FILTER_PORT` 的最优结果同步到 Cloudflare。把 `SYNC_TO_CF_FILTER_PORT` 保持为 `443` 即可保留"只同步 443"的旧行为；设为 `0` 则不限端口。**这条维护路径在 `ENABLE_AUTO_UPDATE=false` 时也会更新参与的 enabled 记录。**

黑名单语义：

- `sync_blacklisted=1`：仅在 Cloudflare DNS 同步选优时跳过该候选，并顺延下一位；同一 `IP:port` 下只要有任一关联记录被 DNS 拉黑，或测速结果无法映射回 CFIP，也会跳过；不会阻止普通检测或启用维护测速。
- `node_blacklisted=1`：在查询 CFIP 列表时直接过滤，不参与普通检测和启用维护的待测集合。

`RUN_MAINTENANCE_ON_STARTUP` 控制服务**启动瞬间是否立即跑一次**启用维护：

- `false`（默认）：服务启动后**不再**自动触发维护，仅按 `SYNC_TO_CF_CRON` 到点执行。
- `true`：保留旧行为，启动时立刻跑一次再进入 cron 等待循环。

需要立即手动触发时，可使用 Telegram `/cfst_maint` 或下方的触发接口。

### 当前 CF 同步 IP 加入 DNS 黑名单

```text
GET /blacklist-current-cf?key=your-trigger-key
GET /blacklist-current-cf?key=your-trigger-key&strategy=maintenance
```

默认 `strategy=blacklist`：会读取 `CF_RECORD_NAME` 的 A 记录、把命中的 CFIP `sync_blacklisted` 设为 1；如果没有匹配的 CFIP 记录，则以当前 Cloudflare A 记录 IP 创建一条已加入 DNS 黑名单的 CFIP，再异步重新触发启用维护。`strategy=maintenance` 时只异步触发启用维护，不读取当前 CF DNS，也不写入黑名单。Telegram 命令 `/cfst_blacklist_current` 行为一致。DNS 黑名单只影响 Cloudflare 同步候选选择，不影响普通检测和启用维护测速。

### 黑名单查询 / 拉黑 / 解黑接口

这组接口可直接给管理界面或脚本使用，统一支持 `DNS` / `节点` 两类黑名单：

```text
GET /cfip-blacklist/query?key=your-trigger-key&type=dns&blacklisted=true
GET /cfip-blacklist/set?key=your-trigger-key&type=node&ids=12,13&blacklisted=false
```

- `type`：`dns` / `node`
- `blacklisted`：`true` / `false`
- `id` 或 `ids`：单个或多个 CFIP ID
- 查询接口还支持：`address`、`port`、`status`、`limit`

查询返回每条记录的 `sync_blacklisted` 和 `node_blacklisted` 两个字段；设置接口通过 `blacklisted=true/false` 分别表示拉黑和解黑。

## 触发接口

启用 `ENABLE_API_TRIGGER=true` 后，监听 `API_TRIGGER_PORT`，所有路径都需要 `?key=API_TRIGGER_KEY`：

| 路径 | 说明 |
|------|------|
| `/trigger?key=xxx` | 触发完整两阶段检测 |
| `/trigger?key=xxx&phase=latency` | 仅跑延迟测试 |
| `/trigger?key=xxx&phase=speed` | 仅跑速度测试（用缓存的延迟数据）|
| `/trigger?key=xxx&phase=reprocess` | 用缓存的延迟+速度数据重新生成结果（不跑 CFST）|
| `/trigger?key=xxx&force=true` | 强制重跑（删除缓存）|
| `/blacklist-current-cf?key=xxx` | 将当前 CF 同步 IP 加入 DNS 黑名单并重新维护 |
| `/blacklist-current-cf?key=xxx&strategy=maintenance` | 不拉黑，直接触发启用维护 |
| `/cfip-blacklist/query?key=xxx&type=dns&blacklisted=true` | 查询 DNS / 节点黑名单状态 |
| `/cfip-blacklist/set?key=xxx&type=node&ids=1,2&blacklisted=false` | 设置或解除指定类型黑名单 |
| `/status?key=xxx` | 查看运行状态 |
| `/health` | 健康检查（无需 key）|

## 使用

### 本地运行

```bash
python -m src.main
```

当 `TG_ENABLED=true` 且 `TG_BOT_COMMANDS_ENABLED=true` 时，Telegram Bot 会随服务自动启动。

### Docker 运行

#### 使用预构建镜像（推荐）

```bash
docker run -d \
  --name cf-auto-check \
  --restart unless-stopped \
  --env-file .env \
  -v ./cfst_data:/app/cfst_data \
  ghcr.io/assast/cf-auto-check:latest
```

#### 本地构建

```bash
docker build -t cf-auto-check .

docker run -d \
  --name cf-auto-check \
  --restart unless-stopped \
  --env-file .env \
  cf-auto-check
```

或使用 Docker Compose：

```bash
docker-compose up -d
```

## 项目结构

```
cf-auto-check/
├── src/
│   ├── main.py              # 主入口、CFST 集成、调度器
│   ├── api_client.py        # 后端 API 交互、批量更新、认证、重试
│   ├── telegram_bot.py      # Telegram 命令机器人（长轮询）
│   ├── telegram_notifier.py # Telegram 消息通知
│   ├── config.py            # 配置加载
│   └── logger.py            # 日志
├── cfst_data/               # CFST 二进制和测试结果（自动创建）
│   ├── cfst                 # CFST 二进制
│   ├── ips_{port}.txt       # 每端口 IP 列表
│   ├── latency_{port}.csv   # Phase 1 延迟结果
│   ├── speed_ips_{port}.txt # Phase 2 选中的 IP 列表
│   └── speed_{port}.csv     # Phase 2 速度结果
├── .env.example
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

---

参考：<https://github.com/XIU2/CloudflareSpeedTest>
