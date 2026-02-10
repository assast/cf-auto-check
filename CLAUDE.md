# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CF Auto Check 是一个 Cloudflare IP/域名延迟和速度测试服务，使用 Python 编写，集成了 CloudflareSpeedTest (CFST) 二进制工具进行精确的延迟和速度测试。

## Development Commands

### 环境设置
```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境 (macOS/Linux)
source venv/bin/activate

# 激活虚拟环境 (Windows)
.\venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt
```

### 运行应用
```bash
# 本地运行
python -m src.main

# Docker 构建
docker build -t cf-auto-check .

# Docker 运行
docker run -d --name cf-auto-check --restart unless-stopped --env-file .env cf-auto-check

# Docker Compose
docker-compose up -d
```

## Architecture

### 核心组件

1. **CFAutoCheck (src/main.py)** - 主服务类
   - 管理整个检测生命周期
   - **两阶段分步执行**：
     - Phase 1 (延迟测试)：使用 CFST `-dd` 纯延迟测试，高并发线程（LATENCY_THREADS=200）
     - Phase 2 (速度测试)：对延迟最优的 Top N 个 IP 进行下载速度测试
   - 支持两种运行模式：
     - Cron 调度器：按 cron 表达式定期执行检测
     - API 触发器：通过 HTTP API 手动触发检测
   - 处理 CFST 二进制的自动下载和执行
   - 实现域名解析（支持多种方法：socket、dig、nslookup）
   - 按端口分组测试 IP，多端口并行执行

2. **ApiClient (src/api_client.py)** - API 客户端
   - 实现会话令牌认证机制
   - 自动重试逻辑（可配置次数和延迟）
   - 401 错误时自动重新登录
   - 支持三种资源类型：cfip、proxyip、outbound
   - **批量 API**：`batch_update_cf_ips_api()` 调用 `/api/cfip/batch/update` 批量更新
   - **批量状态**：`batch_status_cf_ips()` 调用 `/api/cfip/batch/status`

3. **TelegramNotifier (src/telegram_notifier.py)** - Telegram 通知
   - 独立的代理配置（仅用于 Telegram API）
   - 发送测试结果摘要

4. **Config (src/config.py)** - 配置管理
   - 从 .env 文件加载所有配置
   - 提供类型转换和默认值

### 关键工作流程

#### 两阶段 IP 检测流程 (check_cf_ips)

**Phase 1: 延迟测试** (`run_latency_phase`)
1. 从 API 获取 CF IP 列表
2. 域名解析 + 按端口分组
3. 对每个端口组并行运行 CFST（`-dd` 禁用下载，`-n LATENCY_THREADS`）
4. 结果缓存到 `latency_{port}.csv`

**Phase 2: 速度测试** (`run_speed_phase`)
1. 从 Phase 1 结果中按延迟排序，所有端口合计取前 `SPEED_TEST_COUNT` 个 IP（按端口比例分配）
2. 对每个端口组运行 CFST（含下载测速）
3. 结果缓存到 `speed_{port}.csv`
4. 按 `SELECT_MODE` 排序，保留前 `SPEED_ENABLE_COUNT` 个

**API 更新**
5. 使用 `/api/cfip/batch/update` 批量更新所有 CFIP 的测试数据
6. Top M 个 IP 设置为 enabled，其余 disabled
7. 获取 IP 地理信息（ipapi.is API）
8. 同步 CF DNS + 发送 Telegram 通知

#### 缓存和重跑支持

- **缓存文件**：`latency_{port}.csv`（Phase 1）、`speed_{port}.csv`（Phase 2）
- **重跑**：使用缓存数据，无需重新测试
- **强制重跑**：`force=true` 删除缓存后重新测试
- **单阶段重跑**：`phase=latency` 或 `phase=speed` 独立运行

#### CFST 集成
- 自动检测平台（macOS/Linux，ARM/AMD64）
- 从 GitHub releases 下载（支持多个镜像源）
- 自动解压并设置可执行权限
- 实时流式输出 CFST 日志
- 超时保护（600 秒）

#### API 触发器
- HTTP 服务器监听指定端口
- 端点：
  - `/trigger?key=xxx` - 触发全量检测
  - `/trigger?key=xxx&phase=latency` - 只跑延迟测试
  - `/trigger?key=xxx&phase=speed` - 只跑速度测试（用缓存延迟数据）
  - `/trigger?key=xxx&force=true` - 强制重跑（删除缓存）
  - `/trigger?key=xxx&phase=latency&force=true` - 强制重跑延迟
  - `/status?key=xxx` - 查看状态
  - `/health` - 健康检查
- API key 验证
- 防止并发检测

### 配置说明

#### 运行模式
- `ENABLE_CRON_SCHEDULER=true` - 启用定时调度
- `ENABLE_API_TRIGGER=true` - 启用 API 触发
- 两者都禁用时，运行单次检测后退出

#### 测试模式
- `TEST_MODE=cfip` - 仅测试 CF IP
- `TEST_MODE=proxyip` - 仅测试代理 IP
- `TEST_MODE=outbound` - 仅测试出站
- `TEST_MODE=all` - 测试所有类型

#### 测试配置
- `LATENCY_THREADS=200` - Phase 1/Phase 2 线程数（CFST -n 参数），默认 200，最大 1000
- `SPEED_TEST_COUNT=20` - Phase 2 所有端口合计下载测速数量（按端口比例分配）
- `MAX_LATENCY=9999` - 平均延迟上限（ms），超过此值的 IP 将被过滤（-tl 参数）
- `MAX_LOSS=1.0` - 丢包率上限（0.0-1.0），高于此值的 IP 将被过滤（-tlp 参数）
- `SPEED_ENABLE_COUNT=50` - 选择速度最高的前 M 个 IP 设为启用状态

### 重要实现细节

1. **两阶段分步策略**：
   - Phase 1：CFST `-dd` 纯延迟测试，高并发（200线程），结果按延迟排序
   - Phase 2：对 Phase 1 延迟最低的 Top N 个 IP 进行速度测试
   - 两阶段独立缓存，支持单独/合并重跑
   - 多端口在同一阶段内并行执行

2. **批量 API 更新**：
   - 使用 `/api/cfip/batch/update` 一次性更新多条记录
   - D1 `db.batch()` 批量执行，每批 50 条
   - 失败时自动降级为逐条 PUT 请求

3. **域名解析策略**：使用三种方法确保域名解析成功
   - socket.gethostbyname
   - socket.getaddrinfo
   - 系统命令（dig/nslookup）

4. **IP 到 cfip 的映射**：维护 `ip_to_cfip` 字典，因为多个域名可能解析到同一 IP

5. **未解析域名处理**：无法解析的域名会保持当前状态，remark 设置为 "N/A|N/A|N/A 原始地址"

6. **并发控制**：使用 `check_running` 标志防止并发检测

7. **信号处理**：正确处理 SIGINT 和 SIGTERM 以实现优雅关闭

8. **速度单位转换**：CFST 返回 MB/s，API 需要 KB/s（乘以 1024）

9. **端口信息保留**：每个结果都保留端口信息，确保能正确按端口分组

### 文件结构
```
src/
├── __init__.py
├── main.py              # 主服务类，两阶段 CFST 集成，调度器
├── api_client.py        # API 交互，批量更新，认证，重试逻辑
├── telegram_notifier.py # Telegram 通知服务
├── config.py            # 配置加载
└── logger.py            # 日志设置

cfst_data/               # CFST 二进制和结果文件（自动创建）
├── cfst                 # CFST 二进制（自动下载）
├── ips_{port}.txt       # 每个端口的 IP 列表
├── latency_{port}.csv   # Phase 1: 每个端口的延迟测试结果
├── speed_ips_{port}.txt # Phase 2: 每个端口选中的 IP 列表
└── speed_{port}.csv     # Phase 2: 每个端口的速度测试结果
```

## Development Notes

- Python 3.9+ 是最低要求
- 依赖项：requests[socks], python-dotenv, croniter
- Docker 镜像基于 python:3.9-slim，包含 iputils-ping 和 dnsutils
- CFST 版本固定为 v2.3.4
- 所有日志通过 logger 模块统一管理
- API 响应格式：`{'success': bool, 'data': [...], 'message': str}`
