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
   - 支持两种运行模式：
     - Cron 调度器：按 cron 表达式定期执行检测
     - API 触发器：通过 HTTP API 手动触发检测
   - 处理 CFST 二进制的自动下载和执行
   - 实现域名解析（支持多种方法：socket、dig、nslookup）
   - 按端口分组测试 IP

2. **ApiClient (src/api_client.py)** - API 客户端
   - 实现会话令牌认证机制
   - 自动重试逻辑（可配置次数和延迟）
   - 401 错误时自动重新登录
   - 支持三种资源类型：cfip、proxyip、outbound

3. **TelegramNotifier (src/telegram_notifier.py)** - Telegram 通知
   - 独立的代理配置（仅用于 Telegram API）
   - 发送测试结果摘要

4. **Config (src/config.py)** - 配置管理
   - 从 .env 文件加载所有配置
   - 提供类型转换和默认值

### 关键工作流程

#### IP 检测流程 (check_cf_ips)
1. 从 API 获取 CF IP 列表
2. 域名解析：将域名解析为 IP 地址（使用多种方法确保成功）
3. 按端口分组：将 IP 按端口分组（支持多端口测试）
4. **CFST 测试**：
   - 对所有 IP 运行 CFST 测试（延迟 + 速度）
   - CFST 会先测试所有 IP 的延迟，然后对延迟最低的前 N 个 IP 进行速度测试（N = SPEED_TEST_COUNT）
   - 按下载速度排序（降序，越高越好）
   - 选择速度最高的前 M 个 IP（M = SPEED_ENABLE_COUNT）
5. 更新 API：
   - Top M 个 IP 设置为 enabled
   - 其他 IP 设置为 disabled
   - 更新 remark 格式：`速度|延迟|地区 原始地址`
   - 获取 IP 地理信息（使用 ipapi.is API）
6. 发送 Telegram 通知

#### CFST 集成
- 自动检测平台（macOS/Linux，ARM/AMD64）
- 从 GitHub releases 下载（支持多个镜像源）
- 自动解压并设置可执行权限
- 实时流式输出 CFST 日志
- 超时保护（600 秒）

#### API 触发器
- HTTP 服务器监听指定端口
- 端点：
  - `/trigger?key=xxx` - 触发检测
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
- `SPEED_TEST_COUNT=20` - CFST 下载测速数量（-dn 参数），CFST 会先测试所有 IP 的延迟，然后对延迟最低的前 N 个 IP 进行速度测试
- `SPEED_ENABLE_COUNT=50` - 选择速度最高的前 M 个 IP 设为启用状态

### 重要实现细节

1. **CFST 测试策略**：
   - CFST 内部会先测试所有 IP 的延迟，然后按延迟排序
   - 对延迟最低的前 N 个 IP 进行速度测试（N 由 SPEED_TEST_COUNT 控制，对应 CFST 的 -dn 参数）
   - 最终按速度排序，选择速度最高的前 M 个 IP 设为启用（M 由 SPEED_ENABLE_COUNT 控制）

2. **域名解析策略**：使用三种方法确保域名解析成功
   - socket.gethostbyname
   - socket.getaddrinfo
   - 系统命令（dig/nslookup）

3. **IP 到 cfip 的映射**：维护 `ip_to_cfip` 字典，因为多个域名可能解析到同一 IP

4. **未解析域名处理**：无法解析的域名会被标记为 disabled，remark 设置为 "N/A|N/A|N/A 原始地址"

5. **并发控制**：使用 `check_running` 标志防止并发检测

6. **信号处理**：正确处理 SIGINT 和 SIGTERM 以实现优雅关闭

7. **速度单位转换**：CFST 返回 MB/s，API 需要 KB/s（乘以 1024）

8. **端口信息保留**：每个结果都保留端口信息，确保能正确按端口分组

### 文件结构
```
src/
├── __init__.py
├── main.py              # 主服务类，CFST 集成，调度器
├── api_client.py        # API 交互，认证，重试逻辑
├── telegram_notifier.py # Telegram 通知服务
├── config.py            # 配置加载
└── logger.py            # 日志设置

cfst_data/               # CFST 二进制和结果文件（自动创建）
├── cfst                 # CFST 二进制（自动下载）
├── ips_{port}.txt       # 每个端口的 IP 列表
└── result_{port}.csv    # 每个端口的测试结果
```

## Development Notes

- Python 3.9+ 是最低要求
- 依赖项：requests[socks], python-dotenv, croniter
- Docker 镜像基于 python:3.9-slim，包含 iputils-ping 和 dnsutils
- CFST 版本固定为 v2.3.4
- 所有日志通过 logger 模块统一管理
- API 响应格式：`{'success': bool, 'data': [...], 'message': str}`
