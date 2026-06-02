# 更新日志

这个文件用于记录项目中的重要变更。

## Unreleased - 2026-04-25

### 新增
- 新增基于 `SYNC_TO_CF_CRON` 的启用数据维护任务，定时重测已启用记录的延迟和速度。
- 新增 Telegram 命令 `/cfst_maint`，可手动触发启用数据维护任务。
- 新增 Telegram 维护结果通知，包含同步摘要、参与数量、写回数量和同步候选详情。
- 新增 GET 接口 `/blacklist-current-cf?key=...`，可将当前 Cloudflare DNS A 记录对应的 CFIP 加入 DNS 黑名单并重新触发启用数据维护。
- 新增 Telegram 命令 `/cfst_blacklist_current`，复用当前 CF 同步 IP 加入 DNS 黑名单和维护重跑流程。
- 新增 CFIP 黑名单 API 客户端方法，支持 `/api/cfip/batch/blacklist` 并提供单条更新回退。

### 调整
- 原有单一黑名单语义割接为 `DNS` 黑名单，兼容读取旧 `sync_blacklisted` 字段。
- Cloudflare DNS 同步候选会跳过 `sync_blacklisted=1` 的记录、关联不到 CFIP 的测速结果，以及同一 `IP:port` 下任一记录已 DNS 拉黑的重复候选，并顺延到下一位可用候选。
- 普通 CFIP 检测和启用数据维护任务改为只跳过 `node_blacklisted=1` 的 CFIP；`DNS` 黑名单不再阻止测速或维护。
- 本地触发 API 新增双黑名单查询与设置接口，支持界面侧按 `DNS` / `节点` 维度执行拉黑、解黑和查询。
- `/blacklist-current-cf` 新增 `strategy` 参数，支持默认拉黑后维护和 `strategy=maintenance` 直接触发维护。
- 当前 CF 同步 IP 的 DNS 黑名单流程改为实时查询 Cloudflare DNS 当前 A 记录，不依赖本地状态文件。
- 当前 Cloudflare A 记录 IP 没有匹配 CFIP 时，会以当前 CF IP 创建一条已加入 DNS 黑名单的 CFIP，不再直接返回无匹配失败。
- 修复当前 CF 同步 IP 拉黑流程中的误报：当 `/api/cfip` 查询失败时，返回明确的查询失败错误，不再误报为“没有匹配的 CFIP 记录”。
- 维护任务的同步目标重新遵循 `SYNC_TO_CF_FILTER_PORT`；保持 `443` 可延续原有行为，设为 `0` 则允许全端口参与选择。
- 维护任务在域名解析失败或测速失败时恢复 `DOMAIN-KEEP` 语义，不再把域名记录直接标记为 `invalid`。
- 调整服务启动逻辑，使仅启用维护调度器时进程也会常驻运行。
- 更新配置示例和 README，补充维护任务和 Telegram 触发说明。
