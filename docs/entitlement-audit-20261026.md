# 授权与 v1 租约修复（2026-10-26，本地准备）

## 权限事务与重试

本地 SQLite authority 的创建卡和修改 features 先计算临时 record，在一个
`BEGIN IMMEDIATE` 事务中写 `local_licenses` 和 `entitlement_operations`；
后者同一行保存 `operation_id`、规范请求、去除卡密的返回 DTO 快照和不可丢失审计。
COMMIT 成功后才发布共享内存。失败则整体回滚，包括无变化请求的审计。

管理员创建接口和 `/admin/licenses/{license_id}/pip-background` 接受可选
`operation_id`（字符串）。管理页面表单生成隐藏 ID。调用方重试必须保留同一 ID
及相同操作参数；相同 ID 返回首次提交的 DTO 快照（卡密按 license_id 从
local_licenses 补齐），不重新应用权限；参数不同返回
`OPERATION_ID_CONFLICT`。旧调用方缺省时服务端生成 ID，因而不能跨请求去重。
PiP 更新的请求身份是 action/license_id/enabled，与后来其他 features 的变化无关。
ID 必须为字符串或缺省；去除首尾空白，空白/缺省生成新 ID，其他类型返回
`INVALID_OPERATION_ID`。请求经 JSON 归一化后比较，tuple/list 等价。
管理员确认和权限规则继续生效。

新操作不再写 `admin_audit.jsonl`，`SUBSCRIPTION_ADMIN_AUDIT_LOG` 不再用于这些操作；
历史文件留作历史记录。库内 `audit_json` 和 `result_json` 不包含顶层完整卡密，
result_json 仅保存 license_id 和快照字段，重放从 local_licenses 查询 key；原卡记录
不存在则返回 `OPERATION_RESULT_UNAVAILABLE`，不创建替代卡。含 PiP 的 Ultra 审计
保留 action=issue_ultra，并明确标记 pip_background=true；PiP 审计采集须同时覆盖该字段。
启动迁移会清除旧 result_json 的顶层 license_key，可重复执行；历史备份和 SQLite
旧页/WAL 仍按原许可证库保护，此逻辑迁移不声称物理擦除历史副本。
运维可从备份库执行以下只读查询
导出、重复导出审计，按 `operation_id` 去重，不读取 `result_json`：

```sql
SELECT audit_json FROM entitlement_operations ORDER BY rowid;
```

HTTP Keygen 的远端写入不能与本地 SQLite 组成同一事务。因此本轮管理创建/PiP
更新明确拒绝非本地 authority（`ENTITLEMENT_TRANSACTION_UNSUPPORTED`），在任何
远端请求前退出。若计划启用 HTTP authority 管理写入，需要独立的远端事务/幂等
设计；本轮未实现，也不将远端操作宣称为原子事务。
`PROVIDER_MODE=keygen/real/http_keygen/production/compose` 均选择 HTTP Keygen；
该模式也不支持 `/v1/run/acquire`、`/heartbeat`、`/release` 在线租约，统一返回
503 `RUN_LEASE_UNSUPPORTED`。启动能力检查记录 `HTTP_KEYGEN_CAPABILITY_LIMIT`，
管理页明确展示限制，HTML 错误保留可读错误码。JSON 管理发卡及
`scripts/issue_cards.py` 同样受限；这不是支持 v1 在线运行的部署模式。
已有远端延期/到期日/撤卡/解绑路径不由本轮扩展为分布式事务。

## v1 在线租约字段

`POST /v1/run/acquire` 新增可选 `scope`：

| 值 | 本次运行目标 | 服务端 required_features |
| --- | --- | --- |
| 缺省或 `core` | 常规前台 | `["core"]` |
| `pip_background` | PiP 后台 | `["core", "pip_background"]` |

客户端应从本次实际执行目标发送 `scope`，不要根据卡是否拥有 PiP 来推断目标。
`required_features` 由服务端映射并逐项核对可信许可证权益，客户端同名字段不会授予
权限。scope 和 required_features 随租约返回、入库；heartbeat 使用库中范围，不接受
客户端降级。acquire/heartbeat 都检查当前卡状态、期限、绑定设备和范围权益。
过期、暂停、撤卡、解绑、缺权益均拒绝；heartbeat 返回 409 `LEASE_REVOKED` 且不续期。
PiP 撤权只影响 PiP 范围，core 仍可运行。租约截止时间不超过订阅到期时间；过期
租约需重新 acquire，不可通过 heartbeat 复活。原有每卡单租约、acquire 抢占规则保留。

此变更不修改 v1/v2 permit 的签名、发行白名单或离线有效期。既有 v2 permit
的最长撤权延迟仍由其已签名有效期决定。

## PiP 权限真值表

展示仍可用 `derive_tier()` 的历史 fallback；权限只用存储身份和显式 grants。

| 存储证据 | 默认 PiP | 显式存储 PiP |
| --- | --- | --- |
| tier=test/beta（含 metadata.tier） | 有 | 有，禁止取消默认权益 |
| 非正式档位的持久化 is_beta_user=true | 有 | 有 |
| tier=trial 且无 beta 标记 | 无 | 禁止，读取时过滤残留 grant |
| trial_* / is_trial=true，且无 test/beta 身份 | 无 | 禁止，读取时过滤残留 grant |
| go/plus/pro/max/ultra（含 beta 用户的付费卡） | 无 | 逐卡管理员授权后有 |
| 空/未知 plan、缺 metadata、仅有 test_* plan | 无 | 保留已有显式 grant，可由管理员撤销 |

本仓 `snapshot_beta_r71.py` 的持久化 beta 标记是可识别的历史依据；不重新运行该
脚本，不按未知 plan、前缀或展示标签批量赋予内测身份。本轮没有额外可信 legacy
名单，因此没有新增按 plan 默认发权的名单。

## 迁移与上线前步骤

1. 授权运维先备份 SQLite（含一致的 WAL 状态），在离线备份上执行只读盘点：
   `python scripts/inventory_pip_entitlements.py --db <backup.db>`。
   输出总数、PiP 前后总数、失去/获得/不变数量及按状态统计，不输出卡密或 ID。
   连接使用 `mode=ro` 和 `query_only`，不存在的路径会失败，不创建数据库。
2. Owner 审核失去/获得范围，按已有证据处理确需保留的卡；不得重新批量归类为 beta。
3. 客户端 PiP 路径必须发送 `scope=pip_background`；老客户端缺省仅表述 core 前台，
   服务端不能从旧请求识别实际 PiP 执行。上线前补充客户端撤权关闭输入门验收。
   升级前暂停 PiP 会话，让更新后的客户端 release/reacquire；不要把旧行迁移出的
   core 租约当作已绑定 PiP 范围的租约继续使用。
4. 在维护窗口停止服务，部署并启动一个 bridge worker，沿用当前 SQLite authority。
   `SqliteEventStore._init_schema()` 自动创建 `entitlement_operations` 并为 `run_leases`
   增加 `required_features_json`、`scope` 两列；先检查列再 ALTER，可重复执行；
   同时在事务内移除历史重放快照中的顶层 license_key。
   旧行以 core/[core] 升级，权限记录本身不回填、不重分类。
5. 检查 schema/只读审计查询，验证管理重试、core/PiP acquire 与撤权 heartbeat，
   再恢复流量。审计采集改从数据库导出；不要继续依赖旧 JSONL 的新记录。

回滚代码时保留新增表、列及已提交权限和审计，不删除审计或回退整库。旧代码会恢复
本轮修复前的授权/租约缺陷；应由 Owner 决定暂停相关写入与 PiP 运行的回退窗口。
本轮只在合成测试库验证上述迁移和盘点，没有读取或修改真实/生产库，没有部署。
