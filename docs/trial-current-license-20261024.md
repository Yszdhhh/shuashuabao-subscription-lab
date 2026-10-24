# 当前设备许可证与上线说明（2026-10-24）

- `/trial` 状态查询通过仅限 loopback、校验既有 `X-Referral-Internal-Key` 的 `/internal/trials/current` 读取当前许可证。候选只来自该设备的实际 activation；优先 ACTIVE/TRIAL 且 UTC 未过期，再按到期时间、创建时间和 ID 排序。缺失到期时间不会自动当成永久。查询不发卡、不续期、不申请 lease、不签 permit。
- 领取页配置既有 `REFERRAL_INTERNAL_KEY`；bridge 增加 `TRIAL_CLAIM_SYNC_URL=http://127.0.0.1:18012/internal/trials/sync`。写入后更新已有 `device_trial_claims` 指针，再通知领取页更新已有 pool claim 和镜像；不新增 trial 资格。回调失败记 `current_claim_sync_failed`，实时查询仍以 bridge 为准。
- `/usr/local/sbin/shuabao-dashboard-claims-sync` 对应仓库 `ops/shuabao-dashboard-claims-sync.py`。cron 和回调共用 `pool.lock`，cron 从实际绑定重新选卡，下一轮不会覆盖为历史领取卡。
- `activated` 表示当前未过期有效状态；过期返回 `activated=false`、`status=EXPIRED`、`code=LICENSE_EXPIRED` 和 ISO 8601 `expires_at`。保留卡、等级和推荐统计合同；v2 关闭 legacy card 时仍走既有 reveal token。
- 内测采用响应层 `beta_users ∪ 当前卡标记`，validate 仅对实际绑定的请求设备合并名单。正式档位不变，名单变更无需批量重写卡。未提供 hardware 的历史 validate 保留按卡标记的口径。
- 本地同步的 `main.py`、`tiers.py` 及领取页已有页面热修来自生产快照；不将仓库旧档位覆盖生产。离线 permit v2 用户改动不属于本次部署或提交。

## 定向验证

```powershell
python -m pytest tests/integration/test_trial_current_license.py tests/integration/test_batch_a.py tests/integration/test_trial_claim.py -q -k "not test_expiry_fixed_at_claim_time" -o "pythonpath=. bridge"
```

`test_expiry_fixed_at_claim_time` 在未修改的生产 provider 也失败：固定 2026-10-09 时钟命中生产尚保留的周末续领活动分支。此次不修改活动规则。Windows 无 POSIX `fcntl`，只验证只读查询；两个真实写入/锁/cron/reveal 测试在 Linux 执行。

## 客户约时排查（问题 3，仅准备命令）

主机 `tencent-vps`，Caddy 配置 `/etc/shuabao/origin-filter.Caddyfile`；访问日志 `/var/lib/shuabao-origin-filter/logs/access.log`。Cloudflare tunnel 后 `remote_ip` 可能是 loopback，应先按 `Cf-Connecting-Ip` 还原客户 IP。将 `CLIENT_IP` 替换为客户提供的公网 IP；约定窗口才执行持续监听：

```sh
sudo tail -F /var/lib/shuabao-origin-filter/logs/access.log | jq --unbuffered -c --arg ip 'CLIENT_IP' --arg ua 'ShuaBaoClient/1.0' '
  select((.request.headers["Cf-Connecting-Ip"][0] // .request.client_ip // .request.remote_ip) == $ip)
  | select(any(.request.headers["User-Agent"][]?; . == $ua))
  | select(.request.uri | split("?")[0] | test("^/(trial(/|$)|health$|v1/(devices/activate|entitlements/validate|trials/claim|run/))"))
  | {ts, status, method: .request.method, path: (.request.uri | split("?")[0]), ua: .request.headers["User-Agent"][0]}'
```

需要单独按 UA、IP 或路径查看时，删除另外两个 `select`；只看失败再加 `select(.status >= 400)`。有限时间回查使用 `sudo journalctl -u shuabao-origin-filter --since 'START' --until 'END'` 查看代理运行错误，并在访问日志按 `.ts` 过滤同一 UTC 窗口。Caddy 日志没有请求则继续检查客户端 DNS/代理/TLS 和 Cloudflare 边缘；不能据此宣称用户已恢复。当前不监听 `1bb8537b`，它不是 Owner 本机。

## 新构建审批（问题 4）

每个新构建须由客户端提供 `source_sha`、`release_manifest_sha256` 及 `release_channel`，先在 `release_policies` 按完整发行身份登记审批，核验 `/v1/releases/status`，再分发安装包。仅 HTTP 200 或历史 approved 不能代替新构建审批；本次不修改任何已有策略记录。
