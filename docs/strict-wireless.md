# 严格无线保护

严格保护把已登记的校园 Wi-Fi 限制为“固定白名单直连”。名单外目标在有 USB 时使用 USB 代理，USB 不可用时阻断。保护以 Clash TUN 接管流量为前提，关闭 Clash 或 TUN 后无法保证出口。

## 名单来源

运行时名单由 `routing/data/strict-whitelist.json` 定义，`script/generate-strict-whitelist.py` 生成 `Sources/EZSwitchCore/RoutingStrictDomains.swift` 与 `routing/evidence/<日期>-strict-whitelist/` 下的证据文件。订阅刷新不会扩大名单。

条目字段：`host`、`match`（`suffix` 或 `exact`）、`group`（`domestic`、`campus` 或 `apple`）、`decision`（`allow`、`hold`、`reject` 或 `pending`）、`category`、`provenance`、`reason`、`evidence`。`hold` 与 `reject` 必须保留在数据中，避免下一次合并被父域后缀无声回填。

## 规则顺序

严格模式下按以下顺序生成规则：

1. 订阅中的拒绝规则；
2. Apple 中继排除；
3. 上报/统计与境外站点的显式排除；
4. Apple 条件精确主机（关闭“Apple 走代理”时）；
5. 订阅中的代理例外（USB 缺失时改写为拒绝）；
6. Apple 整组强制代理（开启“Apple 走代理”时）；
7. 白名单许可；
8. 兜底（USB 代理或拒绝）。

订阅中原本指向直连校园出口的规则在严格模式下被丢弃；IP、GEOIP、进程、端口与关键词规则不会获得校园直连。纯 IP TLS 关闭 SNI 嗅探，TUN 的 UID/地址排除字段会被移除。

## DNS

严格 Wi-Fi 的系统 DNS 指向 TUN。校内域名 `campus.example` 及其子域使用 `192.0.2.53` 校园解析；USB 在线时公共解析经 USB。USB 缺失时只有 `dns_extra` 中列出的已观察主机使用校园解析，未知子域会失败，需要先补录。

## Apple 开关

关闭“Apple 走代理”时，Apple 条件名单中的精确主机可经校园直连；开启时 Apple 整组使用 USB。Apple 中继端点始终不使用校园出口。Apple 组不参与遥测/境外排除。

## 边界

- 应用崩溃、关闭自动路由、正常退出、拔 USB 后的授权空档：实测保持严格规则或阻断，不退回全局直连。
- 关闭 Clash/TUN：保护不可用；Clash 重启后当前版本需要手动关闭/开启自动路由才能恢复严格模式。
- 关闭 Clash、应用崩溃后的独立阻断，以及睡眠恢复仍需实机验证；关闭 TUN 或其他程序修改网络属于独立边界。

## 修改名单

1. 只改 `routing/data/strict-whitelist.json`，递增 `revision`；
2. 运行 `python3 script/generate-strict-whitelist.py`；
3. 运行 `python3 script/generate-strict-whitelist.py --check` 与 `./script/verify-routing.sh --offline`；
4. 同步更新 `README.md` 与本页的数量说明；
5. 新候选先标记 `pending`，绑定 Wi-Fi 出口探测通过后再改为 `allow`。

## 示例配置

公开版使用示例值：校内域名 `campus.example`、校园 DNS `192.0.2.53`、实验室主机 `192.0.2.10/32`。替换方法见[校园配置](campus-profile.md)。
