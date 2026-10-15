# 校园配置

公开源码使用文档示例域名和地址。普通 USB 与 Wi-Fi 分流可以直接使用；接入学校内网时，按实际网络替换这些值。

| 示例值 | 用途 | 修改位置 |
| --- | --- | --- |
| `campus.example` | 校内域名及子域 | `Sources/EZSwitchCore/RoutingConfiguration.swift` |
| `192.0.2.53` | 校内 DNS | 同上 |
| `192.0.2.10/32` | 仅允许校园出口访问的主机 | 同上、`routing/clash-bootstrap.js` 与 `routing/check_active.py` |

域名例外在 USB 与 Wi-Fi 分流、仅 Wi-Fi 直连模式下使用校园 DNS。主机例外在分流模式下使用 Wi-Fi；手机热点模式与订阅启动阶段拒绝该地址。

修改后同步更新相关测试夹具，再执行 `./script/verify-routing.sh --offline`。接口由应用识别和绑定；独立 Python 诊断工具中的 `en5` 与 `en0` 默认值需要按机器核对。

真实学校地址、设备标识与验证日志放入本机私有目录。提交示例时使用示例域名和地址。
