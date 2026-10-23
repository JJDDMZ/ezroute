# EZ Route

[中文](README.md) · [English](README.en.md)

EZ Route 是 macOS 菜单栏网络分流工具。它协调 USB 供网与 Wi-Fi 出口，让允许直连的业务使用 Wi-Fi，代理业务使用指定的 USB 出口或信任的无线连接。

## 功能

- 识别 iPhone、随身 Wi-Fi 等 USB 供网设备，添加信任的无线连接。
- 按当前网络组合更新 Clash/Mihomo 出口，并清理旧连接。
- 自动管理所选 USB 网络服务的系统 DNS，保存原设置并在停止接管时恢复。
- 查看连接、运行期间的流量记录和网站响应。
- 按需采集测试包头，核对实际出口。
- 在退出时执行路由恢复流程。

| 当前连接 | 路由策略 |
| --- | --- |
| USB 供网与普通 Wi-Fi | 允许直连的域名使用 Wi-Fi，代理与公共 DNS 使用 USB |
| 只有 USB 或信任的无线连接 | 代理、直连和 DNS 使用该出口 |
| USB 与信任的无线连接 | 优先使用 USB |
| 只有未信任的 Wi-Fi | 使用 Wi-Fi 直连，停用代理出口 |
| 离线或网络状态未知 | 阻断 Clash 请求，等待网络恢复 |

## 安装

当前版本：**0.2.20（构建 24）**。需要 macOS 27、Xcode 27、Clash Verge Rev，以及可用的 USB 供网设备（如 iPhone 或随身 Wi-Fi）。离线验证还需要 Node.js 和 Python 3。

```sh
git clone https://github.com/JJDDMZ/ezroute.git
cd ezroute
./script/build_and_run.sh --build-only
./script/install.sh
```

应用安装到 `~/Applications/EZ Route.app`。安装器正常退出旧版、备份应用，再安装并启动新版。旧版备份位于 `~/Applications/EZ Route Backups/`。

## 开始使用

1. 用 USB 连接 iPhone 或随身 Wi-Fi，并开启 USB 供网。iPhone 需信任这台 Mac，并开启个人热点。
2. 在“设备与网络 → 指定 USB 出口”中选择设备。无线连接可在“信任的无线连接”中添加，支持手机热点和随身 Wi-Fi。
3. 在 Clash Verge Rev 开启 TUN，然后开启 EZ Route 的“自动路由”。
4. 首次接管 USB DNS 时，允许 macOS 的网络设置授权；若拒绝，可重新开启自动路由或点击“检查路由”重试。
5. 在“概览”查看出口，在“诊断与监测”查看连接或测试网站。

USB 设备需由 macOS 识别为以太网接口，并取得可用 IPv4 地址。原有 iPhone 选择和无线登记保留；更换 USB 设备时需重新选择。无序列号的设备更换 USB 端口后，也可能需要重新选择。

信任的无线连接按名称与安全类型匹配，请使用独有名称。读取 Wi-Fi 名称需要定位权限；信任记录和流量记录保存在本机。

完整操作见[使用指南](docs/setup.md)。公开源码中的学校内网规则使用 `campus.example` 和示例地址，校园部署前按[校园配置](docs/campus-profile.md)替换。

## 验证与当前边界

```sh
./script/verify-routing.sh --offline
```

离线检查覆盖 Swift 核心、JavaScript 配置转换、Python 工具、构建和签名。实际出口由指定网络与请求的抓包结果确认。当前恢复机制依赖应用和 Clash 运行状态，尚未提供系统级零泄漏保证。切换瞬间、应用崩溃，以及绕过 TUN 的流量仍有保护或验证缺口。0.2.20 已在 ZTE F50 Pro USB 与校园 Wi-Fi 同时连接时，完成 Google 搜索、ChatGPT、B 站首页与视频的定向用户验证。其他设备、插拔后的 DNS 恢复及物理出口仍需分别验证。微信朋友圈大图加载慢或失败仍未解决。

正常退出时，只有 Wi-Fi 在线会切为直连并停用代理，即使它已受信任。需要继续通过该无线连接使用代理时，保持应用和自动路由运行。

支持的订阅结构、已知问题和测试方式见[验证说明](docs/verification.md)。

## 项目结构

- `Sources/EZSwitch/`：macOS 界面、设备监测与应用服务。
- `Sources/EZSwitchCore/`：路由策略、配置转换、协调器与诊断。
- `Sources/EZRoutingTool/`：诊断命令行工具。
- `Tests/`、`routing/`：自动化测试、转换脚本与诊断工具。
- `script/`：构建、安装与验证入口。

Swift 模块、可执行文件和 bundle identifier 沿用 `EZSwitch` 与 `dev.ezswitch.app`，便于读取既有配置。首次从旧包名升级且已启用“登录时启动”时，在“通用”中关闭后重新开启一次，更新系统登记路径。

## 配合 EZ SIM

[EZ SIM](https://github.com/JJDDMZ/ez-sim) 在 iPhone 上协调蜂窝数据卡、VPN 状态与热点共享。两个项目可以独立使用，也可以搭配。

## 许可

[MIT](LICENSE)。第三方工具与资源说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
