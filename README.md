# EZ Route

[中文](README.md) · [English](README.en.md)

EZ Route 是 macOS 菜单栏网络分流工具。它协调 iPhone 热点与 Wi-Fi 出口，让允许直连的业务使用 Wi-Fi，代理业务使用手机网络。

## 功能

- 识别指定 iPhone 的 USB 热点，登记手机无线热点。
- 按当前网络组合更新 Clash/Mihomo 出口，并清理旧连接。
- 查看连接、运行期间的流量记录和网站响应。
- 按需采集测试包头，核对实际出口。
- 在退出时执行路由恢复流程。

| 当前连接 | 路由策略 |
| --- | --- |
| USB 热点与普通 Wi-Fi | 允许直连的域名使用 Wi-Fi，代理与公共 DNS 使用 USB |
| 只有 USB 或已登记无线热点 | 使用手机网络 |
| USB 与已登记无线热点 | 优先使用 USB |
| 只有未登记 Wi-Fi | 使用 Wi-Fi 直连，停用代理出口 |
| 离线或网络状态未知 | 阻断 Clash 请求，等待网络恢复 |

## 安装

当前版本：**0.2.18（构建 22）**。需要 macOS 27、Xcode 27、Clash Verge Rev，以及已开启个人热点的 iPhone。离线验证还需要 Node.js 和 Python 3。

```sh
git clone https://github.com/JJDDMZ/ezroute.git
cd ezroute
./script/build_and_run.sh --build-only
./script/install.sh
```

应用安装到 `~/Applications/EZ Route.app`。安装器正常退出旧版、备份应用，再安装并启动新版。旧版备份位于 `~/Applications/EZ Route Backups/`。

## 开始使用

1. 用 USB 连接 iPhone，允许信任这台 Mac，并开启个人热点。
2. 在“设备与热点”中选择 iPhone。使用手机无线热点时，先连接自己的热点，再登记名称。
3. 在 Clash Verge Rev 开启 TUN，然后开启 EZ Route 的“自动路由”。
4. 在“概览”查看出口，在“诊断与监测”查看连接或测试网站。

USB 需要可用的网络链路。无线热点按名称与安全类型识别，请使用独有名称。热点名称读取需要定位权限；应用保存热点登记和流量记录到本机。

完整操作见[使用指南](docs/setup.md)。公开源码中的学校内网规则使用 `campus.example` 和示例地址，校园部署前按[校园配置](docs/campus-profile.md)替换。

## 验证与当前边界

```sh
./script/verify-routing.sh --offline
```

离线检查覆盖 Swift 核心、JavaScript 配置转换、Python 工具、构建和签名。实际出口由指定网络与请求的抓包结果确认。当前恢复机制依赖应用和 Clash 运行状态；切换瞬间与应用崩溃后的独立阻断仍需验证。

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
