# 路由结构

网络读取器识别指定 USB 手机、Wi-Fi 状态与已登记热点。路由策略生成模式，协调器验证并应用完整 Clash 配置，再关闭旧连接。状态读取或配置应用失败时，现有恢复与阻断流程接管。

界面与系统集成位于 `Sources/EZSwitch/`，可独立测试的策略与协调器位于 `Sources/EZSwitchCore/`。使用步骤见[使用指南](setup.md)，测试与已知问题见[验证说明](verification.md)。
