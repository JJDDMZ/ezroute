# EZ Route

[中文](README.md) · [English](README.en.md)

EZ Route is a macOS menu bar app for routing across USB network devices and Wi-Fi. It sends eligible direct traffic over Wi-Fi and proxy traffic over the selected USB outlet or a trusted wireless connection.

## Features

- Detect iPhone tethering, portable Wi-Fi routers, and other USB network devices; add trusted wireless connections.
- Update Clash/Mihomo egress settings as networks change and clear old connections.
- Inspect connections, traffic recorded while the app runs, and website responses.
- Capture test packet headers on demand to check physical egress.
- Apply a routing recovery policy when quitting.

| Connection | Routing policy |
| --- | --- |
| USB network and ordinary Wi-Fi | Eligible direct domains use Wi-Fi; proxies and public DNS use USB |
| USB or a trusted wireless connection alone | Use that outlet for proxy, direct traffic, and DNS |
| USB and a trusted wireless connection | Prefer USB |
| Untrusted Wi-Fi alone | Use direct Wi-Fi access and disable proxy egress |
| Offline or unreadable network state | Block Clash requests until a usable network returns |

## Install

Current version: **0.2.19 (build 23)**. Requirements: macOS 27, Xcode 27, Clash Verge Rev, and a working USB network device, such as an iPhone or a portable Wi-Fi router. Offline checks also use Node.js and Python 3.

```sh
git clone https://github.com/JJDDMZ/ezroute.git
cd ezroute
./script/build_and_run.sh --build-only
./script/install.sh
```

The installer places the app at `~/Applications/EZ Route.app`. It quits the previous version normally, backs it up, then installs and launches the new version. Backups are stored in `~/Applications/EZ Route Backups/`.

## Get started

1. Connect an iPhone or portable Wi-Fi router over USB and enable USB network sharing. An iPhone also needs to trust the Mac and enable Personal Hotspot.
2. Choose the device in Devices & Networks → Selected USB Outlet (`设备与网络 → 指定 USB 出口`). Add a phone hotspot or portable router under Trusted Wireless Connections (`信任的无线连接`) for wireless use.
3. Enable TUN in Clash Verge Rev, then enable Automatic Routing (`自动路由`) in EZ Route.
4. View egress in Overview (`概览`) and inspect connections or test websites in Diagnostics & Monitoring (`诊断与监测`).

macOS must expose the USB device as an Ethernet interface with a usable IPv4 address. Existing iPhone selections and wireless registrations are preserved. Select the USB outlet again when changing devices; devices without a serial number may also need reselection after moving to another USB port.

Trusted wireless connections are matched by name and security type, so use a distinctive name. Reading Wi-Fi names requires Location permission. Trust registrations and traffic records are stored locally.

See the [usage guide](docs/setup.md). Campus-specific rules in the public source use `campus.example` and example addresses; adapt the [campus profile](docs/campus-profile.md) before deploying them.

## Verification and scope

```sh
./script/verify-routing.sh --offline
```

Offline checks cover the Swift core, JavaScript configuration transforms, Python tools, build, and signature. Packet captures establish physical egress for the tested network and requests. Recovery currently depends on the app and Clash running and does not provide a system-wide zero-leak guarantee. Network transitions, app crashes, and traffic bypassing TUN still have protection or validation gaps. Portable-router detection, reconnection, and physical egress need validation on the actual device.

When quitting normally with only Wi-Fi available, the app switches to direct access and disables proxies, even for a trusted connection. Keep the app and automatic routing running to continue proxy access over that wireless connection.

See [verification notes](docs/verification.md) for supported subscriptions, known issues, and testing procedures.

## Project layout

- `Sources/EZSwitch/`: macOS UI, device monitoring, and app services.
- `Sources/EZSwitchCore/`: routing policy, configuration transforms, coordination, and diagnostics.
- `Sources/EZRoutingTool/`: diagnostic command-line tool.
- `Tests/` and `routing/`: automated tests, transforms, and diagnostic tools.
- `script/`: build, install, and verification entry points.

Swift modules, the executable, and the bundle identifier retain `EZSwitch` and `dev.ezswitch.app` for configuration compatibility. When upgrading from the old bundle name with launch at login enabled, turn that option off and on once in General (`通用`) to refresh its registered path.

## Companion project

[EZ SIM](https://github.com/JJDDMZ/ez-sim) coordinates cellular data plans, VPN state, and hotspot sharing on the iPhone. Both projects work independently and can be used together.

## License

[MIT](LICENSE). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for external tools and resources.
