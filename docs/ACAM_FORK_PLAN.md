# `acam-infra/uu-remote-linux` 跨平台防套娃、纯无头构建与 CLI 穿透优化计划书

## 1. 背景与根因诊断（基于 Multica `LAB-2136` 实机取证）

在跨地域双内网节点（如容器节点 `hermes-wb` `100.79.113.126` 与腾讯云主机 `vm-4-143-ubuntu` `100.80.42.7`、桌面节点 `winown` 与 `ccdsmacbook-air`）实测 [`VallierDev/uu-remote-linux`](https://github.com/VallierDev/uu-remote-linux) 时，我们通过套接字取证（`ss -uanp`）与流量隔离发现了一个严重影响穿透吞吐的**“Overlay 隧道套娃（WebRTC-over-Tailscale-DERP）”**问题：

1. **现象与误判**：当通信双端同时运行 Tailscale 等虚拟组网工具时，WebRTC 会枚举本机 `tailscale0`（IPv4 `100.64.0.0/10`、IPv6 `fd7a:115c:a1e0::/48`）并将其作为最高优先级的局域网候选地址（`typ host`，RFC 8445 优先级权重 `126` > `srflx 100` > `relay 0`）上报。由于双端物理网络均为对称型 NAT（`MappingVariesByDestIP: true`），Tailscale 自身未能打通直连，正在绕行香港/东京公共 `DERP` 中继；此时 WebRTC 选中的 `local=udp/host remote=udp/host` 实际上将 WebRTC SCTP/DTLS/UDP 流量套进了 `tailscale0` 的 `DERP(hkg)` TCP 隧道中。
2. **性能劣化对比**：
   - **未隔离套娃模式（WebRTC over `tailscale0` DERP）**：5 层协议封装 + 1280 MTU 限制 + 双重拥塞控制冲突，5 MiB 高熵随机流下行耗时 `3,117 ms`（**`1.68 MB/s`**），上行耗时 `5,926 ms`（**`0.88 MB/s`**）。
   - **剥离 `tailscale0` 后的纯 UU 模式（直通网易国内/跨境 BGP TURN 专线）**：5 MiB 高熵随机流上下行耗时均降至 `1,214 ms`（**`4.32 MB/s` / `34.6 Mbps`**），**吞吐提升 2.57 倍（下行）至 4.88 倍（上行）**。
3. **上游源码的两处架构疏漏**：
   - `src/webrtc.rs` 中的 `ice_interface_allowed` 仅过滤了 `["zt", "docker", "br-", "veth", "virbr", "lo"]`，**漏掉了 `tailscale`、`wg`、`tun`、`tap`、`utun` 等虚拟网卡**，且在 Windows（网卡名为自定义名称或 GUID）与 macOS（共用 `utun*`）上仅靠网卡名前缀无法可靠识别虚拟网卡。
   - `src/viewer/rtc.rs` / `src/viewer_main.rs` 在初始化 `uuremote-viewer` 的 `SettingEngine` 时传入了空白 `Default::default()`，**完全未挂载任何网卡或 IP 过滤器**，且未对远端发来的虚拟网段 `typ host` 候选做注入拦截。

---

## 2. 核心架构改造方案（四大模块）

### 模块一：跨平台三层防套娃引擎（`src/ice_filter.rs`）

针对 Linux、macOS、Windows 全平台特性，在 WebRTC 引擎层建立三道防线：

| 防线层级 | 实现机制 | 拦截范围与跨平台效果 |
| :--- | :--- | :--- |
| **Layer 1：本地网卡名前缀过滤** | `SettingEngine::set_interface_filter` | 拦截 `tailscale`, `wg`, `tun`, `tap`, `utun`, `zt`, `zerotier`, `meta`, `mihomo`, `sing`, `flannel`, `cali`, `cni`, `docker`, `br-`, `veth`, `virbr`, `vmnet`, `vboxnet`, `lo`（不区分大小写） |
| **Layer 2：本地虚拟 IP 段过滤** | `SettingEngine::set_ip_filter` | 精准拦截 **`100.64.0.0/10`**（Tailscale / CGNAT）、**`fd7a:115c:a1e0::/48`**（Tailscale IPv6 ULA）、**`198.18.0.0/15`**（Clash / Mihomo / Sing-box TUN Fake-IP）及回环/链路本地地址；在 Windows/macOS 上无视网卡命名 100% 生效 |
| **Layer 3：远端 `typ host` 候选拦截** | `remote_candidate_allowed`（信令 `soac` 注入前拦截） | 即使对端是**未修改的 Windows/macOS 网易官方闭源客户端**（仍会发来 `100.64.0.0/10` 的 `typ host` 候选），本端在 `add_ice_candidate` 前直接将其丢弃，单方面阻断套娃握手，同时完整保留 `srflx`、`prflx` 与 `relay` 候选 |

> **调试逃生开关**：如需在特殊无公网环境下强制允许通过虚拟网卡建连，可设置环境变量 `UU_ALLOW_OVERLAY_ICE=1`。

### 模块二：双对称 NAT 秒连加速开关（`UU_FORCE_RELAY=1`）

- **问题**：在已知双端均为对称型 NAT（Symmetric NAT）的场景下，常规 ICE 会先耗费 `2.0 ~ 2.5 秒` 等待必然超时的 STUN `srflx` 打洞探测，随后才回退至 TURN 中继（总建连耗时 `3.5 ~ 4.0 秒`）。
- **实现**：在 `src/session_ice.rs` 与 `src/viewer/rtc.rs` 中接入 `ice_filter::force_relay_by_env()`。当设置 `UU_FORCE_RELAY=1` 时，直接将 `RTCIceTransportPolicy` 设为 `Relay`，立即选用网易多线 BGP TURN 候选，建连耗时缩短至 **`1.2 ~ 1.5 秒`**。

### 模块三：`portmap --stdio`（OpenSSH `ProxyCommand` 直连）与 `ID:CODE` 免绑协助

1. **`uuremote-viewer portmap --stdio <DEVICE> <HOST> <PORT>`**：
   - 在 `src/viewer/tools/portmap.rs` 新增 `run_stdio`，将进程 `stdin` / `stdout` 直接桥接至 WebRTC `FILE_DATA_CHANNEL` 上的 `PortMappingFrame`（`Message 27`）。
   - 用户可在 `~/.ssh/config` 中配置 `ProxyCommand uuremote-viewer portmap --stdio <DEV> 127.0.0.1 %p`，无需后台常驻监听本地端口即可直接执行 `ssh`、`scp`、`rsync` 或 VS Code Remote。
2. **`<CONNECT_ID>:<CODE>` 跨账号免绑工具连接**：
   - 在 `src/viewer_main.rs` 的 `tool_command` 中自动识别 `ID:CODE` 格式并调用 `api.join_share(id, code)`，使 `terminal`、`files`、`portmap` 均可直接连接运行 `uuremote-server assist` 的被控节点，彻底规避同账号单机 JWT `device_id` 互踢限制。

### 模块四：纯无头零图形库构建（`headless-cli` Feature 与 `UU_NO_X11=1`）

- 在 `Cargo.toml` 新增 `headless-cli = ["native-viewer"]` 特性。
- 在 `build.rs` 中增加 `UU_NO_X11=1` 与 `CARGO_FEATURE_HEADLESS_CLI` 判断，并为 Linux 目标开启 `-Wl,--as-needed`。使用 `UU_NO_X11=1 UU_NO_GTK=1 cargo build --release --features headless-cli --bin uuremote-viewer` 编译出的纯 CLI 二进制**彻底剥离 `libgtk-3`、`libSDL2`、`libX11`、`libXtst`、`libXfixes` 动态库依赖**，仅依赖系统基础 `libc`，可在任意极简容器或无头云主机中即拷即用。

---

## 3. 验证与交付清单

1. **单元测试覆盖**：`cargo test` 覆盖 `ice_filter::tests`（网卡名过滤、IPv4 CGNAT / Fake-IP / IPv6 ULA 过滤、远端 SDP 候选解析与 `typ host` 拦截）及原有全部测试套件。
2. **无头动态库校验**：验证 `ldd target/release/uuremote-viewer` 不含任何 X11 / GTK3 / SDL2 动态库。
3. **实机穿透性能复核**：在 `hermes-wb` ↔ `vm-4-143-ubuntu` 双端开启 Tailscale 且**不配置任何 `iptables` 规则**的前提下，实测新版二进制自动跳过 `tailscale0`、直通网易 BGP TURN 并跑出 `> 4.0 MB/s` 吞吐。
