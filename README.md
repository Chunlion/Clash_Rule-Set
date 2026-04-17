根据您提供的详细版本，我将之前的技术要点与您的文案进行了深度融合与优化。新版本保留了您的结构化布局，同时在技术细节处增加了基于配置文件的精确标注与补充。

---

# 🚀 Chunlion Clash Rule-Set (DNS-Leak Version)

[cite_start]本项目基于 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 的分流规则修改而来，深度定制了**金融、游戏及海外通讯**专属分流，并针对 **Mihomo (Clash Meta) 核心**进行了严苛的 **DNS 防泄漏底层优化**。 [cite: 1, 2]

✅ **全面兼容主流 Mihomo 客户端**：
`OpenWrt Clash/Nikki 插件` | `Clashmi` | `FlClash` | `Clash Verge Rev` | `Surfboard` 等。

---

## 🛠️ 核心配置参数

在部署前，了解本配置的基础网络架构：
* [cite_start]**混合端口 (Mixed-Port)**：`7893` [cite: 5]
* [cite_start]**DNS 监听端口**：`7874` [cite: 29]
* [cite_start]**管理面板**：集成 [Zashboard](https://github.com/Zephyruso/zashboard) 外部面板 [cite: 11]
* [cite_start]**流量嗅探 (Sniffer)**：默认开启，支持 TLS/HTTP/QUIC 协议解析，提升分流精准度 [cite: 18, 20-21]

---

## 🚀 部署与使用

### 方式一：完整 YAML 订阅配置（推荐所有客户端）
1. 下载 `Chunlion_Rule-Set_DNS-Leak.yaml`。
2. [cite_start]搜索并替换 `proxy-providers` 下的 `订阅链接` 为您的实际机场 URL。 [cite: 3, 4]
3. 导入客户端即可使用。

### 方式二：JS 全局覆写脚本（推荐 Clash Verge Rev）
1. 复制本项目提供的 `覆写.js` 代码。
2. 在 Verge Rev 的 **“订阅”** -> **“新建”** -> **“Script”** 中粘贴。
3. 启用该脚本，即可在不破坏原订阅的基础上实现本项目的所有功能。

---

## 🔀 独家定制分流规则

针对您的特定需求，本项目对以下策略组进行了深度定制：

| 策略组图标 | 策略组名称 | 包含规则 / 逻辑说明 | 流量特征 [cite] |
| :---: | :--- | :--- | :--- |
| 🦉 | **Wise** | [cite_start]针对 Wise 跨境金融服务进行独立分流，保障资金操作安全。 | [cite: 43, 60] |
| 🎮 | **Games** | [cite_start]精准覆盖 Steam, Epic, EA, Ubisoft, Blizzard, Sony, Xbox, Nintendo。 | [cite: 43, 51-54] |
| 🚀 | **直连优化** | [cite_start]**自动分流**：Steam、微软、苹果的中国区 CDN 流量自动走 `DIRECT`。 | [cite: 49, 50, 62, 63] |
| 🇬🇧 | **UKwifi** | [cite_start]专为英国 SIM 卡（如 giffgaff）Wifi Calling 优化的特定 IP 段分流。 | [cite: 43, 59] |
| 🤖 | **AI Services** | [cite_start]涵盖 ChatGPT, Claude 等主流 AI 服务，默认优先选择美国节点。 | [cite: 41, 48] |

---

## 🔒 四重 DNS 防泄漏机制

[cite_start]本项目在底层预设了严格的隐私防护逻辑，从根源阻断 DNS 泄露[cite: 2]:

1.  **Fake-IP 增强模式**：
    * [cite_start]`enhanced-mode: fake-ip` [cite: 30]
    * [cite_start]关闭 DNS 层的 IPv6 解析 (`ipv6: false`)，防止通过 IPv6 隧道泄露真实地理位置。 [cite: 30]
2.  **精细化 Nameserver 策略**：
    * [cite_start]国内域名与私有域使用腾讯/阿里公共 DNS (`223.5.5.5`, `119.29.29.29`) 直连解析。 [cite: 39, 40]
    * 海外域名强制在远程代理端进行解析，彻底规避 ISP 污染。
3.  **规则优先模式**：
    * [cite_start]`respect-rules: true`：强制核心先进行规则匹配再处理 DNS，避免本地无效请求。 [cite: 31]
4.  **代理服务器专用解析**：
    * [cite_start]`proxy-server-nameserver` 独立配置，确保机场节点域名在解析阶段即受到保护。 [cite: 40]

---

## ⚠️ 常见问题与提示

> [!WARNING]
> [cite_start]* **无法联网？** 请确认 `mixed-port` 没有被其他软件占用，且 `prefer-h3` 已设置为 `false` 以兼容部分旧版核心。 [cite: 5, 32]
> * **DNS 依然有小规模泄露？**
>     [cite_start]1.  **物理网卡设置**：建议将 Windows 网卡的 DNS 手动修改为 `127.0.0.1`，并配合 Clash 的 TUN 模式使用。 [cite: 13]
>     [cite_start]2.  **开启严格路由**：在配置中将 `strict-route` 设为 `true`（注意：这可能会轻微影响访问速度）。 [cite: 17]
>     3.  **关闭第三方覆写**：请务必关闭客户端自带的“系统 DNS 劫持”或“DNS 重定向”功能，以免冲突。

---

## ⚖️ 归属与免责
[cite_start]本配置由原项目 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 优化而来。规则文件通过 `rule-providers` 每日自动更新 [cite: 3]，旨在提供安全、高效的网络环境，请在法律允许的范围内使用。
