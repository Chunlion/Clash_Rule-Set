
---

# 🚀 Chunlion Clash Rule-Set (DNS-Leak Version)

> 🛡️ 面向 Mihomo (Clash Meta) 的高可用分流与 DNS 防泄露配置
>
> ⚡ 主打：稳定、清晰、可维护

本项目基于 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 改造，面向 Mihomo (Clash Meta) 核心，重点强化以下能力：

- 🔒 DNS 防泄露与解析稳定性
- 🎮 游戏、金融、流媒体、AI 等场景分流
- 🔄 统一的 YAML 与 JS 覆写脚本策略

适配客户端示例：`OpenWrt` `Clash/Nikki 插件`、`Clashmi`、`FlClash`、`Clash Verge Rev`、`Surfboard` 等。

---

## 📦 项目文件说明

### 🧩 文件一：Chunlion_Rule-Set_DNS-Leak.yaml

- ✅ 完整配置文件，适合大多数客户端直接导入。
- ✅ 内含 proxy-providers、proxy-groups、rule-providers、rules、DNS 与 TUN 全量配置。

### 🛠️ 文件二：Chunlion_Rule-Set_DNS-Leak.js

- ✅ Clash Verge Rev 场景下的全局覆写脚本。
- ✅ 在不改动原订阅内容的前提下，注入与 YAML 对齐的策略。

---

## 🎯 核心设计目标

1. 降低 DNS 泄露概率
2. 提高规则命中精度（域名 + IP 双层）
3. 保持多区域策略组可控（手动/自动/故障转移）
4. 在不同客户端之间保证行为一致

---

## ⚙️ 关键配置参数

| 参数         | 当前值        | 说明                       |
| :----------- | :------------ | :------------------------- |
| Mixed-Port   | 7893          | HTTP + SOCKS5 混合监听端口 |
| DNS 监听端口 | 7874          | 内置 DNS 服务端口          |
| 工作模式     | rule          | 按规则分流                 |
| TUN          | 开启（mixed） | 提升全局接管能力           |
| Sniffer      | 开启          | 支持 TLS / HTTP / QUIC     |
| 控制面板     | Zashboard     | external-ui-url 已预置     |

---

## 🚀 快速上手

### ✅ 方式一：使用 YAML（推荐）

1. 下载 `Chunlion_Rule-Set_DNS-Leak.yaml`。
2. 修改 `proxy-providers` 下的 `订阅链接` 与 `机场名`。
3. 导入客户端并启用配置。

### ✅ 方式二：使用 JS 覆写（推荐 Clash Verge Rev）

1. 复制 `Chunlion_Rule-Set_DNS-Leak.js` 内容。
2. Clash Verge Rev 中新建 `Script` 订阅并粘贴。
3. 启用脚本后刷新订阅。

> 💡 说明：JS 脚本已与 YAML 保持策略一致，适合不方便直接维护完整 YAML 的用户。

---

## 🔀 策略分流详解

### 🌐 服务策略组

| 策略组        | 用途                                                          |
| :------------ | :------------------------------------------------------------ |
| 🤖 AI Services | AI 服务统一分流，优先可用美区路径                             |
| 🎮 Games       | 覆盖 Steam、Epic、EA、Ubisoft、Blizzard、Sony、Xbox、Nintendo |
| 💳 Wise        | 金融场景独立策略                                              |
| 📺 Emby        | 媒体流量独立分组，含域名 + IP 双命中                          |
| 🇬🇧 UKwifi      | 英国 WiFi Calling 专用 IP 分流                                |
| 🧰 兜底流量    | 未命中规则时统一承接                                          |

### 🗺️ 区域策略组

每个区域均包含三种角色：

- ✋ 手动组：便于固定节点。
- ⚡ 自动组（url-test）：自动测延迟选优。
- 🔁 故障转移组（fallback）：自动组不可用时切换。

区域覆盖：香港、台湾、日本、韩国、新加坡、美国、欧洲、其他。

---

## 🔒 DNS 防泄露机制（重点）

### 1️⃣ Fake-IP 增强模式

- `enhanced-mode: fake-ip`
- `fake-ip-range: 198.18.0.1/16`
- `DNS ipv6: false`（DNS 层关闭 IPv6 解析）

### 2️⃣ 规则优先解析

- `respect-rules: true`
- 先规则匹配，再走 DNS 解析路径。

### 3️⃣ 分角色 DNS 服务器

- `default-nameserver：223.5.5.5、119.29.29.29`
- `proxy-server-nameserver：https://dns.alidns.com/dns-query、https://doh.pub/dns-query`
- `direct-nameserver：223.5.5.5、119.29.29.29`

### 4️⃣ nameserver-policy 精细化

已对以下规则集定向到国内 DNS：

- `rule-set:cn_domain`
- `rule-set:private_domain`
- `rule-set:add_direct_domain`

这能减少直连域名被错误送往远端解析的概率，提升稳定性。

### 5️⃣ fake-ip-filter 增强

已将以下项纳入真实解析路径：

- `rule-set:cn_domain`
- `rule-set:private_domain`
- `rule-set:add_direct_domain`
- 常见局域网/NTP/STUN/Windows 探测域名

### 6️⃣ TUN + DNS 劫持

- `dns-hijack: any:53 与 tcp://any:53`
- 配合 `auto-route/auto-redirect`，尽量减少系统层绕行。

---

## 🆕 规则更新说明（当前版本）

相较早期版本，当前配置已补强：

1. 广告规则
   - 新增 `ads_domain`，并在规则前列执行 REJECT。
2. Emby 双通道规则
   - 同时使用 `emby_domain` 与 `emby_ip`，提升命中率。
3. DNS 策略增强
   - `nameserver-policy` 增加 `add_direct_domain`。
   - `fake-ip-filter` 增加 `private_domain` 以及更多局域网/NTP/STUN/TURN/Xbox 探测域名防御泄露。
   - `proxy-server-nameserver` 升级使用 `DoH (alidns 和 doh.pub)`。
4. 测速与直连优化
   - 测试链接统一替换为更贴近落地延迟的 `cp.cloudflare.com/generate_204`。
   - 修正了 `add_direct_domain`（直连域名）的规则层级，确保其优先级高于 `geolocation-!cn`。

---

## ❓ 常见问题

### 🌐 无法联网或部分站点超时

- 检查 `mixed-port` 是否被占用。
- 确认客户端没有叠加其他 DNS 覆写脚本。
- 旧内核建议保持 `prefer-h3: false`。
- 如果节点使用的是`ipv6`，请自己修改配置文件中关于`ipv6`的部分。

### 🧪 怀疑仍有 DNS 泄露

- Windows 网卡 DNS 可改为 `127.0.0.1` 并配合 `TUN模式`。
- 可尝试 `strict-route: true`（可能牺牲少量性能，不推荐）。
- 关闭客户端内额外 DNS 劫持插件，避免重复重定向。
- 禁用浏览器中`使用安全DNS`，并保持实验性功能`Experimental QUIC protocol`关闭。
- `WebRTC泄露`可通过安装浏览器插件[WebRTC Network Limiter](https://chromewebstore.google.com/detail/webrtc-network-limiter/npeicpdbkakmehahjeeohfdhnlpdklia)解决。
- 尝试`禁用Windows智能多宿主名称解析`，`本地组策略编辑器`-`计算机配置`-`管理模板`-`网络`-`DNS客户端`-`禁用智能多宿主名称解析`-选择`已启用`。

### 📍 节点很多但区域组为空

- 检查节点命名是否包含地区关键字（如 HK、JP、US 等）。
- 如机场命名不规范，可在区域正则中补充关键字。

---

## ⚠️ 安全与合规

- 请勿公开泄露订阅链接与机场信息。
- 本仓库规则来自公开规则源，按需自动更新。
- 请在当地法律法规允许范围内使用。

---

## 🙏 致谢

- 原始项目与思路来源：[Seven1echo/Yaml](https://github.com/Seven1echo/Yaml)
- 规则数据来源：MetaCubeX、Koolson、及其他公开规则维护者
