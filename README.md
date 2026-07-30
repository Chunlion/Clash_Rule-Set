<div align="center">

# 🚀 Chunlion Clash Rule-Set

**面向 Mihomo（Clash Meta）的高可用分流与 DNS 防泄露配置**

`完整 / Lite` · `YAML / JS` · `Fake-IP` · `TUN` · `Bettbox`

[![Release](https://img.shields.io/github/v/release/Chunlion/Clash_Rule-Set?label=Release&color=blue)](https://github.com/Chunlion/Clash_Rule-Set/releases/latest)
[![Mihomo](https://img.shields.io/badge/Core-Mihomo-5c7cfa)](https://github.com/MetaCubeX/mihomo)
[![DNS](https://img.shields.io/badge/DNS-Fake--IP-2f9e44)](#-dns-防泄露)
[![Format](https://img.shields.io/badge/Format-YAML%20%2B%20JS-f08c00)](#-版本选择)

[📥 快速导入](#-快速导入) · [🧭 版本选择](#-版本选择) · [🔀 策略分流](#-策略分流) · [🔒 DNS 机制](#-dns-防泄露) · [❓ 常见问题](#-常见问题)

</div>

> [!IMPORTANT]
> **使用前必读**
>
> - 独立使用 YAML：导入后先替换 `订阅链接` 与 `机场名`。
> - 已有机场订阅：优先使用 JS 覆写，不要把 JS 当成独立配置。
> - 不要公开分享已填入订阅信息的配置文件。

本项目基于 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 改造，并参考 [AIsouler/MyClash](https://github.com/AIsouler/MyClash) 与 [HenryChiao/MIHOMO_YAMLS](https://github.com/HenryChiao/MIHOMO_YAMLS) 的节点管理与配置筛选思路。

---

## 🧭 版本选择

> [!TIP]
> **不知道怎么选？** 已有机场订阅选 JS；需要独立配置选 YAML。设备性能一般或节点较多时选 Lite。

| 使用场景 | 推荐版本 | 推荐格式 | 原因 |
| :-- | :--: | :--: | :-- |
| Bettbox，已有机场订阅 | 完整 / Lite | **JS** | 通过脚本覆写原订阅 |
| Clash Verge Rev，已有机场订阅 | 完整 / Lite | **JS** | 使用 Script 覆写 |
| OpenWrt / Nikki / FlClash | 完整 / Lite | **YAML** | 直接导入完整配置 |
| 需要精细服务分流 | **完整** | YAML / JS | 43 个策略组，服务分类更细 |
| 节点多或设备资源有限 | **Lite** | YAML / JS | 23 个策略组，规则源更少 |

<details>
<summary><strong>📦 展开查看项目文件说明</strong></summary>

| 文件 | 类型 | 说明 |
| :-- | :-- | :-- |
| `Chunlion_Rule-Set_DNS-Leak.yaml` | 完整 YAML | 完整分流、规则源、DNS、TUN 与面板配置 |
| `Chunlion_Rule-Set_DNS-Leak.js` | 完整 JS | 为已有订阅注入完整策略与规则 |
| `Chunlion_Rule-Set_DNS-Leak_Lite.yaml` | Lite YAML | 保留核心 DNS、防泄露和常用服务分流 |
| `Chunlion_Rule-Set_DNS-Leak_Lite.js` | Lite JS | 轻量覆写，适合节点较多或低资源设备 |

</details>

---

## 📥 快速导入

### Bettbox

[Bettbox](https://github.com/appshubcc/Bettbox) 支持远程配置与远程脚本：

- **YAML**：`配置 → 添加配置 → URL`
- **JS**：`配置 → 脚本 → 导入 → URL`

| 类型 | 完整版 | Lite 版 |
| :-- | :--: | :--: |
| YAML 配置 | [打开 Raw 链接](https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak.yaml) | [打开 Raw 链接](https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak_Lite.yaml) |
| JS 覆写 | [打开 Raw 链接](https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak.js) | [打开 Raw 链接](https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak_Lite.js) |

<details>
<summary><strong>📋 展开复制四个 Raw URL</strong></summary>

**完整 YAML**

```text
https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak.yaml
```

**Lite YAML**

```text
https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak_Lite.yaml
```

**完整 JS**

```text
https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak.js
```

**Lite JS**

```text
https://raw.githubusercontent.com/Chunlion/Clash_Rule-Set/main/Chunlion_Rule-Set_DNS-Leak_Lite.js
```

</details>

> [!NOTE]
> YAML 导入后仍需替换 `订阅链接` 与 `机场名`；JS 必须作为已有机场配置的覆写脚本使用。

### 其他 Mihomo 客户端

1. **Clash Verge Rev**：新建 `Script`，粘贴 JS 或使用远程脚本链接。
2. **OpenWrt / Nikki / FlClash**：下载 YAML，替换订阅信息后导入。
3. 启用配置后刷新规则提供者、代理提供者和节点延迟。

---

## ✨ 核心能力

| 🔒 DNS 稳定 | 🔀 精细分流 | ⚡ 节点健康 | 🛡️ 网络兼容 |
| :-- | :-- | :-- | :-- |
| Fake-IP + `respect-rules` | 域名与 IP 双层规则 | HTTP 204 有效性检测 | TUN + 保守嗅探 |
| 私有 DNS 与节点 hosts 保留 | 流媒体、AI、金融、游戏 | 自动、故转、全局均衡 | 内网、远控、Tailscale 保护 |

---

## ⚙️ 关键配置参数

| 参数         | 当前值        | 说明                       |
| :----------- | :------------ | :------------------------- |
| Mixed-Port   | 7893          | HTTP + SOCKS5 混合监听端口 |
| DNS 监听端口 | 7874          | 内置 DNS 服务端口          |
| 工作模式     | rule          | 按规则分流                 |
| TUN          | 开启（mixed） | 提升全局接管能力           |
| Sniffer      | 开启          | 支持 TLS / HTTP / QUIC     |
| TCP Keep Alive | 600 / 60 秒 | 空闲 600 秒，间隔 60 秒探测 |
| 控制面板     | Zashboard     | external-ui-url 已预置     |
| NTP          | 30 分钟       | 内核校时，默认不写系统时间 |
| Fallback 检测 | 180 秒 / 2 次 | 更快发现并切换不可用节点   |
| URL-Test 容差 | 30 ms         | 新节点至少快 30 ms 才切换  |
| 测速状态     | HTTP 204      | 仅 204 响应视为可用节点    |
| 空节点回退   | REJECT        | 动态节点组为空时自动拒绝   |
| 规则源更新   | 一键代理      | 远程规则集通过代理下载     |
| 规则格式     | MRS / GEOSITE | 减少文本规则体积与加载压力 |

---

## 🔀 策略分流

| 对比项 | 🚀 完整版 | ⚡ Lite 版 |
| :-- | :--: | :--: |
| 策略组数量 | **43** | **23** |
| 服务策略组 | 16 | 11 |
| 地区模式 | 手动 + 自动 + 故转 | 单一地区选择组 |
| 全局均衡 | ✅ | — |
| 全局最优 / 稳定备用 | — | ✅ |
| 适合场景 | 精细分流 | 轻量运行 |

> [!TIP]
> 完整版适合需要细分服务和多种地区选择方式的用户；Lite 版减少后台测速与外部规则源，更适合节点较多或资源有限的设备。

<details>
<summary><strong>🧩 展开查看完整策略组对比</strong></summary>

### 🌐 服务策略组

| 🧩 版本 | 🌐 服务策略组 |
| :-- | :-- |
| 🚀 完整版 | 🚀 一键代理、📺 Streaming、🐙 GitHub、🔎 Google、🤖 AI Services、🎞️ Emby、🍎 Apple、✈️ Telegram、🐦 Twitter、🎵 TikTok、🪟 Microsoft、💳 PayPal、₿ Crypto、🎮 Games、🇬🇧 UKwifi、🧰 兜底流量 |
| ⚡ Lite 版 | 🚀 一键代理、📺 Streaming、✈️ Telegram、🎞️ Emby、🔎 Google、🤖 AI Services、🎵 TikTok、💳 PayPal、₿ Crypto、🎮 Games、🧰 兜底流量 |

### 🗺️ 区域策略组

| 🧩 版本 | 🗺️ 区域策略组 |
| :-- | :-- |
| 🚀 完整版 | 🇭🇰 香港、🇲🇴 澳门、🇹🇼 台湾、🇯🇵 日本、🇰🇷 韩国、🇸🇬 新加坡、🇺🇸 美国、🇪🇺 欧洲均包含 ✋ 手动、⚡ 自动、🔁 故转；另有 ⚖️ 全局均衡、🏠 家宽节点、📦 其他手动 |
| ⚡ Lite 版 | 🇭🇰 香港、🇲🇴 澳门、🇹🇼 台湾、🇯🇵 日本、🇰🇷 韩国、🇸🇬 新加坡、🇺🇸 美国、🇪🇺 欧洲均为 📍 节点组；另有 🏠 家宽节点、📦 其他节点 |

### 节点分组对比

| 📌 特征维度 | 🚀 完整版 | ⚡ Lite 版 |
| :-- | :--: | :--: |
| 🧩 策略组数量 | 43 | 23 |
| 🌐 服务策略组数量 | 16 | 11 |
| 🗺️ 区域分组形态 | ✋ 手动 + ⚡ 自动 + 🔁 故转 | 📍 节点 |
| ⚡ 全局最优 | ❌ | ✅ |
| 🛟 稳定备用 | ❌ | ✅ |
| ⚖️ 全局均衡 | ✅ | ❌ |
| 🏠 家宽节点 | ✅ | ✅ |

| 🧩 策略组 | 🚀 完整版 | ⚡ Lite 版 |
| :-- | :--: | :--: |
| 🚀 一键代理 | ✅ | ✅ |
| 📺 Streaming | ✅ | ✅ |
| 🐙 GitHub | ✅ | ❌ |
| 🔎 Google | ✅ | ✅ |
| 🤖 AI Services | ✅ | ✅ |
| 🎞️ Emby | ✅ | ✅ |
| 🍎 Apple | ✅ | ❌ |
| ✈️ Telegram | ✅ | ✅ |
| 🐦 Twitter | ✅ | ❌ |
| 🎵 TikTok | ✅ | ✅ |
| 🪟 Microsoft | ✅ | ❌ |
| 💳 PayPal | ✅ | ✅ |
| ₿ Crypto | ✅ | ✅ |
| 🎮 Games | ✅ | ✅ |
| 🇬🇧 UKwifi | ✅ | ❌ |
| 🧰 兜底流量 | ✅ | ✅ |
| ⚡ 全局最优 | ❌ | ✅ |
| 🛟 稳定备用 | ❌ | ✅ |
| ⚖️ 全局均衡 | ✅ | ❌ |
| 🇭🇰 香港 | ✋ / ⚡ / 🔁 | 📍 |
| 🇲🇴 澳门 | ✋ / ⚡ / 🔁 | 📍 |
| 🇹🇼 台湾 | ✋ / ⚡ / 🔁 | 📍 |
| 🇯🇵 日本 | ✋ / ⚡ / 🔁 | 📍 |
| 🇰🇷 韩国 | ✋ / ⚡ / 🔁 | 📍 |
| 🇸🇬 新加坡 | ✋ / ⚡ / 🔁 | 📍 |
| 🇺🇸 美国 | ✋ / ⚡ / 🔁 | 📍 |
| 🇪🇺 欧洲 | ✋ / ⚡ / 🔁 | 📍 |
| 🏠 家宽节点 | ✅ | ✅ |
| 📦 其他 | 其他手动 | 其他节点 |

</details>

---

## 🔒 DNS 防泄露

| 防护层 | 当前配置 | 作用 |
| :-- | :-- | :-- |
| DNS 模式 | `fake-ip` + `respect-rules` | 境外域名交由代理侧解析，降低污染风险 |
| 解析分工 | 默认 / 节点 / 直连 DNS 分离 | 节点域名与直连域名使用对应解析路径 |
| Hosts | 配置 hosts + 系统 hosts | 兼顾预设映射、内网和节点域名 |
| TUN | UDP/TCP 53 劫持 | 减少系统 DNS 绕行 |
| Sniffer | 全局不覆盖、私网目标跳过 | 降低 NAS、远控、IoT 和 Tailscale 异常 |

> [!NOTE]
> DNS、Fake-IP 过滤、TUN 和规则顺序是一套配套设计，不建议再叠加其他 DNS 覆写。

<details>
<summary><strong>🔍 展开查看 DNS、TUN 与 Sniffer 细节</strong></summary>

### 1️⃣ Fake-IP 增强模式

- `enhanced-mode: fake-ip`
- `fake-ip-range: 198.18.0.1/16`
- `DNS ipv6: false`（DNS 层关闭 IPv6 解析）

### 2️⃣ 规则优先解析

- `respect-rules: true`
- 先规则匹配，再走 DNS 解析路径。
- 境外域名由 Fake-IP 交给代理侧远程解析，天然防污染；因此不再配置老式 `fallback` / `fallback-filter`（与 `respect-rules` 机制重复，实际不再生效）。

### 3️⃣ 分角色 DNS 服务器

- `default-nameserver：223.5.5.5、119.29.29.29`
- `proxy-server-nameserver：https://dns.alidns.com/dns-query、https://doh.pub/dns-query`
- `direct-nameserver：223.5.5.5、119.29.29.29`
- `use-hosts` 与 `use-system-hosts` 均开启，配置内映射和系统 hosts 同时生效。

### 4️⃣ nameserver-policy 精细化

已对以下规则集定向到国内 DNS：

- `rule-set:add_direct_domain`
- `geosite:cn,private`

这能减少直连域名被错误送往远端解析的概率，提升稳定性。`cn_domain` / `private_domain` 规则集与 `geosite:cn,private` 数据同源，不再重复登记。

### 5️⃣ fake-ip-filter 增强

已将以下项纳入真实解析路径：

- `rule-set:fakeip_filter`（外部维护的 Fake-IP 兼容域名）
- `rule-set:add_direct_domain`
- `geosite:cn`（与 `rule-set:cn_domain` 同源，保留一份）
- `geosite:private`（与 `rule-set:private_domain` 同源，保留一份）
- 常见局域网/NTP/STUN/Windows 探测域名
- `services.googleapis.cn` 映射至 `services.googleapis.com`，改善 Google Play 下载兼容性

### 6️⃣ TUN + DNS 劫持

- `dns-hijack: any:53 与 tcp://any:53`
- 配合 `auto-route/auto-redirect`，尽量减少系统层绕行。
- 通过 `route-exclude-address` 显式绕过回环、私网、链路本地及 `100.64.0.0/10`，避免 NAS、路由器和 Tailscale 流量进入 TUN。
- Linux + nftables 环境会通过 `route-exclude-address-set: [cn_ip]` 将大陆 IP 绕过 TUN；Windows 和 macOS 不使用该规则。

### 7️⃣ 节点 hosts 与保守嗅探

- JS 覆写只保留与实际节点服务器域名匹配的原订阅 hosts、`nameserver-policy` 和 `proxy-server-nameserver-policy`，避免覆盖节点域名所需的内网解析，同时不把无关映射带入新配置。
- Sniffer 不嗅探回环、私网、链路本地及 `100.64.0.0/10` 目标，减少 NAS、路由器、远控、Tailscale 和内网 HTTP 被改写的概率。
- 全局 `override-destination` 与 `parse-pure-ip` 保持关闭，仅 HTTP 协议嗅探按原配置覆盖目标。

</details>

---

## 🆕 当前版本改进

<details>
<summary><strong>展开查看完整改进记录</strong></summary>

相较早期版本，当前配置已补强：

1. 广告规则
   - 完整版新增 `ads_domain`，并在规则前列执行 REJECT。
2. Emby 双通道规则
   - 同时使用 `emby_domain` 与 `emby_ip`，提升命中率。
3. DNS 策略增强
   - `nameserver-policy` 增加 `add_direct_domain`，并与 `geosite:cn,private` 配合覆盖国内/私有域名（去除同源重复登记）。
   - `fake-ip-filter` 增加国内、私有、直连规则以及更多局域网/NTP/STUN/TURN/Xbox 探测域名。
   - `proxy-server-nameserver` 升级使用 `DoH (alidns 和 doh.pub)`。
   - JS 覆写会保留订阅中非公共的私有 DNS，以及与实际节点服务器域名匹配的 hosts 和 DNS policy，避免覆写后节点域名失效。
   - 显式启用配置 hosts 与系统 hosts，并为回环、私网、链路本地和 CGNAT/Tailscale 目标关闭嗅探、绕过 TUN。
   - 移除老式 `fallback` / `fallback-filter`：防污染统一由 Fake-IP + `respect-rules` 承担，避免两套机制并存造成误解。
4. 测速与直连优化
   - 测试链接统一使用 `www.gstatic.com/generate_204`，仅 HTTP 204 响应视为可用，减少劫持页误判。
   - 动态节点组、Fallback 与 URL-Test 组无可用节点时使用 `REJECT`，不自动改走其他节点。
   - 修正了 `add_direct_domain`（直连域名）的规则层级，确保其优先级高于 `geolocation-!cn`。
5. 规则源优化
   - 规则源统一走 `cdn.jsdelivr.net` 多节点 CDN（GitHub Release 附件除外），广告规则改用 anti-AD 官方地址，下载更稳。
   - 所有远程规则集通过“一键代理”更新；订阅源仍保持 `DIRECT`，避免首启代理依赖。
   - 四份配置统一使用 PayPal 金融分流与 Crypto 加密货币分流。
6. 连接层兼容
   - 移除 [Mihomo v1.19.27](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.27) 已废弃的 `global-client-fingerprint`；TLS 指纹改由订阅节点自身的 `client-fingerprint` 管理。
   - 设置 TCP Keep Alive 空闲 600 秒、探测间隔 60 秒，降低频繁探测带来的移动设备耗电。
   - 订阅健康检查补充 `expected-status: 204`，与策略组测速判定标准一致。
7. 地区正则与安全加固
   - 地区正则的 2–3 字母代码（HK/UK/GB/SEL/OSA 等）统一加 `\b` 单词边界，修复 `Fukuoka` 误入欧洲组、`South Africa` 误入韩国组、带 `10GB` 标签误入欧洲组等错分。
   - “其他”组排除正则补充 `(?i)` 与地区词全集，全大写命名（如 `RUSSIA`、`PANAMA`）不再凭空消失。
   - 面板 API 默认启用密码 `123456`（首次打开 zashboard 时输入；建议改成自己的随机值）。
   - 图标地址统一为 `raw.githubusercontent.com` 写法。
8. 节点选择增强
   - 完整版新增懒加载 `sticky-sessions` 全局均衡组；同一来源与目标的连接保持在同一节点，未选择该组时不进行测速。
   - 所有 `include-all` 动态组排除 `direct` 出站，避免全局测速误选直连；订阅信息节点过滤补充获取、版本、官址、已用、联系、说明、教程、关注等常见标签。

</details>

---

## 🧪 维护与自检

修改配置后建议完成三类检查：

| 检查项 | 目标 |
| :-- | :-- |
| YAML 语法 | 客户端可以正常解析和导入 |
| JS 语法 | 覆写脚本能够通过 `node --check` |
| 规则源 | URL 可访问，`rules` 引用均有对应提供者 |

> [!TIP]
> 仓库会在每次推送或 PR 时校验 YAML/JS 一致性，并在每周一巡检规则源与 geodata 地址。

**维护原则**

- 规则顺序比数量更重要，直连、私有、特殊规则应放在泛规则前。
- DNS 相关配置要和规则层级保持一致，避免直连域名走远端解析。
- 节点分组正则只按地区关键词归类，线路标签如 IEPL / IPLC / BGP / 倍率不参与地区判断。

---

## ❓ 常见问题

<details>
<summary><strong>🌐 无法联网或部分站点超时</strong></summary>

- 检查 `mixed-port` 是否被占用。
- 确认客户端没有叠加其他 DNS 覆写脚本。
- 旧内核建议保持 `prefer-h3: false`。
- 如果节点使用 IPv6，请同步调整配置中的 `ipv6` 设置。

</details>

<details>
<summary><strong>🧪 怀疑仍有 DNS 泄露</strong></summary>

- 已开启 `TUN 模式` 时，可将 Windows 网卡 DNS 改为 `127.0.0.1`，由 `dns-hijack` 接管 DNS 请求；未开启 TUN 时不要这样设置。
- 对防泄露要求较高时可启用 `strict-route: true`；Windows 会增加 DNS 泄露防护规则，但可能影响 VirtualBox 等软件。
- 关闭客户端内额外 DNS 劫持插件，避免重复重定向。
- 禁用浏览器的“使用安全 DNS”，并关闭实验性的 QUIC 功能。
- WebRTC 泄露可使用 [WebRTC Network Limiter](https://chromewebstore.google.com/detail/webrtc-network-limiter/npeicpdbkakmehahjeeohfdhnlpdklia) 限制。
- Windows 可在组策略中启用“禁用智能多宿主名称解析”。

</details>

<details>
<summary><strong>🕒 OpenWrt 系统时间不准确</strong></summary>

- 配置默认启用 Mihomo 内部 NTP 校时，每 30 分钟通过 `DIRECT` 查询 `time.apple.com`，但不会修改系统时间。
- 确认 Mihomo 以 root 权限运行后，可将 `ntp.write-to-system` 改为 `true`，让内核同时校准 OpenWrt 系统时间。

</details>

<details>
<summary><strong>📍 节点很多但区域组为空</strong></summary>

- 检查节点命名是否包含地区关键字（如 HK、JP、US 等）。
- 如机场命名不规范，可在区域正则中补充关键字。
- 动态节点组为空时会返回 `REJECT`，不会自动改走其他地区节点。

</details>

<details>
<summary><strong>🔄 规则源更新失败</strong></summary>

- 确认“一键代理”已选择可用节点；远程规则集通过该策略组下载。
- 重新加载配置后刷新规则提供者；订阅源仍按 `DIRECT` 更新。

</details>

---

## ⚠️ 安全与合规

> [!WARNING]
> - 请勿公开泄露订阅链接、机场信息或已填写凭据的配置。
> - 面板默认密码为 `123456`，建议修改为自己的随机密码。
> - 本仓库规则来自公开规则源，请在当地法律法规允许范围内使用。

---

## 🙏 致谢

- 原始项目与思路来源：[Seven1echo/Yaml](https://github.com/Seven1echo/Yaml)
- 私有 DNS 与负载均衡思路参考：[AIsouler/MyClash](https://github.com/AIsouler/MyClash)
- 节点筛选与规则组织参考：[HenryChiao/MIHOMO_YAMLS](https://github.com/HenryChiao/MIHOMO_YAMLS)
- 规则数据来源：MetaCubeX、Koolson、及其他公开规则维护者

<div align="center">

[⬆ 返回顶部](#-chunlion-clash-rule-set)

</div>
