# 🚀 Clash Rule-Set (防泄漏强化版)

本项目基于 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 的规则分流文件修改而来，深度定制了**自定义规则分流**，并在此基础上进行了**DNS 防泄漏处理**。

✅ **全面兼容搭载 Mihomo 核心的客户端**，包括但不限于：  
`OpenWrt Clash/Nikki 插件` | `Clashmi` | `FlClash` | `Clash Meta` 等。

---

## 📖 使用指南

### 方法一：YAML 完整配置导入
1. 下载本项目中的 `Chunlion_Rule-Set_DNS-Leak.yaml` 文件。
2. 使用文本编辑器打开，将文件中的 `订阅链接` 替换为您购买的机场订阅 URL。
3. 将文件中的 `机场名` 替换为您的机场名称。
4. 保存修改，并直接导入到您的 Clash / Mihomo 客户端中即可使用。

### 方法二：JS 全局覆写 (脚本模式)
1. 下载本项目中的 `Chunlion_Rule-Set_DNS-Leak_覆写.js` 文件。
2. 打开该文件，将所有 JS 代码复制。
3. 粘贴到客户端的**全局覆写（Script/Override）**输入框中并保存生效。

---

## 🔀 自定义分流规则

在原版规则的基础上，本项目重点增加了以下自定义策略组：

| 策略组 | 规则说明 | 默认策略 |
| :--- | :--- | :--- |
| 🦉 **Wise** | Wise 跨境汇款相关服务直连 | `DIRECT` (直连) |
| 🎮 **Games** | 游戏平台精准分流，Steam 游戏下载直连（不消耗机场流量） | `DIRECT` (直连) |
| 🇬🇧 **UKwifi** | 英国 SIM 卡专属 Wifi Calling 规则优化 | 根据节点选择 |

---

## 🛡️ DNS 防泄漏机制说明

为了最大程度保护隐私，本项目配置了以下**防泄漏机制**：

1. **`enhanced-mode: fake-ip` (Fake-IP 模式)**  
   所有 DNS 请求优先返回虚假 IP，真实的域名解析完全在代理服务器端完成，从根源避免本地 DNS 泄漏。
2. **`nameserver-policy` (分流解析策略)**  
   国内域名 ➡️ 走国内加密 DNS（腾讯/阿里 DoH），保证国内访问速度。  
3. **`proxy-server-nameserver` (节点专属解析)**  
   为代理节点的地址单独配置解析 DNS，有效防止节点 IP 在连接前就被污染或阻断。
4. **`respect-rules: true` (遵循规则)**  
   开启遵循规则模式，避免本地发起DNS请求。开启后**不影响速度**，是Mihomo内核用来防止DNS泄露的完美工具。

---
