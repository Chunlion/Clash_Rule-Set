# Clash_Rule-Set

基于 [Seven1echo/Yaml](https://github.com/Seven1echo/Yaml) 的 Rule-Set 分流文件修改而来，添加了自定义规则分流，并做了 DNS 防泄漏处理。

适用于 **Mihomo 核心** 的工具（OpenWrt Clash/Nikki 插件、Clashmi、FlClash、Clash Meta 等）。

## YAML使用说明

1. 下载 `Chunlion_Rule-Set_DNS-Leak.yaml`
2. 将文件中的 `订阅链接` 替换为你的机场订阅 URL
3. 将文件中的 `机场名` 替换为你的机场名称
4. 导入 Clash / Mihomo 客户端

## 全局覆写使用说明

1. 下载 `Chunlion_Rule-Set_DNS-Leak_覆写.js`
2. 将js内容复制粘贴到全局覆写脚本中

## 自定义分流

在原版基础上新增了以下策略组与规则：

| 策略组    | 说明                           |
|-----------|-------------------------------|
|   Wise    | Wise默认直连 |
|   Games   | 游戏平台分流，Steam下载直连 |
|   UKwifi  | 英国SIM卡Wifi Calling |
## DNS 防泄漏说明

配置采用以下四重防泄漏机制：

1. **`enhanced-mode: fake-ip`** — 所有 DNS 请求返回虚假 IP，真实解析在代理侧完成，避免本地 DNS 泄漏
2. **`nameserver-policy`** — 国内域名走国内加密 DNS（腾讯/阿里 DoH）；其余域名走 Cloudflare / Google DoH
3. **`proxy-server-nameserver`** — 单独配置代理节点地址的解析 DNS，防止节点 IP 被污染
4. **`strict-route: true`** — 严格路由模式，打开后不影响速度，防止DNS泄露

## 提示
 1. **如果导入Clash / Mihomo 客户端后无法正常使用，尝试关闭严格路由，关闭严格路由后可能会产生DNS泄露**
 2. **想要使用本项目DNS规则请把客户端中 DNS覆写 关闭**

