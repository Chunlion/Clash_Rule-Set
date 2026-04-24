// Clash Verge Rev 全局覆写脚本 - 策略分流版

function main(config) {
  // --- 1. 基础设置 ---
  config["mixed-port"] = 7893;
  config["mode"] = "rule";
  config["allow-lan"] = true;
  config["ipv6"] = false;
  config["log-level"] = "info";
  config["tcp-concurrent"] = true;
  config["unified-delay"] = true;

  // --- 2. DNS 配置 ---
  config["dns"] = {
    "enable": true,
    "listen": "0.0.0.0:7874",
    "ipv6": false,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "respect-rules": true,
    "prefer-h3": false,
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],
    "direct-nameserver": ["223.5.5.5", "119.29.29.29"],
    "direct-nameserver-follow-policy": true,
    "nameserver-policy": {
      "rule-set:cn_domain,private_domain,add_direct_domain": ["223.5.5.5", "119.29.29.29"],
      "geosite:cn,private": ["223.5.5.5", "119.29.29.29"]
    },
    "nameserver": [
      "https://dns.alidns.com/dns-query",
      "https://doh.pub/dns-query"
    ],
    "fake-ip-filter": [
      "+.lan",
      "rule-set:cn_domain",
      "rule-set:private_domain",
      "rule-set:add_direct_domain",
      "+.local",
      "+.msftconnecttest.com",
      "+.msftncsi.com",
      "localhost.ptlogin2.qq.com",
      "localhost.sec.qq.com",
      "+.in-addr.arpa",
      "+.ip6.arpa",
      "stun.*",
      "time.*.com",
      "time.*.gov",
      "pool.ntp.org",
      "+.ntp.org",
      "+.pool.ntp.org",
      "+._tcp.*",
      "+._udp.*",
      "WORKGROUP",
      "+.stun.*.*",
      "+.stun.*.*.*",
      "+.xbox.com",
      "+.xboxlive.com",
      "+.turn.*",
      "+.turn.*.*"
    ]
  };

  // --- 3. TUN 配置 ---
  config["tun"] = {
    "enable": true,
    "stack": "mixed",
    "dns-hijack": ["any:53", "tcp://any:53"],
    "auto-detect-interface": true,
    "auto-route": true,
    "auto-redirect": true,
    "strict-route": false,
    "endpoint-independent-nat": true
  };

  // --- 4. 策略组 (Proxy Groups) ---
  const commonProxies = [
    "一键代理", "香港手动", "台湾手动", "日本手动", "韩国手动", "新加坡手动", "美国手动", "欧洲手动",
    "香港自动", "台湾自动", "日本自动", "韩国自动", "新加坡自动", "美国自动", "欧洲自动",
    "香港故转", "台湾故转", "日本故转", "韩国故转", "新加坡故转", "美国故转", "欧洲故转",
    "其他手动", "DIRECT", "REJECT"
  ];

  const aiProxies = ["美国手动", ...commonProxies];

  config["proxy-groups"] = [
    {
      name: "一键代理",
      type: "select",
      proxies: commonProxies.filter(p => p !== "一键代理"),
      icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Rocket.png"
    },
    { name: "YouTube", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/YouTube.png" },
    { name: "Google", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Google.png" },
    { name: "AI Services", type: "select", proxies: aiProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/AI.png" },
    { name: "GitHub", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/github(1).png" },
    { name: "AppleTV", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/AppleTV.png" },
    { name: "Emby", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Emby.png" },
    { name: "Apple", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Apple.png" },
    { name: "TikTok", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/TikTok.png" },
    { name: "Twitter", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Twitter.png" },
    { name: "Telegram", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Telegram.png" },
    { name: "Speedtest", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Speedtest.png" },
    { name: "Wise", type: "select", proxies: commonProxies, icon: "https://fastly.jsdelivr.net/gh/Chunlion/Clash-Icons@main/wise.png" },
    { name: "Games", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png" },
    { name: "UKwifi", type: "select", proxies: ["欧洲手动", "DIRECT"], icon: "https://www.giffgaff.design/iconography/icons/library/coverage-signal.svg" },
    { name: "Netflix", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Netflix.png" },
    { name: "Disney", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Disney.png" },
    { name: "Spotify", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Spotify.png" },
    { name: "PayPal", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/PayPal.png" },
    { name: "OneDrive", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/OneDrive.png" },
    { name: "Microsoft", type: "select", proxies: commonProxies, icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/Microsoft.png" },
    { name: "兜底流量", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Final.png" },

    // 区域自动/手动组
    ...["香港", "台湾", "日本", "韩国", "新加坡", "美国", "欧洲"].map(region => {
      const regMap = { "香港": "HK", "台湾": "TW", "日本": "JP", "韩国": "KR", "新加坡": "SG", "美国": "US", "欧洲": "EU" };
      const filterMap = {
        "香港": '^(?i)(?=.*(香港|🇭🇰|\\bHK\\b|Hong(?:\\s?Kong)?|HKG)).*$',
        "台湾": '^(?i)(?=.*(台湾|台灣|🇹🇼|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|taiwan|TPE|TSA|KHH)).*$',
        "日本": '^(?i)(?=.*(日本|🇯🇵|\\bJP\\b|Japan|NRT|HND|KIX|CTS|FUK)).*$',
        "韩国": '^(?i)(?=.*(韩国|韓國|🇰🇷|首尔|首爾|\\bKR\\b|\\bKOR\\b|Korea|Seoul|South)).*$',
        "新加坡": '^(?i)(?=.*(新加坡|🇸🇬|\\bSG\\b|Singapore|SIN|XSP)).*$',
        "美国": '^(?i)(?=.*(美国|美國|🇺🇸|\\bUS\\b|\\bUSA\\b|SJC|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD)).*$',
        "欧洲": '^(?i)(?=.*(奥地利|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|🇬🇧|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU)).*$'
      };
      return [
        { name: `${region}故转`, type: "fallback", url: "https://cp.cloudflare.com/generate_204", interval: 300, proxies: [`${region}手动`, `${region}自动`], icon: `https://github.com/Seven1echo/Yaml/raw/main/icons/${regMap[region]}.png`, hidden: true },
        { name: `${region}手动`, type: "select", "include-all": true, filter: filterMap[region], icon: `https://github.com/Seven1echo/Yaml/raw/main/icons/${regMap[region]}.png` },
        { name: `${region}自动`, type: "url-test", url: "https://cp.cloudflare.com/generate_204", interval: 300, tolerance: 50, "include-all": true, filter: filterMap[region], icon: `https://github.com/Seven1echo/Yaml/raw/main/icons/${regMap[region]}.png`, hidden: true }
      ];
    }).flat(),

    {
      name: "其他手动",
      type: "select",
      "include-all": true,
      filter: '^(?!.*(DIRECT|直接连接|香港|台湾|台灣|日本|韩国|韓國|新加坡|美国|美國|奥地利|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|🇭🇰|🇹🇼|🇸🇬|🇯🇵|🇰🇷|🇺🇸|🇬🇧|HK|TW|SG|JP|KR|US|GB|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU|HKG|TPE|TSA|KHH|SIN|XSP|NRT|HND|KIX|CTS|FUK|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD|LHR|LGW)).*$',
      icon: "https://github.com/Seven1echo/Yaml/raw/main/icons/OT.png"
    }
  ];

  // --- 5. 规则集 (Rule Providers) ---
  config["rule-providers"] = {
    "ads_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/privacy-protection-tools/anti-ad.github.io/master/docs/mihomo.mrs" },
    "private_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs" },
    "speedtest_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ookla-speedtest.mrs" },
    "ai": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs" },
    "github_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs" },
    "youtube_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs" },
    "google_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs" },
    "telegram_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs" },
    "tiktok_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs" },
    "twitter_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs" },
    "netflix_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs" },
    "disney_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/disney.mrs" },
    "spotify_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs" },
    "paypal_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/paypal.mrs" },
    "wise_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/wise.mrs" },

    // 游戏平台国内下载 (DIRECT)
    "steam_cn_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam@cn.mrs" },
    "microsoft_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft@cn.mrs" },
    "apple_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple@cn.mrs" },

    // 游戏平台主域名 (Games)
    "steam_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs" },
    "epic_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/epicgames.mrs" },
    "ea_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ea.mrs" },
    "ubisoft_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/ubisoft.mrs" },
    "blizzard_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/blizzard.mrs" },
    "sony_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/sony.mrs" },
    "xbox_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/xbox.mrs" },
    "nintendo_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/nintendo.mrs" },

    // 微软/苹果/其他
    "onedrive_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/onedrive.mrs" },
    "microsoft_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs" },
    "appletv_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple-tvplus.mrs" },
    "emby_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://github.com/666OS/rules/raw/release/mihomo/domain/Emby.mrs" },
    "apple_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs" },

    // IP 规则
    "geolocation-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs" },
    "cn_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs" },
    "add_direct_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/Seven1echo/Yaml/refs/heads/main/rules/Seven1_Direct_Domain.mrs" },
    "private_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs" },
    "google_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/google.mrs" },
    "emby_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://github.com/666OS/rules/raw/release/mihomo/ip/Emby.mrs" },
    "telegram_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs" },
    "twitter_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/twitter.mrs" },
    "netflix_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/netflix.mrs" },
    "ukwifi_ip": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://raw.githubusercontent.com/iniwex5/tools/refs/heads/main/rules/UK-wifi-call.list" },
    "cn_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs" }
  };
  // --- 6. 规则匹配 (Rules) ---
  config["rules"] = [
    "RULE-SET,ads_domain,REJECT",
    "RULE-SET,private_domain,DIRECT",
    "RULE-SET,private_ip,DIRECT,no-resolve",
    "RULE-SET,ukwifi_ip,UKwifi",
    "RULE-SET,steam_cn_domain,DIRECT",
    "RULE-SET,microsoft_cn,DIRECT",
    "RULE-SET,apple_cn,DIRECT",
    "RULE-SET,speedtest_domain,Speedtest",
    "RULE-SET,ai,AI Services",
    "RULE-SET,github_domain,GitHub",
    "RULE-SET,youtube_domain,YouTube",
    "RULE-SET,google_domain,Google",
    "RULE-SET,steam_domain,Games",
    "RULE-SET,epic_domain,Games",
    "RULE-SET,ea_domain,Games",
    "RULE-SET,ubisoft_domain,Games",
    "RULE-SET,blizzard_domain,Games",
    "RULE-SET,sony_domain,Games",
    "RULE-SET,xbox_domain,Games",
    "RULE-SET,nintendo_domain,Games",
    "RULE-SET,onedrive_domain,OneDrive",
    "RULE-SET,microsoft_domain,Microsoft",
    "RULE-SET,appletv_domain,AppleTV",
    "RULE-SET,emby_domain,Emby",
    "RULE-SET,emby_ip,Emby,no-resolve",
    "RULE-SET,apple_domain,Apple",
    "RULE-SET,telegram_domain,Telegram",
    "RULE-SET,tiktok_domain,TikTok",
    "RULE-SET,twitter_domain,Twitter",
    "RULE-SET,netflix_domain,Netflix",
    "RULE-SET,disney_domain,Disney",
    "RULE-SET,spotify_domain,Spotify",
    "RULE-SET,paypal_domain,PayPal",
    "RULE-SET,wise_domain,Wise",
    "RULE-SET,add_direct_domain,DIRECT",
    "RULE-SET,google_ip,Google,no-resolve",
    "RULE-SET,telegram_ip,Telegram,no-resolve",
    "RULE-SET,twitter_ip,Twitter,no-resolve",
    "RULE-SET,netflix_ip,Netflix,no-resolve",
    "RULE-SET,geolocation-!cn,一键代理",
    "RULE-SET,cn_domain,DIRECT",
    "RULE-SET,cn_ip,DIRECT,no-resolve",
    "MATCH,兜底流量"
  ];

  return config;

}
