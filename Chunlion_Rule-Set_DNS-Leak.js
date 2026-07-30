/**
 * 名称： Chunlion_Rule-Set_DNS-Leak 覆写脚本
 * 说明： 基于 YAML 配置文件生成的 JS 脚本，用于 Clash Verge 等客户端的 Merge 覆写。
 */

function collectPrivateNameservers(dnsConfig = {}) {
  const publicNameserverHosts = [
    '223.5.5.5', '223.6.6.6', '119.29.29.29', '1.12.12.12', '120.53.53.53',
    '114.114.114.114', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4',
    '9.9.9.9', '127.0.0.1'
  ];
  const publicNameserverKeywords = [
    'alidns', 'doh.pub', 'dot.pub', 'dnspod', 'dns.google', 'cloudflare',
    'quad9', 'opendns', 'nextdns', 'adguard', 'system'
  ];
  const candidates = [
    ...(Array.isArray(dnsConfig['nameserver']) ? dnsConfig['nameserver'] : []),
    ...(Array.isArray(dnsConfig['proxy-server-nameserver']) ? dnsConfig['proxy-server-nameserver'] : [])
  ];

  return [...new Set(candidates
    .filter(nameserver => typeof nameserver === 'string')
    .map(nameserver => nameserver.trim())
    .filter(Boolean))]
    .filter(nameserver => {
      const normalized = nameserver.toLowerCase();
      const host = normalized.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/:#?]/, 1)[0];
      return !publicNameserverHosts.includes(host)
        && !publicNameserverKeywords.some(keyword => normalized.includes(keyword));
    });
}

function collectProxyServerDomains(proxies = []) {
  return new Set((Array.isArray(proxies) ? proxies : [])
    .map(proxy => proxy && proxy.server)
    .filter(server => typeof server === 'string')
    .map(server => server.trim().toLowerCase())
    .filter(Boolean));
}

function hostPatternMatchesDomains(pattern, domains) {
  if (typeof pattern !== 'string') {
    return false;
  }

  return pattern.split(',').some(rawPattern => {
    const candidate = rawPattern.trim().toLowerCase();
    if (!candidate || candidate.startsWith('rule-set:') || candidate.startsWith('geosite:')) {
      return false;
    }

    const suffix = candidate.startsWith('+.') || candidate.startsWith('*.')
      ? candidate.slice(2)
      : candidate.startsWith('.') ? candidate.slice(1) : null;
    return suffix
      ? [...domains].some(domain => domain === suffix || domain.endsWith(`.${suffix}`))
      : domains.has(candidate);
  });
}

function collectProxyDomainMappings(sources, domains) {
  const mappings = {};
  for (const source of sources) {
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      continue;
    }
    for (const [pattern, value] of Object.entries(source)) {
      if (hostPatternMatchesDomains(pattern, domains)) {
        mappings[pattern] = value;
      }
    }
  }
  return mappings;
}

function main(config) {
  const originalDnsConfig = config['dns'] || {};
  const proxyServerDomains = collectProxyServerDomains(config['proxies']);
  const privateNameservers = collectPrivateNameservers(originalDnsConfig);
  const proxyServerPolicy = collectProxyDomainMappings([
    originalDnsConfig['nameserver-policy'],
    originalDnsConfig['proxy-server-nameserver-policy']
  ], proxyServerDomains);
  const proxyServerHosts = collectProxyDomainMappings([config['hosts']], proxyServerDomains);

  // ==================== 基础配置 ====================
  config['mixed-port'] = 7893;
  config['mode'] = 'rule';
  config['find-process-mode'] = 'strict';
  config['allow-lan'] = false;
  config['bind-address'] = '127.0.0.1';
  config['tcp-concurrent'] = true;
  config['unified-delay'] = true;
  config['keep-alive-idle'] = 600;
  config['keep-alive-interval'] = 60;
  config['log-level'] = 'info';
  config['ipv6'] = false;
  config['profile'] = {
    'store-selected': true,
    'store-fake-ip': true
  };
  config['ntp'] = {
    'enable': true,
    'write-to-system': false,
    'server': 'time.apple.com',
    'port': 123,
    'interval': 30,
    'dialer-proxy': 'DIRECT'
  };
  config['geo-auto-update'] = true;
  config['geo-update-interval'] = 24;
  config['geodata-mode'] = true;
  config['geox-url'] = {
    'geosite': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    'geoip': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
    'mmdb': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb',
    'asn': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb'
  };
  config['external-controller'] = '127.0.0.1:9090';
  config['external-ui-name'] = 'zashboard';
  config['external-ui'] = 'ui';
  config['secret'] = '123456';
  config['external-ui-url'] = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-no-fonts.zip';

  // ==================== TUN 配置 ====================
  config['tun'] = {
    'enable': true,
    'stack': 'mixed',
    'dns-hijack': ['any:53', 'tcp://any:53'],
    'auto-detect-interface': true,
    'auto-route': true,
    'auto-redirect': true,
    'strict-route': false,
    'endpoint-independent-nat': true,
    'route-exclude-address-set': ['cn_ip']
  };

  // ==================== 嗅探功能 ====================
  config['sniffer'] = {
    'enable': true,
    'override-destination': false,
    'parse-pure-ip': false,
    'force-dns-mapping': true,
    'sniff': {
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true },
      'TLS': { 'ports': [443, 8443] },
      'QUIC': { 'ports': [443, 8443] }
    },
    'force-domain': [
      '+.netflix.com',
      '+.nflxvideo.net',
      '+.media.dssott.com'
    ],
    'skip-domain': [
      '+.apple.com',
      'Mijia Cloud',
      'dlg.io.mi.com',
      '+.oray.com',
      '+.sunlogin.net'
    ],
    'skip-dst-address': [
      '127.0.0.0/8',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      '169.254.0.0/16',
      '100.64.0.0/10',
      '::1/128',
      'fc00::/7',
      'fe80::/10'
    ]
  };

  config['hosts'] = {
    'services.googleapis.cn': ['services.googleapis.com'],
    ...proxyServerHosts
  };

  // ==================== DNS 设置 ====================
  config['dns'] = {
    'enable': true,
    'use-hosts': true,
    'use-system-hosts': true,
    'cache-algorithm': 'arc',
    'listen': '127.0.0.1:7874',
    'ipv6': false,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter-mode': 'blacklist',
    'respect-rules': true,
    'prefer-h3': false,
    'fake-ip-filter': [
      'rule-set:fakeip_filter',
      '+.lan',
      '+.local',
      'geosite:cn',
      'geosite:private',
      'rule-set:add_direct_domain',
      '+.msftconnecttest.com',
      '+.msftncsi.com',
      'localhost.ptlogin2.qq.com',
      'localhost.sec.qq.com',
      '+.in-addr.arpa',
      '+.ip6.arpa',
      'stun.*',
      '+.stun.*.*',
      '+.turn.*.*',
      '+.ntp.org',
      'time.windows.com',
      'time.apple.com',
      'time-ios.apple.com',
      'time.google.com'
    ],
    // 默认 DNS 用于解析 DoH / DoT 服务器域名，节点 DNS 避免解析代理节点时产生循环。
    'default-nameserver': ['223.5.5.5', '119.29.29.29'],
    'proxy-server-nameserver': [
      'https://dns.alidns.com/dns-query',
      'https://doh.pub/dns-query',
      ...privateNameservers
    ],
    ...(Object.keys(proxyServerPolicy).length > 0 && {
      'proxy-server-nameserver-policy': proxyServerPolicy
    }),
    'direct-nameserver': ['223.5.5.5', '119.29.29.29'],
    'direct-nameserver-follow-policy': true,
    'nameserver-policy': {
      'rule-set:add_direct_domain': ['223.5.5.5', '119.29.29.29'],
      'geosite:cn,private': ['223.5.5.5', '119.29.29.29']
    },
    // 不再配置 fallback / fallback-filter：境外域名由 Fake-IP 交给代理侧远程解析，
    // 配合 respect-rules 已天然防污染；老式 GeoIP fallback 与其重复且实际不再生效。
    'nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
  };

  // --- 4. 策略组 (Proxy Groups) ---
  const commonProxies = [
    "一键代理", "全局均衡", "家宽节点",
    "香港手动", "澳门手动", "台湾手动", "日本手动", "韩国手动", "新加坡手动", "美国手动", "欧洲手动",
    "香港自动", "澳门自动", "台湾自动", "日本自动", "韩国自动", "新加坡自动", "美国自动", "欧洲自动",
    "香港故转", "澳门故转", "台湾故转", "日本故转", "韩国故转", "新加坡故转", "美国故转", "欧洲故转",
    "其他手动"
  ];
  const specialProxies = [...commonProxies, "DIRECT"];

  const homeIcon = "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/05icon/home.png";
  const homeFilter = '^(?i)(?=.*(家宽|🏠|家庭宽带|宽带|住宅|民宅|\\bResidential\\b|\\bHome\\b|\\bISP\\b|Broadband)).*$';
  const excludeInfoFilter = '(?i)(群|返利|邀请|客服|工单|官网|网站|网址|邮箱|订阅|套餐|流量|到期|过期|剩余|重置|通知|更新|作者|频道|获取|下次|版本|官址|已用|联系|贩卖|倒卖|地址|说明|教程|关注|加入|http|expire|traffic|reset|subscription|remaining|used|total|email|panel|channel|author)';
  const aiProxies = ["家宽节点", "美国手动", ...commonProxies.filter(p => p !== "家宽节点" && p !== "美国手动")];

  config["proxy-groups"] = [
    {
      name: "一键代理",
      type: "select",
      proxies: commonProxies.filter(p => p !== "一键代理"),
      icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Rocket.png"
    },
    { name: "Streaming", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/YouTube.png" },
    { name: "GitHub", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/github(1).png" },
    { name: "Google", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Google.png" },
    { name: "AI Services", type: "select", proxies: aiProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/AI.png" },
    { name: "Emby", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Emby.png" },
    { name: "Apple", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Apple.png" },
    { name: "Telegram", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Telegram.png" },
    { name: "Twitter", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Twitter.png" },
    { name: "TikTok", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/TikTok.png" },
    { name: "Microsoft", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/Microsoft.png" },
    { name: "PayPal", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/paypal(2).png" },
    { name: "Crypto", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/Bitcoin.png" },
    { name: "Games", type: "select", proxies: specialProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png" },
    { name: "UKwifi", type: "select", proxies: ["欧洲手动", "DIRECT"], icon: "https://www.giffgaff.design/iconography/icons/library/coverage-signal.svg" },
    { name: "兜底流量", type: "select", proxies: commonProxies, icon: "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Final.png" },

    // 区域自动/手动组
    // 地区词决定归属；IEPL / IPLC / BGP / Game / 倍率等线路标签不参与地区判断。
    // 没有明确地区词的节点进入“其他手动”，避免把线路标签误当成地区特征。
    {
      name: "全局均衡",
      type: "load-balance",
      strategy: "sticky-sessions",
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      lazy: true,
      timeout: 2000,
      "max-failed-times": 3,
      hidden: true,
      "include-all": true,
      "exclude-filter": excludeInfoFilter
    },
    { name: "家宽节点", type: "select", "include-all": true, "exclude-filter": excludeInfoFilter, filter: homeFilter, icon: homeIcon },

    ...["香港", "澳门", "台湾", "日本", "韩国", "新加坡", "美国", "欧洲"].map(region => {
      const iconMap = {
        "香港": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Hongkong(3).png",
        "澳门": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Macao.png",
        "台湾": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/taiwan(4).png",
        "日本": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Japan(2).png",
        "韩国": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Korea(2).png",
        "新加坡": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/singapore.png",
        "美国": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/US(2).png",
        "欧洲": "https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/EuropeanUnion(2).png"
      };
      const filterMap = {
        "香港": '^(?i)(?=.*(香港|🇭🇰|\\bHK\\b|Hong(?:\\s?Kong)?|\\bHKG\\b|\\bHKT\\b|\\bHKBN\\b)).*$',
        "澳门": '^(?i)(?=.*(澳门|澳門|🇲🇴|\\bMO\\b|\\bMFM\\b|Macao|Macau)).*$',
        "台湾": '^(?i)(?=.*(台湾|台灣|🇹🇼|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|Taiwan|Taipei|Kaohsiung)).*$',
        "日本": '^(?i)(?=.*(日本|🇯🇵|\\bJP\\b|Japan|Tokyo|Osaka|Fukuoka|\\bTYO\\b|\\bOSA\\b|\\bNRT\\b|\\bHND\\b|\\bKIX\\b|\\bCTS\\b|\\bFUK\\b)).*$',
        "韩国": '^(?i)(?=.*(韩国|韓國|🇰🇷|首尔|首爾|\\bKR\\b|\\bKOR\\b|Korea|Seoul|\\bSEL\\b|\\bICN\\b)).*$',
        "新加坡": '^(?i)(?=.*(新加坡|🇸🇬|\\bSG\\b|Singapore|\\bSGP\\b|\\bSIN\\b|\\bXSP\\b)).*$',
        "美国": '^(?i)(?=.*(美国|美國|🇺🇸|\\bUS\\b|\\bUSA\\b|\\bNA\\b|United\\s?States|America|\\bSJC\\b|\\bJFK\\b|\\bLAX\\b|\\bORD\\b|\\bATL\\b|\\bDFW\\b|\\bSFO\\b|\\bMIA\\b|\\bSEA\\b|\\bIAD\\b)).*$',
        "欧洲": '^(?i)(?=.*(奥地利|奥地利共和国|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|United\\s?Kingdom|England|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|\\bLON\\b|\\bUK\\b|\\bGB\\b|\\bGBR\\b|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|🇬🇧|\\bCDG\\b|\\bFRA\\b|\\bAMS\\b|\\bMAD\\b|\\bBCN\\b|\\bFCO\\b|\\bMUC\\b|\\bBRU\\b|\\bLHR\\b|\\bLGW\\b)).*$'
      };
      return [
        { name: `${region}故转`, type: "fallback", url: "https://www.gstatic.com/generate_204", interval: 180, lazy: false, timeout: 2000, "max-failed-times": 2, proxies: [`${region}手动`, `${region}自动`], icon: iconMap[region], hidden: true },
        { name: `${region}手动`, type: "select", "include-all": true, "exclude-filter": excludeInfoFilter, filter: filterMap[region], icon: iconMap[region] },
        { name: `${region}自动`, type: "url-test", url: "https://www.gstatic.com/generate_204", interval: 300, lazy: false, tolerance: 30, timeout: 2000, "max-failed-times": 3, "include-all": true, "exclude-filter": excludeInfoFilter, filter: filterMap[region], icon: iconMap[region], hidden: true }
      ];
    }).flat(),

    {
      name: "其他手动",
      type: "select",
      "include-all": true,
      "exclude-filter": excludeInfoFilter,
      filter: '^(?i)(?!.*(DIRECT|直接连接|香港|澳门|澳門|台湾|台灣|日本|韩国|韓國|首尔|首爾|新加坡|美国|美國|奥地利|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|Hong(?:\\s?Kong)?|Taiwan|Taipei|Kaohsiung|Macau|Macao|Japan|Tokyo|Osaka|Fukuoka|Korea|Seoul|Singapore|United\\s?States|America|United\\s?Kingdom|England|London|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|🇭🇰|🇲🇴|🇹🇼|🇸🇬|🇯🇵|🇰🇷|🇺🇸|🇬🇧|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|\\bHK\\b|\\bHKG\\b|\\bHKT\\b|\\bHKBN\\b|\\bMO\\b|\\bMFM\\b|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|\\bJP\\b|\\bTYO\\b|\\bOSA\\b|\\bNRT\\b|\\bHND\\b|\\bKIX\\b|\\bCTS\\b|\\bFUK\\b|\\bKR\\b|\\bKOR\\b|\\bSEL\\b|\\bICN\\b|\\bSG\\b|\\bSGP\\b|\\bSIN\\b|\\bXSP\\b|\\bUS\\b|\\bUSA\\b|\\bNA\\b|\\bUK\\b|\\bGB\\b|\\bGBR\\b|\\bLON\\b|\\bSJC\\b|\\bJFK\\b|\\bLAX\\b|\\bORD\\b|\\bATL\\b|\\bDFW\\b|\\bSFO\\b|\\bMIA\\b|\\bSEA\\b|\\bIAD\\b|\\bCDG\\b|\\bFRA\\b|\\bAMS\\b|\\bMAD\\b|\\bBCN\\b|\\bFCO\\b|\\bMUC\\b|\\bBRU\\b|\\bLHR\\b|\\bLGW\\b)).*$',
      icon: "https://raw.githubusercontent.com/Seven1echo/Yaml/main/icons/OT.png"
    }
  ];

  for (const group of config["proxy-groups"]) {
    if (group["include-all"]) {
      group["exclude-type"] = "direct";
    }
    if (group.type === "fallback" || group.type === "url-test" || group.type === "load-balance") {
      group["empty-fallback"] = "REJECT";
      group["expected-status"] = 204;
    } else if (group.type === "select" && group["include-all"]) {
      group["empty-fallback"] = "REJECT";
    }
  }

  // --- 5. 规则集 (Rule Providers) ---
  config["rule-providers"] = {
    "fakeip_filter": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/fakeip-filter.mrs" },
    "ads_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://anti-ad.net/mihomo.mrs" },
    "private_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/private.mrs" },
    "speedtest_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/ookla-speedtest.mrs" },
    "ai": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-ai-!cn.mrs" },
    "github_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/github.mrs" },
    "youtube_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/youtube.mrs" },
    "google_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/google.mrs" },
    "telegram_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/telegram.mrs" },
    "tiktok_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/tiktok.mrs" },
    "twitter_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/twitter.mrs" },
    "netflix_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/netflix.mrs" },
    "disney_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/disney.mrs" },
    "spotify_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/spotify.mrs" },
    "crypto_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-cryptocurrency.mrs" },
    "paypal_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/paypal.mrs" },
    "finance_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-finance.mrs" },

    "microsoft_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft@cn.mrs" },
    "apple_cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple@cn.mrs" },

    // 微软/苹果/其他
    "onedrive_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/onedrive.mrs" },
    "microsoft_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/microsoft.mrs" },
    "appletv_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple-tvplus.mrs" },
    "emby_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/666OS/rules@release/mihomo/domain/Emby.mrs" },
    "add_emby": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/Chunlion/Clash-Icons@main/Emby.mrs" },
    "apple_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/apple.mrs" },

    // IP 规则
    "geolocation-!cn": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/geolocation-!cn.mrs" },
    "cn_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/cn.mrs" },
    "add_direct_domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/Seven1echo/Yaml@main/rules/Seven1_Direct_Domain.mrs" },
    "private_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/private.mrs" },
    "google_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/google.mrs" },
    "emby_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/666OS/rules@release/mihomo/ip/Emby.mrs" },
    "telegram_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/telegram.mrs" },
    "twitter_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/twitter.mrs" },
    "netflix_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/netflix.mrs" },
    "ukwifi_ip": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://cdn.jsdelivr.net/gh/iniwex5/tools@main/rules/UK-wifi-call.list" },
    "cn_ip": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geoip/cn.mrs" }
  };
  for (const provider of Object.values(config["rule-providers"])) {
    if (provider.type === "http") provider.proxy = "一键代理";
  }
  // --- 6. 规则匹配 (Rules) ---
  config["rules"] = [
    "RULE-SET,ads_domain,REJECT",
    "RULE-SET,private_domain,DIRECT",
    "RULE-SET,private_ip,DIRECT,no-resolve",
    "RULE-SET,ukwifi_ip,UKwifi",
    "RULE-SET,microsoft_cn,DIRECT",
    "RULE-SET,apple_cn,DIRECT",
    "RULE-SET,speedtest_domain,DIRECT",
    "RULE-SET,ai,AI Services",
    "RULE-SET,github_domain,GitHub",
    "RULE-SET,youtube_domain,Streaming",
    "RULE-SET,google_domain,Google",
    "GEOSITE,category-games@cn,DIRECT",
    "GEOSITE,category-games,Games",
    "RULE-SET,onedrive_domain,Microsoft",
    "RULE-SET,microsoft_domain,Microsoft",
    "RULE-SET,appletv_domain,Streaming",
    "RULE-SET,emby_domain,Emby",
    "RULE-SET,apple_domain,Apple",
    "RULE-SET,telegram_domain,Telegram",
    "RULE-SET,tiktok_domain,TikTok",
    "RULE-SET,twitter_domain,Twitter",
    "RULE-SET,netflix_domain,Streaming",
    "RULE-SET,disney_domain,Streaming",
    "RULE-SET,spotify_domain,Streaming",
    "RULE-SET,crypto_domain,Crypto",
    "RULE-SET,paypal_domain,PayPal",
    "RULE-SET,finance_domain,PayPal",
    "RULE-SET,add_emby,Emby",
    "RULE-SET,add_direct_domain,DIRECT",
    "RULE-SET,emby_ip,Emby,no-resolve",
    "RULE-SET,google_ip,Google,no-resolve",
    "RULE-SET,telegram_ip,Telegram,no-resolve",
    "RULE-SET,twitter_ip,Twitter,no-resolve",
    "RULE-SET,netflix_ip,Streaming,no-resolve",
    "RULE-SET,cn_domain,DIRECT",
    "RULE-SET,cn_ip,DIRECT,no-resolve",
    "RULE-SET,geolocation-!cn,一键代理",
    "MATCH,兜底流量"
  ];

  return config;

}
