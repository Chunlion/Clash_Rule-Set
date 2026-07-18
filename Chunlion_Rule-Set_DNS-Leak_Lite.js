/**
 * 名称： Chunlion_Rule-Set_DNS-Leak_Lite 覆写脚本
 * 说明： 基于 Lite 版 YAML 配置文件生成的 JS 脚本，用于 Clash Verge 等客户端的 Merge 覆写。
 */

function main(config) {
  // ==================== 基础配置 ====================
  config['mixed-port'] = 7893;
  config['mode'] = 'rule';
  config['find-process-mode'] = 'strict';
  config['allow-lan'] = false;
  config['bind-address'] = '127.0.0.1';
  config['tcp-concurrent'] = true;
  config['unified-delay'] = true;
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

  // ==================== 地理数据 ====================
  config['geo-auto-update'] = true; // 自动更新 geodata
  config['geo-update-interval'] = 24; // 更新间隔  单位：小时
  config['geodata-mode'] = true; // 数据分流  使用数据集进行规则与分流匹配
  config['geox-url'] = {
    'geosite': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    'geoip': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
    'mmdb': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb',
    'asn': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb'
  };
  config['external-controller'] = '127.0.0.1:9090';
  config['external-ui-name'] = 'zashboard';
  config['external-ui'] = 'ui';
  config['secret'] = '';
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
    'endpoint-independent-nat': true
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
    ]
  };

  // ==================== DNS 设置 ====================
  config['dns'] = {
    'enable': true,
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
    'proxy-server-nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
    'direct-nameserver': ['223.5.5.5', '119.29.29.29'],
    'direct-nameserver-follow-policy': true,
    'nameserver-policy': {
      'rule-set:add_direct_domain': ['223.5.5.5', '119.29.29.29'],
      'geosite:cn,private': ['223.5.5.5', '119.29.29.29']
    },
    'nameserver': ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
    'fallback': ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
    'fallback-filter': {
      'geoip': true,
      'geoip-code': 'CN'
    }
  };

  // ==================== 策略组 ====================
  const Anchor_OB = ['一键代理', '全局最优', '稳定备用', '香港节点', '澳门节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '美国节点', '欧洲节点', '家宽节点', '其他节点'];
  const Anchor_SP = ['一键代理', '全局最优', '稳定备用', '香港节点', '澳门节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '美国节点', '欧洲节点', '家宽节点', '其他节点', 'DIRECT'];
  const Anchor_AI = ['家宽节点', '美国节点', '一键代理', '香港节点', '澳门节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '欧洲节点', '其他节点'];
  const excludeInfoFilter = '(?i)(到期|过期|剩余|网址|官网|邮箱|订阅|套餐|流量|时间|说明|重置|Expire|Traffic|Reset|Subscription|Remaining)';


  // 区域正则锚点转译
  // 地区词决定归属；IEPL / IPLC / BGP / Game / 倍率等线路标签不参与地区判断。
  // 没有明确地区词的节点进入“其他节点”，避免把线路标签误当成地区特征。
  const regexHK = '^(?i)(?=.*(香港|🇭🇰|\\bHK\\b|Hong(?:\\s?Kong)?|HKG|HKT|HK|HKBN)).*$';
  const regexMO = '^(?i)(?=.*(澳门|澳門|🇲🇴|\\bMO\\b|\\bMFM\\b|Macao|Macau)).*$';
  const regexTW = '^(?i)(?=.*(台湾|台灣|🇹🇼|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|Taiwan|Taipei|Kaohsiung|taiwan|TPE|TSA|KHH)).*$';
  const regexJP = '^(?i)(?=.*(日本|🇯🇵|\\bJP\\b|Japan|Tokyo|Osaka|TYO|OSA|NRT|HND|KIX|CTS|FUK)).*$';
  const regexKR = '^(?i)(?=.*(韩国|韓國|🇰🇷|首尔|首爾|\\bKR\\b|\\bKOR\\b|Korea|Seoul|SEL|ICN|South)).*$';
  const regexSG = '^(?i)(?=.*(新加坡|🇸🇬|\\bSG\\b|Singapore|SGP|SIN|XSP)).*$';
  const regexUS = '^(?i)(?=.*(美国|美國|🇺🇸|\\bUS\\b|\\bUSA\\b|\\bNA\\b|United\\s?States|America|SJC|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD)).*$';
  const regexHOME = '^(?i)(?=.*(家宽|🏠|家庭宽带|宽带|住宅|民宅|\\bResidential\\b|\\bHome\\b|\\bISP\\b|Broadband)).*$';
  const regexEU = '^(?i)(?=.*(奥地利|奥地利共和国|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|United\\s?Kingdom|England|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|LON|UK|GB|GBR|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|🇬🇧|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU|LHR|LGW)).*$';
  const regexOT = '^(?!.*(DIRECT|直接连接|香港|澳门|澳門|台湾|台灣|日本|韩国|韓國|新加坡|美国|美國|奥地利|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|Germany|France|Netherlands|Tokyo|Osaka|Seoul|Singapore|Taipei|Kaohsiung|Macau|Macao|🇭🇰|🇲🇴|🇹🇼|🇸🇬|🇯🇵|🇰🇷|🇺🇸|🇬🇧|HK|HKBN|MO|MFM|TW|SG|SGP|JP|TYO|OSA|KR|SEL|ICN|US|USA|NA|GB|GBR|LON|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU|HKG|HKT|TPE|TSA|KHH|SIN|XSP|NRT|HND|KIX|CTS|FUK|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD|LHR|LGW)).*$';

  config['proxy-groups'] = [
    { name: '一键代理', type: 'select', proxies: ['全局最优', '稳定备用', '香港节点', '澳门节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '美国节点', '欧洲节点', '家宽节点', '其他节点'], icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Rocket.png' },
    { name: 'Streaming', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/YouTube.png' },
    { name: 'Telegram', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Telegram.png' },
    { name: 'Emby', type: 'select', proxies: Anchor_SP, icon: 'https://github.com/Koolson/Qure/raw/master/IconSet/Color/Emby.png' },
    { name: 'Google', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Google.png' },
    { name: 'AI Services', type: 'select', proxies: Anchor_AI, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/AI.png' },
    { name: 'TikTok', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/TikTok.png' },
    // Optional software groups: uncomment these groups and their matching rules to enable them.
    // { name: 'GitHub', type: 'select', proxies: Anchor_OB, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/github(1).png' },
    // { name: 'Apple', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Apple.png' },
    // { name: 'Twitter', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Twitter.png' },
    // { name: 'Microsoft', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Microsoft.png' },
    { name: 'PayPal', type: 'select', proxies: Anchor_SP, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/paypal(2).png' },
    { name: 'Crypto', type: 'select', proxies: Anchor_SP, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/04ProxySoft/Bitcoin.png' },
    { name: 'Games', type: 'select', proxies: Anchor_SP, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png' },
    { name: '兜底流量', type: 'select', proxies: Anchor_OB, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Final.png' },
    // 区域与特殊策略组
    { name: '全局最优', type: 'url-test', url: 'https://www.gstatic.com/generate_204', interval: 300, tolerance: 30, timeout: 2000, hidden: true, 'include-all': true, 'exclude-filter': excludeInfoFilter },
    { name: '稳定备用', type: 'fallback', url: 'https://www.gstatic.com/generate_204', interval: 180, timeout: 2000, 'max-failed-times': 2, hidden: true, proxies: ['香港节点', '澳门节点', '新加坡节点', '日本节点', '韩国节点', '美国节点', '欧洲节点', '家宽节点', '其他节点'] },
    { name: '家宽节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexHOME, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/05icon/home.png' },
    { name: '香港节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexHK, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Hongkong(3).png' },
    { name: '澳门节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexMO, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Macao.png' },
    { name: '台湾节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexTW, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/taiwan(4).png' },
    { name: '日本节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexJP, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Japan(2).png' },
    { name: '韩国节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexKR, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/Korea(2).png' },
    { name: '新加坡节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexSG, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/singapore.png' },
    { name: '美国节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexUS, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/US(2).png' },
    { name: '欧洲节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexEU, icon: 'https://raw.githubusercontent.com/lige47/QuanX-icon-rule/main/icon/01Country/EuropeanUnion(2).png' },
    { name: '其他节点', type: 'select', 'include-all': true, 'exclude-filter': excludeInfoFilter, filter: regexOT, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/OT.png' }
  ];

  // ==================== 规则匹配 ====================
  config['rules'] = [
    // 特殊自定义规则
    "RULE-SET,emby_domain,Emby",
    "RULE-SET,emby_ip,Emby,no-resolve",
    "RULE-SET,add_emby,Emby",
    "RULE-SET,add_direct_domain,DIRECT",
    // 服务分流
    "GEOSITE,private,DIRECT",
    "GEOIP,private,DIRECT,no-resolve",
    "GEOSITE,microsoft@cn,DIRECT",
    "GEOSITE,apple@cn,DIRECT",
    "GEOSITE,category-ai-!cn,AI Services",
    "GEOSITE,youtube,Streaming",
    "GEOIP,netflix,Streaming,no-resolve",
    "GEOSITE,apple-tvplus,Streaming",
    "GEOSITE,netflix,Streaming",
    "GEOSITE,disney,Streaming",
    "GEOSITE,spotify,Streaming",
    "GEOSITE,tiktok,TikTok",
    "GEOSITE,telegram,Telegram",
    "GEOIP,telegram,Telegram,no-resolve",
    "GEOSITE,google,Google",
    "GEOIP,google,Google,no-resolve",
    // Optional software rules: uncomment with their matching proxy groups above.
    // "GEOSITE,github,GitHub",
    // "GEOSITE,apple,Apple",
    // "GEOSITE,twitter,Twitter",
    // "GEOIP,twitter,Twitter,no-resolve",
    // "GEOSITE,microsoft,Microsoft",
    "GEOSITE,category-cryptocurrency,Crypto",
    "GEOSITE,paypal,PayPal",
    "GEOSITE,category-finance,PayPal",
    "GEOSITE,category-games@cn,DIRECT",
    "GEOSITE,category-games,Games",
    // 区域划分兜底
    "GEOSITE,cn,DIRECT",
    "GEOIP,cn,DIRECT,no-resolve",
    "GEOSITE,geolocation-!cn,一键代理",
    "MATCH,兜底流量"
  ];

  // ==================== 规则来源 ====================
  config['rule-providers'] = {
    fakeip_filter: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/fakeip-filter.mrs" },
    emby_domain: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://raw.githubusercontent.com/666OS/rules/release/mihomo/domain/Emby.mrs" },
    emby_ip: { type: 'http', interval: 86400, behavior: 'ipcidr', format: 'mrs', url: "https://raw.githubusercontent.com/666OS/rules/release/mihomo/ip/Emby.mrs" },
    add_direct_domain: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://raw.githubusercontent.com/Seven1echo/Yaml/refs/heads/main/rules/Seven1_Direct_Domain.mrs" },
    add_emby: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://raw.githubusercontent.com/Chunlion/Clash-Icons/main/Emby.mrs" }
  };
  return config;
}
