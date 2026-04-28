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

  // ==================== 地理数据 ====================
  config['geo-auto-update'] = true; // 自动更新 geodata
  config['geo-update-interval'] = 24; // 更新间隔  单位：小时
  config['geodata-mode'] = true; // 数据分流  使用数据集进行规则与分流匹配
  config['geox-url'] = {
    'geosite': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat',
    'geoip': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat',
    'mmdb': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb',
    'asn': 'https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/GeoLite2-ASN.mmdb'
  }

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
    'override-destination': true,
    'parse-pure-ip': true,
    'force-dns-mapping': true,
    'sniff': {
      'QUIC': { 'ports': [443, 8443] },
      'TLS': { 'ports': [443, 8443] },
      'HTTP': { 'ports': [80, '8080-8880'], 'override-destination': true }
    },
    'force-domain': [
      '+.netflix.com',
      '+.nflxvideo.net',
      '+.amazonaws.com',
      '+.media.dssott.com'
    ],
    'skip-domain': [
      '+.apple.com',
      'Mijia Cloud',
      'dlg.io.mi.com',
      '+.oray.com',
      '+.sunlogin.net',
      '+.push.apple.com'
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
      '+.lan',
      'geosite:cn',
      'geosite:private',
      'rule-set:add_direct_domain',
      '+.local',
      '+.msftconnecttest.com',
      '+.msftncsi.com',
      'localhost.ptlogin2.qq.com',
      'localhost.sec.qq.com',
      '+.in-addr.arpa',
      '+.ip6.arpa',
      'stun.*',
      'time.*.com',
      'time.*.gov',
      'pool.ntp.org',
      '+.ntp.org',
      '+.pool.ntp.org',
      '+._tcp.*',
      '+._udp.*',
      '+.stun.*.*',
      '+.stun.*.*.*',
      '+.xbox.com',
      '+.xboxlive.com',
      '+.srv.nintendo.net',
      '+.stun.playstation.net',
      'stun.l.google.com',
      'stun1.l.google.com',
      'stun2.l.google.com',
      'stun3.l.google.com',
      'stun4.l.google.com',
      '+.turn.*',
      '+.turn.*.*',
      '+.turn.*.*.*',
      '+.stun.cloudflare.com',
      '+.webrtc.org',
      '+.zoom.us',
      '+.teams.microsoft.com',
      '+.skype.com',
      '+.meet.google.com',
      '+.push-apple.com.akadns.net'
    ],
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
  const Anchor_OB = ['一键代理', '全局最优', '稳定备用', '香港节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '美国节点', '欧洲节点', '其他节点', 'DIRECT', 'REJECT'];
  const Anchor_AI = ['美国节点', '一键代理', '香港节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '欧洲节点', '其他节点', 'DIRECT', 'REJECT'];
  const Anchor_UK = ['欧洲节点', 'DIRECT'];

  // 区域正则锚点转译
  // 地区词决定归属；IEPL / IPLC / BGP / Game / 倍率等线路标签不参与地区判断。
  // 没有明确地区词的节点进入“其他节点”，避免把线路标签误当成地区特征。
  const regexHK = '^(?i)(?=.*(香港|🇭🇰|\\bHK\\b|Hong(?:\\s?Kong)?|HKG|HKT|HK|HKBN)).*$';
  const regexTW = '^(?i)(?=.*(台湾|台灣|🇹🇼|\\bTW\\b|\\bTPE\\b|\\bTSA\\b|\\bKHH\\b|Taiwan|Taipei|Kaohsiung|taiwan|TPE|TSA|KHH)).*$';
  const regexJP = '^(?i)(?=.*(日本|🇯🇵|\\bJP\\b|Japan|Tokyo|Osaka|TYO|OSA|NRT|HND|KIX|CTS|FUK)).*$';
  const regexKR = '^(?i)(?=.*(韩国|韓國|🇰🇷|首尔|首爾|\\bKR\\b|\\bKOR\\b|Korea|Seoul|SEL|ICN|South)).*$';
  const regexSG = '^(?i)(?=.*(新加坡|🇸🇬|\\bSG\\b|Singapore|SGP|SIN|XSP)).*$';
  const regexUS = '^(?i)(?=.*(美国|美國|🇺🇸|\\bUS\\b|\\bUSA\\b|\\bNA\\b|United\\s?States|America|SJC|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD)).*$';
  const regexEU = '^(?i)(?=.*(奥地利|奥地利共和国|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|United\\s?Kingdom|England|Germany|France|Netherlands|Amsterdam|Frankfurt|Paris|LON|UK|GB|GBR|🇧🇪|🇨🇿|🇩🇰|🇫🇮|🇫🇷|🇩🇪|🇮🇪|🇮🇹|🇱🇹|🇱🇺|🇳🇱|🇵🇱|🇸🇪|🇬🇧|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU|LHR|LGW)).*$';
  const regexOT = '^(?!.*(DIRECT|直接连接|香港|台湾|台灣|日本|韩国|韓國|新加坡|美国|美國|奥地利|比利时|保加利亚|克罗地亚|塞浦路斯|捷克|丹麦|爱沙尼亚|芬兰|法国|德国|希腊|匈牙利|爱尔兰|意大利|拉脱维亚|立陶宛|卢森堡|荷兰|波兰|葡萄牙|罗马尼亚|斯洛伐克|斯洛文尼亚|西班牙|瑞典|英国|London|Germany|France|Netherlands|Tokyo|Osaka|Seoul|Singapore|Taipei|Kaohsiung|🇭🇰|🇹🇼|🇸🇬|🇯🇵|🇰🇷|🇺🇸|🇬🇧|HK|HKBN|TW|SG|SGP|JP|TYO|OSA|KR|SEL|ICN|US|USA|NA|GB|GBR|LON|CDG|FRA|AMS|MAD|BCN|FCO|MUC|BRU|HKG|HKT|TPE|TSA|KHH|SIN|XSP|NRT|HND|KIX|CTS|FUK|JFK|LAX|ORD|ATL|DFW|SFO|MIA|SEA|IAD|LHR|LGW)).*$';

  config['proxy-groups'] = [
    { name: '一键代理', type: 'select', proxies: ['全局最优', '稳定备用', '香港节点', '台湾节点', '日本节点', '韩国节点', '新加坡节点', '美国节点', '欧洲节点', '其他节点', 'DIRECT', 'REJECT'], icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Rocket.png' },
    { name: 'Streaming', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/YouTube.png' },
    { name: 'Emby', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Koolson/Qure/raw/master/IconSet/Color/Emby.png' },
    { name: 'Google', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/Google.png' },
    { name: 'AI Services', type: 'select', proxies: Anchor_AI, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/AI.png' },
    { name: 'TikTok', type: 'select', proxies: Anchor_OB, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/TikTok.png' },
    { name: 'Wise', type: 'select', proxies: Anchor_OB, icon: 'https://fastly.jsdelivr.net/gh/Chunlion/Clash-Icons@main/wise.png' },
    { name: 'Games', type: 'select', proxies: Anchor_OB, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Game.png' },
    { name: 'UKwifi', type: 'select', proxies: Anchor_UK, icon: 'https://www.giffgaff.design/iconography/icons/library/coverage-signal.svg' },
    { name: '兜底流量', type: 'select', proxies: Anchor_OB, icon: 'https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Final.png' },
    // 区域与特殊策略组
    { name: '全局最优', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 300, tolerance: 50, timeout: 2000, hidden: true, 'include-all': true },
    { name: '稳定备用', type: 'fallback', url: 'https://cp.cloudflare.com/generate_204', interval: 300, timeout: 2000, hidden: true, proxies: ['香港节点', '新加坡节点', '日本节点', '韩国节点', '美国节点', '欧洲节点'] },
    { name: '香港节点', type: 'select', 'include-all': true, filter: regexHK, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/HK.png' },
    { name: '台湾节点', type: 'select', 'include-all': true, filter: regexTW, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/TW.png' },
    { name: '日本节点', type: 'select', 'include-all': true, filter: regexJP, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/JP.png' },
    { name: '韩国节点', type: 'select', 'include-all': true, filter: regexKR, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/KR.png' },
    { name: '新加坡节点', type: 'select', 'include-all': true, filter: regexSG, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/SG.png' },
    { name: '美国节点', type: 'select', 'include-all': true, filter: regexUS, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/US.png' },
    { name: '欧洲节点', type: 'select', 'include-all': true, filter: regexEU, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/EU.png' },
    { name: '其他节点', type: 'select', 'include-all': true, filter: regexOT, icon: 'https://github.com/Seven1echo/Yaml/raw/main/icons/OT.png' }
  ];

  // ==================== 规则匹配 ====================
  config['rules'] = [
    // 特殊自定义规则
    "RULE-SET,ukwifi_ip,UKwifi",
    "RULE-SET,emby_domain,Emby",
    "RULE-SET,emby_ip,Emby,no-resolve",
    "RULE-SET,add_emby,Emby",
    "RULE-SET,add_direct_domain,DIRECT",
    // 服务分流
    "GEOSITE,private,DIRECT",
    "GEOIP,private,DIRECT,no-resolve",
    "GEOSITE,steam@cn,DIRECT",
    "GEOSITE,microsoft@cn,DIRECT",
    "GEOSITE,apple@cn,DIRECT",
    "GEOSITE,category-ai-!cn,AI Services",
    "GEOSITE,youtube,Streaming",
    "GEOSITE,google,Google",
    "GEOSITE,wise,Wise",
    "GEOSITE,steam,Games",
    "GEOSITE,epicgames,Games",
    "GEOSITE,ea,Games",
    "GEOSITE,tiktok,TikTok",
    "GEOSITE,apple-tvplus,Streaming",
    "GEOSITE,netflix,Streaming",
    "GEOSITE,disney,Streaming",
    "GEOSITE,spotify,Streaming",
    "GEOIP,google,Google,no-resolve",
    "GEOIP,netflix,Streaming,no-resolve",
    // 区域划分兜底
    "GEOSITE,cn,DIRECT",
    "GEOIP,cn,DIRECT,no-resolve",
    "GEOSITE,geolocation-!cn,一键代理",
    "MATCH,兜底流量"
  ];

  // ==================== 规则来源 ====================
  config['rule-providers'] = {
    emby_domain: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://github.com/666OS/rules/raw/release/mihomo/domain/Emby.mrs" },
    emby_ip: { type: 'http', interval: 86400, behavior: 'ipcidr', format: 'mrs', url: "https://github.com/666OS/rules/raw/release/mihomo/ip/Emby.mrs" },
    ukwifi_ip: { type: 'http', interval: 86400, behavior: 'classical', format: 'text', url: "https://raw.githubusercontent.com/iniwex5/tools/refs/heads/main/rules/UK-wifi-call.list" },
    add_direct_domain: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://raw.githubusercontent.com/Seven1echo/Yaml/refs/heads/main/rules/Seven1_Direct_Domain.mrs" },
    add_emby: { type: 'http', interval: 86400, behavior: 'domain', format: 'mrs', url: "https://raw.githubusercontent.com/Chunlion/Clash-Icons/main/Emby.mrs" }
  };
  return config;
}
