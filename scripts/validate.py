from __future__ import annotations

import argparse
import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
PAIRS = (
    "Chunlion_Rule-Set_DNS-Leak",
    "Chunlion_Rule-Set_DNS-Leak_Lite",
)
BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
INFO_FILTER_TOKENS = (
    "获取",
    "下次",
    "版本",
    "官址",
    "已用",
    "联系",
    "贩卖",
    "倒卖",
    "地址",
    "说明",
    "教程",
    "关注",
    "加入",
    "used",
    "total",
    "email",
    "panel",
    "channel",
    "author",
)
CRITICAL_KEYS = (
    "mixed-port",
    "mode",
    "find-process-mode",
    "allow-lan",
    "bind-address",
    "tcp-concurrent",
    "unified-delay",
    "keep-alive-idle",
    "keep-alive-interval",
    "log-level",
    "ipv6",
    "profile",
    "ntp",
    "geo-auto-update",
    "geo-update-interval",
    "geodata-mode",
    "geox-url",
    "external-controller",
    "external-ui-name",
    "external-ui",
    "secret",
    "external-ui-url",
    "tun",
    "sniffer",
    "hosts",
    "dns",
    "rule-providers",
)
NODE_RENDER = r"""
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const input = fs.readFileSync(0, 'utf8').trim();
const context = {};
vm.createContext(context);
vm.runInContext(source, context);
const initialConfig = input ? JSON.parse(input) : { proxies: [], 'proxy-providers': {} };
const config = context.main(initialConfig);
process.stdout.write(JSON.stringify(config));
"""


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as file:
        config = yaml.safe_load(file)
    if not isinstance(config, dict):
        raise AssertionError(f"{path.name}: top-level config must be a mapping")
    return config


def load_js(path: Path, initial_config: dict[str, Any] | None = None) -> dict[str, Any]:
    subprocess.run(["node", "--check", str(path)], check=True, capture_output=True, text=True)
    result = subprocess.run(
        ["node", "-e", NODE_RENDER, str(path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        input=json.dumps(initial_config or {"proxies": [], "proxy-providers": {}}),
    )
    config = json.loads(result.stdout)
    if not isinstance(config, dict):
        raise AssertionError(f"{path.name}: main() must return a config object")
    return config


def validate_references(name: str, config: dict[str, Any]) -> None:
    groups = config.get("proxy-groups", [])
    rules = config.get("rules", [])
    providers = config.get("rule-providers", {})
    group_names = [group["name"] for group in groups]

    if len(group_names) != len(set(group_names)):
        raise AssertionError(f"{name}: duplicate proxy-group names")

    known_targets = set(group_names) | BUILTIN_TARGETS
    for rule in rules:
        parts = rule.split(",")
        if len(parts) >= 3 and parts[2] not in known_targets:
            raise AssertionError(f"{name}: unknown rule target {parts[2]!r}")
        if parts[0] == "RULE-SET" and parts[1] not in providers:
            raise AssertionError(f"{name}: unknown rule provider {parts[1]!r}")

    for group in groups:
        for target in group.get("proxies", []):
            if target not in known_targets:
                raise AssertionError(f"{name}: group {group['name']!r} references {target!r}")

    dns = config.get("dns", {})
    for item in dns.get("fake-ip-filter", []):
        if item.startswith("rule-set:"):
            provider_name = item.removeprefix("rule-set:")
            provider = providers.get(provider_name)
            if not provider or provider.get("behavior") not in {"domain", "classical"}:
                raise AssertionError(f"{name}: invalid fake-ip rule provider {provider_name!r}")

    for policy_key in dns.get("nameserver-policy", {}):
        if policy_key.startswith("rule-set:"):
            provider_name = policy_key.removeprefix("rule-set:")
            provider = providers.get(provider_name)
            if not provider or provider.get("behavior") not in {"domain", "classical"}:
                raise AssertionError(f"{name}: invalid nameserver-policy rule provider {provider_name!r}")

    # 防污染由 Fake-IP + respect-rules 承担，禁止再引入与其重复的老式 fallback。
    if "fallback" in dns or "fallback-filter" in dns:
        raise AssertionError(f"{name}: dns fallback/fallback-filter is superseded by respect-rules")
    if dns.get("respect-rules") is not True:
        raise AssertionError(f"{name}: dns respect-rules must be enabled")

    for provider_name in config.get("tun", {}).get("route-exclude-address-set", []):
        provider = providers.get(provider_name)
        if not provider or provider.get("behavior") != "ipcidr":
            raise AssertionError(f"{name}: invalid TUN route-exclude provider {provider_name!r}")

    for provider_name, provider in providers.items():
        if provider.get("type") == "http" and provider.get("proxy") != "一键代理":
            raise AssertionError(f"{name}: remote rule provider {provider_name!r} must use 一键代理")


def normalized_groups(config: dict[str, Any]) -> list[dict[str, Any]]:
    groups = []
    for source in config["proxy-groups"]:
        group = dict(source)
        group.pop("exclude-filter", None)
        groups.append(group)
    return groups


def validate_pair(stem: str) -> None:
    yaml_config = load_yaml(ROOT / f"{stem}.yaml")
    js_config = load_js(ROOT / f"{stem}.js")

    validate_references(f"{stem}.yaml", yaml_config)
    validate_references(f"{stem}.js", js_config)

    for key in CRITICAL_KEYS:
        if yaml_config.get(key) != js_config.get(key):
            raise AssertionError(f"{stem}: YAML/JS mismatch at {key}")
    if "global-client-fingerprint" in yaml_config or "global-client-fingerprint" in js_config:
        raise AssertionError(f"{stem}: global-client-fingerprint was removed by Mihomo")
    if yaml_config.get("keep-alive-idle") != 600 or yaml_config.get("keep-alive-interval") != 60:
        raise AssertionError(f"{stem}: TCP keep-alive settings mismatch")

    dns = yaml_config["dns"]
    if dns.get("use-hosts") is not True or dns.get("use-system-hosts") is not True:
        raise AssertionError(f"{stem}: configured and system hosts must be enabled")

    expected_skip_dst = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    sniffer = yaml_config["sniffer"]
    if sniffer.get("override-destination") is not False or sniffer.get("parse-pure-ip") is not False:
        raise AssertionError(f"{stem}: global sniffer overrides must remain conservative")
    if sniffer.get("skip-dst-address") != expected_skip_dst:
        raise AssertionError(f"{stem}: sniffer private destination exclusions mismatch")

    provider_filter = yaml_config.get("Anchor_PR", {}).get("filter", "")
    js_info_filters = [
        group.get("exclude-filter", "")
        for group in js_config["proxy-groups"]
        if group.get("include-all")
    ]
    if not js_info_filters:
        raise AssertionError(f"{stem}: JS config must filter subscription information nodes")
    for token in INFO_FILTER_TOKENS:
        if token not in provider_filter:
            raise AssertionError(f"{stem}: YAML subscription filter missing {token!r}")
        if any(token not in item for item in js_info_filters):
            raise AssertionError(f"{stem}: JS subscription filter missing {token!r}")

    if normalized_groups(yaml_config) != normalized_groups(js_config):
        raise AssertionError(f"{stem}: YAML/JS proxy-group mismatch")
    if yaml_config["rules"] != js_config["rules"]:
        raise AssertionError(f"{stem}: YAML/JS rule order mismatch")

    expected_ntp = {
        "enable": True,
        "write-to-system": False,
        "server": "time.apple.com",
        "port": 123,
        "interval": 30,
        "dialer-proxy": "DIRECT",
    }
    if yaml_config.get("ntp") != expected_ntp:
        raise AssertionError(f"{stem}: NTP settings mismatch")

    for group in yaml_config["proxy-groups"]:
        if group.get("include-all"):
            excluded_types = {item.lower() for item in group.get("exclude-type", "").split("|")}
            if "direct" not in excluded_types:
                raise AssertionError(f"{stem}: include-all groups must exclude direct outbound proxies")

        if group["type"] == "fallback":
            if group.get("empty-fallback") != "REJECT" or group.get("expected-status") != 204:
                raise AssertionError(f"{stem}: fallback groups must reject empty members and require HTTP 204")
            if group.get("interval") != 180 or group.get("max-failed-times") != 2:
                raise AssertionError(f"{stem}: fallback health-check settings mismatch")
        elif group["type"] == "url-test":
            if group.get("empty-fallback") != "REJECT" or group.get("expected-status") != 204:
                raise AssertionError(f"{stem}: url-test groups must reject empty members and require HTTP 204")
            if group.get("tolerance") != 30:
                raise AssertionError(f"{stem}: url-test tolerance must be 30 ms")
        elif group["type"] == "load-balance":
            if group.get("empty-fallback") != "REJECT" or group.get("expected-status") != 204:
                raise AssertionError(f"{stem}: load-balance groups must reject empty members and require HTTP 204")
            if group.get("strategy") != "sticky-sessions" or group.get("lazy") is not True:
                raise AssertionError(f"{stem}: load-balance groups must use lazy sticky sessions")
        elif group["type"] == "select" and group.get("include-all") and group.get("empty-fallback") != "REJECT":
            raise AssertionError(f"{stem}: dynamic select groups must reject empty members")

    group_names = {group["name"] for group in yaml_config["proxy-groups"]}
    if {"低倍率节点", "高倍率节点"} & group_names:
        raise AssertionError(f"{stem}: removed rate-aware proxy groups must not be restored")
    if stem.endswith("_Lite"):
        if "全局均衡" in group_names:
            raise AssertionError(f"{stem}: Lite config must not add load-balance background checks")
    elif "全局均衡" not in group_names:
        raise AssertionError(f"{stem}: full config must provide global load balancing")

    private_dns_config = load_js(
        ROOT / f"{stem}.js",
        {
            "proxies": [
                {"name": "node-a", "type": "ss", "server": "edge.node.example"},
                {"name": "node-b", "type": "trojan", "server": "api.other.net"},
            ],
            "proxy-providers": {},
            "hosts": {
                "edge.node.example": "10.0.0.8",
                "+.node.example": "10.0.0.9",
                "unrelated.example": "203.0.113.10",
            },
            "dns": {
                "nameserver": [
                    "https://10.0.0.53/dns-query",
                    "https://11.1.1.1/dns-query",
                    "https://dns.google/dns-query",
                ],
                "proxy-server-nameserver": ["tls://192.168.1.1", "223.5.5.5"],
                "nameserver-policy": {
                    "+.node.example": ["10.0.0.53"],
                    "unrelated.example": ["203.0.113.53"],
                },
                "proxy-server-nameserver-policy": {
                    "api.other.net": ["192.168.1.53"],
                },
            },
        },
    )
    proxy_nameservers = private_dns_config["dns"]["proxy-server-nameserver"]
    for private_nameserver in (
        "https://10.0.0.53/dns-query",
        "https://11.1.1.1/dns-query",
        "tls://192.168.1.1",
    ):
        if private_nameserver not in proxy_nameservers:
            raise AssertionError(f"{stem}: JS override did not preserve private DNS {private_nameserver!r}")
    if "https://dns.google/dns-query" in proxy_nameservers:
        raise AssertionError(f"{stem}: JS override retained a redundant public DNS server")

    proxy_hosts = private_dns_config["hosts"]
    for proxy_host in ("edge.node.example", "+.node.example"):
        if proxy_host not in proxy_hosts:
            raise AssertionError(f"{stem}: JS override did not preserve proxy hosts entry {proxy_host!r}")
    if "unrelated.example" in proxy_hosts:
        raise AssertionError(f"{stem}: JS override retained an unrelated hosts entry")
    if proxy_hosts.get("services.googleapis.cn") != ["services.googleapis.com"]:
        raise AssertionError(f"{stem}: mandatory Google Play hosts entry mismatch")

    proxy_policy = private_dns_config["dns"].get("proxy-server-nameserver-policy", {})
    for policy_key in ("+.node.example", "api.other.net"):
        if policy_key not in proxy_policy:
            raise AssertionError(f"{stem}: JS override did not preserve proxy DNS policy {policy_key!r}")
    if "unrelated.example" in proxy_policy:
        raise AssertionError(f"{stem}: JS override retained an unrelated DNS policy")

    cn_index = yaml_config["rules"].index("GEOSITE,category-games@cn,DIRECT")
    games_index = yaml_config["rules"].index("GEOSITE,category-games,Games")
    if cn_index >= games_index:
        raise AssertionError(f"{stem}: category-games@cn must precede category-games")

    print(
        f"PASS {stem}: "
        f"{len(yaml_config['proxy-groups'])} groups, "
        f"{len(yaml_config['rules'])} rules, "
        f"{len(yaml_config['rule-providers'])} providers"
    )


def collect_remote_urls() -> list[str]:
    urls: set[str] = set()
    for stem in PAIRS:
        config = load_yaml(ROOT / f"{stem}.yaml")
        for provider in config.get("rule-providers", {}).values():
            if provider.get("type") == "http":
                urls.add(provider["url"])
        urls.update(config.get("geox-url", {}).values())
    return sorted(urls)


def probe_url(url: str) -> str | None:
    """探测 URL 可达性；可达返回 None，否则返回失败原因。"""
    last_error = "unknown error"
    for method in ("HEAD", "GET"):
        for _attempt in range(2):
            request = urllib.request.Request(url, method=method, headers={"User-Agent": "Clash-Rule-Set-CI"})
            try:
                with urllib.request.urlopen(request, timeout=30):
                    return None
            except urllib.error.HTTPError as error:
                last_error = f"{method} -> HTTP {error.code}"
                break  # HTTP 状态明确，重试无益；部分源不支持 HEAD，换 GET 再试
            except OSError as error:
                last_error = f"{method} -> {error}"
    return last_error


def check_remote_urls() -> None:
    failures = []
    for url in collect_remote_urls():
        error = probe_url(url)
        if error is None:
            print(f"PASS url {url}")
        else:
            print(f"FAIL url {url}: {error}")
            failures.append(url)
    if failures:
        raise AssertionError(f"{len(failures)} unreachable rule source(s): {failures}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Clash rule-set configs")
    parser.add_argument("--check-urls", action="store_true", help="probe every remote rule/geodata URL")
    args = parser.parse_args()
    for stem in PAIRS:
        validate_pair(stem)
    if args.check_urls:
        check_remote_urls()


if __name__ == "__main__":
    main()
