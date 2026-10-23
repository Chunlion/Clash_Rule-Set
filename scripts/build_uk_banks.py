from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
LABEL_PATTERN = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
DOMAIN_PATTERN = rf"(?:{LABEL_PATTERN}\.)+{LABEL_PATTERN}"
# fake-ip-filter 的通配后缀：任一标签可为 *（Mihomo 后缀匹配将 * 当作通配标签，
# 如 stun.*.* 匹配 stun.example.com 与 eu.stun.twilio.com）。
WILDCARD_SUFFIX_PATTERN = rf"(?:{LABEL_PATTERN}|\*)(?:\.(?:{LABEL_PATTERN}|\*))*"
# Egern 侧可读的键 → 该键的规则形态。
KEYWORD_KEY = "domain_keyword_set"
PREFIXED_KEYS = {
    "domain_set": "domain",
}
ALLOWED_KEYS = (*PREFIXED_KEYS, "domain_suffix_set", KEYWORD_KEY, "domain_regex_set", "ip_cidr_set")


def load_source(path: Path) -> dict[str, list[str]]:
    source = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(source, dict) or not source or set(source) - set(ALLOWED_KEYS):
        raise ValueError(f"{path.name} contains unsupported rule types")
    for key, values in source.items():
        if not isinstance(values, list) or not values or any(not isinstance(value, str) for value in values):
            raise ValueError(f"{path.name}: {key} must contain a nonempty string list")
        if len(values) != len(set(values)):
            raise ValueError(f"{path.name}: {key} contains duplicate rules")
    if source.get("ip_cidr_set") and set(source) - {"ip_cidr_set"}:
        raise ValueError(f"{path.name}: ip_cidr_set cannot be mixed with domain rules")
    return source


def payload_lines(source: dict[str, list[str]], path: Path) -> set[str]:
    """生成 Mihomo domain behavior 文本规则集内容，供 MRS 编译与产物比对。

    domain behavior 的文本格式是**裸域名模式列表**（+.x / *.x / 精确域名），不是
    classical 规则语法。classical 行（domain-suffix,x）会被 rulesParse 原样当作
    域名字符串 Insert 进字典树（见 rules/provider/provider.go 与 domain_strategy.go），
    永不命中任何真实域名——2026-09-10 的五个规则集就是这样坏的。后缀必须写成 +.x：
    DomainTrie.Insert 见到前导 + 会同时写入裸键与点通配键，二者都参与匹配。
    """
    lines = set()
    for domain in source.get("domain_set", []):
        if not re.fullmatch(DOMAIN_PATTERN, domain):
            raise ValueError(f"{path.name} contains an invalid domain: {domain!r}")
        lines.add(domain)
    for suffix in source.get("domain_suffix_set", []):
        if not re.fullmatch(WILDCARD_SUFFIX_PATTERN, suffix):
            raise ValueError(f"{path.name} contains an invalid domain suffix: {suffix!r}")
        lines.add(f"+.{suffix}")
    for cidr in source.get("ip_cidr_set", []):
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError as error:
            raise ValueError(f"{path.name} contains an invalid CIDR: {cidr!r}") from error
        lines.add(cidr)
    return lines


def keyword_lines(source: dict[str, list[str]], path: Path) -> list[str]:
    """keyword 规则无法用 domain behavior 表达（字典树只存域名模式），
    单独输出为 classical behavior 的 YAML provider 负载，由规则引擎匹配。"""
    keywords = []
    for keyword in source.get(KEYWORD_KEY, []):
        if not keyword or "," in keyword or keyword.startswith(("+", "*", ".")):
            raise ValueError(f"{path.name} contains an invalid domain keyword: {keyword!r}")
        keywords.append(keyword)
    return keywords


def decode(mihomo: str, behavior: str, mrs_path: Path, temp: Path) -> set[str]:
    text_path = temp / "decoded.txt"
    subprocess.run(
        [mihomo, "convert-ruleset", behavior, "mrs", str(mrs_path), str(text_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in text_path.read_text(encoding="utf-8").splitlines() if line.strip()}


def compile_rules(mihomo: str, behavior: str, lines: set[str], target: Path, temp: Path) -> None:
    text_path = temp / "payload.txt"
    text_path.write_text("".join(f"{line}\n" for line in sorted(lines)), encoding="utf-8")
    subprocess.run(
        [mihomo, "convert-ruleset", behavior, "text", str(text_path), str(target)],
        check=True,
        capture_output=True,
        text=True,
    )


def write_side_outputs(ruleset: str, source: dict[str, list[str]]) -> None:
    regexes = source.get("domain_regex_set", [])
    if regexes:
        (RULES_DIR / f"{ruleset}-regex-mihomo.yaml").write_text(
            yaml.safe_dump({"payload": [f"DOMAIN-REGEX,{pattern}" for pattern in regexes]}, sort_keys=False),
            encoding="utf-8",
        )
    keywords = keyword_lines(source, RULES_DIR / f"{ruleset}.yaml")
    if keywords:
        (RULES_DIR / f"{ruleset}-keyword-mihomo.yaml").write_text(
            yaml.safe_dump(
                {"payload": [f"DOMAIN-KEYWORD,{keyword}" for keyword in keywords]}, sort_keys=False
            ),
            encoding="utf-8",
        )


def check_side_outputs(ruleset: str, source: dict[str, list[str]]) -> None:
    regexes = source.get("domain_regex_set", [])
    if regexes:
        expected = {"payload": [f"DOMAIN-REGEX,{pattern}" for pattern in regexes]}
        actual = yaml.safe_load((RULES_DIR / f"{ruleset}-regex-mihomo.yaml").read_text(encoding="utf-8"))
        if actual != expected:
            raise ValueError(f"{ruleset}-regex-mihomo.yaml is out of sync; rebuild the rules")
    keywords = keyword_lines(source, RULES_DIR / f"{ruleset}.yaml")
    keyword_path = RULES_DIR / f"{ruleset}-keyword-mihomo.yaml"
    if keywords:
        expected = {"payload": [f"DOMAIN-KEYWORD,{keyword}" for keyword in keywords]}
        actual = yaml.safe_load(keyword_path.read_text(encoding="utf-8"))
        if actual != expected:
            raise ValueError(f"{ruleset}-keyword-mihomo.yaml is out of sync; rebuild the rules")
    elif keyword_path.exists():
        raise ValueError(f"{ruleset}-keyword-mihomo.yaml is stale; the source has no keyword rules")


def resolve_mihomo(path: str) -> str:
    """MRS 编译依赖外部 mihomo 核心；缺失时给出可执行的提示，而不是 subprocess 的裸 traceback。"""
    resolved = shutil.which(path) or (path if Path(path).is_file() else None)
    if resolved is None:
        raise SystemExit(
            f"mihomo not found: {path!r}. 用 --mihomo 指向 mihomo 可执行文件（版本需与产出 MRS 的核心一致）。"
        )
    return resolved


def main() -> None:
    # 选项同时从既有 MRS 产物与 YAML 源派生：新增规则集只有源文件时也能构建。
    # *-regex-mihomo / *-keyword-mihomo 是 classical side output，不是可构建的规则集。
    rulesets = sorted(
        {path.stem for path in RULES_DIR.glob("*.mrs")}
        | {
            path.stem
            for path in RULES_DIR.glob("*.yaml")
            if not (path.stem.endswith("-regex-mihomo") or path.stem.endswith("-keyword-mihomo"))
        }
    )
    parser = argparse.ArgumentParser(
        description="Build Mihomo MRS rule sets from the Egern YAML sources in rules/"
    )
    parser.add_argument("--ruleset", choices=rulesets, default="UK-banks" if "UK-banks" in rulesets else rulesets[0])
    parser.add_argument("--mihomo", default="mihomo", help="Mihomo executable path")
    parser.add_argument("--check", action="store_true", help="check committed outputs against the source")
    args = parser.parse_args()

    source_path = RULES_DIR / f"{args.ruleset}.yaml"
    mrs_path = RULES_DIR / f"{args.ruleset}.mrs"
    source = load_source(source_path)
    lines = payload_lines(source, source_path)
    behavior = "ipcidr" if source.get("ip_cidr_set") else "domain"

    if not lines:
        # 纯 keyword 源无法编译 MRS（domain behavior 不表达 keyword），只维护 side output。
        if args.check:
            check_side_outputs(args.ruleset, source)
            print(f"PASS: {args.ruleset}, keyword-only, no MRS")
        else:
            write_side_outputs(args.ruleset, source)
            print(f"Built: {args.ruleset}, keyword-only, no MRS")
        return

    with tempfile.TemporaryDirectory(prefix=f"{args.ruleset.lower()}-") as temp:
        mihomo = resolve_mihomo(args.mihomo)
        if args.check:
            if not mrs_path.is_file():
                raise ValueError(f"{mrs_path.name} is missing; build the rule set first")
            if decode(mihomo, behavior, mrs_path, Path(temp)) != lines:
                raise ValueError(f"{mrs_path.name} is out of sync; rebuild the rules")
        else:
            built = Path(temp) / f"{args.ruleset}.mrs"
            compile_rules(mihomo, behavior, lines, built, Path(temp))
            if decode(mihomo, behavior, built, Path(temp)) != lines:
                raise ValueError(f"{args.ruleset}: rebuilt MRS does not reproduce the source rules")
            mrs_path.write_bytes(built.read_bytes())

    if args.check:
        check_side_outputs(args.ruleset, source)
    else:
        write_side_outputs(args.ruleset, source)

    print(f"{'PASS' if args.check else 'Built'}: {args.ruleset}, {len(lines)} rules, {behavior}")


if __name__ == "__main__":
    main()
