from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "rules"
SING_BOX_RULESETS = frozenset({"UK-banks", "Crypto-extra"})
DOMAIN_PATTERN = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
# Egern 侧可读的键 → Mihomo 文本规则集的类型前缀。
PREFIXED_KEYS = {
    "domain_set": "domain",
    "domain_suffix_set": "domain-suffix",
    "domain_keyword_set": "domain-keyword",
}
ALLOWED_KEYS = (*PREFIXED_KEYS, "domain_regex_set", "ip_cidr_set")


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
    """生成 Mihomo 文本规则集内容，供 MRS 编译与产物比对。"""
    lines = set()
    for key, prefix in PREFIXED_KEYS.items():
        for rule in source.get(key, []):
            if key != "domain_keyword_set" and not re.fullmatch(DOMAIN_PATTERN, rule):
                raise ValueError(f"{path.name} contains an invalid domain: {rule!r}")
            lines.add(f"{prefix},{rule}")
    for cidr in source.get("ip_cidr_set", []):
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError as error:
            raise ValueError(f"{path.name} contains an invalid CIDR: {cidr!r}") from error
        lines.add(cidr)
    if not lines:
        raise ValueError(f"{path.name} must contain at least one rule")
    return lines


def decode(mihomo: str, behavior: str, mrs_path: Path, temp: Path) -> set[str]:
    text_path = temp / "decoded.txt"
    subprocess.run(
        [mihomo, "convert-ruleset", behavior, "mrs", str(mrs_path), str(text_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.strip() for line in text_path.read_text(encoding="utf-8").splitlines() if line.strip()}


def canonical(lines: set[str], behavior: str) -> set[tuple[str, str]]:
    """按语义归一：`+.x` 与 `domain-suffix,x` 等价，裸域名与 `domain,x` 等价。

    MRS 保存的是原始规则文本，历史上不同工具写出的前缀形式不同，比对前必须归一，
    否则会误判为不同步并触发无意义的重建。
    """
    if behavior == "ipcidr":
        return {("cidr", line.lower()) for line in lines}
    result = set()
    for line in lines:
        rule = line.strip()
        lowered = rule.lower()
        for prefix, kind in (("domain-suffix,", "suffix"), ("domain-keyword,", "keyword"), ("keyword,", "keyword")):
            if lowered.startswith(prefix):
                result.add((kind, lowered.removeprefix(prefix)))
                break
        else:
            if lowered.startswith("+.") or lowered.startswith("*."):
                result.add(("suffix", lowered[2:]))
            elif lowered.startswith("domain,"):
                result.add(("exact", lowered.removeprefix("domain,")))
            else:
                # 裸域名即精确匹配；其余带逗号的规则类型保持原样。
                result.add(("literal", lowered) if "," in lowered else ("exact", lowered))
    return result


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
    if ruleset in SING_BOX_RULESETS:
        sing_box = {"version": 1, "rules": [{"domain_suffix": sorted(source["domain_suffix_set"])}]}
        (RULES_DIR / f"{ruleset}-sing-box.json").write_text(
            json.dumps(sing_box, indent=2) + "\n", encoding="utf-8"
        )


def check_side_outputs(ruleset: str, source: dict[str, list[str]]) -> None:
    regexes = source.get("domain_regex_set", [])
    if regexes:
        expected = {"payload": [f"DOMAIN-REGEX,{pattern}" for pattern in regexes]}
        actual = yaml.safe_load((RULES_DIR / f"{ruleset}-regex-mihomo.yaml").read_text(encoding="utf-8"))
        if actual != expected:
            raise ValueError(f"{ruleset}-regex-mihomo.yaml is out of sync; rebuild the rules")
    if ruleset in SING_BOX_RULESETS:
        expected = {"version": 1, "rules": [{"domain_suffix": sorted(source["domain_suffix_set"])}]}
        actual = json.loads((RULES_DIR / f"{ruleset}-sing-box.json").read_text(encoding="utf-8"))
        if actual != expected:
            raise ValueError(f"{ruleset}-sing-box.json is out of sync; rebuild the rules")


def main() -> None:
    rulesets = sorted(path.stem for path in RULES_DIR.glob("*.mrs"))
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

    with tempfile.TemporaryDirectory(prefix=f"{args.ruleset.lower()}-") as temp:
        if args.check:
            if not mrs_path.is_file():
                raise ValueError(f"{mrs_path.name} is missing; build the rule set first")
            if canonical(decode(args.mihomo, behavior, mrs_path, Path(temp)), behavior) != canonical(lines, behavior):
                raise ValueError(f"{mrs_path.name} is out of sync; rebuild the rules")
        else:
            built = Path(temp) / f"{args.ruleset}.mrs"
            compile_rules(args.mihomo, behavior, lines, built, Path(temp))
            if canonical(decode(args.mihomo, behavior, built, Path(temp)), behavior) != canonical(lines, behavior):
                raise ValueError(f"{args.ruleset}: rebuilt MRS does not reproduce the source rules")
            mrs_path.write_bytes(built.read_bytes())

    if args.check:
        check_side_outputs(args.ruleset, source)
    else:
        write_side_outputs(args.ruleset, source)

    print(f"{'PASS' if args.check else 'Built'}: {args.ruleset}, {len(lines)} rules, {behavior}")


if __name__ == "__main__":
    main()
