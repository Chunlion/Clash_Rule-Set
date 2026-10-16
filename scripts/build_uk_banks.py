from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build domain rules from an Egern YAML source")
    parser.add_argument(
        "--ruleset",
        choices=("UK-banks", "Crypto-extra", "Finance-custom", "Crypto-custom", "AI-custom"),
        default="UK-banks",
    )
    parser.add_argument("--mihomo", default="mihomo", help="Mihomo executable path")
    parser.add_argument("--check", action="store_true", help="check committed outputs against the source")
    args = parser.parse_args()

    source_path = ROOT / f"rules/{args.ruleset}.yaml"
    mrs_path = ROOT / f"rules/{args.ruleset}.mrs"
    sing_box_path = ROOT / f"rules/{args.ruleset}-sing-box.json"
    with_sing_box = args.ruleset in {"UK-banks", "Crypto-extra"}
    regex_path = ROOT / f"rules/{args.ruleset}-regex-mihomo.yaml"
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    if not isinstance(source, dict) or not source or set(source) - {
        "domain_set", "domain_suffix_set", "domain_regex_set"
    }:
        raise ValueError(f"{source_path.name} contains unsupported rule types")
    for key, values in source.items():
        if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
            raise ValueError(f"{source_path.name}: {key} must contain a nonempty string list")
        if len(values) != len(set(values)):
            raise ValueError(f"{source_path.name}: {key} contains duplicate rules")
    domains = source.get("domain_suffix_set", [])
    exact_domains = source.get("domain_set", [])
    regexes = source.get("domain_regex_set", [])
    pattern = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    if any(not re.fullmatch(pattern, domain) for domain in domains + exact_domains):
        raise ValueError(f"{source_path.name} contains an invalid domain suffix")
    domains = sorted(domains)
    expected = {f"+.{domain}" for domain in domains} | set(exact_domains)
    if not expected:
        raise ValueError(f"{source_path.name} must contain domains for MRS output")
    regex_rules = {"payload": [f"DOMAIN-REGEX,{pattern}" for pattern in regexes]}
    sing_box = {"version": 1, "rules": [{"domain_suffix": domains}]}

    with tempfile.TemporaryDirectory(prefix=f"{args.ruleset.lower()}-") as temp:
        text_path = Path(temp) / "domains.txt"
        if args.check:
            subprocess.run(
                [args.mihomo, "convert-ruleset", "domain", "mrs", str(mrs_path), str(text_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            actual = set(text_path.read_text(encoding="utf-8").splitlines())
            if actual != expected:
                raise ValueError(f"{mrs_path.name} is out of sync; rebuild the rules")
            if with_sing_box and json.loads(sing_box_path.read_text(encoding="utf-8")) != sing_box:
                raise ValueError(f"{sing_box_path.name} is out of sync; rebuild the rules")
            if regexes and yaml.safe_load(regex_path.read_text(encoding="utf-8")) != regex_rules:
                raise ValueError(f"{regex_path.name} is out of sync; rebuild the rules")
        else:
            text_path.write_text("".join(f"{domain}\n" for domain in sorted(expected)), encoding="utf-8")
            built_mrs_path = Path(temp) / f"{args.ruleset}.mrs"
            subprocess.run(
                [args.mihomo, "convert-ruleset", "domain", "text", str(text_path), str(built_mrs_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            mrs_path.write_bytes(built_mrs_path.read_bytes())
            if with_sing_box:
                sing_box_path.write_text(json.dumps(sing_box, indent=2) + "\n", encoding="utf-8")
            if regexes:
                regex_path.write_text(yaml.safe_dump(regex_rules, sort_keys=False), encoding="utf-8")

    print(f"{'PASS' if args.check else 'Built'}: {args.ruleset}, {len(expected)} domains, {len(regexes)} regexes")


if __name__ == "__main__":
    main()
