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
    parser.add_argument("--ruleset", choices=("UK-banks", "Crypto-extra"), default="UK-banks")
    parser.add_argument("--mihomo", default="mihomo", help="Mihomo executable path")
    parser.add_argument("--check", action="store_true", help="check committed outputs against the source")
    args = parser.parse_args()

    source_path = ROOT / f"rules/{args.ruleset}.yaml"
    mrs_path = ROOT / f"rules/{args.ruleset}.mrs"
    sing_box_path = ROOT / f"rules/{args.ruleset}-sing-box.json"
    source = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    if not isinstance(source, dict) or set(source) != {"domain_suffix_set"}:
        raise ValueError(f"{source_path.name} must contain only domain_suffix_set")
    domains = source["domain_suffix_set"]
    if not isinstance(domains, list) or not domains:
        raise ValueError(f"{source_path.name} must contain a nonempty domain list")
    pattern = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    if any(not isinstance(domain, str) or not re.fullmatch(pattern, domain) for domain in domains):
        raise ValueError(f"{source_path.name} contains an invalid domain suffix")
    if len(domains) != len(set(domains)):
        raise ValueError(f"{source_path.name} contains duplicate domain suffixes")
    domains = sorted(domains)
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
            expected = {f"+.{domain}" for domain in domains}
            actual = set(text_path.read_text(encoding="utf-8").splitlines())
            if actual != expected:
                raise ValueError(f"{mrs_path.name} is out of sync; rebuild the rules")
            if json.loads(sing_box_path.read_text(encoding="utf-8")) != sing_box:
                raise ValueError(f"{sing_box_path.name} is out of sync; rebuild the rules")
        else:
            text_path.write_text("".join(f"+.{domain}\n" for domain in domains), encoding="utf-8")
            built_mrs_path = Path(temp) / f"{args.ruleset}.mrs"
            subprocess.run(
                [args.mihomo, "convert-ruleset", "domain", "text", str(text_path), str(built_mrs_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            mrs_path.write_bytes(built_mrs_path.read_bytes())
            sing_box_path.write_text(json.dumps(sing_box, indent=2) + "\n", encoding="utf-8")

    label = "UK bank" if args.ruleset == "UK-banks" else "crypto supplemental"
    print(f"{'PASS' if args.check else 'Built'}: {len(domains)} {label} domain suffixes")


if __name__ == "__main__":
    main()
