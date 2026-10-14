from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "rules/UK-banks.yaml"
MRS = ROOT / "rules/UK-banks.mrs"
SING_BOX = ROOT / "rules/UK-banks-sing-box.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build UK bank rules from the Egern YAML source")
    parser.add_argument("--mihomo", default="mihomo", help="Mihomo executable path")
    parser.add_argument("--check", action="store_true", help="check committed outputs against the source")
    args = parser.parse_args()

    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    if not isinstance(source, dict) or set(source) != {"domain_suffix_set"}:
        raise ValueError("UK-banks.yaml must contain only domain_suffix_set")
    domains = source["domain_suffix_set"]
    if not isinstance(domains, list) or not domains:
        raise ValueError("UK-banks.yaml must contain a nonempty domain list")
    pattern = r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    if any(not isinstance(domain, str) or not re.fullmatch(pattern, domain) for domain in domains):
        raise ValueError("UK-banks.yaml contains an invalid domain suffix")
    if len(domains) != len(set(domains)):
        raise ValueError("UK-banks.yaml contains duplicate domain suffixes")
    domains = sorted(domains)
    sing_box = {"version": 1, "rules": [{"domain_suffix": domains}]}

    with tempfile.TemporaryDirectory(prefix="uk-banks-") as temp:
        text_path = Path(temp) / "domains.txt"
        if args.check:
            subprocess.run(
                [args.mihomo, "convert-ruleset", "domain", "mrs", str(MRS), str(text_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            expected = {f"+.{domain}" for domain in domains}
            actual = set(text_path.read_text(encoding="utf-8").splitlines())
            if actual != expected:
                raise ValueError("UK-banks.mrs is out of sync; rebuild the rules")
            if json.loads(SING_BOX.read_text(encoding="utf-8")) != sing_box:
                raise ValueError("UK-banks-sing-box.json is out of sync; rebuild the rules")
        else:
            text_path.write_text("".join(f"+.{domain}\n" for domain in domains), encoding="utf-8")
            mrs_path = Path(temp) / "UK-banks.mrs"
            subprocess.run(
                [args.mihomo, "convert-ruleset", "domain", "text", str(text_path), str(mrs_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            MRS.write_bytes(mrs_path.read_bytes())
            SING_BOX.write_text(json.dumps(sing_box, indent=2) + "\n", encoding="utf-8")

    print(f"{'PASS' if args.check else 'Built'}: {len(domains)} UK bank domain suffixes")


if __name__ == "__main__":
    main()
