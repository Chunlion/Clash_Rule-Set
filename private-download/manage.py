"""Deploy and update the private Egern download using an existing Wrangler login."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import yaml


BASE = Path(__file__).resolve().parent
PRIVATE = BASE / ".private"
STATE = PRIVATE / "state.json"
CONFIG = PRIVATE / "wrangler.json"
LINK = PRIVATE / "download-link.txt"
SOURCE = BASE.parent / "Egern 精细分流.yaml"


class SetupError(Exception):
    pass


def wrangler_command():
    executable = shutil.which("wrangler.cmd") or shutil.which("wrangler")
    if not executable:
        raise SetupError("未找到 Wrangler，请先安装或将它加入 PATH。")
    # Run the npm entry point directly to avoid cmd.exe argument expansion.
    npm_entry = Path(executable).parent / "node_modules" / "wrangler" / "bin" / "wrangler.js"
    if os.name == "nt" and npm_entry.is_file():
        node = shutil.which("node")
        if not node:
            raise SetupError("未找到 Node.js。")
        return [node, str(npm_entry)]
    if os.name == "nt":
        raise SetupError("未找到 Wrangler 的 npm 入口，请检查本地安装。")
    return [executable]


def run_wrangler(arguments, phase, data=None):
    environment = os.environ.copy()
    environment.update({
        "CI": "true",
        "WRANGLER_SEND_METRICS": "false",
        "WRANGLER_LOG": "log",
        "WRANGLER_LOG_SANITIZE": "true",
        "WRANGLER_LOG_PATH": str(PRIVATE / "logs"),
    })
    result = subprocess.run(
        [*wrangler_command(), *arguments], cwd=BASE, env=environment,
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    if result.returncode:
        # Wrangler errors can contain request data; never echo their raw output.
        code = re.search(r"\[code:\s*(\d+)\]", output)
        detail = f"（Cloudflare 错误码 {code.group(1)}）" if code else ""
        raise SetupError(f"{phase}失败{detail}。未输出可能含私密信息的原始日志。")
    return result.stdout.decode("utf-8", errors="replace")


def atomic_write(path, content):
    PRIVATE.mkdir(exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=PRIVATE, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def save_state(state):
    atomic_write(STATE, (json.dumps(state, indent=2) + "\n").encode("utf-8"))


def load_state():
    if not STATE.exists():
        return None
    try:
        state = json.loads(STATE.read_text(encoding="utf-8"))
        if not isinstance(state, dict):
            raise ValueError
        patterns = {"account_id": r"[0-9a-f]{32}",
                    "worker": r"clash-private-config-[0-9a-f]{8}",
                    "bucket": r"clash-private-files-[0-9a-f]{8}",
                    "token": r"[A-Za-z0-9_-]{43}"}
        if any(not re.fullmatch(pattern, state[key]) for key, pattern in patterns.items()):
            raise ValueError
        if state.get("endpoint") and not re.fullmatch(
            rf"https://{re.escape(state['worker'])}\.[a-z0-9-]+\.workers\.dev", state["endpoint"]
        ):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise SetupError("本地部署状态无效；请保留 .private 目录并检查 state.json。") from None
    return state


def logged_in_account(requested, state):
    try:
        output = run_wrangler(["whoami", "--json"], "登录检查")
    except SetupError:
        raise SetupError("登录检查未通过。请先手动运行 wrangler login；脚本不会启动登录。") from None
    try:
        user = json.loads(output)
        accounts = user["accounts"]
        if user.get("loggedIn") is not True or not isinstance(accounts, list):
            raise ValueError
        account_id = requested or (state or {}).get("account_id")
        if not account_id and len(accounts) == 1:
            account_id = accounts[0]["id"]
        if not account_id:
            raise SetupError("存在多个 Cloudflare 账户；请用 --account-id 指定目标账户。")
        if not any(account.get("id") == account_id for account in accounts):
            raise SetupError("目标账户不在当前登录账户中。")
        if state and account_id != state["account_id"]:
            raise SetupError("账户与既有部署不同；不会覆盖已有部署状态。")
        if not re.fullmatch(r"[0-9a-f]{32}", account_id):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise SetupError("无法读取 Wrangler 登录状态；未输出账户信息。") from None
    return account_id


def prepare_yaml(original, link):
    try:
        text = original.decode("utf-8")
        before = yaml.safe_load(text)
        root = yaml.compose(text)
        if not isinstance(before, dict) or not isinstance(root, yaml.MappingNode):
            raise ValueError
        newline = "\r\n" if "\r\n" in text else "\n"
        quoted = json.dumps(link)
        if "auto_update" not in before:
            block = newline.join([
                "auto_update:", f"  url: {quoted}", "  interval: 86400", "",
            ])
            position = root.start_mark.index
            text = text[:position] + block + text[position:]
        else:
            auto = before["auto_update"]
            if not isinstance(auto, dict) or "url" not in auto:
                raise SetupError("现有 auto_update 格式不支持；请保留配置并检查 url 字段。")
            nodes = [value for key, value in root.value if key.value == "auto_update"]
            if len(nodes) != 1 or not isinstance(nodes[0], yaml.MappingNode):
                raise ValueError
            urls = [value for key, value in nodes[0].value if key.value == "url"]
            if len(urls) != 1 or not isinstance(urls[0], yaml.ScalarNode):
                raise ValueError
            node = urls[0]
            start, end = node.start_mark.index, node.end_mark.index
            tail = newline if text[start:end].endswith("\n") else ""
            text = text[:start] + quoted + tail + text[end:]
        after = yaml.safe_load(text)
        expected = dict(before)
        expected["auto_update"] = dict(before.get("auto_update", {"interval": 86400}), url=link)
        if after != expected:
            raise ValueError
    except (UnicodeError, yaml.YAMLError, ValueError, TypeError, AttributeError):
        raise SetupError("Egern 配置校验失败；未输出配置内容，未修改源文件。") from None
    return text.encode("utf-8")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_download(state, payload):
    base_url = state["endpoint"] + "/egern.yaml"
    opener = urllib.request.build_opener(NoRedirect)
    checks = [(base_url, 403), (base_url + "?key=invalid", 403),
              (base_url + "?" + urllib.parse.urlencode({"key": state["token"]}), 200)]
    for url, expected_status in checks:
        try:
            with opener.open(url, timeout=30) as response:
                if response.status != expected_status:
                    raise SetupError("下载入口状态不符合预期。")
                if expected_status == 200:
                    if response.read(len(payload) + 1) != payload:
                        raise SetupError("远端配置与本地内容不一致。")
                    if response.headers.get("Cache-Control") != "private, no-store, max-age=0":
                        raise SetupError("下载入口缓存策略不符合预期。")
        except urllib.error.HTTPError as error:
            error.close()
            if error.code != expected_status:
                raise SetupError(f"下载验证失败（HTTP {error.code}）；未输出私有链接。") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise SetupError("下载验证连接失败；本地 Egern 配置尚未修改。") from None


def main():
    parser = argparse.ArgumentParser(description="私有 Egern 下载：手动登录后部署或更新")
    parser.add_argument("action", choices=["deploy", "update"])
    parser.add_argument("--account-id", help="多个账户时指定 Cloudflare Account ID")
    arguments = parser.parse_args()
    state = load_state()
    if arguments.action == "update" and (not state or not state.get("endpoint")):
        raise SetupError("尚未部署，请先运行 deploy。")
    original = SOURCE.read_bytes()
    # Validate before creating any remote resource; this URL is never saved or uploaded.
    prepare_yaml(original, "https://validation.invalid/egern.yaml")
    account_id = logged_in_account(arguments.account_id, state)
    if not state:
        suffix = secrets.token_hex(4)
        state = {"account_id": account_id, "worker": "clash-private-config-" + suffix,
                 "bucket": "clash-private-files-" + suffix, "token": secrets.token_urlsafe(32)}
        save_state(state)
    config = json.loads((BASE / "wrangler.json").read_text(encoding="utf-8"))
    config.update(name=state["worker"], account_id=account_id, main="../worker.mjs")
    config["r2_buckets"][0]["bucket_name"] = state["bucket"]
    atomic_write(CONFIG, (json.dumps(config, indent=2) + "\n").encode("utf-8"))
    flags = ["--config", str(CONFIG)]
    if arguments.action == "deploy":
        if not state.get("bucket_created"):
            print("创建私有存储…", flush=True)
            run_wrangler(["r2", "bucket", "create", state["bucket"], *flags], "创建 R2 存储")
            state["bucket_created"] = True
            save_state(state)
        print("部署下载入口…", flush=True)
        output = run_wrangler(["deploy", *flags], "部署 Worker")
        endpoints = re.findall(
            rf"https://{re.escape(state['worker'])}\.[a-z0-9-]+\.workers\.dev", output
        )
        if not endpoints:
            raise SetupError("部署输出中没有 workers.dev 地址；请检查账户的 Workers 子域名。")
        state["endpoint"] = endpoints[-1]
        save_state(state)
        run_wrangler(["secret", "put", "DOWNLOAD_TOKEN", *flags], "保存下载密钥",
                    (state["token"] + "\n").encode("utf-8"))
    link = state["endpoint"] + "/egern.yaml?" + urllib.parse.urlencode({"key": state["token"]})
    payload = prepare_yaml(original, link)
    print("上传并验证私有配置…", flush=True)
    run_wrangler(["r2", "object", "put", state["bucket"] + "/egern.yaml", "--pipe",
                 "--remote", "--content-type", "application/yaml", *flags], "上传配置", payload)
    verify_download(state, payload)
    if SOURCE.read_bytes() != original:
        raise SetupError("源文件在上传期间发生变化；已保留你的修改，请重新运行 update。")
    atomic_write(SOURCE, payload)
    atomic_write(LINK, (link + "\n").encode("utf-8"))
    print("完成：无密钥请求已拒绝，私有下载内容校验通过。")
    print(f"导入链接保存在本地：{LINK}")


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    try:
        main()
    except SetupError as error:
        print(f"未完成：{error}", file=sys.stderr)
        sys.exit(1)
    except OSError:
        print("未完成：本地文件读写或工具启动失败；未输出私密内容。", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("已中止；保留本地部署状态，可重新运行。", file=sys.stderr)
        sys.exit(130)
