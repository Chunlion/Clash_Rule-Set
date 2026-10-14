import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import yaml

import manage


LINK = "https://test.invalid/egern.yaml?key=test-only"


class ConfigTests(unittest.TestCase):
    def test_add_update_preserves_original_config_text(self):
        for prefix, newline in [("", "\n"), ("\ufeff---\r\n# comment\r\n", "\r\n")]:
            body = "rules: []" + newline + "private_setting: 'test-only-value' # keep" + newline
            source = (prefix + body).encode("utf-8")
            result = manage.prepare_yaml(source, LINK)
            parsed = yaml.safe_load(result)
            self.assertEqual(parsed["auto_update"], {"url": LINK, "interval": 86400})
            self.assertTrue(result.decode("utf-8").endswith(body))
            self.assertTrue(result.decode("utf-8").startswith(prefix))
            self.assertEqual(parsed["private_setting"], "test-only-value")

    def test_existing_update_preserves_interval_comments_and_other_fields(self):
        sources = [
            "auto_update:\n  url: 'https://old.invalid/' # keep\n  interval: 1234\nrules: []\n",
            "auto_update: {url: 'https://old.invalid/', interval: 1234} # keep\nrules: []\n",
            "auto_update:\n  url: >-\n    https://old.invalid/\n  interval: 1234 # keep\nrules: []\n",
        ]
        for source in sources:
            with self.subTest(source=source):
                result = manage.prepare_yaml(source.encode(), LINK)
                self.assertEqual(yaml.safe_load(result), {
                    "auto_update": {"url": LINK, "interval": 1234}, "rules": [],
                })
                self.assertIn("# keep", result.decode())

    def test_yaml_errors_do_not_echo_source(self):
        with self.assertRaises(manage.SetupError) as caught:
            manage.prepare_yaml(b"private: [test-only-secret", LINK)
        self.assertNotIn("test-only-secret", str(caught.exception))

    def test_rejects_alias_updates_that_change_other_settings(self):
        source = b"other: &value https://old.invalid/\nauto_update: {url: *value}\n"
        with self.assertRaises(manage.SetupError):
            manage.prepare_yaml(source, LINK)


class ToolTests(unittest.TestCase):
    def test_cli_failure_redacts_output_and_disables_automatic_login(self):
        result = subprocess.CompletedProcess([], 1, b"test-only-private-value", b"[code: 10042]")
        with patch.object(manage, "wrangler_command", return_value=["wrangler"]), \
                patch.object(manage.subprocess, "run", return_value=result) as run:
            with self.assertRaises(manage.SetupError) as caught:
                manage.run_wrangler(["secret", "put", "DOWNLOAD_TOKEN"], "保存密钥", b"test-only-key\n")
        self.assertIn("10042", str(caught.exception))
        self.assertNotIn("test-only", str(caught.exception))
        self.assertEqual(run.call_args.kwargs["env"]["CI"], "true")
        self.assertEqual(run.call_args.kwargs["env"]["WRANGLER_LOG_SANITIZE"], "true")
        self.assertNotIn("test-only-key", " ".join(run.call_args.args[0]))

    def test_deploy_stops_before_any_mutation_without_login(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.yaml"
            source.write_bytes(b"rules: []\n")
            with patch.object(manage, "SOURCE", source), \
                    patch.object(manage, "load_state", return_value=None), \
                    patch.object(manage, "run_wrangler", side_effect=manage.SetupError("unauthenticated")) as run, \
                    patch.object(manage, "atomic_write") as write, \
                    patch.object(manage.sys, "argv", ["manage.py", "deploy"]):
                with self.assertRaisesRegex(manage.SetupError, "登录检查"):
                    manage.main()
                run.assert_called_once_with(["whoami", "--json"], "登录检查")
                write.assert_not_called()
            self.assertEqual(source.read_bytes(), b"rules: []\n")

    def test_deploy_streams_config_and_saves_link_only_after_verification(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            root = Path(directory)
            private = root / ".private"
            source = root / "source.yaml"
            source.write_bytes(b"private_setting: test-only-value\nrules: []\n")
            state_path = private / "state.json"
            link_path = private / "download-link.txt"
            for name, value in [("PRIVATE", private), ("STATE", state_path),
                                ("CONFIG", private / "wrangler.json"), ("LINK", link_path),
                                ("SOURCE", source)]:
                stack.enter_context(patch.object(manage, name, value))
            stack.enter_context(patch.object(manage.secrets, "token_hex", return_value="12345678"))
            stack.enter_context(patch.object(manage.secrets, "token_urlsafe", return_value="x" * 43))
            stack.enter_context(patch.object(manage.sys, "argv", ["manage.py", "deploy"]))
            calls = []

            def cli(arguments, phase, data=None):
                calls.append((arguments, data))
                if arguments == ["whoami", "--json"]:
                    return json.dumps({"loggedIn": True, "accounts": [{"id": "a" * 32}]})
                if arguments[0] == "deploy":
                    return "https://clash-private-config-12345678.test.workers.dev"
                return ""

            def verify(state, payload):
                self.assertFalse(link_path.exists())
                self.assertNotIn(b"auto_update", source.read_bytes())
                self.assertEqual(yaml.safe_load(payload)["private_setting"], "test-only-value")

            stack.enter_context(patch.object(manage, "run_wrangler", side_effect=cli))
            verification = stack.enter_context(patch.object(manage, "verify_download", side_effect=verify))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            manage.main()
            verification.assert_called_once()
            state = json.loads(state_path.read_text())
            self.assertEqual(state["token"], "x" * 43)
            self.assertNotIn(state["token"], output.getvalue())
            self.assertEqual(yaml.safe_load(source.read_bytes())["auto_update"]["url"], link_path.read_text().strip())
            upload = [call for call in calls if call[0][:3] == ["r2", "object", "put"]][0]
            self.assertIn("--pipe", upload[0])
            self.assertEqual(upload[1], source.read_bytes())
            self.assertNotIn("x" * 43, " ".join(upload[0]))

    def test_redirects_are_rejected(self):
        self.assertIsNone(manage.NoRedirect().redirect_request(None, None, 302, "", {}, LINK))
        error = urllib.error.HTTPError(LINK, 302, "redirect", {}, None)
        with patch.object(manage.urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = error
            with self.assertRaisesRegex(manage.SetupError, "HTTP 302"):
                manage.verify_download({"endpoint": "https://test.invalid", "token": "test-only"}, b"rules: []\n")


if __name__ == "__main__":
    unittest.main()
