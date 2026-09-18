"""Automated test suite for openclaw-secret-drop."""

from __future__ import annotations

import base64
import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secret_drop.dotenv_file import format_assignment, upsert_env_file, write_secret_file
from secret_drop.errors import SecretDropError
from secret_drop.net import assert_public_https
from secret_drop.cli import main as cli_main
from secret_drop.providers.pwpush import retrieve as pwpush_retrieve
from secret_drop.providers.registry import detect_provider
from secret_drop.providers.snappwd import retrieve as snappwd_retrieve
from secret_drop.redact import host_of, redact_text, sanitize_url

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_BASE58[r])
    res = "".join(reversed(res))
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + res


class RedactTests(unittest.TestCase):
    def test_sanitize_url_strips_fragment_and_query_secrets(self) -> None:
        url = "https://example.com/p/token?passphrase=supersecret#fragmentkey123"
        clean = sanitize_url(url)
        self.assertNotIn("supersecret", clean)
        self.assertNotIn("fragmentkey123", clean)
        self.assertIn("https://example.com/p/token", clean)

    def test_redact_text_replaces_secret_and_fragment(self) -> None:
        raw = "error fetching https://snappwd.io/g/sp-123#mykey: sk-proj-12345 failed"
        safe = redact_text(raw, secret="sk-proj-12345", url="https://snappwd.io/g/sp-123#mykey")
        self.assertNotIn("sk-proj-12345", safe)
        self.assertNotIn("mykey", safe)
        self.assertIn("[redacted-secret]", safe)

    def test_host_of_normalizes(self) -> None:
        self.assertEqual(host_of("https://PWPUSH.com/p/abc"), "pwpush.com")


class NetSecurityTests(unittest.TestCase):
    def test_rejects_non_https(self) -> None:
        with self.assertRaises(SecretDropError):
            assert_public_https("http://pwpush.com/p/test")

    def test_rejects_localhost_by_default(self) -> None:
        with self.assertRaises(SecretDropError):
            assert_public_https("https://localhost/p/test")

    def test_allows_private_host_when_explicitly_authorized(self) -> None:
        assert_public_https("https://localhost/p/test", allow_private=True)


class DotenvWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.env_file = Path(self.temp_dir.name) / ".env"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_atomic_append_and_replace_maintains_mode_0600(self) -> None:
        upsert_env_file(self.env_file, "KEY_ONE", "value_1")
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)
        self.assertIn("KEY_ONE=value_1", self.env_file.read_text())

        upsert_env_file(self.env_file, "KEY_ONE", "value_2_updated")
        self.assertEqual(stat.S_IMODE(self.env_file.stat().st_mode), 0o600)
        content = self.env_file.read_text()
        self.assertIn("KEY_ONE=value_2_updated", content)
        self.assertNotIn("value_1", content)

    def test_refuses_symlink_target_or_directory(self) -> None:
        symlink = Path(self.temp_dir.name) / "symlink.env"
        real = Path(self.temp_dir.name) / "real.env"
        real.write_text("FOO=bar\n")
        symlink.symlink_to(real)
        with self.assertRaises(SecretDropError):
            upsert_env_file(symlink, "KEY", "val")
        with self.assertRaises(SecretDropError):
            write_secret_file(symlink, "val")

    def test_quotes_special_characters(self) -> None:
        line = format_assignment("COMPLEX", 'secret "quoted" with spaces')
        self.assertEqual(line, 'COMPLEX="secret \\"quoted\\" with spaces"\n')

    def test_write_file_creates_mode_0600(self) -> None:
        target = Path(self.temp_dir.name) / "secret.key"
        write_secret_file(target, "raw_secret_data")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(target.read_text(), "raw_secret_data")

    def test_write_file_refuses_overwrite_without_replace_flag(self) -> None:
        target = Path(self.temp_dir.name) / "existing.key"
        target.write_text("initial")
        with self.assertRaises(SecretDropError):
            write_secret_file(target, "new")
        write_secret_file(target, "new", replace=True)
        self.assertEqual(target.read_text(), "new")


class ProviderAdapterTests(unittest.TestCase):
    def test_detect_provider(self) -> None:
        self.assertEqual(detect_provider("https://pwpush.com/p/abcd1234"), "pwpush")
        self.assertEqual(detect_provider("https://snappwd.io/g/sp-1234#key5678"), "snappwd")

    def test_unknown_self_host_requires_explicit_provider(self) -> None:
        with self.assertRaises(SecretDropError):
            detect_provider("https://secrets.example.com/p/abcd1234")

    @patch("secret_drop.providers.pwpush.request_json")
    def test_pwpush_retrieves_payload(self, mock_json) -> None:
        mock_json.return_value = (200, {"payload": "secret-value-from-pwpush"}, b"")
        val = pwpush_retrieve("https://pwpush.com/p/testtoken123", allow_private=True)
        self.assertEqual(val, "secret-value-from-pwpush")
        mock_json.assert_called_once()
        self.assertEqual(mock_json.call_args[0][0], "https://pwpush.com/p/testtoken123.json")

    @patch("secret_drop.providers.pwpush.request_json")
    def test_pwpush_completes_retrieval_step(self, mock_json) -> None:
        mock_json.side_effect = [
            (200, {"retrieval_step": True, "payload": None}, b""),
            (200, {"status": "previewed"}, b""),
            (200, {"retrieval_step": True, "payload": "final-secret"}, b""),
        ]
        value = pwpush_retrieve("https://pwpush.com/p/testtoken123", allow_private=True)
        self.assertEqual(value, "final-secret")
        self.assertEqual(mock_json.call_count, 3)
        self.assertEqual(
            mock_json.call_args_list[1][0][0],
            "https://pwpush.com/p/testtoken123/preview.json",
        )

    @patch("secret_drop.providers.snappwd.request_json")
    def test_snappwd_decrypts_v2_payload(self, mock_json) -> None:
        raw_key = os.urandom(32)
        b58_key = _b58encode(raw_key)
        iv = os.urandom(12)
        aesgcm = AESGCM(raw_key)
        ciphertext = aesgcm.encrypt(iv, b"snappwd-plain-text", None)
        versioned = bytes([2]) + iv + ciphertext
        b64_payload = base64.b64encode(versioned).decode("ascii")

        mock_json.return_value = (200, {"encryptedSecret": b64_payload}, b"")
        url = f"https://snappwd.io/g/sp-uuid123#{b58_key}"
        val = snappwd_retrieve(url, allow_private=True)
        self.assertEqual(val, "snappwd-plain-text")


class CliLeakTests(unittest.TestCase):
    @patch("secret_drop.cli.write_secret")
    @patch("secret_drop.cli.retrieve_secret")
    def test_success_output_never_contains_secret(self, retrieve, write) -> None:
        secret = "sk-super-secret-value-1234567890"
        retrieve.return_value = ("pwpush", secret)
        write.return_value = {
            "destination": "openclaw-env",
            "name": "OPENROUTER_API_KEY",
            "restart_required": True,
            "created": False,
            "replaced": True,
            "path": "/tmp/.env",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli_main(
                [
                    "ingest",
                    "https://pwpush.com/p/testtoken123",
                    "--to",
                    "openclaw-env",
                    "--name",
                    "OPENROUTER_API_KEY",
                    "--json",
                ]
            )
        self.assertEqual(code, 0)
        self.assertNotIn(secret, stdout.getvalue())
        self.assertNotIn(secret, stderr.getvalue())

    @patch("secret_drop.cli.write_secret")
    @patch("secret_drop.cli.retrieve_secret")
    def test_failure_output_never_contains_secret_or_fragment(self, retrieve, write) -> None:
        secret = "sk-super-secret-value-1234567890"
        retrieve.return_value = ("snappwd", secret)
        write.side_effect = SecretDropError(f"failed with {secret}")
        url = "https://snappwd.io/g/sp-example#fragment-decryption-key"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli_main(
                [
                    "ingest",
                    url,
                    "--to",
                    "openclaw-env",
                    "--name",
                    "OPENROUTER_API_KEY",
                    "--json",
                ]
            )
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(code, 2)
        self.assertNotIn(secret, combined)
        self.assertNotIn("fragment-decryption-key", combined)


if __name__ == "__main__":
    unittest.main()
