import csv
import os
import tempfile
import time
import unittest
from datetime import timezone
from pathlib import Path
from unittest import mock

from cloud_checks.core import auth
from cloud_checks.core.env import env_bool, env_int, env_list, load_dotenv
from cloud_checks.core.findings import Finding, meets_threshold, raise_severity, lower_severity, sort_findings
from cloud_checks.core.http import HttpError, Response, redact_url
from cloud_checks.core.output import md_table, write_csv
from cloud_checks.core.timeutil import parse_time
from tests.fakes import NETWORK_DOWN, FakeTransport, body_form, json_response


class HttpClientTests(unittest.TestCase):
    def test_retries_429_with_retry_after_then_succeeds(self):
        sleeps = []
        fake = FakeTransport().add("GET", "example.test", [
            Response(429, b"{}", {"Retry-After": "3"}), json_response({"ok": True})])
        client = fake.client(sleep=sleeps.append)
        self.assertEqual(client.request("GET", "https://example.test/x").json(), {"ok": True})
        self.assertEqual(sleeps, [3.0])

    def test_retries_server_errors_and_network_errors(self):
        fake = FakeTransport().add("GET", "example.test", [
            Response(503, b""), NETWORK_DOWN, json_response({"n": 1})])
        self.assertEqual(fake.client(retries=3).request("GET", "https://example.test").json(), {"n": 1})
        self.assertEqual(len(fake.calls), 3)

    def test_gives_up_and_redacts_query_string(self):
        fake = FakeTransport().add("GET", "example.test", Response(500, b'{"error": {"code": "Boom", "message": "bad"}}'))
        with self.assertRaises(HttpError) as ctx:
            fake.client(retries=1).request("GET", "https://example.test/path?key=SECRET&sig=abc")
        self.assertEqual(ctx.exception.status, 500)
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertIn("Boom: bad", str(ctx.exception))
        self.assertEqual(len(fake.calls), 2)

    def test_network_failure_after_retries_is_status_zero(self):
        fake = FakeTransport().add("GET", "example.test", NETWORK_DOWN)
        fake.routes[-1] = ("GET", fake.routes[-1][1], [NETWORK_DOWN])
        with self.assertRaises(HttpError) as ctx:
            fake.client(retries=2).request("GET", "https://example.test")
        self.assertEqual(ctx.exception.status, 0)

    def test_allowed_status_is_returned_not_raised(self):
        fake = FakeTransport().add("GET", "example.test", Response(404, b""))
        self.assertEqual(fake.client().request("GET", "https://example.test", allow=(404,)).status, 404)

    def test_params_form_and_json_bodies(self):
        fake = FakeTransport().add("POST", "example.test", json_response({}))
        client = fake.client()
        client.request("POST", "https://example.test/a", params={"q": "a b"}, form={"x": "1"})
        self.assertIn("q=a+b", fake.calls[-1].url)
        self.assertEqual(body_form(fake.calls[-1]), {"x": "1"})
        client.request("POST", "https://example.test/b", json_body={"k": [1]})
        self.assertEqual(fake.calls[-1].headers["Content-Type"], "application/json")

    def test_redact_url(self):
        self.assertEqual(redact_url("https://h/p?a=1#f"), "https://h/p")


class AuthTests(unittest.TestCase):
    def test_client_secret_token_is_cached_per_scope(self):
        fake = FakeTransport().add("POST", "login.microsoftonline.com/tenant/oauth2/v2.0/token",
                                   json_response({"access_token": "tok", "expires_in": 3600}))
        cred = auth.ClientSecretCredential("tenant", "client", "secret", fake.client())
        self.assertEqual(cred.get_token(auth.ARM_SCOPE), "tok")
        self.assertEqual(cred.get_token(auth.ARM_SCOPE), "tok")
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(body_form(fake.calls[0])["scope"], auth.ARM_SCOPE)
        cred.get_token("https://vault.azure.net/.default")
        self.assertEqual(len(fake.calls), 2)

    def test_client_secret_error_is_readable_and_hides_secret(self):
        fake = FakeTransport().add("POST", "oauth2", json_response(
            {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided.\nTrace"}, 401))
        cred = auth.ClientSecretCredential("tenant", "client", "s3cr3t", fake.client())
        with self.assertRaises(auth.AuthError) as ctx:
            cred.get_token(auth.ARM_SCOPE)
        self.assertIn("AADSTS7000215", str(ctx.exception))
        self.assertNotIn("s3cr3t", str(ctx.exception))

    def test_managed_identity_imds_and_app_service(self):
        fake = FakeTransport().add("GET", "169.254.169.254", json_response(
            {"access_token": "mi", "expires_on": str(int(time.time()) + 3600)}))
        with mock.patch.dict(os.environ, {}, clear=True):
            cred = auth.ManagedIdentityCredential(fake.client(), client_id="cid")
            self.assertEqual(cred.get_token(auth.ARM_SCOPE), "mi")
        self.assertIn("resource=https%3A%2F%2Fmanagement.azure.com", fake.calls[0].url)
        self.assertIn("client_id=cid", fake.calls[0].url)
        fake2 = FakeTransport().add("GET", "identity.local", json_response({"access_token": "app", "expires_on": "9999999999"}))
        with mock.patch.dict(os.environ, {"IDENTITY_ENDPOINT": "http://identity.local/msi", "IDENTITY_HEADER": "h"}, clear=True):
            self.assertEqual(auth.ManagedIdentityCredential(fake2.client()).get_token("https://vault.azure.net/.default"), "app")
        self.assertEqual(fake2.calls[0].headers["X-IDENTITY-HEADER"], "h")

    def test_credential_from_env_selects_mode(self):
        http = FakeTransport().client()
        with mock.patch.dict(os.environ, {"AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "s"}, clear=True):
            self.assertIsInstance(auth.credential_from_env(http), auth.ClientSecretCredential)
        with mock.patch.dict(os.environ, {"USE_MANAGED_IDENTITY": "true"}, clear=True):
            self.assertIsInstance(auth.credential_from_env(http), auth.ManagedIdentityCredential)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsInstance(auth.credential_from_env(http), auth.AzureCliCredential)
        with mock.patch.dict(os.environ, {"AZURE_AUTH": "nope"}, clear=True):
            with self.assertRaises(auth.AuthError):
                auth.credential_from_env(http)
        with mock.patch.dict(os.environ, {"AZURE_AUTH": "secret"}, clear=True):
            with self.assertRaises(auth.AuthError):
                auth.credential_from_env(http)

    def test_azure_cli_missing(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(auth.AuthError):
                auth.AzureCliCredential().get_token(auth.ARM_SCOPE)


class SmallHelpersTests(unittest.TestCase):
    def test_parse_time_handles_microsoft_formats(self):
        self.assertEqual(parse_time("2026-09-30T16:02:11.1234567Z").microsecond, 123456)
        self.assertEqual(parse_time("2026-09-30T16:02:11").tzinfo, timezone.utc)
        self.assertIsNone(parse_time("0001-01-01T00:00:00Z"))
        self.assertIsNone(parse_time("not a date"))
        self.assertIsNone(parse_time(None))

    def test_dotenv_does_not_override_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("# c\nA=1\nexport B='two words'\nC=3 # comment\nEXISTING=file\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"EXISTING": "shell"}, clear=True):
                load_dotenv(path)
                self.assertEqual((os.environ["A"], os.environ["B"], os.environ["C"]), ("1", "two words", "3"))
                self.assertEqual(os.environ["EXISTING"], "shell")
                self.assertEqual(env_int("A", 0), 1)
                self.assertTrue(env_bool("MISSING", True))
                os.environ["L"] = "a, b c"
                self.assertEqual(env_list("L"), ["a", "b", "c"])
                os.environ["BAD"] = "x"
                with self.assertRaises(ValueError):
                    env_int("BAD", 0)

    def test_csv_neutralises_formula_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.csv"
            write_csv(path, [{"a": "=cmd|' /C calc'!A0", "b": ["x", "y"]}], ["a", "b"])
            text = path.read_text(encoding="utf-8")
            self.assertIn("'=cmd", text)
            self.assertIn("x; y", text)

    def test_csv_neutralises_formula_injection_in_list_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.csv"
            write_csv(path, [{"a": ["=HYPERLINK(\"http://x.example\")", "y"], "b": ("+1", "2"), "c": {"k": "=1"}}],
                      ["a", "b", "c"])
            with path.open(newline="", encoding="utf-8") as handle:
                row = list(csv.DictReader(handle))[0]
            self.assertEqual(row["a"], "'=HYPERLINK(\"http://x.example\"); y")
            self.assertEqual(row["b"], "'+1; 2")
            self.assertEqual(row["c"], '{"k": "=1"}')  # JSON text starts with a brace: not a formula

    def test_markdown_table_escapes_pipes_and_newlines(self):
        table = md_table(["h"], [["a|b\nc"]])
        self.assertIn("a\\|b<br>c", table)

    def test_severity_helpers(self):
        self.assertEqual(raise_severity("medium"), "high")
        self.assertEqual(raise_severity("critical"), "critical")
        self.assertEqual(lower_severity("info"), "info")
        findings = [Finding("a", "low", "t", "x", "d"), Finding("b", "critical", "t", "y", "d")]
        self.assertEqual(sort_findings(findings)[0].severity, "critical")
        self.assertTrue(meets_threshold(findings, "high"))
        self.assertFalse(meets_threshold([findings[0]], "medium"))
        self.assertFalse(meets_threshold(findings, "none"))


if __name__ == "__main__":
    unittest.main()
