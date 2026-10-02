import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cloud_checks import cli
from cloud_checks.core import engine
from cloud_checks.report import catalog_markdown, render_markdown

REPO = Path(__file__).resolve().parent.parent


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main([*argv])
        except SystemExit as exc:  # argparse errors
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class ScanTests(unittest.TestCase):
    def test_demo_writes_reports_for_every_cloud(self):
        for cloud in engine.CLOUDS:
            with self.subTest(cloud=cloud), tempfile.TemporaryDirectory() as tmp:
                code, out, _ = run(cloud, "--demo", "--out", tmp, "--env-file", "/nonexistent", "--no-color")
                self.assertEqual(code, 1)  # the demo accounts have high and critical findings
                names = sorted(p.name for p in Path(tmp).iterdir())
                stem = f"{cloud}-security-check-2026-10-01"
                self.assertEqual(names, [f"{stem}.csv", f"{stem}.json", f"{stem}.md"])
                self.assertIn("failed", out)
                payload = json.loads((Path(tmp) / f"{stem}.json").read_text(encoding="utf-8"))
                self.assertEqual(payload["cloud"], cloud)
                self.assertEqual(payload["summary"]["checks"]["skipped"], 0)
                self.assertEqual(len(payload["findings"]), sum(c["findings"] for c in payload["checks"]))
                markdown = (Path(tmp) / f"{stem}.md").read_text(encoding="utf-8")
                self.assertIn("## Check results", markdown)
                self.assertIn("**Why it matters:**", markdown)
                self.assertIn("Read-only: nothing was changed.", markdown)
                csv_text = (Path(tmp) / f"{stem}.csv").read_text(encoding="utf-8")
                self.assertTrue(csv_text.startswith("severity,check,title,resource,region,detail,fix,cis"))

    def test_fail_on_and_check_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = ["aws", "--demo", "--out", tmp, "--quiet", "--env-file", "/x", "--format", "json"]
            self.assertEqual(run(*base, "--fail-on", "none")[0], 0)
            self.assertEqual(run(*base, "--checks", "guardduty")[0], 0)  # only medium findings, threshold is high
            self.assertEqual(run(*base, "--checks", "guardduty", "--fail-on", "medium")[0], 1)
            self.assertEqual(run(*base, "--checks", "aws-iam-root-access-key", "--fail-on", "info")[0], 0)
            code, _, _ = run(*base, "--checks", "s3,rds", "--skip", "aws-s3-bucket-tls")
            payload = json.loads((Path(tmp) / "aws-security-check-2026-10-01.json").read_text(encoding="utf-8"))
            self.assertEqual({c["service"] for c in payload["checks"]}, {"s3", "rds"})
            self.assertNotIn("aws-s3-bucket-tls", {c["id"] for c in payload["checks"]})
            self.assertEqual(code, 1)

    def test_snapshot_round_trip_and_coverage_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved = Path(tmp) / "snap.json"
            run("gcp", "--demo", "--out", tmp, "--quiet", "--env-file", "/x", "--save-snapshot", str(saved))
            snapshot = json.loads(saved.read_text(encoding="utf-8"))
            snapshot["data"]["sql_instances"] = None
            snapshot["errors"] = {"sql_instances": "HTTP 403: denied", "buckets (partial)": "proj-x: HTTP 500"}
            saved.write_text(json.dumps(snapshot), encoding="utf-8")
            code, _, err = run("gcp", "--snapshot", str(saved), "--out", tmp, "--env-file", "/x", "--format", "md")
            self.assertEqual(code, 1)
            self.assertIn("gcp-sql-public-network skipped", err)
            markdown = (Path(tmp) / "gcp-security-check-2026-10-01.md").read_text(encoding="utf-8")
            self.assertIn("## Coverage notes", markdown)
            self.assertIn("`gcp-sql-no-ssl`: sql_instances: HTTP 403: denied", markdown)
            self.assertIn("buckets (partial): proj-x: HTTP 500", markdown)
            self.assertIn("⚪ SKIPPED", markdown)
            # a snapshot for another cloud is rejected
            self.assertEqual(run("aws", "--snapshot", str(saved), "--env-file", "/x")[0], 2)

    def test_errors_are_explained_with_exit_code_2(self):
        self.assertEqual(run("aws", "--demo", "--checks", "nope", "--env-file", "/x")[0], 2)
        self.assertEqual(run("aws", "--demo", "--format", "pdf", "--env-file", "/x")[0], 2)
        self.assertEqual(run("aws", "--snapshot", "/no/such/file.json", "--env-file", "/x")[0], 2)
        self.assertEqual(run()[0], 2)
        with mock.patch.dict(os.environ, {"AWS_SHARED_CREDENTIALS_FILE": "/nonexistent", "AWS_EC2_METADATA_DISABLED": "true"},
                             clear=True), mock.patch("shutil.which", return_value=None):
            code, _, err = run("aws", "--env-file", "/x", "--quiet")
            self.assertEqual(code, 2)
            self.assertIn("no AWS credentials found", err)
            code, _, err = run("azure", "--env-file", "/x", "--quiet")
            self.assertEqual(code, 2)
            self.assertIn("Azure CLI not found", err)

    def test_hostile_resource_names_are_escaped(self):
        snapshot = {"cloud": "gcp", "captured_at": "2026-10-01T12:00:00Z", "account": {"id": "p"}, "errors": {},
                    "data": {"buckets": [{"project": "p", "name": "a|b\n=cmd()", "location": "US",
                                          "public_access_prevention": "inherited", "uniform_access": False,
                                          "public_bindings": []}]}}
        results = engine.run(snapshot, engine.select("gcp", ["gcp-storage-uniform-access"]))
        markdown = render_markdown(snapshot, results, "test")
        self.assertIn("a\\|b<br>=cmd()", markdown)


class ListTests(unittest.TestCase):
    def test_list_table(self):
        code, out, _ = run("list", "--cloud", "azure")
        self.assertEqual(code, 0)
        self.assertIn("azure-storage-https-only", out)
        self.assertIn("[CIS 3.1]", out)
        self.assertNotIn("aws-", out)
        self.assertIn("14 checks", out)

    def test_catalog_document_is_current(self):
        engine.load_checks()
        checks = [c for cloud in engine.CLOUDS for c in engine.checks_for(cloud)]
        expected = catalog_markdown(checks)
        self.assertEqual(run("list", "--format", "md")[1], expected)
        self.assertEqual((REPO / "docs" / "CHECKS.md").read_text(encoding="utf-8"), expected,
                         "run: cloud-checks list --format md > docs/CHECKS.md")


if __name__ == "__main__":
    unittest.main()
