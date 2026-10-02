"""cloud-checks: read-only misconfiguration scanners for AWS, Azure and Google Cloud."""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from cloud_checks import __version__
from cloud_checks.core import engine
from cloud_checks.core.env import env_int, env_list, env_str, load_dotenv
from cloud_checks.core.findings import SEVERITIES, meets_threshold
from cloud_checks.core.http import HttpClient, HttpError
from cloud_checks.core.output import color_enabled, paint, parse_formats, to_json, write_text
from cloud_checks.report import CLOUD_NAMES, catalog_markdown, print_summary, write_reports

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

EPILOG = """examples:
  cloud-checks aws --demo                          try it offline on a fictional account
  cloud-checks aws --profile audit                 scan an AWS account (all enabled regions)
  cloud-checks aws --region us-east-1,eu-west-1 --checks s3,iam
  cloud-checks azure --subscription <id>           scan one Azure subscription
  cloud-checks gcp --project my-project            scan a Google Cloud project
  cloud-checks aws --save-snapshot aws.json        keep the raw data, then re-check it offline:
  cloud-checks aws --snapshot aws.json --fail-on critical
  cloud-checks list --cloud aws                    show every check

exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 error"""


class UsageError(Exception):
    """A problem the user can fix: bad arguments, missing credentials, unreadable file."""


def _csv(values: list[str] | None, env_name: str = "") -> list[str]:
    raw = values if values else (env_list(env_name) if env_name else [])
    return [part.strip() for value in raw for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-checks", epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Read-only misconfiguration scanners for AWS, Azure and Google Cloud.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="{aws,azure,gcp,list}")

    def scan_parser(name: str, help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.add_argument("--demo", action="store_true", help="use the built-in fictional account (no credentials)")
        p.add_argument("--snapshot", metavar="FILE", help="check a snapshot saved with --save-snapshot")
        p.add_argument("--save-snapshot", metavar="FILE", help="also save the collected data as JSON")
        p.add_argument("--checks", action="append", metavar="LIST",
                       help="only these check ids or services, comma-separated (e.g. s3,aws-iam-root-mfa)")
        p.add_argument("--skip", action="append", metavar="LIST", help="check ids or services to leave out")
        p.add_argument("--out", metavar="DIR", default="reports", help="report folder (default: reports)")
        p.add_argument("--format", default="md,csv,json", metavar="LIST", help="report formats: md, csv, json")
        p.add_argument("--fail-on", default="high", choices=[*SEVERITIES, "none"],
                       help="exit 1 when a finding is at or above this severity (default: high)")
        p.add_argument("--env-file", default=".env", metavar="PATH", help="settings file (default: .env)")
        p.add_argument("--quiet", action="store_true", help="print only the report paths")
        p.add_argument("--no-color", action="store_true", help="disable coloured output")
        return p

    aws = scan_parser("aws", "Scan an AWS account.")
    aws.add_argument("--profile", default="", help="AWS CLI profile (default: environment or default profile)")
    aws.add_argument("--region", action="append", metavar="LIST",
                     help="regions to scan, comma-separated (default: every enabled region)")
    azure = scan_parser("azure", "Scan Azure subscriptions.")
    azure.add_argument("--subscription", action="append", metavar="ID",
                       help="subscription id(s) (default: every subscription the identity can read)")
    gcp = scan_parser("gcp", "Scan Google Cloud projects.")
    gcp.add_argument("--project", action="append", metavar="ID",
                     help="project id(s) (default: every active project the identity can list)")
    gcp.add_argument("--impersonate", default="", metavar="SERVICE_ACCOUNT",
                     help="service account to impersonate through gcloud")
    gcp.add_argument("--quota-project", default="", metavar="ID",
                     help="project to bill API quota to when signed in as a user (X-Goog-User-Project)")

    lst = sub.add_parser("list", help="List the checks.", description="List the checks.")
    lst.add_argument("--cloud", choices=engine.CLOUDS, help="only this cloud")
    lst.add_argument("--format", choices=("table", "md"), default="table")
    return parser


# --------------------------------------------------------------------------------------------- collection

def _demo(cloud: str) -> dict[str, Any]:
    return json.loads(resources.files(f"cloud_checks.{cloud}").joinpath("demo.json").read_text(encoding="utf-8"))


def _collect_aws(args: argparse.Namespace, log: Callable[[str], None]) -> dict[str, Any]:
    from cloud_checks.aws.api import AwsClient, AwsError
    from cloud_checks.aws.collect import collect
    from cloud_checks.aws.credentials import CredentialError, resolve

    try:
        credentials = resolve(args.profile)
    except CredentialError as exc:
        raise UsageError(str(exc)) from exc
    log(f"credentials: {credentials.source}")
    client = AwsClient(HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 30))), credentials)
    try:
        return collect(client, only_regions=_csv(args.region, "AWS_REGIONS") or None, log=log)
    except AwsError as exc:
        raise UsageError(f"could not identify the AWS account: {exc}") from exc


def _collect_azure(args: argparse.Namespace, log: Callable[[str], None]) -> dict[str, Any]:
    from cloud_checks.azure.collect import ARM_BASE, ARM_SCOPE, ArmApi, collect
    from cloud_checks.core.auth import AuthError, credential_from_env

    http = HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 30)))
    base = env_str("AZURE_ARM_BASE_URL", ARM_BASE)
    try:
        arm = ArmApi(http, credential_from_env(http), base, f"{base.rstrip('/')}/.default" if base != ARM_BASE else ARM_SCOPE)
        return collect(arm, only_subscriptions=_csv(args.subscription, "AZURE_SUBSCRIPTION_IDS") or None, log=log)
    except (AuthError, ValueError) as exc:
        raise UsageError(str(exc)) from exc
    except HttpError as exc:
        raise UsageError(f"could not list Azure subscriptions: {exc}") from exc


def _collect_gcp(args: argparse.Namespace, log: Callable[[str], None]) -> dict[str, Any]:
    from cloud_checks.gcp.auth import GcpAuthError, GcpCredential
    from cloud_checks.gcp.collect import GcpApi, collect

    api = GcpApi(HttpClient(timeout=float(env_int("HTTP_TIMEOUT_SECONDS", 30))), GcpCredential(args.impersonate),
                 args.quota_project or env_str("GCP_QUOTA_PROJECT"))
    try:
        return collect(api, only_projects=_csv(args.project, "GCP_PROJECT_IDS") or None, log=log)
    except GcpAuthError as exc:
        raise UsageError(str(exc)) from exc
    except HttpError as exc:
        raise UsageError(f"could not list Google Cloud projects: {exc}. Pass --project <id>.") from exc


COLLECTORS = {"aws": _collect_aws, "azure": _collect_azure, "gcp": _collect_gcp}


# --------------------------------------------------------------------------------------------- commands

def _list(args: argparse.Namespace) -> int:
    engine.load_checks()
    clouds = [args.cloud] if args.cloud else list(engine.CLOUDS)
    checks = [c for cloud in clouds for c in engine.checks_for(cloud)]
    if args.format == "md":
        print(catalog_markdown(checks), end="")
        return EXIT_OK
    for c in checks:
        print(f"{c.severity:<9} {c.id:<38} {c.title}" + (f"  [CIS {c.cis}]" if c.cis else ""))
    print(f"{len(checks)} checks")
    return EXIT_OK


def _scan(args: argparse.Namespace) -> int:
    cloud = args.command
    load_dotenv(args.env_file)
    formats = parse_formats(args.format, ("md", "csv", "json"))
    checks = engine.select(cloud, _csv(args.checks), _csv(args.skip))
    if not checks:
        raise UsageError("no checks selected")
    log = (lambda _m: None) if args.quiet else (lambda m: print(f"  {m}", file=sys.stderr))

    if args.demo:
        snapshot, source = _demo(cloud), "built-in demo account (fictional data)"
    elif args.snapshot:
        try:
            snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise UsageError(f"cannot read snapshot {args.snapshot}: {exc}") from exc
        if snapshot.get("cloud") != cloud:
            raise UsageError(f"{args.snapshot} is a {snapshot.get('cloud')} snapshot, not {cloud}")
        source = f"snapshot {args.snapshot}"
    else:
        if not args.quiet:
            print(f"Collecting from {CLOUD_NAMES[cloud]} (read-only)...", file=sys.stderr)
        snapshot, source = COLLECTORS[cloud](args, log), f"{CLOUD_NAMES[cloud]} APIs"
    if args.save_snapshot:
        write_text(Path(args.save_snapshot), to_json(snapshot))

    results = engine.run(snapshot, checks)
    stamp = str(snapshot.get("captured_at") or "")[:10] or "undated"
    paths = write_reports(Path(args.out), f"{cloud}-security-check-{stamp}", formats, snapshot, results, source)
    if not args.quiet:
        use_color = color_enabled(disabled=args.no_color)
        print_summary(results, lambda sev, text: paint(sev, text, use_color))
        for r in results:
            if r.status == engine.SKIPPED:
                print(f"  note: {r.check.id} skipped: {r.reason}", file=sys.stderr)
    for path in paths:
        print(f"Report: {path}")
    return EXIT_FINDINGS if meets_threshold(engine.to_findings(results), args.fail_on) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _list(args) if args.command == "list" else _scan(args)
    except (UsageError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
