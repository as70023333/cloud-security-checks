"""Find AWS credentials without the AWS SDK.

Order:
1. Environment variables (``AWS_ACCESS_KEY_ID`` ...), unless a profile was asked for. This is
   what GitHub Actions' OIDC role assumption and most CI systems provide.
2. The AWS CLI (``aws configure export-credentials``), which resolves everything the CLI can:
   IAM Identity Center (SSO), assumed roles, credential processes.
3. The shared credentials file (``~/.aws/credentials``) for plain access-key profiles.
4. Container credentials (ECS, EKS Pod Identity) and the EC2 instance metadata service.
"""

from __future__ import annotations

import configparser
import json
import os
import shutil
import subprocess
from pathlib import Path

from cloud_checks.aws.sigv4 import Credentials
from cloud_checks.core.http import HttpClient, HttpError

IMDS = "http://169.254.169.254"
ECS_RELATIVE_HOST = "http://169.254.170.2"


class CredentialError(Exception):
    """No usable AWS credentials were found."""


def _from_env() -> Credentials | None:
    key, secret = os.environ.get("AWS_ACCESS_KEY_ID", ""), os.environ.get("AWS_SECRET_ACCESS_KEY", "")
    if key and secret:
        return Credentials(key, secret, os.environ.get("AWS_SESSION_TOKEN", ""), "environment variables")
    return None


def _from_cli(profile: str) -> Credentials | None:
    aws = shutil.which("aws")
    if not aws:
        return None
    cmd = [aws, "configure", "export-credentials", "--format", "process"]
    if profile:
        cmd += ["--profile", profile]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if not data.get("AccessKeyId") or not data.get("SecretAccessKey"):
        return None
    label = f"AWS CLI profile {profile}" if profile else "AWS CLI default profile"
    return Credentials(data["AccessKeyId"], data["SecretAccessKey"], data.get("SessionToken") or "", label)


def _from_file(profile: str) -> Credentials | None:
    path = Path(os.environ.get("AWS_SHARED_CREDENTIALS_FILE") or Path.home() / ".aws" / "credentials")
    if not path.is_file():
        return None
    parser = configparser.RawConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error:
        return None
    section = profile or "default"
    if not parser.has_section(section):
        return None
    key = parser.get(section, "aws_access_key_id", fallback="")
    secret = parser.get(section, "aws_secret_access_key", fallback="")
    if not key or not secret:
        return None
    return Credentials(key, secret, parser.get(section, "aws_session_token", fallback=""),
                       f"shared credentials file [{section}]")


def _from_container(http: HttpClient) -> Credentials | None:
    full = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
    relative = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
    url = full or (ECS_RELATIVE_HOST + relative if relative else "")
    if not url:
        return None
    headers = {}
    token_file = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "")
    if token_file and Path(token_file).is_file():
        headers["Authorization"] = Path(token_file).read_text(encoding="utf-8").strip()
    elif os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN"):
        headers["Authorization"] = os.environ["AWS_CONTAINER_AUTHORIZATION_TOKEN"]
    try:
        data = http.request("GET", url, headers=headers, ok=(200,)).json() or {}
    except (HttpError, ValueError):
        return None
    if data.get("AccessKeyId") and data.get("SecretAccessKey"):
        return Credentials(data["AccessKeyId"], data["SecretAccessKey"], data.get("Token") or "",
                           "container credentials")
    return None


def _from_imds(http: HttpClient) -> Credentials | None:
    if os.environ.get("AWS_EC2_METADATA_DISABLED", "").lower() == "true":
        return None
    try:
        token = http.request("PUT", f"{IMDS}/latest/api/token", ok=(200,),
                             headers={"X-aws-ec2-metadata-token-ttl-seconds": "300"}).text.strip()
        headers = {"X-aws-ec2-metadata-token": token}
        base = f"{IMDS}/latest/meta-data/iam/security-credentials/"
        role = http.request("GET", base, headers=headers, ok=(200,)).text.strip().splitlines()[0]
        data = http.request("GET", base + role, headers=headers, ok=(200,)).json() or {}
    except (HttpError, ValueError, IndexError):
        return None
    if data.get("AccessKeyId") and data.get("SecretAccessKey"):
        return Credentials(data["AccessKeyId"], data["SecretAccessKey"], data.get("Token") or "",
                           f"EC2 instance role {role}")
    return None


def resolve(profile: str = "", metadata_http: HttpClient | None = None) -> Credentials:
    profile = profile or os.environ.get("AWS_PROFILE", "")
    if not profile:
        found = _from_env()
        if found:
            return found
    for finder in (_from_cli, _from_file):
        found = finder(profile)
        if found:
            return found
    if profile:
        raise CredentialError(f"no credentials for AWS profile '{profile}'. Run 'aws sso login --profile "
                              f"{profile}' or check ~/.aws/credentials.")
    # Metadata endpoints are link-local: fail fast when not running in AWS.
    quick = metadata_http or HttpClient(timeout=2.0, retries=0)
    for finder in (_from_container, _from_imds):
        found = finder(quick)
        if found:
            return found
    raise CredentialError("no AWS credentials found. Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, use "
                          "--profile, run 'aws sso login', or run on a host with an IAM role.")
