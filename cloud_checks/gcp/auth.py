"""Google Cloud access tokens without the Google SDK.

Order:
1. ``GOOGLE_OAUTH_ACCESS_TOKEN`` (or ``CLOUDSDK_AUTH_ACCESS_TOKEN``): a token you already have,
   for example from Workload Identity Federation in CI.
2. The gcloud CLI (``gcloud auth print-access-token``), optionally impersonating a service account.
3. The metadata server, when running on Compute Engine, Cloud Run, GKE or Cloud Shell.

Service account key files are deliberately not supported: long-lived keys are one of the things
this scanner reports. Use impersonation or workload identity instead.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time

from cloud_checks.core.http import HttpClient, HttpError

METADATA_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
_REFRESH_MARGIN = 300


class GcpAuthError(Exception):
    """No Google Cloud access token could be obtained."""


class GcpCredential:
    def __init__(self, impersonate: str = "", metadata_http: HttpClient | None = None) -> None:
        self.impersonate = impersonate
        self._metadata_http = metadata_http or HttpClient(timeout=2.0, retries=0)
        self._token = ""
        self._expires = 0.0
        self._lock = threading.Lock()
        self.source = ""

    def get_token(self) -> str:
        with self._lock:
            if self._token and self._expires - _REFRESH_MARGIN > time.time():
                return self._token
            self._token, self._expires, self.source = self._fetch()
            return self._token

    def _fetch(self) -> tuple[str, float, str]:
        env = os.environ.get("GOOGLE_OAUTH_ACCESS_TOKEN") or os.environ.get("CLOUDSDK_AUTH_ACCESS_TOKEN")
        if env and not self.impersonate:
            # Lifetime unknown: treat as valid for the run (tokens last an hour).
            return env.strip(), time.time() + 3600, "access token from the environment"
        gcloud = shutil.which("gcloud")
        if gcloud:
            cmd = [gcloud, "auth", "print-access-token"]
            if self.impersonate:
                cmd.append(f"--impersonate-service-account={self.impersonate}")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise GcpAuthError(f"gcloud could not produce a token: {exc}") from exc
            token = proc.stdout.strip()
            if proc.returncode == 0 and token:
                label = f"gcloud, impersonating {self.impersonate}" if self.impersonate else "gcloud"
                return token, time.time() + 1800, label
            message = (proc.stderr or "").strip().splitlines()
            raise GcpAuthError("gcloud could not produce a token: " + (message[-1] if message else "unknown error")
                               + ". Run 'gcloud auth login'.")
        if self.impersonate:
            raise GcpAuthError("--impersonate needs the gcloud CLI, which was not found")
        try:
            data = self._metadata_http.request("GET", METADATA_URL, headers={"Metadata-Flavor": "Google"},
                                               ok=(200,)).json() or {}
        except (HttpError, ValueError):
            data = {}
        if data.get("access_token"):
            return data["access_token"], time.time() + float(data.get("expires_in", 600)), "metadata server"
        raise GcpAuthError("no Google Cloud credentials found. Run 'gcloud auth login', set "
                           "GOOGLE_OAUTH_ACCESS_TOKEN, or run on a Google Cloud host with a service account.")
