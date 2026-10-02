"""Microsoft Entra ID tokens without the Azure SDK.

Three ways to authenticate, chosen with AZURE_AUTH (or automatically):

* ``secret``           app registration + client secret (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
* ``managed_identity`` Azure managed identity (Container Apps, Functions, Automation, VMs)
* ``cli``              the signed-in Azure CLI user (``az login``), handy for one-off audits

Tokens are cached per scope until five minutes before they expire.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from typing import Protocol

from cloud_checks.core.http import HttpClient, HttpError

ARM_SCOPE = "https://management.azure.com/.default"
DEFAULT_AUTHORITY = "https://login.microsoftonline.com"
_REFRESH_MARGIN = 300


class AuthError(Exception):
    """A token could not be obtained."""


class TokenCredential(Protocol):
    def get_token(self, scope: str) -> str: ...


class _CachedCredential:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get_token(self, scope: str) -> str:
        with self._lock:
            cached = self._cache.get(scope)
            if cached and cached[1] - _REFRESH_MARGIN > time.time():
                return cached[0]
            token, expires_at = self._fetch(scope)
            self._cache[scope] = (token, expires_at)
            return token

    def _fetch(self, scope: str) -> tuple[str, float]:  # pragma: no cover - abstract
        raise NotImplementedError


class ClientSecretCredential(_CachedCredential):
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, http: HttpClient,
                 authority: str = DEFAULT_AUTHORITY) -> None:
        super().__init__()
        if not (tenant_id and client_id and client_secret):
            raise AuthError("AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are all required")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self._secret = client_secret
        self.http = http
        self.authority = authority.rstrip("/")

    def _fetch(self, scope: str) -> tuple[str, float]:
        url = f"{self.authority}/{self.tenant_id}/oauth2/v2.0/token"
        try:
            resp = self.http.request(
                "POST", url,
                form={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self._secret, "scope": scope},
                ok=(200,), allow=(400, 401, 403),
            )
        except HttpError as exc:
            raise AuthError(f"token request failed: {exc}") from exc
        data = resp.json() or {}
        if resp.status != 200 or "access_token" not in data:
            detail = str(data.get("error_description") or data.get("error") or "unknown error").splitlines()[0]
            raise AuthError(f"token request for {scope} failed: {detail}")
        return data["access_token"], time.time() + float(data.get("expires_in", 3600))


class ManagedIdentityCredential(_CachedCredential):
    """App Service / Container Apps / Functions identity endpoint, or the VM IMDS endpoint."""

    IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"

    def __init__(self, http: HttpClient, client_id: str = "") -> None:
        super().__init__()
        self.http = http
        self.client_id = client_id

    def _fetch(self, scope: str) -> tuple[str, float]:
        resource = scope[: -len("/.default")] if scope.endswith("/.default") else scope
        endpoint = os.environ.get("IDENTITY_ENDPOINT")
        header = os.environ.get("IDENTITY_HEADER")
        if endpoint and header:
            params = {"resource": resource, "api-version": "2019-08-01"}
            headers = {"X-IDENTITY-HEADER": header}
            url = endpoint
        else:
            params = {"resource": resource, "api-version": "2018-02-01"}
            headers = {"Metadata": "true"}
            url = self.IMDS
        if self.client_id:
            params["client_id"] = self.client_id
        try:
            resp = self.http.request("GET", url, params=params, headers=headers, ok=(200,),
                                     allow=(400, 401, 403, 404))
        except HttpError as exc:
            raise AuthError(f"managed identity endpoint unreachable: {exc}") from exc
        data = resp.json() or {}
        if resp.status != 200 or "access_token" not in data:
            detail = data.get("error_description") or data.get("message") or f"HTTP {resp.status}"
            raise AuthError(f"managed identity token for {resource} failed: {detail}")
        expires_on = data.get("expires_on")
        try:
            expires_at = float(expires_on)
        except (TypeError, ValueError):
            expires_at = time.time() + float(data.get("expires_in", 3600))
        return data["access_token"], expires_at


class AzureCliCredential(_CachedCredential):
    """Uses ``az account get-access-token``. Good for ad-hoc runs by a signed-in admin."""

    def __init__(self, tenant_id: str = "", timeout: float = 30.0) -> None:
        super().__init__()
        self.tenant_id = tenant_id
        self.timeout = timeout

    def _fetch(self, scope: str) -> tuple[str, float]:
        az = shutil.which("az")
        if not az:
            raise AuthError("Azure CLI not found. Install it and run 'az login', or set AZURE_CLIENT_SECRET "
                            "or USE_MANAGED_IDENTITY=true.")
        cmd = [az, "account", "get-access-token", "--scope", scope, "--output", "json"]
        if self.tenant_id:
            cmd += ["--tenant", self.tenant_id]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise AuthError("Azure CLI timed out getting a token") from exc
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "unknown error").strip().splitlines()
            raise AuthError(f"Azure CLI could not get a token for {scope}: {message[0] if message else ''}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AuthError("Azure CLI returned output that is not JSON") from exc
        token = data.get("accessToken")
        if not token:
            raise AuthError("Azure CLI response had no accessToken")
        try:
            expires_at = float(data.get("expires_on"))
        except (TypeError, ValueError):
            expires_at = time.time() + 600  # be conservative when only a local-time string is given
        return token, expires_at


def credential_from_env(http: HttpClient) -> TokenCredential:
    """Pick a credential from environment variables (see module docstring)."""
    mode = os.environ.get("AZURE_AUTH", "").strip().lower()
    tenant = os.environ.get("AZURE_TENANT_ID", "").strip()
    client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
    secret = os.environ.get("AZURE_CLIENT_SECRET", "").strip()
    use_mi = os.environ.get("USE_MANAGED_IDENTITY", "").strip().lower() in ("1", "true", "yes", "on")
    authority = os.environ.get("AZURE_AUTHORITY_HOST", DEFAULT_AUTHORITY).strip() or DEFAULT_AUTHORITY
    if not mode:
        mode = "secret" if secret else ("managed_identity" if use_mi else "cli")
    if mode == "secret":
        return ClientSecretCredential(tenant, client_id, secret, http, authority)
    if mode in ("managed_identity", "mi", "msi"):
        return ManagedIdentityCredential(http, client_id)
    if mode in ("cli", "azure_cli", "az"):
        return AzureCliCredential(tenant)
    raise AuthError(f"Unknown AZURE_AUTH value {mode!r}; use secret, managed_identity or cli")
