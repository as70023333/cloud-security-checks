"""Read-only collection from Google Cloud REST APIs into a snapshot.

Every request is a GET, plus ``getIamPolicy`` (a read that Google exposes as POST). An API that is
not enabled in a project means there is nothing of that kind to check, so it counts as empty.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Protocol

from cloud_checks.core.http import HttpClient, HttpError
from cloud_checks.core.timeutil import iso, utcnow

CRM = "https://cloudresourcemanager.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
SQLADMIN = "https://sqladmin.googleapis.com/v1"
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
API_DISABLED_MARKERS = ("SERVICE_DISABLED", "accessNotConfigured", "has not been used in project",
                        "it is disabled")

Log = Callable[[str], None]


class Token(Protocol):
    def get_token(self) -> str: ...


_CONSUMER = re.compile(r'"consumer":\s*"projects/([^"]+)"|project[= ]+([0-9]{6,}|[a-z][a-z0-9-]{4,}[a-z0-9])')


class ApiDisabled(Exception):
    """A service API is not enabled. ``consumer`` is the project Google says it is disabled in."""

    def __init__(self, url: str, consumer: str) -> None:
        super().__init__(url)
        self.consumer = consumer


def _consumer(body: str) -> str:
    found = _CONSUMER.search(body)
    return (found.group(1) or found.group(2)) if found else ""


class GcpApi:
    def __init__(self, http: HttpClient, credential: Token, quota_project: str = "") -> None:
        self.http = http
        self.credential = credential
        self.quota_project = quota_project

    def _headers(self) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.credential.get_token()}"}
        if self.quota_project:
            # User credentials are otherwise metered against the gcloud CLI's own project.
            headers["X-Goog-User-Project"] = self.quota_project
        return headers

    def _call(self, method: str, url: str, params: Mapping[str, str] | None, body: Any = None) -> dict:
        try:
            resp = self.http.request(method, url, params=params, headers=self._headers(), json_body=body, ok=(200,))
        except HttpError as exc:
            if exc.status in (400, 403) and any(marker in exc.body for marker in API_DISABLED_MARKERS):
                raise ApiDisabled(url, _consumer(exc.body)) from exc
            raise
        return resp.json() or {}

    def get(self, url: str, params: Mapping[str, str] | None = None) -> dict:
        return self._call("GET", url, params)

    def post(self, url: str, body: Any) -> dict:
        return self._call("POST", url, None, body)

    def pages(self, url: str, params: Mapping[str, str] | None = None, max_pages: int = 500):
        query = dict(params or {})
        for _ in range(max_pages):
            data = self.get(url, query)
            yield data
            token = data.get("nextPageToken")
            if not token:
                return
            query["pageToken"] = token

    def list(self, url: str, key: str, params: Mapping[str, str] | None = None) -> list[dict]:
        return [item for page in self.pages(url, params) for item in page.get(key) or []]


def projects(api: GcpApi) -> list[dict[str, str]]:
    return [{"id": p.get("projectId", ""), "name": p.get("name", ""), "number": str(p.get("projectNumber", ""))}
            for p in api.list(f"{CRM}/projects", "projects", {"filter": "lifecycleState:ACTIVE"})]


def iam_bindings(api: GcpApi, project: str) -> list[dict[str, Any]]:
    policy = api.post(f"{CRM}/projects/{project}:getIamPolicy", {"options": {"requestedPolicyVersion": 3}})
    return [{"project": project, "role": b.get("role", ""), "members": b.get("members") or [],
             "conditional": bool(b.get("condition"))} for b in policy.get("bindings") or []]


def service_account_keys(api: GcpApi, project: str) -> list[dict[str, Any]]:
    keys = []
    for account in api.list(f"{IAM}/projects/{project}/serviceAccounts", "accounts", {"pageSize": "100"}):
        data = api.get(f"{IAM}/{account['name']}/keys", {"keyTypes": "USER_MANAGED"})
        for key in data.get("keys") or []:
            keys.append({"project": project, "email": account.get("email", ""),
                         "key_id": str(key.get("name", "")).rsplit("/", 1)[-1],
                         "created": key.get("validAfterTime", ""), "disabled": bool(key.get("disabled"))})
    return keys


def buckets(api: GcpApi, project: str) -> list[dict[str, Any]]:
    out = []
    for bucket in api.list(f"{STORAGE}/b", "items", {"project": project, "projection": "noAcl"}):
        config = bucket.get("iamConfiguration") or {}
        prevention = config.get("publicAccessPrevention") or "inherited"
        entry = {"project": project, "name": bucket.get("name", ""), "location": bucket.get("location", ""),
                 "public_access_prevention": prevention,
                 "uniform_access": bool((config.get("uniformBucketLevelAccess") or {}).get("enabled")),
                 "public_bindings": []}
        if prevention != "enforced":  # enforced prevention makes public grants impossible
            policy = api.get(f"{STORAGE}/b/{bucket['name']}/iam", {"optionsRequestedPolicyVersion": "3"})
            for binding in policy.get("bindings") or []:
                for member in binding.get("members") or []:
                    if member in PUBLIC_MEMBERS:
                        entry["public_bindings"].append({"role": binding.get("role", ""), "member": member})
        out.append(entry)
    return out


def firewalls(api: GcpApi, project: str) -> list[dict[str, Any]]:
    return [{"project": project, "name": f.get("name", ""), "network": str(f.get("network", "")).rsplit("/", 1)[-1],
             "direction": f.get("direction", "INGRESS"), "disabled": bool(f.get("disabled")),
             "source_ranges": f.get("sourceRanges") or [],
             "allowed": [{"protocol": a.get("IPProtocol", ""), "ports": a.get("ports") or []}
                         for a in f.get("allowed") or []]}
            for f in api.list(f"{COMPUTE}/projects/{project}/global/firewalls", "items")]


def instances(api: GcpApi, project: str) -> list[dict[str, Any]]:
    out = []
    for page in api.pages(f"{COMPUTE}/projects/{project}/aggregated/instances"):
        for scope, group in (page.get("items") or {}).items():
            for vm in group.get("instances") or []:
                public = [c.get("natIP") for nic in vm.get("networkInterfaces") or []
                          for c in nic.get("accessConfigs") or [] if c.get("natIP")]
                out.append({"project": project, "zone": scope.rsplit("/", 1)[-1], "name": vm.get("name", ""),
                            "status": vm.get("status", ""), "public_ips": public,
                            "service_accounts": [{"email": sa.get("email", ""), "scopes": sa.get("scopes") or []}
                                                 for sa in vm.get("serviceAccounts") or []]})
    return out


def sql_instances(api: GcpApi, project: str) -> list[dict[str, Any]]:
    out = []
    for db in api.list(f"{SQLADMIN}/projects/{project}/instances", "items"):
        settings = db.get("settings") or {}
        ip = settings.get("ipConfiguration") or {}
        out.append({"project": project, "name": db.get("name", ""), "version": db.get("databaseVersion", ""),
                    "region": db.get("region", ""), "instance_type": db.get("instanceType", ""),
                    "public_ip": bool(ip.get("ipv4Enabled")),
                    "authorized_networks": [n.get("value", "") for n in ip.get("authorizedNetworks") or []],
                    "require_ssl": bool(ip.get("requireSsl")), "ssl_mode": ip.get("sslMode") or "",
                    "backups": bool((settings.get("backupConfiguration") or {}).get("enabled"))})
    return out


def _describe(api: GcpApi, project_id: str) -> dict[str, str]:
    """Name and number of a project given by id; the number is needed to read "API disabled" errors."""
    try:
        p = api.get(f"{CRM}/projects/{project_id}")
    except (HttpError, ApiDisabled):
        return {"id": project_id, "name": project_id, "number": ""}
    return {"id": project_id, "name": p.get("name") or project_id, "number": str(p.get("projectNumber") or "")}


SECTIONS: dict[str, Callable[[GcpApi, str], list]] = {
    "iam_bindings": iam_bindings, "service_account_keys": service_account_keys, "buckets": buckets,
    "firewalls": firewalls, "instances": instances, "sql_instances": sql_instances,
}


def collect(api: GcpApi, *, only_projects: list[str] | None = None, log: Log = lambda _m: None) -> dict[str, Any]:
    """Collect everything the checks need. Raises HttpError only if projects cannot be listed."""
    if only_projects:
        chosen = [_describe(api, p) for p in dict.fromkeys(only_projects)]
    else:
        chosen = projects(api)
    data: dict[str, Any] = {"projects": chosen}
    errors: dict[str, str] = {}
    log(f"projects: {len(chosen)}")
    for key, fn in SECTIONS.items():
        collected: list = []
        failures: list[str] = []
        disabled: list[str] = []
        for project in chosen:
            try:
                collected.extend(fn(api, project["id"]))
            except ApiDisabled as exc:
                # Only "disabled in the project being scanned" means there is nothing to check. With
                # user credentials Google may be reporting on the credential's quota project instead,
                # and treating that as "nothing here" would be a false pass.
                if exc.consumer and exc.consumer in (project["id"], project["number"]):
                    disabled.append(project["id"])
                else:
                    failures.append(f"{project['id']}: the API is not usable through project "
                                    f"'{exc.consumer or 'unknown'}' (the credential's quota project). "
                                    "Use --quota-project or --impersonate a service account")
            except HttpError as exc:
                hint = " (grant roles/viewer and roles/iam.securityReviewer)" if exc.status in (401, 403) else ""
                failures.append(f"{project['id']}: {exc}{hint}")
        if failures and len(failures) + len(disabled) == len(chosen):
            data[key] = None
            errors[key] = failures[0]
        else:
            data[key] = collected
            if failures:
                errors[f"{key} (partial)"] = "; ".join(failures)
        if disabled:
            errors[f"{key} (API not enabled)"] = "nothing to check in " + ", ".join(disabled)
        log(f"{key}: {'skipped' if data[key] is None else len(collected)}")
    return {"cloud": "gcp", "captured_at": iso(utcnow()),
            "account": {"id": ", ".join(p["id"] for p in chosen), "name": ", ".join(p["name"] for p in chosen)},
            "data": data, "errors": errors}
