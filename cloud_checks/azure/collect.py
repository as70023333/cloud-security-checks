"""Read-only collection from Azure Resource Manager into a snapshot.

Every request is a GET. The Reader role on each subscription is enough. Sections are collected
independently per subscription: a provider that is not registered or a missing permission skips
that section and is recorded under ``errors``.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Callable, Mapping

from cloud_checks.core.auth import ARM_SCOPE, TokenCredential
from cloud_checks.core.http import HttpClient, HttpError
from cloud_checks.core.timeutil import iso, utcnow

ARM_BASE = "https://management.azure.com"

Log = Callable[[str], None]


class ArmApi:
    """Azure Resource Manager GET client with ``nextLink`` paging."""

    def __init__(self, http: HttpClient, credential: TokenCredential, base: str = ARM_BASE,
                 scope: str = ARM_SCOPE) -> None:
        self.http = http
        self.credential = credential
        self.base = base.rstrip("/")
        self.scope = scope
        self._host = urllib.parse.urlsplit(self.base).netloc.lower()

    def get_all(self, path: str, api_version: str, params: Mapping[str, str] | None = None) -> list[dict]:
        query = {"api-version": api_version, **(params or {})}
        url: str | None = f"{self.base}{path}"
        items: list[dict] = []
        while url:
            # Never send the token to another host, even if a paging link points there.
            if urllib.parse.urlsplit(url).netloc.lower() != self._host:
                raise HttpError(0, "refusing to follow a paging link to another host")
            headers = {"Authorization": f"Bearer {self.credential.get_token(self.scope)}"}
            data = self.http.request("GET", url, params=query, headers=headers, ok=(200,)).json() or {}
            items.extend(data.get("value") or [])
            url = data.get("nextLink")
            query = None  # the next link carries its own query
        return items


def _props(resource: dict) -> dict:
    return resource.get("properties") or {}


def _as_list(single: Any, many: Any) -> list[str]:
    values = list(many or [])
    if single not in (None, ""):
        values.append(single)
    return [str(v) for v in values]


def subscriptions(arm: ArmApi) -> list[dict[str, str]]:
    return [{"id": s.get("subscriptionId", ""), "name": s.get("displayName", "")}
            for s in arm.get_all("/subscriptions", "2022-12-01") if s.get("state") == "Enabled"]


def storage_accounts(arm: ArmApi, sub: str) -> list[dict[str, Any]]:
    out = []
    for item in arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts", "2023-01-01"):
        p = _props(item)
        out.append({"subscription": sub, "id": item.get("id", ""), "name": item.get("name", ""),
                    "location": item.get("location", ""),
                    "allow_blob_public_access": p.get("allowBlobPublicAccess"),
                    "https_only": p.get("supportsHttpsTrafficOnly"),
                    "minimum_tls": p.get("minimumTlsVersion") or "",
                    "network_default_action": (p.get("networkAcls") or {}).get("defaultAction") or "",
                    "public_network_access": p.get("publicNetworkAccess") or ""})
    return out


def network_security_groups(arm: ArmApi, sub: str) -> list[dict[str, Any]]:
    out = []
    for item in arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups", "2023-09-01"):
        p = _props(item)
        rules = []
        for rule in p.get("securityRules") or []:
            r = _props(rule)
            rules.append({"name": rule.get("name", ""), "direction": r.get("direction", ""),
                          "access": r.get("access", ""), "protocol": r.get("protocol", ""),
                          "priority": r.get("priority"),
                          "sources": _as_list(r.get("sourceAddressPrefix"), r.get("sourceAddressPrefixes")),
                          "ports": _as_list(r.get("destinationPortRange"), r.get("destinationPortRanges"))})
        out.append({"subscription": sub, "id": item.get("id", ""), "name": item.get("name", ""),
                    "location": item.get("location", ""),
                    "attached": bool(p.get("subnets") or p.get("networkInterfaces")), "rules": rules})
    return out


def sql_servers(arm: ArmApi, sub: str) -> list[dict[str, Any]]:
    out = []
    for item in arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.Sql/servers", "2021-11-01"):
        rules = [{"name": r.get("name", ""), "start": _props(r).get("startIpAddress", ""),
                  "end": _props(r).get("endIpAddress", "")}
                 for r in arm.get_all(f"{item['id']}/firewallRules", "2021-11-01")]
        out.append({"subscription": sub, "id": item.get("id", ""), "name": item.get("name", ""),
                    "location": item.get("location", ""),
                    "public_network_access": _props(item).get("publicNetworkAccess") or "",
                    "firewall_rules": rules})
    return out


def key_vaults(arm: ArmApi, sub: str) -> list[dict[str, Any]]:
    out = []
    for item in arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults", "2023-07-01"):
        p = _props(item)
        out.append({"subscription": sub, "id": item.get("id", ""), "name": item.get("name", ""),
                    "location": item.get("location", ""), "soft_delete": p.get("enableSoftDelete"),
                    "purge_protection": p.get("enablePurgeProtection"),
                    "public_network_access": p.get("publicNetworkAccess") or "",
                    "network_default_action": (p.get("networkAcls") or {}).get("defaultAction") or ""})
    return out


def defender_plans(arm: ArmApi, sub: str) -> list[dict[str, str]]:
    return [{"subscription": sub, "plan": item.get("name", ""), "tier": _props(item).get("pricingTier", "")}
            for item in arm.get_all(f"/subscriptions/{sub}/providers/Microsoft.Security/pricings", "2024-01-01")]


def role_assignments(arm: ArmApi, sub: str) -> list[dict[str, str]]:
    path = f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments"
    return [{"subscription": sub, "principal_id": _props(a).get("principalId", ""),
             "principal_type": _props(a).get("principalType", ""),
             "role_definition_id": str(_props(a).get("roleDefinitionId", "")).rsplit("/", 1)[-1],
             "scope": _props(a).get("scope", "")}
            for a in arm.get_all(path, "2022-04-01", {"$filter": "atScope()"})]


def custom_roles(arm: ArmApi, sub: str) -> list[dict[str, Any]]:
    path = f"/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions"
    out = []
    for role in arm.get_all(path, "2022-04-01", {"$filter": "type eq 'CustomRole'"}):
        p = _props(role)
        actions = [a for perm in p.get("permissions") or [] for a in perm.get("actions") or []]
        out.append({"subscription": sub, "name": p.get("roleName", ""), "actions": actions,
                    "assignable_scopes": p.get("assignableScopes") or []})
    return out


def activity_log_settings(arm: ArmApi, sub: str) -> list[dict[str, str]]:
    path = f"/subscriptions/{sub}/providers/Microsoft.Insights/diagnosticSettings"
    settings = [{"subscription": sub, "name": s.get("name", "")} for s in arm.get_all(path, "2021-05-01-preview")]
    # An empty-name row records "checked, none found", so a subscription that could not be read is
    # never mistaken for one without a setting.
    return settings or [{"subscription": sub, "name": ""}]


SECTIONS: dict[str, Callable[[ArmApi, str], list]] = {
    "storage_accounts": storage_accounts, "network_security_groups": network_security_groups,
    "sql_servers": sql_servers, "key_vaults": key_vaults, "defender_plans": defender_plans,
    "role_assignments": role_assignments, "custom_roles": custom_roles,
    "activity_log_settings": activity_log_settings,
}
HINT = "assign the Reader role on the subscription"


def collect(arm: ArmApi, *, only_subscriptions: list[str] | None = None, log: Log = lambda _m: None) -> dict[str, Any]:
    """Collect everything the checks need. Raises HttpError only if subscriptions cannot be listed."""
    subs = subscriptions(arm)
    if only_subscriptions:
        wanted = {s.lower() for s in only_subscriptions}
        known = {s["id"].lower() for s in subs}
        missing = sorted(wanted - known)
        if missing:
            raise ValueError(f"subscription(s) not visible to these credentials: {', '.join(missing)}")
        subs = [s for s in subs if s["id"].lower() in wanted]
    data: dict[str, Any] = {"subscriptions": subs}
    errors: dict[str, str] = {}
    log(f"subscriptions: {len(subs)}")
    for key, fn in SECTIONS.items():
        collected: list = []
        failures: list[str] = []
        for sub in subs:
            try:
                collected.extend(fn(arm, sub["id"]))
            except HttpError as exc:
                hint = f" ({HINT})" if exc.status in (401, 403) else ""
                failures.append(f"{sub['name'] or sub['id']}: {exc}{hint}")
        if failures and len(failures) == len(subs):
            data[key] = None
            errors[key] = failures[0]
        else:
            data[key] = collected
            if failures:
                errors[f"{key} (partial)"] = "; ".join(failures)
        log(f"{key}: {'skipped' if data[key] is None else len(collected)}")
    return {"cloud": "azure", "captured_at": iso(utcnow()),
            "account": {"id": ", ".join(s["id"] for s in subs), "name": ", ".join(s["name"] for s in subs)},
            "data": data, "errors": errors}
