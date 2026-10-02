"""Azure checks. Pure functions over the collected snapshot data.

CIS numbers refer to the CIS Microsoft Azure Foundations Benchmark v2.0.0 and are given only
where they were verified against Microsoft's published Azure Policy mapping.
"""

from __future__ import annotations

from typing import Any, Iterator

from cloud_checks.core.engine import Hit, check
from cloud_checks.core.ports import exposure, is_internet, parse_port_range

OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
MAX_OWNERS = 3
# Defender for Cloud plans that protect the resource types this scanner looks at.
KEY_PLANS = {"VirtualMachines": "Servers", "StorageAccounts": "Storage", "SqlServers": "Azure SQL",
             "KeyVaults": "Key Vault", "Arm": "Resource Manager"}
WEAK_TLS = {"TLS1_0", "TLS1_1"}


def _sub_names(data: dict[str, Any]) -> dict[str, str]:
    return {s["id"]: s.get("name") or s["id"] for s in data.get("subscriptions") or []}


def _label(data: dict[str, Any], resource: dict[str, Any]) -> str:
    sub = _sub_names(data).get(resource.get("subscription", ""), resource.get("subscription", ""))
    return f"{resource.get('name')} ({sub})"


# --------------------------------------------------------------------------------------------- storage

@check(id="azure-storage-public-blob-access", cloud="azure", service="storage", severity="high", cis="3.7",
       title="Storage account allows anonymous blob access", needs=["storage_accounts"],
       why="Any container in the account can be made readable by anyone on the internet with one setting.",
       fix="Set 'Allow Blob anonymous access' to Disabled on the storage account.")
def storage_public_blob(data: dict[str, Any]) -> Iterator[Hit]:
    for account in data["storage_accounts"]:
        if account.get("allow_blob_public_access") is True:
            yield Hit(_label(data, account), "allowBlobPublicAccess is enabled.", region=account.get("location", ""))


@check(id="azure-storage-https-only", cloud="azure", service="storage", severity="high", cis="3.1",
       title="Storage account accepts plain HTTP", needs=["storage_accounts"],
       why="Data and access keys can cross the network unencrypted.",
       fix="Set 'Secure transfer required' to Enabled.")
def storage_https(data: dict[str, Any]) -> Iterator[Hit]:
    for account in data["storage_accounts"]:
        if account.get("https_only") is False:
            yield Hit(_label(data, account), "Secure transfer (HTTPS only) is not required.",
                      region=account.get("location", ""))


@check(id="azure-storage-min-tls", cloud="azure", service="storage", severity="medium", cis="3.15",
       title="Storage account allows TLS older than 1.2", needs=["storage_accounts"],
       why="TLS 1.0 and 1.1 have known weaknesses and are retired across Azure services.",
       fix="Set the minimum TLS version to 1.2.")
def storage_tls(data: dict[str, Any]) -> Iterator[Hit]:
    for account in data["storage_accounts"]:
        if account.get("minimum_tls") in WEAK_TLS:
            yield Hit(_label(data, account), f"Minimum TLS version is {account['minimum_tls']}.",
                      region=account.get("location", ""))


@check(id="azure-storage-network-default-allow", cloud="azure", service="storage", severity="medium", cis="3.8",
       title="Storage account is reachable from all networks", needs=["storage_accounts"],
       why="With the default network rule set to Allow, a leaked key or SAS token works from anywhere.",
       fix="Set the default network access rule to Deny and allow only the virtual networks, private "
           "endpoints or IP ranges that need access.")
def storage_network(data: dict[str, Any]) -> Iterator[Hit]:
    for account in data["storage_accounts"]:
        if account.get("public_network_access") == "Disabled":
            continue
        if account.get("network_default_action") == "Allow":
            yield Hit(_label(data, account), "Default network access rule is Allow.", region=account.get("location", ""))


# --------------------------------------------------------------------------------------------- network

def _open_rules(nsg: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, object]]]:
    """Inbound Allow rules whose source is the internet, with what each port range exposes."""
    for rule in nsg.get("rules", []):
        if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
            continue
        if not any(is_internet(source) for source in rule.get("sources", [])):
            continue
        combined: dict[str, Any] = {"all": False, "admin": [], "sensitive": []}
        for port in rule.get("ports", []):
            for part in str(port).split(","):
                parsed = parse_port_range(part)
                if parsed is None:
                    continue
                exposed = exposure(rule.get("protocol", ""), parsed[0], parsed[1])
                combined["all"] = combined["all"] or bool(exposed["all"])
                combined["admin"] += [p for p in exposed["admin"] if p not in combined["admin"]]
                combined["sensitive"] += [p for p in exposed["sensitive"] if p not in combined["sensitive"]]
        yield rule, combined


def _nsg_hit(data: dict[str, Any], nsg: dict[str, Any], rule: dict[str, Any], what: str) -> Hit:
    note = "" if nsg.get("attached") else " The NSG is not attached to any subnet or network interface."
    return Hit(_label(data, nsg), f"Rule '{rule.get('name')}' allows {what} from the internet.{note}",
               region=nsg.get("location", ""), severity=None if nsg.get("attached") else "low",
               evidence={"rule": rule.get("name"), "priority": rule.get("priority")})


@check(id="azure-nsg-open-all-ports", cloud="azure", service="network", severity="critical",
       title="Network security group allows all ports from the internet", needs=["network_security_groups"],
       why="Every service on every attached machine is reachable by anyone.",
       fix="Replace the rule with the specific ports and source ranges that are needed.")
def nsg_open_all(data: dict[str, Any]) -> Iterator[Hit]:
    for nsg in data["network_security_groups"]:
        for rule, exposed in _open_rules(nsg):
            if exposed["all"]:
                yield _nsg_hit(data, nsg, rule, "all ports")


@check(id="azure-nsg-open-admin-ports", cloud="azure", service="network", severity="high",
       title="Network security group allows SSH or RDP from the internet", needs=["network_security_groups"],
       why="Internet-facing SSH and RDP are brute-forced constantly and are a leading entry point for "
           "ransomware.",
       fix="Remove the rule and use Azure Bastion or just-in-time VM access, or restrict the source range.")
def nsg_open_admin(data: dict[str, Any]) -> Iterator[Hit]:
    for nsg in data["network_security_groups"]:
        for rule, exposed in _open_rules(nsg):
            if exposed["admin"]:
                yield _nsg_hit(data, nsg, rule, ", ".join(exposed["admin"]))


@check(id="azure-nsg-open-sensitive-ports", cloud="azure", service="network", severity="high",
       title="Network security group exposes a database or internal service to the internet",
       needs=["network_security_groups"],
       why="Databases, caches and management APIs are not built to face the internet.",
       fix="Allow these ports only from application subnets or private ranges; prefer private endpoints.")
def nsg_open_sensitive(data: dict[str, Any]) -> Iterator[Hit]:
    for nsg in data["network_security_groups"]:
        for rule, exposed in _open_rules(nsg):
            if exposed["sensitive"]:
                yield _nsg_hit(data, nsg, rule, ", ".join(exposed["sensitive"]))


# --------------------------------------------------------------------------------------------- data services

@check(id="azure-sql-firewall-any-ip", cloud="azure", service="sql", severity="critical", cis="4.1.2",
       title="Azure SQL server firewall allows any IP address", needs=["sql_servers"],
       why="The database accepts connections from the whole internet; only the password protects it.",
       fix="Delete the rule and allow specific ranges, or disable public network access and use a private "
           "endpoint.")
def sql_any_ip(data: dict[str, Any]) -> Iterator[Hit]:
    for server in data["sql_servers"]:
        if server.get("public_network_access") == "Disabled":
            continue
        for rule in server.get("firewall_rules", []):
            start, end = rule.get("start"), rule.get("end")
            if start == "0.0.0.0" and end == "255.255.255.255":
                yield Hit(_label(data, server), f"Firewall rule '{rule.get('name')}' allows 0.0.0.0 to "
                          "255.255.255.255.", region=server.get("location", ""))
            elif start == "0.0.0.0" and end == "0.0.0.0":
                yield Hit(_label(data, server), f"Firewall rule '{rule.get('name')}' allows all Azure services, "
                          "including other customers' subscriptions.", region=server.get("location", ""),
                          severity="medium")


@check(id="azure-keyvault-purge-protection", cloud="azure", service="keyvault", severity="medium",
       title="Key vault can be permanently deleted", needs=["key_vaults"],
       why="Without purge protection, an attacker or a mistake can destroy keys and secrets for good, "
           "making encrypted data unrecoverable.",
       fix="Enable purge protection (and soft delete) on the vault. It cannot be turned off afterwards.")
def keyvault_purge(data: dict[str, Any]) -> Iterator[Hit]:
    for vault in data["key_vaults"]:
        missing = []
        if vault.get("soft_delete") is False:
            missing.append("soft delete")
        if vault.get("purge_protection") is not True:
            missing.append("purge protection")
        if missing:
            yield Hit(_label(data, vault), "Not enabled: " + ", ".join(missing) + ".", region=vault.get("location", ""))


@check(id="azure-keyvault-public-network", cloud="azure", service="keyvault", severity="low",
       title="Key vault is reachable from all networks", needs=["key_vaults"],
       why="A stolen token can read secrets from anywhere on the internet.",
       fix="Set the vault firewall default action to Deny and use private endpoints or selected networks.")
def keyvault_network(data: dict[str, Any]) -> Iterator[Hit]:
    for vault in data["key_vaults"]:
        if vault.get("public_network_access") == "Disabled":
            continue
        if vault.get("network_default_action") in ("", "Allow"):
            yield Hit(_label(data, vault), "Vault firewall allows access from all networks.",
                      region=vault.get("location", ""))


# --------------------------------------------------------------------------------------------- subscription

@check(id="azure-defender-plan-off", cloud="azure", service="defender", severity="medium",
       cis="2.1.1, 2.1.3, 2.1.4, 2.1.7, 2.1.10",
       title="Microsoft Defender for Cloud plan is off", needs=["defender_plans"],
       why="Without the plan there is no threat detection for that resource type in the subscription.",
       fix="Turn on the Defender plan in Defender for Cloud > Environment settings (plans are billed per "
           "resource; decide per subscription).")
def defender_plans(data: dict[str, Any]) -> Iterator[Hit]:
    names = _sub_names(data)
    for plan in data["defender_plans"]:
        if plan.get("plan") in KEY_PLANS and plan.get("tier") != "Standard":
            yield Hit(f"Defender for {KEY_PLANS[plan['plan']]} ({names.get(plan['subscription'], plan['subscription'])})",
                      f"Plan '{plan['plan']}' is on the {plan.get('tier') or 'Free'} tier.")


@check(id="azure-subscription-owner-count", cloud="azure", service="iam", severity="medium",
       title=f"More than {MAX_OWNERS} owners on a subscription", needs=["role_assignments"],
       why="Every owner can grant access, delete resources and disable security controls; each extra owner "
           "is another account worth stealing.",
       fix="Keep two or three owners (ideally through PIM-eligible assignments) and give others narrower roles.")
def owner_count(data: dict[str, Any]) -> Iterator[Hit]:
    names = _sub_names(data)
    owners: dict[str, list[dict[str, str]]] = {}
    for assignment in data["role_assignments"]:
        scope = assignment.get("scope", "").lower().rstrip("/")
        if assignment.get("role_definition_id") == OWNER_ROLE_ID and scope == f"/subscriptions/{assignment['subscription']}".lower():
            owners.setdefault(assignment["subscription"], []).append(assignment)
    for sub, assigned in sorted(owners.items()):
        if len(assigned) > MAX_OWNERS:
            kinds: dict[str, int] = {}
            for a in assigned:
                kinds[a.get("principal_type") or "Unknown"] = kinds.get(a.get("principal_type") or "Unknown", 0) + 1
            breakdown = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
            yield Hit(names.get(sub, sub), f"{len(assigned)} Owner role assignments at subscription scope "
                      f"({breakdown}).", evidence={"count": len(assigned)})


@check(id="azure-custom-owner-role", cloud="azure", service="iam", severity="high", cis="1.23",
       title="Custom role grants full control", needs=["custom_roles"],
       why='A custom role with the "*" action is an Owner under another name and is easy to overlook in '
           "access reviews.",
       fix="Delete the role or reduce its actions to what is needed; use the built-in Owner role when full "
           "control is really intended.")
def custom_owner_role(data: dict[str, Any]) -> Iterator[Hit]:
    names = _sub_names(data)
    seen: set[str] = set()
    for role in data["custom_roles"]:
        if "*" not in role.get("actions", []) or role.get("name") in seen:
            continue
        scopes = [s for s in role.get("assignable_scopes", []) if s == "/" or s.lower().count("/") == 2]
        if scopes:
            seen.add(role.get("name", ""))
            yield Hit(f"{role.get('name')} ({names.get(role['subscription'], role['subscription'])})",
                      f'Allows the "*" action; assignable at {", ".join(scopes)}.')


@check(id="azure-activity-log-export", cloud="azure", service="logging", severity="medium",
       title="Subscription activity log is not exported", needs=["activity_log_settings", "subscriptions"],
       why="Activity logs record who changed what. Without a diagnostic setting they are kept for 90 days "
           "only and never reach your SIEM.",
       fix="Add a diagnostic setting on the subscription that sends activity logs to Log Analytics "
           "(Microsoft Sentinel) or a storage account.")
def activity_log_export(data: dict[str, Any]) -> Iterator[Hit]:
    checked = {s["subscription"] for s in data["activity_log_settings"]}
    exported = {s["subscription"] for s in data["activity_log_settings"] if s.get("name")}
    for sub in data["subscriptions"]:
        if sub["id"] in checked and sub["id"] not in exported:
            yield Hit(sub.get("name") or sub["id"], "No diagnostic setting exports the activity log.")
