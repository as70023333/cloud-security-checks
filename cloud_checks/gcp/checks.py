"""Google Cloud checks. Pure functions over the collected snapshot data.

These follow the intent of the CIS Google Cloud Platform Foundation Benchmark. Control numbers
are not cited because they could not be verified against a published mapping.
"""

from __future__ import annotations

from typing import Any, Iterator

from cloud_checks.core.engine import Hit, check
from cloud_checks.core.ports import exposure, is_internet, parse_port_range
from cloud_checks.core.timeutil import days_between, parse_time

PUBLIC_MEMBERS = {"allUsers": "anyone on the internet", "allAuthenticatedUsers": "any Google account"}
BASIC_ROLES = {"roles/owner": "Owner", "roles/editor": "Editor"}
PERSONAL_DOMAINS = ("gmail.com", "googlemail.com")
FULL_ACCESS_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
KEY_MAX_AGE_DAYS = 90
SSL_REQUIRED_MODES = {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}


def service_account_kind(email: str) -> str:
    """'default' (Compute Engine / App Engine default), 'user' (created by you) or 'google' (service agent)."""
    domain = email.rsplit("@", 1)[-1].lower()
    if email.lower().endswith("-compute@developer.gserviceaccount.com") or domain == "appspot.gserviceaccount.com":
        return "default"
    if domain.endswith(".iam.gserviceaccount.com") and not domain.startswith("gcp-sa-"):
        return "user"
    return "google"


# --------------------------------------------------------------------------------------------- IAM

@check(id="gcp-iam-public-member", cloud="gcp", service="iam", severity="critical",
       title="Project IAM policy grants a role to everyone", needs=["iam_bindings"],
       why="allUsers and allAuthenticatedUsers mean anyone on the internet; a project-level grant applies to "
           "every resource in the project.",
       fix="Remove the binding and grant the role to named users, groups or service accounts.")
def iam_public_member(data: dict[str, Any]) -> Iterator[Hit]:
    for binding in data["iam_bindings"]:
        for member in binding.get("members", []):
            if member in PUBLIC_MEMBERS:
                yield Hit(binding["project"], f"{binding['role']} is granted to {member} "
                          f"({PUBLIC_MEMBERS[member]}).")


@check(id="gcp-iam-service-account-basic-role", cloud="gcp", service="iam", severity="high",
       title="Service account holds Owner or Editor", needs=["iam_bindings"],
       why="Anything running as that service account (a VM, a function, a leaked key) can change or delete "
           "almost everything in the project.",
       fix="Replace the basic role with the specific predefined roles the workload needs. For the default "
           "Compute Engine service account, create a dedicated account per workload.")
def iam_service_account_basic_role(data: dict[str, Any]) -> Iterator[Hit]:
    for binding in data["iam_bindings"]:
        role = BASIC_ROLES.get(binding.get("role", ""))
        if not role:
            continue
        for member in binding.get("members", []):
            if not member.startswith("serviceAccount:"):
                continue
            email = member.split(":", 1)[1]
            kind = service_account_kind(email)
            if kind == "google":
                continue  # Google-managed service agents; their roles are set by Google
            note = " This is a default service account, used by every VM that does not specify one." \
                if kind == "default" else ""
            yield Hit(f"{email} ({binding['project']})", f"Has the {role} role on the project.{note}",
                      severity="medium" if kind == "default" else None)


@check(id="gcp-iam-personal-account", cloud="gcp", service="iam", severity="medium",
       title="Personal Google account has access to the project", needs=["iam_bindings"],
       why="A gmail.com account is outside your organization's control: no enforced MFA, no offboarding, "
           "no audit of the account itself.",
       fix="Remove the binding and grant access to a managed (Cloud Identity or Workspace) account.")
def iam_personal_account(data: dict[str, Any]) -> Iterator[Hit]:
    seen: dict[tuple[str, str], list[str]] = {}
    for binding in data["iam_bindings"]:
        for member in binding.get("members", []):
            if member.startswith("user:") and member.lower().endswith(PERSONAL_DOMAINS):
                seen.setdefault((member.split(":", 1)[1], binding["project"]), []).append(binding.get("role", ""))
    for (email, project), roles in sorted(seen.items()):
        privileged = any(role in BASIC_ROLES for role in roles)
        yield Hit(f"{email} ({project})", "Roles: " + ", ".join(sorted(roles)) + ".",
                  severity="high" if privileged else None)


@check(id="gcp-iam-service-account-key", cloud="gcp", service="iam", severity="low",
       title="Service account has a user-managed key", needs=["service_account_keys"],
       why="A downloaded key is a password that never expires; leaked keys are the most common cause of "
           "Google Cloud compromises.",
       fix="Delete the key and use workload identity federation, attached service accounts or impersonation. "
           f"If a key is unavoidable, rotate it at least every {KEY_MAX_AGE_DAYS} days.")
def iam_service_account_key(data: dict[str, Any]) -> Iterator[Hit]:
    now = parse_time(data.get("captured_at"))
    for key in data["service_account_keys"]:
        if key.get("disabled"):
            continue
        created = parse_time(key.get("created"))
        age = days_between(now, created) if now and created else None
        old = age is not None and age > KEY_MAX_AGE_DAYS
        detail = f"Key {key.get('key_id', '')[:8]}... " + (f"created {age} days ago." if age is not None
                                                          else "of unknown age.")
        yield Hit(f"{key['email']} ({key['project']})", detail, severity="medium" if old else None,
                  evidence={"age_days": age})


# --------------------------------------------------------------------------------------------- storage

@check(id="gcp-storage-public-bucket", cloud="gcp", service="storage", severity="critical",
       title="Cloud Storage bucket is public", needs=["buckets"],
       why="Anyone on the internet can read (or write) the bucket's objects.",
       fix="Remove the allUsers / allAuthenticatedUsers binding and set public access prevention to enforced.")
def storage_public_bucket(data: dict[str, Any]) -> Iterator[Hit]:
    for bucket in data["buckets"]:
        if bucket.get("public_bindings"):
            grants = ", ".join(sorted({f"{b['role']} to {b['member']}" for b in bucket["public_bindings"]}))
            yield Hit(f"{bucket['name']} ({bucket['project']})", f"Grants {grants}.",
                      region=bucket.get("location", ""))


@check(id="gcp-storage-uniform-access", cloud="gcp", service="storage", severity="low",
       title="Bucket does not use uniform bucket-level access", needs=["buckets"],
       why="With per-object ACLs, individual objects can be public without it showing in the bucket's IAM "
           "policy.",
       fix="Enable uniform bucket-level access so IAM alone controls access.")
def storage_uniform_access(data: dict[str, Any]) -> Iterator[Hit]:
    for bucket in data["buckets"]:
        if not bucket.get("uniform_access"):
            yield Hit(f"{bucket['name']} ({bucket['project']})", "Uniform bucket-level access is disabled.",
                      region=bucket.get("location", ""))


# --------------------------------------------------------------------------------------------- network

def _open_rules(firewall: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """What each enabled ingress rule exposes to the internet."""
    if firewall.get("direction") != "INGRESS" or firewall.get("disabled"):
        return
    if not any(is_internet(source) for source in firewall.get("source_ranges", [])):
        return
    combined: dict[str, Any] = {"all": False, "admin": [], "sensitive": []}
    for allowed in firewall.get("allowed", []):
        ports = allowed.get("ports") or []
        # No port list means every port of that protocol; an unparseable entry is ignored.
        ranges = [parse_port_range(p) for p in ports] if ports else [(None, None)]
        for parsed in ranges:
            if parsed is None:
                continue
            start, end = parsed
            exposed = exposure(allowed.get("protocol", ""), start, end)
            combined["all"] = combined["all"] or bool(exposed["all"])
            combined["admin"] += [p for p in exposed["admin"] if p not in combined["admin"]]
            combined["sensitive"] += [p for p in exposed["sensitive"] if p not in combined["sensitive"]]
    yield combined


def _firewall_label(firewall: dict[str, Any]) -> str:
    return f"{firewall['name']} ({firewall['project']}, network {firewall.get('network')})"


@check(id="gcp-firewall-open-all-ports", cloud="gcp", service="network", severity="critical",
       title="Firewall rule allows all ports from the internet", needs=["firewalls"],
       why="Every service on every matching VM is reachable by anyone.",
       fix="Replace the rule with the specific ports, source ranges and target tags that are needed.")
def firewall_open_all(data: dict[str, Any]) -> Iterator[Hit]:
    for firewall in data["firewalls"]:
        for exposed in _open_rules(firewall):
            if exposed["all"]:
                yield Hit(_firewall_label(firewall), "All ports are open to 0.0.0.0/0.")


@check(id="gcp-firewall-open-admin-ports", cloud="gcp", service="network", severity="high",
       title="Firewall rule allows SSH or RDP from the internet", needs=["firewalls"],
       why="Internet-facing SSH and RDP are brute-forced constantly. The default network ships with these "
           "rules.",
       fix="Delete the rule and use Identity-Aware Proxy TCP forwarding (source range 35.235.240.0/20) or a VPN.")
def firewall_open_admin(data: dict[str, Any]) -> Iterator[Hit]:
    for firewall in data["firewalls"]:
        for exposed in _open_rules(firewall):
            if exposed["admin"]:
                yield Hit(_firewall_label(firewall), f"{', '.join(exposed['admin'])} open to the internet.")


@check(id="gcp-firewall-open-sensitive-ports", cloud="gcp", service="network", severity="high",
       title="Firewall rule exposes a database or internal service to the internet", needs=["firewalls"],
       why="Databases, caches and management APIs are not built to face the internet.",
       fix="Restrict the source ranges to internal networks or use private service access.")
def firewall_open_sensitive(data: dict[str, Any]) -> Iterator[Hit]:
    for firewall in data["firewalls"]:
        for exposed in _open_rules(firewall):
            if exposed["sensitive"]:
                yield Hit(_firewall_label(firewall), f"{', '.join(exposed['sensitive'])} open to the internet.")


# --------------------------------------------------------------------------------------------- compute and databases

@check(id="gcp-compute-default-sa-full-access", cloud="gcp", service="compute", severity="medium",
       title="VM runs as the default service account with full API access", needs=["instances"],
       why="The default Compute Engine service account usually has the Editor role; with the cloud-platform "
           "scope, anyone who gets a shell on the VM controls the project.",
       fix="Run the VM as a dedicated service account with only the roles it needs.")
def compute_default_sa(data: dict[str, Any]) -> Iterator[Hit]:
    for vm in data["instances"]:
        for account in vm.get("service_accounts", []):
            if service_account_kind(account.get("email", "")) == "default" and FULL_ACCESS_SCOPE in account.get("scopes", []):
                public = f" Public IP {', '.join(vm['public_ips'])}." if vm.get("public_ips") else ""
                yield Hit(f"{vm['name']} ({vm['project']})", f"Uses {account['email']} with the cloud-platform "
                          f"scope.{public}", region=vm.get("zone", ""),
                          severity="high" if vm.get("public_ips") else None)


@check(id="gcp-sql-public-network", cloud="gcp", service="sql", severity="critical",
       title="Cloud SQL instance accepts connections from any IP address", needs=["sql_instances"],
       why="The database is reachable from the whole internet; only its password protects it.",
       fix="Remove 0.0.0.0/0 from authorized networks; use private IP or the Cloud SQL Auth Proxy.")
def sql_public_network(data: dict[str, Any]) -> Iterator[Hit]:
    for db in data["sql_instances"]:
        open_networks = [n for n in db.get("authorized_networks", []) if is_internet(n)]
        if db.get("public_ip") and open_networks:
            yield Hit(f"{db['name']} ({db['project']})", f"{db.get('version')} instance authorizes "
                      f"{', '.join(open_networks)}.", region=db.get("region", ""))


@check(id="gcp-sql-no-ssl", cloud="gcp", service="sql", severity="medium",
       title="Cloud SQL instance does not require TLS", needs=["sql_instances"],
       why="Clients can connect over the public IP without encryption, exposing credentials and data.",
       fix="Set the SSL mode to 'Allow only SSL connections' (ENCRYPTED_ONLY) or require client certificates.")
def sql_no_ssl(data: dict[str, Any]) -> Iterator[Hit]:
    for db in data["sql_instances"]:
        if db.get("public_ip") and not db.get("require_ssl") and db.get("ssl_mode") not in SSL_REQUIRED_MODES:
            yield Hit(f"{db['name']} ({db['project']})", "Public IP is enabled and unencrypted connections "
                      "are allowed.", region=db.get("region", ""))


@check(id="gcp-sql-no-backups", cloud="gcp", service="sql", severity="low",
       title="Cloud SQL instance has no automated backups", needs=["sql_instances"],
       why="Without backups, ransomware, a bad migration or an accidental delete is unrecoverable.",
       fix="Enable automated backups and point-in-time recovery.")
def sql_no_backups(data: dict[str, Any]) -> Iterator[Hit]:
    for db in data["sql_instances"]:
        if db.get("instance_type") in ("", "CLOUD_SQL_INSTANCE") and not db.get("backups"):
            yield Hit(f"{db['name']} ({db['project']})", "Automated backups are disabled.", region=db.get("region", ""))
