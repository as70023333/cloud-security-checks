"""AWS checks. Pure functions over the collected snapshot data.

CIS numbers refer to the CIS AWS Foundations Benchmark v3.0.0 and are given only where they
were verified against AWS's published Security Hub mapping.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterator

from cloud_checks.core.engine import Hit, check
from cloud_checks.core.ports import exposure, is_internet
from cloud_checks.core.timeutil import days_between, parse_time

ROOT = "<root_account>"
PAB_FIELDS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
KEY_MAX_AGE_DAYS = 90
UNUSED_DAYS = 45
ROOT_RECENT_DAYS = 30


def _now(data: dict[str, Any]) -> datetime:
    now = parse_time(data.get("captured_at"))
    if now is None:
        raise ValueError("snapshot has no captured_at time")
    return now


def _age(data: dict[str, Any], value: str) -> int | None:
    """Days since an ISO timestamp from the credential report ('N/A' and similar -> None)."""
    when = parse_time(value)
    return days_between(_now(data), when) if when else None


def _users(data: dict[str, Any]) -> list[dict[str, str]]:
    return [row for row in data["credential_report"] if row.get("user") != ROOT]


# --------------------------------------------------------------------------------------------- IAM

@check(id="aws-iam-root-access-key", cloud="aws", service="iam", severity="critical", cis="1.4",
       title="Root user has an access key", needs=["iam_summary"],
       why="A root access key has unlimited power over the account and cannot be restricted by any policy.",
       fix="Delete the root access keys and use IAM roles or IAM Identity Center for all access.")
def root_access_key(data: dict[str, Any]) -> Iterator[Hit]:
    if data["iam_summary"].get("AccountAccessKeysPresent", 0):
        yield Hit("root user", "The root user has at least one access key.")


@check(id="aws-iam-root-mfa", cloud="aws", service="iam", severity="critical", cis="1.5",
       title="Root user has no MFA", needs=["iam_summary"],
       why="Without MFA, the root password alone gives full control of the account.",
       fix="Enable MFA on the root user, preferably a hardware key, and store it safely.")
def root_mfa(data: dict[str, Any]) -> Iterator[Hit]:
    if not data["iam_summary"].get("AccountMFAEnabled", 0):
        yield Hit("root user", "MFA is not enabled for the root user.")


@check(id="aws-iam-root-recently-used", cloud="aws", service="iam", severity="medium",
       title="Root user was used recently", needs=["credential_report"],
       why="The root user should be reserved for the few tasks that require it; routine use means its "
           "credentials are in circulation.",
       fix="Use IAM roles for daily work. Keep root credentials offline and alert on every root sign-in.")
def root_recently_used(data: dict[str, Any]) -> Iterator[Hit]:
    for row in data["credential_report"]:
        if row.get("user") != ROOT:
            continue
        used = {"password": row.get("password_last_used", ""),
                "access key 1": row.get("access_key_1_last_used_date", ""),
                "access key 2": row.get("access_key_2_last_used_date", "")}
        recent = {name: age for name, value in used.items()
                  if (age := _age(data, value)) is not None and age <= ROOT_RECENT_DAYS}
        if recent:
            parts = ", ".join(f"{name} {age} day(s) ago" for name, age in sorted(recent.items()))
            yield Hit("root user", f"Root credentials used in the last {ROOT_RECENT_DAYS} days: {parts}.",
                      evidence=recent)


@check(id="aws-iam-password-policy", cloud="aws", service="iam", severity="medium", cis="1.8, 1.9",
       title="Weak IAM password policy", needs=["password_policy"],
       why="Short or reusable passwords make IAM users with console access easy to compromise.",
       fix="Set a minimum length of 14 and remember the last 24 passwords; better, move people to "
           "IAM Identity Center and remove console passwords.")
def weak_password_policy(data: dict[str, Any]) -> Iterator[Hit]:
    policy = data["password_policy"]
    if not policy.get("exists"):
        yield Hit("account password policy", "No custom password policy is set; the AWS default "
                  "(8 characters, no reuse prevention) applies.")
        return
    problems = []
    if (policy.get("minimum_length") or 0) < 14:
        problems.append(f"minimum length is {policy.get('minimum_length')} (should be 14 or more)")
    if (policy.get("reuse_prevention") or 0) < 24:
        problems.append(f"password reuse prevention is {policy.get('reuse_prevention') or 'off'} (should be 24)")
    if problems:
        yield Hit("account password policy", "; ".join(problems).capitalize() + ".", evidence=dict(policy))


@check(id="aws-iam-user-no-mfa", cloud="aws", service="iam", severity="high", cis="1.10",
       title="IAM user with a console password has no MFA", needs=["credential_report"],
       why="A phished or reused password is enough to sign in to the console as this user.",
       fix="Enable MFA for the user, or remove the console password if it is a service account.")
def user_no_mfa(data: dict[str, Any]) -> Iterator[Hit]:
    for row in _users(data):
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            yield Hit(row["user"], "Console password is enabled and MFA is not.", evidence={"arn": row.get("arn")})


@check(id="aws-iam-access-key-rotation", cloud="aws", service="iam", severity="medium", cis="1.14",
       title=f"Access key older than {KEY_MAX_AGE_DAYS} days", needs=["credential_report"],
       why="Long-lived keys accumulate in laptops, CI systems and old scripts; the older a key, the more "
           "places it may have leaked.",
       fix="Rotate the key, or replace it with a role (IAM Roles Anywhere, OIDC federation for CI).")
def access_key_rotation(data: dict[str, Any]) -> Iterator[Hit]:
    for row in _users(data):
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            age = _age(data, row.get(f"access_key_{n}_last_rotated", ""))
            if age is not None and age > KEY_MAX_AGE_DAYS:
                yield Hit(f"{row['user']} (access key {n})", f"Active access key created {age} days ago.",
                          evidence={"age_days": age})


@check(id="aws-iam-unused-credentials", cloud="aws", service="iam", severity="medium", cis="1.12",
       title=f"Credentials unused for {UNUSED_DAYS} days", needs=["credential_report"],
       why="Credentials nobody uses are still valid for an attacker and nobody notices when they are abused.",
       fix="Disable or delete the unused password or access key.")
def unused_credentials(data: dict[str, Any]) -> Iterator[Hit]:
    for row in _users(data):
        stale = []
        if row.get("password_enabled") == "true":
            used = _age(data, row.get("password_last_used", ""))
            # Never used: fall back to when the password was set, then to when the user was created.
            if used is None:
                used = _age(data, row.get("password_last_changed", ""))
            if used is None:
                used = _age(data, row.get("user_creation_time", ""))
            if used is not None and used > UNUSED_DAYS:
                stale.append(f"console password ({used} days)")
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            used = _age(data, row.get(f"access_key_{n}_last_used_date", ""))
            if used is None:
                used = _age(data, row.get(f"access_key_{n}_last_rotated", ""))
            if used is not None and used > UNUSED_DAYS:
                stale.append(f"access key {n} ({used} days)")
        if stale:
            yield Hit(row["user"], "Not used: " + ", ".join(stale) + ".")


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def allows_everything(document: dict[str, Any] | None) -> bool:
    """True when a policy has an Allow statement for Action * on Resource *."""
    for statement in _as_list((document or {}).get("Statement")):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if "*" in _as_list(statement.get("Action")) and "*" in _as_list(statement.get("Resource")):
            return True
    return False


@check(id="aws-iam-admin-policy", cloud="aws", service="iam", severity="high",
       title="Customer-managed policy grants full administrative access", needs=["customer_policies"],
       why='A policy allowing "Action": "*" on "Resource": "*" makes every attached identity an account '
           "administrator, usually without anyone tracking it as one.",
       fix="Replace it with least-privilege policies; use the AWS-managed AdministratorAccess only for a "
           "small, named admin role.")
def admin_policy(data: dict[str, Any]) -> Iterator[Hit]:
    for policy in data["customer_policies"]:
        if allows_everything(policy.get("document")):
            yield Hit(policy["name"], f'Allows "*" on "*" and is attached to {policy.get("attachment_count", 0)} '
                      "identity(ies).", evidence={"arn": policy.get("arn")})


@check(id="aws-iam-user-admin-direct", cloud="aws", service="iam", severity="medium", cis="1.15",
       title="AdministratorAccess attached directly to a user", needs=["admin_entities"],
       why="Admin rights on a long-lived user (rather than a role people assume with MFA) are always on and "
           "hard to review.",
       fix="Remove the direct attachment; grant admin through a role or an IAM Identity Center permission set.")
def user_admin_direct(data: dict[str, Any]) -> Iterator[Hit]:
    for user in sorted(data["admin_entities"].get("users", [])):
        yield Hit(user, "The AWS-managed AdministratorAccess policy is attached directly to this user.")


# --------------------------------------------------------------------------------------------- S3

def _all_blocked(block: dict[str, Any] | None) -> bool:
    return bool(block) and all(block.get(name) for name in PAB_FIELDS)


@check(id="aws-s3-account-public-access-block", cloud="aws", service="s3", severity="high", cis="2.1.4",
       title="Account-level S3 Block Public Access is not fully on", needs=["s3_account_block"],
       why="The account-level setting is the safety net that stops any bucket, present or future, from being "
           "made public by mistake.",
       fix="Turn on all four Block Public Access settings for the account (S3 console > Block Public Access "
           "settings for this account).")
def s3_account_block(data: dict[str, Any]) -> Iterator[Hit]:
    block = data["s3_account_block"]
    if not _all_blocked(block):
        off = [name for name in PAB_FIELDS if not block.get(name)]
        yield Hit("account", "Not enabled: " + ", ".join(off) + ".", evidence=dict(block))


@check(id="aws-s3-bucket-public", cloud="aws", service="s3", severity="critical",
       title="S3 bucket is public", needs=["s3_buckets", "s3_account_block"],
       why="Anyone on the internet can read (or write) the bucket's contents. Public buckets are the most "
           "common cause of cloud data leaks.",
       fix="Remove the public statement or ACL grant and turn on Block Public Access. If the content must "
           "be public, serve it through CloudFront with origin access control.")
def s3_bucket_public(data: dict[str, Any]) -> Iterator[Hit]:
    account = data["s3_account_block"]
    for bucket in data["s3_buckets"]:
        block = bucket.get("public_access_block") or {}
        ignore_acls = bool(block.get("IgnorePublicAcls") or account.get("IgnorePublicAcls"))
        restrict = bool(block.get("RestrictPublicBuckets") or account.get("RestrictPublicBuckets"))
        ways, masked = [], []
        if bucket.get("policy_public"):
            (masked if restrict else ways).append("bucket policy allows public access")
        if bucket.get("public_acl_grants"):
            (masked if ignore_acls else ways).append("ACL grants " + ", ".join(bucket["public_acl_grants"]))
        if ways:
            yield Hit(bucket["name"], "; ".join(ways).capitalize() + ".", region=bucket.get("region", ""))
        elif masked:
            yield Hit(bucket["name"], "; ".join(masked).capitalize() + ". Only Block Public Access is "
                      "preventing exposure; remove the public policy or ACL.", region=bucket.get("region", ""),
                      severity="low")


@check(id="aws-s3-bucket-public-access-block", cloud="aws", service="s3", severity="medium", cis="2.1.4",
       title="S3 bucket without full Block Public Access", needs=["s3_buckets", "s3_account_block"],
       why="A bucket without these settings can be made public by a single policy or ACL change.",
       fix="Enable all four Block Public Access settings on the bucket, or for the whole account.")
def s3_bucket_block(data: dict[str, Any]) -> Iterator[Hit]:
    if _all_blocked(data["s3_account_block"]):
        return  # the account-level setting covers every bucket
    for bucket in data["s3_buckets"]:
        block = bucket.get("public_access_block")
        if block is None:
            continue  # could not be read; listed under coverage notes
        if not _all_blocked(block):
            off = [name for name in PAB_FIELDS if not block.get(name)]
            yield Hit(bucket["name"], "Not enabled: " + ", ".join(off) + ".", region=bucket.get("region", ""))


@check(id="aws-s3-bucket-tls", cloud="aws", service="s3", severity="low", cis="2.1.1",
       title="S3 bucket does not require TLS", needs=["s3_buckets"],
       why="Without a policy that denies plain HTTP, data and credentials can cross the network unencrypted.",
       fix='Add a bucket policy statement that denies all actions when "aws:SecureTransport" is "false".')
def s3_bucket_tls(data: dict[str, Any]) -> Iterator[Hit]:
    for bucket in data["s3_buckets"]:
        if bucket.get("tls_enforced") is False:
            yield Hit(bucket["name"], "No bucket policy statement denies requests made without TLS.",
                      region=bucket.get("region", ""))


# --------------------------------------------------------------------------------------------- EC2

def _open_rules(group: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, object], list[str]]]:
    for rule in group.get("ingress", []):
        sources = [c for c in rule.get("cidrs", []) if is_internet(c)]
        if sources:
            yield rule, exposure(rule.get("protocol", ""), rule.get("from_port"), rule.get("to_port")), sources


def _group_label(group: dict[str, Any]) -> str:
    return f"{group['id']} ({group.get('name') or 'unnamed'})"


@check(id="aws-ec2-sg-open-all-ports", cloud="aws", service="ec2", severity="critical",
       title="Security group allows all ports from the internet", needs=["security_groups"],
       why="Every service on every attached instance is reachable by anyone, including ones nobody meant "
           "to publish.",
       fix="Replace the rule with the specific ports and source ranges that are actually needed.")
def sg_open_all(data: dict[str, Any]) -> Iterator[Hit]:
    for group in data["security_groups"]:
        for rule, exposed, sources in _open_rules(group):
            if exposed["all"]:
                yield Hit(_group_label(group), f"All {rule.get('protocol')} ports open to {', '.join(sources)}.",
                          region=group["region"], evidence={"vpc": group.get("vpc_id")})


@check(id="aws-ec2-sg-open-admin-ports", cloud="aws", service="ec2", severity="high", cis="5.2, 5.3",
       title="Security group allows SSH or RDP from the internet", needs=["security_groups"],
       why="Internet-facing SSH and RDP are scanned and brute-forced constantly and are a leading entry "
           "point for ransomware.",
       fix="Restrict the source to your VPN or office ranges, or remove the rule and use Session Manager "
           "or EC2 Instance Connect Endpoint.")
def sg_open_admin(data: dict[str, Any]) -> Iterator[Hit]:
    for group in data["security_groups"]:
        for _rule, exposed, sources in _open_rules(group):
            if exposed["admin"]:
                yield Hit(_group_label(group), f"{', '.join(exposed['admin'])} open to {', '.join(sources)}.",
                          region=group["region"], evidence={"vpc": group.get("vpc_id")})


@check(id="aws-ec2-sg-open-sensitive-ports", cloud="aws", service="ec2", severity="high",
       title="Security group exposes a database or internal service to the internet",
       needs=["security_groups"],
       why="Databases, caches and management APIs are not built to face the internet; exposed ones are found "
           "by scanners within hours.",
       fix="Allow these ports only from application security groups or private ranges.")
def sg_open_sensitive(data: dict[str, Any]) -> Iterator[Hit]:
    for group in data["security_groups"]:
        for _rule, exposed, sources in _open_rules(group):
            if exposed["sensitive"]:
                yield Hit(_group_label(group), f"{', '.join(exposed['sensitive'])} open to {', '.join(sources)}.",
                          region=group["region"], evidence={"vpc": group.get("vpc_id")})


@check(id="aws-ec2-default-sg-rules", cloud="aws", service="ec2", severity="low", cis="5.4",
       title="Default security group has rules", needs=["security_groups"],
       why="Resources launched without an explicit security group land in the default one; if it allows "
           "traffic they are connected by accident.",
       fix="Remove all inbound and outbound rules from each VPC's default security group and use purpose-built "
           "groups.")
def default_sg_rules(data: dict[str, Any]) -> Iterator[Hit]:
    for group in data["security_groups"]:
        if group.get("name") == "default" and (group.get("ingress") or group.get("egress_rule_count")):
            yield Hit(_group_label(group), f"{len(group.get('ingress', []))} inbound and "
                      f"{group.get('egress_rule_count', 0)} outbound rule(s).", region=group["region"],
                      evidence={"vpc": group.get("vpc_id")})


@check(id="aws-ec2-ebs-default-encryption", cloud="aws", service="ec2", severity="medium", cis="2.2.1",
       title="EBS encryption by default is off", needs=["ebs_default_encryption"],
       why="New volumes and snapshots in the region are created unencrypted unless someone remembers to tick "
           "the box.",
       fix="Enable EBS encryption by default in each region you use (EC2 > Settings > Data protection).")
def ebs_default_encryption(data: dict[str, Any]) -> Iterator[Hit]:
    for region, enabled in sorted(data["ebs_default_encryption"].items()):
        if not enabled:
            yield Hit(f"region {region}", "EBS encryption by default is disabled.", region=region)


@check(id="aws-ec2-public-snapshot", cloud="aws", service="ec2", severity="critical",
       title="EBS snapshot is public", needs=["public_snapshots"],
       why="Any AWS account can copy a public snapshot and read the whole disk: databases, keys, source code.",
       fix="Make the snapshot private. Turn on 'Block public access for EBS snapshots' for the account.")
def public_snapshot(data: dict[str, Any]) -> Iterator[Hit]:
    for snap in data["public_snapshots"]:
        yield Hit(snap["id"], f"Public snapshot, {snap.get('size_gb')} GB, "
                  f"{'encrypted' if snap.get('encrypted') else 'unencrypted'}.", region=snap["region"])


@check(id="aws-ec2-public-ami", cloud="aws", service="ec2", severity="high",
       title="Machine image (AMI) is public", needs=["public_images"],
       why="Public images are launched by strangers and often contain credentials, keys or internal software.",
       fix="Make the AMI private unless you publish it on purpose. Turn on 'Block public access for AMIs'.")
def public_ami(data: dict[str, Any]) -> Iterator[Hit]:
    for image in data["public_images"]:
        yield Hit(f"{image['id']} ({image.get('name') or 'unnamed'})", "Image is shared with all AWS accounts.",
                  region=image["region"])


@check(id="aws-ec2-imdsv1", cloud="aws", service="ec2", severity="medium",
       title="Instance allows IMDSv1", needs=["instances"],
       why="With IMDSv1, a server-side request forgery bug in any application on the instance can steal the "
           "instance role's credentials (the Capital One breach pattern).",
       fix="Require IMDSv2 (HttpTokens=required) on the instance and set it as the account default.")
def imdsv1(data: dict[str, Any]) -> Iterator[Hit]:
    for instance in data["instances"]:
        if instance.get("state") in ("terminated", "shutting-down"):
            continue
        if instance.get("http_endpoint") == "enabled" and instance.get("http_tokens") != "required":
            label = f"{instance['id']} ({instance['name']})" if instance.get("name") else instance["id"]
            public = f" Public IP {instance['public_ip']}." if instance.get("public_ip") else ""
            yield Hit(label, f"Metadata service accepts IMDSv1 requests.{public}", region=instance["region"],
                      severity="high" if instance.get("public_ip") else None)


# --------------------------------------------------------------------------------------------- logging and detection

@check(id="aws-cloudtrail-multi-region", cloud="aws", service="cloudtrail", severity="high", cis="3.1",
       title="No multi-region CloudTrail trail is logging", needs=["trails"],
       why="Without a trail covering every region there is no record of who did what; an attacker can work in "
           "an unused region unseen.",
       fix="Create a multi-region trail (ideally an organization trail) delivering to a locked-down bucket.")
def cloudtrail_multi_region(data: dict[str, Any]) -> Iterator[Hit]:
    if not any(t.get("multi_region") and t.get("is_logging") is not False for t in data["trails"]):
        stopped = [t["name"] for t in data["trails"] if t.get("multi_region")]
        detail = (f"Multi-region trail(s) exist but logging is stopped: {', '.join(stopped)}." if stopped
                  else f"{len(data['trails'])} trail(s) found, none is multi-region.")
        yield Hit("account", detail)


@check(id="aws-cloudtrail-log-validation", cloud="aws", service="cloudtrail", severity="low", cis="3.2",
       title="CloudTrail log file validation is off", needs=["trails"],
       why="Without validation you cannot prove that log files were not altered or deleted after delivery.",
       fix="Enable log file validation on the trail.")
def cloudtrail_validation(data: dict[str, Any]) -> Iterator[Hit]:
    for trail in data["trails"]:
        if not trail.get("log_validation"):
            yield Hit(trail["name"], "Log file validation is disabled.", region=trail.get("home_region", ""))


@check(id="aws-cloudtrail-kms", cloud="aws", service="cloudtrail", severity="low", cis="3.5",
       title="CloudTrail logs are not encrypted with a KMS key", needs=["trails"],
       why="A customer-managed KMS key adds a second permission (kms:Decrypt) between an attacker with bucket "
           "access and your audit logs.",
       fix="Configure the trail to encrypt log files with a KMS key.")
def cloudtrail_kms(data: dict[str, Any]) -> Iterator[Hit]:
    for trail in data["trails"]:
        if not trail.get("kms_key_id"):
            yield Hit(trail["name"], "No KMS key is configured for the trail.", region=trail.get("home_region", ""))


@check(id="aws-rds-public", cloud="aws", service="rds", severity="high", cis="2.3.3",
       title="RDS instance is publicly accessible", needs=["rds_instances"],
       why="The database has a public address; only its security group and password stand between it and "
           "the internet.",
       fix="Set PubliclyAccessible to false and reach the database through private networking.")
def rds_public(data: dict[str, Any]) -> Iterator[Hit]:
    for db in data["rds_instances"]:
        if db.get("public"):
            yield Hit(db["id"], f"{db.get('engine')} instance has PubliclyAccessible enabled.", region=db["region"])


@check(id="aws-rds-unencrypted", cloud="aws", service="rds", severity="medium", cis="2.3.1",
       title="RDS instance storage is not encrypted", needs=["rds_instances"],
       why="Snapshots and underlying storage are readable by anyone who obtains them.",
       fix="Encryption cannot be switched on in place: snapshot, copy the snapshot with encryption, restore.")
def rds_unencrypted(data: dict[str, Any]) -> Iterator[Hit]:
    for db in data["rds_instances"]:
        if not db.get("encrypted"):
            yield Hit(db["id"], f"{db.get('engine')} instance storage is unencrypted.", region=db["region"])


@check(id="aws-guardduty-disabled", cloud="aws", service="guardduty", severity="medium",
       title="GuardDuty is not enabled", needs=["guardduty"],
       why="GuardDuty is AWS's built-in threat detection (credential misuse, crypto-mining, C2 traffic); "
           "a region without it is unmonitored.",
       fix="Enable GuardDuty in every region, ideally from a delegated administrator account.")
def guardduty_disabled(data: dict[str, Any]) -> Iterator[Hit]:
    enabled = {d["region"] for d in data["guardduty"].get("detectors", []) if d.get("status") == "ENABLED"}
    for region in data["guardduty"].get("regions_checked", []):
        if region not in enabled:
            yield Hit(f"region {region}", "No enabled GuardDuty detector.", region=region)
