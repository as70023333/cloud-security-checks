"""Read-only collection from an AWS account into a snapshot.

Every call is a Describe*, Get* or List* (plus GenerateCredentialReport, which only asks IAM to
refresh its own report). Each section is collected independently: a missing permission skips that
section, records why under ``errors``, and the affected checks are reported as skipped.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from cloud_checks.aws.api import GLOBAL_REGION, AwsClient, AwsError, flag, parse_xml, txt
from cloud_checks.core.timeutil import iso, utcnow

IAM_VERSION = "2010-05-08"
EC2_VERSION = "2016-11-15"
RDS_VERSION = "2014-10-31"
IAM_HOST = "iam.amazonaws.com"
ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
PUBLIC_GROUPS = {"http://acs.amazonaws.com/groups/global/AllUsers": "everyone",
                 "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account"}
PAB_FIELDS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
TRAIL_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101."

Log = Callable[[str], None]


def _iam(client: AwsClient, action: str, params: dict | None = None):
    return client.query("iam", GLOBAL_REGION, action, IAM_VERSION, params, host=IAM_HOST)


def _iam_pages(client: AwsClient, action: str, params: dict | None = None):
    return client.query_pages("iam", GLOBAL_REGION, action, IAM_VERSION, params, ".//Marker", "Marker", host=IAM_HOST)


# --------------------------------------------------------------------------------------------- IAM

def identity(client: AwsClient) -> dict[str, str]:
    root = client.query("sts", GLOBAL_REGION, "GetCallerIdentity", "2011-06-15", host="sts.amazonaws.com")
    return {"id": txt(root, ".//Account"), "arn": txt(root, ".//Arn")}


def iam_summary(client: AwsClient) -> dict[str, int]:
    root = _iam(client, "GetAccountSummary")
    summary = {}
    for entry in root.findall(".//SummaryMap/entry"):
        try:
            summary[txt(entry, "key")] = int(txt(entry, "value") or 0)
        except ValueError:
            continue
    return summary


def password_policy(client: AwsClient) -> dict[str, Any]:
    try:
        root = _iam(client, "GetAccountPasswordPolicy")
    except AwsError as exc:
        if exc.code == "NoSuchEntity":
            return {"exists": False}
        raise
    policy = root.find(".//PasswordPolicy")

    def number(name: str) -> int | None:
        value = txt(policy, name)
        return int(value) if value.isdigit() else None

    return {"exists": True, "minimum_length": number("MinimumPasswordLength"),
            "reuse_prevention": number("PasswordReusePrevention"), "max_age_days": number("MaxPasswordAge"),
            "require_symbols": flag(policy, "RequireSymbols"), "require_numbers": flag(policy, "RequireNumbers"),
            "require_uppercase": flag(policy, "RequireUppercaseCharacters"),
            "require_lowercase": flag(policy, "RequireLowercaseCharacters")}


def credential_report(client: AwsClient, sleep: Callable[[float], None], attempts: int = 20) -> list[dict[str, str]]:
    for _ in range(attempts):
        state = txt(_iam(client, "GenerateCredentialReport"), ".//State")
        if state == "COMPLETE":
            break
        sleep(2.0)
    else:
        raise AwsError("ReportInProgress", "the IAM credential report was not ready after 40 seconds")
    content = txt(_iam(client, "GetCredentialReport"), ".//Content")
    text = base64.b64decode(content).decode("utf-8")
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def customer_policies(client: AwsClient) -> list[dict[str, Any]]:
    """Attached customer-managed policies with their default version's document."""
    policies = []
    for page in _iam_pages(client, "ListPolicies", {"Scope": "Local", "OnlyAttached": "true", "MaxItems": "1000"}):
        for member in page.findall(".//Policies/member"):
            arn, version = txt(member, "Arn"), txt(member, "DefaultVersionId")
            entry: dict[str, Any] = {"name": txt(member, "PolicyName"), "arn": arn,
                                     "attachment_count": int(txt(member, "AttachmentCount") or 0)}
            try:
                root = _iam(client, "GetPolicyVersion", {"PolicyArn": arn, "VersionId": version})
                entry["document"] = json.loads(urllib.parse.unquote(txt(root, ".//PolicyVersion/Document")))
            except (AwsError, ValueError) as exc:
                entry["document"] = None
                entry["error"] = str(exc)
            policies.append(entry)
    return policies


def admin_entities(client: AwsClient) -> dict[str, list[str]]:
    """Who has the AWS-managed AdministratorAccess policy attached."""
    out: dict[str, list[str]] = {"users": [], "groups": [], "roles": []}
    for page in _iam_pages(client, "ListEntitiesForPolicy", {"PolicyArn": ADMIN_POLICY_ARN, "MaxItems": "1000"}):
        out["users"] += [txt(m, "UserName") for m in page.findall(".//PolicyUsers/member")]
        out["groups"] += [txt(m, "GroupName") for m in page.findall(".//PolicyGroups/member")]
        out["roles"] += [txt(m, "RoleName") for m in page.findall(".//PolicyRoles/member")]
    return out


# --------------------------------------------------------------------------------------------- S3

def _public_access_block(body: bytes) -> dict[str, bool]:
    root = parse_xml(body)
    return {name: bool(flag(root, f".//{name}")) for name in PAB_FIELDS}


def policy_enforces_tls(document: dict[str, Any]) -> bool:
    """True when the bucket policy denies requests that do not use TLS (aws:SecureTransport false)."""
    statements = document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Deny":
            continue
        for operator, conditions in (statement.get("Condition") or {}).items():
            if not operator.lower().startswith("bool") or not isinstance(conditions, dict):
                continue
            for key, value in conditions.items():
                values = value if isinstance(value, list) else [value]
                if key.lower() == "aws:securetransport" and any(str(v).lower() == "false" for v in values):
                    return True
    return False


def s3_account_block(client: AwsClient, account_id: str) -> dict[str, Any]:
    resp = client.s3("GET", GLOBAL_REGION, "/v20180820/configuration/publicAccessBlock",
                     host=f"{account_id}.s3-control.{GLOBAL_REGION}.amazonaws.com",
                     headers={"x-amz-account-id": account_id}, allow=(404,))
    if resp.status == 404:
        return {"configured": False, **{name: False for name in PAB_FIELDS}}
    return {"configured": True, **_public_access_block(resp.body)}


def _bucket_region(client: AwsClient, name: str, listed: str) -> str:
    if listed:
        return listed
    resp = client.s3("HEAD", GLOBAL_REGION, f"/{name}", allow=(301, 307, 400, 403, 404))
    return resp.header("x-amz-bucket-region") or GLOBAL_REGION


def _bucket(client: AwsClient, name: str, listed_region: str) -> dict[str, Any]:
    bucket: dict[str, Any] = {"name": name, "region": "", "public_access_block": None, "policy_public": None,
                              "public_acl_grants": None, "tls_enforced": None, "errors": {}}

    def part(key: str, fn: Callable[[], Any]) -> None:
        try:
            bucket[key] = fn()
        except (AwsError, ValueError) as exc:
            bucket["errors"][key] = str(exc)

    part("region", lambda: _bucket_region(client, name, listed_region))
    region = bucket["region"] or GLOBAL_REGION

    def block() -> dict[str, bool]:
        resp = client.s3("GET", region, f"/{name}?publicAccessBlock", allow=(404,))
        return {n: False for n in PAB_FIELDS} if resp.status == 404 else _public_access_block(resp.body)

    def policy_public() -> bool:
        resp = client.s3("GET", region, f"/{name}?policyStatus", allow=(404,))
        return False if resp.status == 404 else bool(flag(parse_xml(resp.body), ".//IsPublic"))

    def acl_grants() -> list[str]:
        root = parse_xml(client.s3("GET", region, f"/{name}?acl").body)
        grants = []
        for grant in root.findall(".//AccessControlList/Grant"):
            audience = PUBLIC_GROUPS.get(txt(grant, "Grantee/URI"))
            if audience:
                grants.append(f"{txt(grant, 'Permission')} to {audience}")
        return sorted(set(grants))

    def tls() -> bool:
        resp = client.s3("GET", region, f"/{name}?policy", allow=(404,))
        return False if resp.status == 404 else policy_enforces_tls(json.loads(resp.body.decode("utf-8")))

    part("public_access_block", block)
    part("policy_public", policy_public)
    part("public_acl_grants", acl_grants)
    part("tls_enforced", tls)
    return bucket


def s3_buckets(client: AwsClient, workers: int) -> list[dict[str, Any]]:
    root = parse_xml(client.s3("GET", GLOBAL_REGION, "/").body)
    listed = [(txt(b, "Name"), txt(b, "BucketRegion")) for b in root.findall(".//Buckets/Bucket")]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda item: _bucket(client, item[0], item[1]), listed))


# --------------------------------------------------------------------------------------------- regional

def regions(client: AwsClient) -> list[str]:
    root = client.query("ec2", GLOBAL_REGION, "DescribeRegions", EC2_VERSION)
    return sorted(txt(item, "regionName") for item in root.findall(".//regionInfo/item"))


def _ec2_pages(client: AwsClient, region: str, action: str, params: dict | None = None):
    return client.query_pages("ec2", region, action, EC2_VERSION, params, "nextToken", "NextToken")


def _port(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def security_groups(client: AwsClient, region: str) -> list[dict[str, Any]]:
    groups = []
    for page in _ec2_pages(client, region, "DescribeSecurityGroups", {"MaxResults": "1000"}):
        for item in page.findall("securityGroupInfo/item"):
            ingress = []
            for perm in item.findall("ipPermissions/item"):
                protocol = txt(perm, "ipProtocol")
                cidrs = [txt(r, "cidrIp") for r in perm.findall("ipRanges/item")]
                cidrs += [txt(r, "cidrIpv6") for r in perm.findall("ipv6Ranges/item")]
                ingress.append({"protocol": "all" if protocol == "-1" else protocol,
                                "from_port": _port(txt(perm, "fromPort")), "to_port": _port(txt(perm, "toPort")),
                                "cidrs": [c for c in cidrs if c]})
            groups.append({"region": region, "id": txt(item, "groupId"), "name": txt(item, "groupName"),
                           "vpc_id": txt(item, "vpcId"), "ingress": ingress,
                           "egress_rule_count": len(item.findall("ipPermissionsEgress/item"))})
    return groups


def ebs_default_encryption(client: AwsClient, region: str) -> bool:
    return bool(flag(client.query("ec2", region, "GetEbsEncryptionByDefault", EC2_VERSION), "ebsEncryptionByDefault"))


def public_snapshots(client: AwsClient, region: str) -> list[dict[str, Any]]:
    params = {"Owner.1": "self", "RestorableBy.1": "all", "MaxResults": "1000"}
    return [{"region": region, "id": txt(item, "snapshotId"), "size_gb": _port(txt(item, "volumeSize")),
             "encrypted": bool(flag(item, "encrypted")), "description": txt(item, "description")}
            for page in _ec2_pages(client, region, "DescribeSnapshots", params)
            for item in page.findall("snapshotSet/item")]


def public_images(client: AwsClient, region: str) -> list[dict[str, Any]]:
    params = {"Owner.1": "self", "Filter.1.Name": "is-public", "Filter.1.Value.1": "true"}
    return [{"region": region, "id": txt(item, "imageId"), "name": txt(item, "name")}
            for page in _ec2_pages(client, region, "DescribeImages", params)
            for item in page.findall("imagesSet/item")]


def instances(client: AwsClient, region: str) -> list[dict[str, Any]]:
    out = []
    for page in _ec2_pages(client, region, "DescribeInstances", {"MaxResults": "1000"}):
        for item in page.findall("reservationSet/item/instancesSet/item"):
            name = next((txt(tag, "value") for tag in item.findall("tagSet/item") if txt(tag, "key") == "Name"), "")
            out.append({"region": region, "id": txt(item, "instanceId"), "name": name,
                        "state": txt(item, "instanceState/name"), "public_ip": txt(item, "ipAddress"),
                        "http_tokens": txt(item, "metadataOptions/httpTokens"),
                        "http_endpoint": txt(item, "metadataOptions/httpEndpoint")})
    return out


def rds_instances(client: AwsClient, region: str) -> list[dict[str, Any]]:
    out = []
    pages = client.query_pages("rds", region, "DescribeDBInstances", RDS_VERSION, {"MaxRecords": "100"},
                               ".//DescribeDBInstancesResult/Marker", "Marker")
    for page in pages:
        for item in page.findall(".//DBInstances/DBInstance"):
            out.append({"region": region, "id": txt(item, "DBInstanceIdentifier"), "engine": txt(item, "Engine"),
                        "public": bool(flag(item, "PubliclyAccessible")),
                        "encrypted": bool(flag(item, "StorageEncrypted"))})
    return out


def guardduty(client: AwsClient, region: str) -> list[dict[str, str]]:
    detectors = []
    for detector_id in client.rest_json("guardduty", region, "/detector").get("detectorIds") or []:
        detail = client.rest_json("guardduty", region, f"/detector/{detector_id}")
        detectors.append({"region": region, "id": detector_id, "status": str(detail.get("status") or "")})
    return detectors


def trails_in(client: AwsClient, region: str) -> list[dict[str, Any]]:
    data = client.json_rpc("cloudtrail", region, TRAIL_TARGET + "DescribeTrails", {"includeShadowTrails": True})
    return [{"name": t.get("Name", ""), "arn": t.get("TrailARN", ""), "home_region": t.get("HomeRegion", region),
             "multi_region": bool(t.get("IsMultiRegionTrail")), "log_validation": bool(t.get("LogFileValidationEnabled")),
             "kms_key_id": t.get("KmsKeyId") or "", "organization_trail": bool(t.get("IsOrganizationTrail"))}
            for t in data.get("trailList") or []]


# --------------------------------------------------------------------------------------------- orchestration

REGIONAL: dict[str, Callable[[AwsClient, str], Any]] = {
    "security_groups": security_groups, "ebs_default_encryption": ebs_default_encryption,
    "public_snapshots": public_snapshots, "public_images": public_images, "instances": instances,
    "rds_instances": rds_instances, "guardduty": guardduty, "trails": trails_in,
}


def _guarded(fn: Callable[[], Any]) -> Any:
    """Run a collector; an unexpected response shape becomes an AwsError instead of a crash."""
    try:
        return fn()
    except AwsError:
        raise
    except (ET.ParseError, ValueError, KeyError, TypeError) as exc:
        raise AwsError("UnexpectedResponse", f"{type(exc).__name__}: {exc}") from exc


def _explain(exc: AwsError | None) -> str:
    if exc is None:
        return "unknown error"
    return f"{exc} (permission missing)" if exc.denied else str(exc)


def collect(client: AwsClient, *, only_regions: list[str] | None = None, workers: int = 8,
            log: Log = lambda _m: None) -> dict[str, Any]:
    """Collect everything the checks need. Raises AwsError only if the identity call fails."""
    account = identity(client)
    data: dict[str, Any] = {}
    errors: dict[str, str] = {}
    snapshot = {"cloud": "aws", "captured_at": iso(utcnow()), "account": account, "data": data, "errors": errors}
    log(f"account {account['id']} as {account['arn']}")

    def section(key: str, fn: Callable[[], Any]) -> None:
        try:
            data[key] = _guarded(fn)
        except AwsError as exc:
            data[key] = None
            errors[key] = _explain(exc)
            log(f"{key}: skipped ({exc})")

    section("iam_summary", lambda: iam_summary(client))
    section("password_policy", lambda: password_policy(client))
    section("credential_report", lambda: credential_report(client, client.sleep))
    section("customer_policies", lambda: customer_policies(client))
    section("admin_entities", lambda: admin_entities(client))
    section("s3_account_block", lambda: s3_account_block(client, account["id"]))
    section("s3_buckets", lambda: s3_buckets(client, workers))
    if data.get("s3_buckets") is not None:
        log(f"S3 buckets: {len(data['s3_buckets'])}")

    if only_regions:
        data["regions"] = sorted(set(only_regions))
    else:
        section("regions", lambda: regions(client))
    scan = data.get("regions") or []
    log(f"regions: {len(scan)}")

    jobs = [(key, region) for key in REGIONAL for region in scan]

    def run(job: tuple[str, str]) -> tuple[str, str, Any, AwsError | None]:
        key, region = job
        try:
            return key, region, _guarded(lambda: REGIONAL[key](client, region)), None
        except AwsError as exc:
            return key, region, None, exc

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(run, jobs))

    for key in REGIONAL:
        mine = [o for o in outcomes if o[0] == key]
        good = [o for o in mine if o[3] is None]
        failed = [o for o in mine if o[3] is not None]
        if failed and not good:
            data[key] = None
            errors[key] = _explain(failed[0][3])
            continue
        if failed:
            errors[f"{key} (partial)"] = "not read in " + ", ".join(
                f"{region}: {exc.code}" for _k, region, _v, exc in failed if exc)
        if key == "ebs_default_encryption":
            data[key] = {region: value for _k, region, value, _e in good}
        elif key == "guardduty":
            data[key] = {"regions_checked": sorted(region for _k, region, _v, _e in good),
                         "detectors": [d for _k, _r, value, _e in good for d in value]}
        elif key == "trails":
            unique = {t["arn"]: t for _k, _r, value, _e in good for t in value}
            data[key] = _trail_status(client, list(unique.values()), errors)
        else:
            data[key] = [item for _k, _r, value, _e in good for item in value]
    return snapshot


def _trail_status(client: AwsClient, trails: list[dict[str, Any]], errors: dict[str, str]) -> list[dict[str, Any]]:
    for trail in trails:
        try:
            status = client.json_rpc("cloudtrail", trail["home_region"], TRAIL_TARGET + "GetTrailStatus",
                                     {"Name": trail["arn"]})
            trail["is_logging"] = bool(status.get("IsLogging"))
        except AwsError as exc:
            trail["is_logging"] = None
            errors[f"trails (status of {trail['name']})"] = str(exc)
    return sorted(trails, key=lambda t: t["name"])
