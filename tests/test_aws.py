import base64
import json
import os
import tempfile
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from cloud_checks.aws import credentials as creds
from cloud_checks.aws.api import AwsClient, AwsError, error_from, parse_xml, txt
from cloud_checks.aws.checks import allows_everything
from cloud_checks.aws.collect import collect, policy_enforces_tls
from cloud_checks.aws.sigv4 import Credentials, canonical_query, sign, signing_key
from cloud_checks.core import engine
from cloud_checks.core.http import Response
from tests.fakes import FakeTransport, body_form, json_response

# AWS's published example credentials (documentation and the official SigV4 test suite).
EXAMPLE = Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
WHEN = datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)


def signature(headers):
    return headers["Authorization"].rsplit("Signature=", 1)[1]


class SigV4Tests(unittest.TestCase):
    def test_aws_documentation_example(self):
        headers = sign("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
                       {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}, b"", EXAMPLE,
                       "us-east-1", "iam", WHEN)
        self.assertEqual(signature(headers), "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
        self.assertIn("Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request", headers["Authorization"])
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", headers["Authorization"])

    def test_official_test_suite_vectors(self):
        cases = {
            ("GET", "https://example.amazonaws.com/", None, b""):
                "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            ("GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", None, b""):
                "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
            ("POST", "https://example.amazonaws.com/", "application/x-www-form-urlencoded", b"Param1=value1"):
                "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
        }
        for (method, url, content_type, body), expected in cases.items():
            with self.subTest(url=url, method=method):
                headers = {"Content-Type": content_type} if content_type else {}
                self.assertEqual(signature(sign(method, url, headers, body, EXAMPLE, "us-east-1", "service", WHEN)),
                                 expected)

    def test_signing_key_derivation(self):
        key = signing_key(EXAMPLE.secret_key, "20120215", "us-east-1", "iam")
        self.assertEqual(key.hex(), "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d")

    def test_session_token_s3_payload_hash_and_subresources(self):
        temp = Credentials("ASIAEXAMPLE", "secret", "session-token")
        headers = sign("GET", "https://s3.eu-west-1.amazonaws.com/my.bucket?acl", {}, b"", temp, "eu-west-1", "s3", WHEN)
        self.assertEqual(headers["X-Amz-Security-Token"], "session-token")
        self.assertEqual(headers["X-Amz-Content-Sha256"],
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertIn("x-amz-content-sha256;x-amz-date;x-amz-security-token", headers["Authorization"])
        self.assertEqual(canonical_query("acl"), "acl=")
        self.assertEqual(canonical_query("b=2&a=1&a=0"), "a=0&a=1&b=2")
        self.assertEqual(canonical_query("k=a+b%2Fc"), "k=a%20b%2Fc")

    def test_secret_never_appears_in_repr(self):
        self.assertNotIn("wJalr", repr(EXAMPLE))


class CredentialTests(unittest.TestCase):
    def test_environment_first(self):
        env = {"AWS_ACCESS_KEY_ID": "AKIAENV", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "t"}
        with mock.patch.dict(os.environ, env, clear=True):
            found = creds.resolve()
        self.assertEqual((found.access_key, found.session_token, found.source), ("AKIAENV", "t", "environment variables"))

    def test_profile_skips_environment_and_uses_cli(self):
        output = json.dumps({"Version": 1, "AccessKeyId": "ASIACLI", "SecretAccessKey": "s", "SessionToken": "tok"})
        env = {"AWS_ACCESS_KEY_ID": "AKIAENV", "AWS_SECRET_ACCESS_KEY": "s"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("shutil.which", return_value="/usr/bin/aws"), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout=output, stderr="")) as run:
            found = creds.resolve("audit")
        self.assertEqual(found.access_key, "ASIACLI")
        self.assertEqual(run.call_args[0][0][-2:], ["--profile", "audit"])

    def test_shared_credentials_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials"
            path.write_text("[default]\naws_access_key_id = AKIADEFAULT\naws_secret_access_key = s1\n"
                            "[audit]\naws_access_key_id = AKIAAUDIT\naws_secret_access_key = s2\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"AWS_SHARED_CREDENTIALS_FILE": str(path)}, clear=True), \
                    mock.patch("shutil.which", return_value=None):
                self.assertEqual(creds.resolve().access_key, "AKIADEFAULT")
                self.assertEqual(creds.resolve("audit").access_key, "AKIAAUDIT")
                with self.assertRaisesRegex(creds.CredentialError, "profile 'missing'"):
                    creds.resolve("missing")

    def test_instance_role_and_nothing_found(self):
        fake = FakeTransport()
        fake.add("PUT", "169.254.169.254/latest/api/token", Response(200, b"imds-token"))
        fake.add("GET", "security-credentials/$", Response(200, b"AuditRole\n"))
        fake.add("GET", "security-credentials/AuditRole", json_response(
            {"AccessKeyId": "ASIAIMDS", "SecretAccessKey": "s", "Token": "t"}))
        with mock.patch.dict(os.environ, {"AWS_SHARED_CREDENTIALS_FILE": "/nonexistent"}, clear=True), \
                mock.patch("shutil.which", return_value=None):
            found = creds.resolve(metadata_http=fake.client(retries=0))
            self.assertEqual((found.access_key, found.source), ("ASIAIMDS", "EC2 instance role AuditRole"))
            self.assertEqual(fake.calls[1].headers["X-aws-ec2-metadata-token"], "imds-token")
            empty = FakeTransport()
            empty.add("PUT", "169.254.169.254", Response(404, b""))
            with self.assertRaisesRegex(creds.CredentialError, "no AWS credentials found"):
                creds.resolve(metadata_http=empty.client(retries=0))


# --------------------------------------------------------------------------------------------- fake AWS

def xml(text: str, status: int = 200) -> Response:
    return Response(status, text.encode("utf-8"), {"Content-Type": "text/xml"})


def error_xml(code: str, status: int = 403) -> Response:
    return xml(f"<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code><Message>no</Message></Error></ErrorResponse>",
               status)


REPORT_CSV = ("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,"
              "password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,"
              "access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
              "<root_account>,arn:aws:iam::111122223333:root,2020-01-01T00:00:00+00:00,not_supported,"
              "no_information,not_supported,not_supported,true,false,N/A,N/A,false,N/A,N/A\n"
              "bob,arn:aws:iam::111122223333:user/bob,2024-01-01T00:00:00+00:00,true,2099-01-01T00:00:00+00:00,"
              "2024-01-01T00:00:00+00:00,N/A,false,false,N/A,N/A,false,N/A,N/A\n")
ADMIN_DOC = urllib.parse.quote(json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
SG_PAGE_1 = """<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<securityGroupInfo><item><groupId>sg-1</groupId><groupName>open-ssh</groupName><vpcId>vpc-1</vpcId>
<ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort>
<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges><ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges>
</item></ipPermissions><ipPermissionsEgress><item><ipProtocol>-1</ipProtocol></item></ipPermissionsEgress></item>
</securityGroupInfo><nextToken>page2</nextToken></DescribeSecurityGroupsResponse>"""
SG_PAGE_2 = """<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
<securityGroupInfo><item><groupId>sg-2</groupId><groupName>everything</groupName><vpcId>vpc-1</vpcId>
<ipPermissions><item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>
</item></ipPermissions><ipPermissionsEgress/></item></securityGroupInfo></DescribeSecurityGroupsResponse>"""


class FakeAws:
    """Answers the calls collect() makes. Regions: us-east-1 (full) and eu-west-1 (RDS denied)."""

    def __init__(self):
        self.report_states = ["STARTED", "COMPLETE"]
        self.throttle_once = True
        self.transport = FakeTransport()
        t = self.transport
        t.add("POST", r"^https://sts\.amazonaws\.com/", xml(
            '<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>'
            "<Arn>arn:aws:iam::111122223333:role/Audit</Arn><Account>111122223333</Account>"
            "</GetCallerIdentityResult></GetCallerIdentityResponse>"))
        t.add("POST", r"^https://iam\.amazonaws\.com/", self.iam)
        t.add("POST", r"^https://ec2\.", self.ec2)
        t.add("POST", r"^https://rds\.", self.rds)
        t.add("POST", r"^https://cloudtrail\.", self.cloudtrail)
        t.add("GET", r"^https://guardduty\.us-east-1\.amazonaws\.com/detector$", json_response({"detectorIds": ["d1"]}))
        t.add("GET", r"guardduty\.us-east-1\.amazonaws\.com/detector/d1", json_response({"status": "ENABLED"}))
        t.add("GET", r"^https://guardduty\.eu-west-1", json_response({"detectorIds": []}))
        t.add("GET", r"s3-control", xml("<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>", 404))
        t.add("HEAD", r"s3\.amazonaws\.com/legacy\.bucket", Response(301, b"", {"x-amz-bucket-region": "eu-west-1"}))
        t.add("GET", r"s3\.", self.s3)

    def iam(self, req):
        form = body_form(req)
        action = form["Action"]
        if action == "GetAccountSummary":
            if self.throttle_once:
                self.throttle_once = False
                return error_xml("Throttling", 400)
            return xml('<GetAccountSummaryResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
                       "<GetAccountSummaryResult><SummaryMap><entry><key>AccountMFAEnabled</key><value>1</value></entry>"
                       "<entry><key>AccountAccessKeysPresent</key><value>1</value></entry></SummaryMap>"
                       "</GetAccountSummaryResult></GetAccountSummaryResponse>")
        if action == "GetAccountPasswordPolicy":
            return error_xml("NoSuchEntity", 404)
        if action == "GenerateCredentialReport":
            state = self.report_states.pop(0) if len(self.report_states) > 1 else self.report_states[0]
            return xml(f"<R><GenerateCredentialReportResult><State>{state}</State></GenerateCredentialReportResult></R>")
        if action == "GetCredentialReport":
            content = base64.b64encode(REPORT_CSV.encode()).decode()
            return xml(f"<R><GetCredentialReportResult><Content>{content}</Content></GetCredentialReportResult></R>")
        if action == "ListPolicies":
            if form.get("Marker") == "m1":
                return xml("<R><ListPoliciesResult><Policies><member><PolicyName>ReadOnly</PolicyName>"
                           "<Arn>arn:p2</Arn><DefaultVersionId>v1</DefaultVersionId><AttachmentCount>1</AttachmentCount>"
                           "</member></Policies><IsTruncated>false</IsTruncated></ListPoliciesResult></R>")
            return xml("<R><ListPoliciesResult><Policies><member><PolicyName>FullAdmin</PolicyName><Arn>arn:p1</Arn>"
                       "<DefaultVersionId>v3</DefaultVersionId><AttachmentCount>2</AttachmentCount></member></Policies>"
                       "<IsTruncated>true</IsTruncated><Marker>m1</Marker></ListPoliciesResult></R>")
        if action == "GetPolicyVersion":
            doc = ADMIN_DOC if form["PolicyArn"] == "arn:p1" else urllib.parse.quote('{"Statement": []}')
            return xml(f"<R><GetPolicyVersionResult><PolicyVersion><Document>{doc}</Document></PolicyVersion>"
                       "</GetPolicyVersionResult></R>")
        if action == "ListEntitiesForPolicy":
            return xml("<R><ListEntitiesForPolicyResult><PolicyUsers><member><UserName>bob</UserName></member>"
                       "</PolicyUsers><PolicyGroups/><PolicyRoles><member><RoleName>Admin</RoleName></member>"
                       "</PolicyRoles><IsTruncated>false</IsTruncated></ListEntitiesForPolicyResult></R>")
        raise AssertionError(action)

    def ec2(self, req):
        form = body_form(req)
        action = form["Action"]
        east = "us-east-1" in req.url
        if action == "DescribeRegions":
            return xml("<R><regionInfo><item><regionName>us-east-1</regionName></item>"
                       "<item><regionName>eu-west-1</regionName></item></regionInfo></R>")
        if action == "DescribeSecurityGroups":
            if not east:
                return xml("<R><securityGroupInfo/></R>")
            return xml(SG_PAGE_2 if form.get("NextToken") == "page2" else SG_PAGE_1)
        if action == "GetEbsEncryptionByDefault":
            return xml(f"<R><ebsEncryptionByDefault>{'true' if east else 'false'}</ebsEncryptionByDefault></R>")
        if action == "DescribeSnapshots":
            self.snapshot_form = form
            return xml("<R><snapshotSet><item><snapshotId>snap-1</snapshotId><volumeSize>8</volumeSize>"
                       "<encrypted>false</encrypted></item></snapshotSet></R>" if east else "<R><snapshotSet/></R>")
        if action == "DescribeImages":
            return xml("<R><imagesSet/></R>")
        if action == "DescribeInstances":
            return xml("<R><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId>"
                       "<instanceState><name>running</name></instanceState><ipAddress>203.0.113.9</ipAddress>"
                       "<metadataOptions><httpTokens>optional</httpTokens><httpEndpoint>enabled</httpEndpoint>"
                       "</metadataOptions><tagSet><item><key>Name</key><value>web</value></item></tagSet></item>"
                       "</instancesSet></item></reservationSet></R>" if east else "<R><reservationSet/></R>")
        raise AssertionError(action)

    def rds(self, req):
        if "eu-west-1" in req.url:
            return error_xml("AccessDenied", 403)
        return xml("<R><DescribeDBInstancesResult><DBInstances><DBInstance><DBInstanceIdentifier>db1"
                   "</DBInstanceIdentifier><Engine>mysql</Engine><PubliclyAccessible>true</PubliclyAccessible>"
                   "<StorageEncrypted>false</StorageEncrypted></DBInstance></DBInstances></DescribeDBInstancesResult></R>")

    def cloudtrail(self, req):
        target = req.headers["X-Amz-Target"]
        if target.endswith("DescribeTrails"):
            return json_response({"trailList": [{"Name": "org", "TrailARN": "arn:trail/org", "HomeRegion": "us-east-1",
                                                 "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
                                                 "KmsKeyId": "arn:kms"}]})
        self.status_urls = getattr(self, "status_urls", []) + [req.url]
        return json_response({"IsLogging": True})

    def s3(self, req):
        url = req.url
        if url.rstrip("/") == "https://s3.amazonaws.com":
            return xml('<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets>'
                       "<Bucket><Name>public-data</Name><BucketRegion>us-east-1</BucketRegion></Bucket>"
                       "<Bucket><Name>legacy.bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>")
        public = "public-data" in url
        if url.endswith("?publicAccessBlock"):
            if public:
                return xml("<Error><Code>NoSuchPublicAccessBlockConfiguration</Code></Error>", 404)
            return xml("<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true"
                       "</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true"
                       "</RestrictPublicBuckets></PublicAccessBlockConfiguration>")
        if url.endswith("?policyStatus"):
            return xml("<PolicyStatus><IsPublic>TRUE</IsPublic></PolicyStatus>") if public else \
                xml("<Error><Code>NoSuchBucketPolicy</Code></Error>", 404)
        if url.endswith("?acl"):
            grant = ('<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">'
                     "<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission>"
                     "</Grant>") if public else ""
            return xml(f"<AccessControlPolicy><AccessControlList>{grant}</AccessControlList></AccessControlPolicy>")
        if url.endswith("?policy"):
            if public:
                return json_response({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]})
            return xml("<Error><Code>NoSuchBucketPolicy</Code></Error>", 404)
        raise AssertionError(url)

    def client(self, credentials=EXAMPLE):
        return AwsClient(self.transport.client(retries=0), credentials, sleep=lambda _s: None)


class CollectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fake = FakeAws()
        cls.snapshot = collect(cls.fake.client(), workers=2)
        cls.data = cls.snapshot["data"]

    def test_identity_and_iam(self):
        self.assertEqual(self.snapshot["account"]["id"], "111122223333")
        self.assertEqual(self.data["iam_summary"], {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1})
        self.assertEqual(self.data["password_policy"], {"exists": False})
        self.assertEqual([row["user"] for row in self.data["credential_report"]], ["<root_account>", "bob"])
        self.assertEqual([p["name"] for p in self.data["customer_policies"]], ["FullAdmin", "ReadOnly"])
        self.assertTrue(allows_everything(self.data["customer_policies"][0]["document"]))
        self.assertEqual(self.data["admin_entities"], {"users": ["bob"], "groups": [], "roles": ["Admin"]})

    def test_s3(self):
        self.assertEqual(self.data["s3_account_block"]["configured"], False)
        buckets = {b["name"]: b for b in self.data["s3_buckets"]}
        public = buckets["public-data"]
        self.assertEqual(public["region"], "us-east-1")
        self.assertEqual(public["public_access_block"]["BlockPublicAcls"], False)
        self.assertTrue(public["policy_public"])
        self.assertEqual(public["public_acl_grants"], ["READ to everyone"])
        self.assertIs(public["tls_enforced"], False)
        legacy = buckets["legacy.bucket"]
        self.assertEqual(legacy["region"], "eu-west-1")  # from the HEAD response header
        self.assertTrue(all(legacy["public_access_block"].values()))
        self.assertEqual((legacy["policy_public"], legacy["public_acl_grants"], legacy["errors"]), (False, [], {}))
        regional = [c.url for c in self.fake.transport.calls if "legacy.bucket?acl" in c.url]
        self.assertEqual(regional, ["https://s3.eu-west-1.amazonaws.com/legacy.bucket?acl"])

    def test_regional_sections_pagination_and_partial_failure(self):
        self.assertEqual(self.data["regions"], ["eu-west-1", "us-east-1"])
        groups = {g["id"]: g for g in self.data["security_groups"]}
        self.assertEqual(set(groups), {"sg-1", "sg-2"})  # second page followed
        self.assertEqual(groups["sg-1"]["ingress"], [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                                                      "cidrs": ["0.0.0.0/0", "::/0"]}])
        self.assertEqual(groups["sg-2"]["ingress"][0]["protocol"], "all")
        self.assertEqual(self.data["ebs_default_encryption"], {"eu-west-1": False, "us-east-1": True})
        self.assertEqual(self.data["public_snapshots"][0]["id"], "snap-1")
        self.assertEqual((self.fake.snapshot_form["Owner.1"], self.fake.snapshot_form["RestorableBy.1"]), ("self", "all"))
        self.assertEqual(self.data["instances"][0]["name"], "web")
        self.assertEqual([d["id"] for d in self.data["rds_instances"]], ["db1"])  # eu-west-1 was denied
        self.assertIn("eu-west-1: AccessDenied", self.snapshot["errors"]["rds_instances (partial)"])
        self.assertEqual(self.data["guardduty"]["regions_checked"], ["eu-west-1", "us-east-1"])
        self.assertEqual(len(self.data["trails"]), 1)  # the shadow trail seen in both regions is de-duplicated
        self.assertTrue(self.data["trails"][0]["is_logging"])
        self.assertTrue(all("cloudtrail.us-east-1" in u for u in self.fake.status_urls))

    def test_requests_are_signed_and_ask_for_native_format(self):
        call = next(c for c in self.fake.transport.calls if "iam.amazonaws.com" in c.url)
        self.assertTrue(call.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"))
        self.assertIn("/us-east-1/iam/aws4_request", call.headers["Authorization"])
        self.assertEqual(call.headers["Accept"], "*/*")
        self.assertEqual(body_form(call)["Version"], "2010-05-08")

    def test_every_call_is_read_only(self):
        for call in self.fake.transport.calls:
            if call.method in ("GET", "HEAD"):
                continue
            self.assertEqual(call.method, "POST")
            if "X-Amz-Target" in call.headers:  # JSON protocol (CloudTrail)
                action = call.headers["X-Amz-Target"].rsplit(".", 1)[-1]
            else:  # Query protocol (IAM, STS, EC2, RDS)
                action = body_form(call)["Action"]
            # GenerateCredentialReport only asks IAM to refresh its own report.
            self.assertRegex(action, r"^(Describe|Get|List)|^GenerateCredentialReport$", call.url)

    def test_checks_run_on_collected_data(self):
        results = {r.check.id: r for r in engine.run(self.snapshot, engine.checks_for("aws"))}
        failed = {cid for cid, r in results.items() if r.status == engine.FAIL}
        for expected in ("aws-iam-root-access-key", "aws-iam-password-policy", "aws-iam-user-no-mfa",
                         "aws-iam-admin-policy", "aws-iam-user-admin-direct", "aws-s3-account-public-access-block",
                         "aws-s3-bucket-public", "aws-ec2-sg-open-all-ports", "aws-ec2-sg-open-admin-ports",
                         "aws-ec2-ebs-default-encryption", "aws-ec2-public-snapshot", "aws-ec2-imdsv1",
                         "aws-rds-public", "aws-rds-unencrypted", "aws-guardduty-disabled"):
            self.assertIn(expected, failed)
        for expected in ("aws-iam-root-mfa", "aws-cloudtrail-multi-region", "aws-cloudtrail-log-validation",
                         "aws-ec2-public-ami"):
            self.assertEqual(results[expected].status, engine.PASS, expected)
        self.assertFalse([r for r in results.values() if r.status == engine.SKIPPED])

    def test_section_denied_everywhere_is_skipped_not_passed(self):
        fake = FakeAws()
        fake.transport.routes.insert(0, ("POST", __import__("re").compile(r"^https://rds\."),
                                         error_xml("AccessDenied", 403)))
        fake.transport.routes.insert(0, ("POST", __import__("re").compile(r"^https://iam\.amazonaws\.com/"),
                                         error_xml("AccessDenied", 403)))
        snapshot = collect(fake.client(), only_regions=["us-east-1"], workers=1)
        self.assertIsNone(snapshot["data"]["rds_instances"])
        self.assertIn("permission missing", snapshot["errors"]["rds_instances"])
        self.assertIsNone(snapshot["data"]["credential_report"])
        results = {r.check.id: r for r in engine.run(snapshot, engine.checks_for("aws"))}
        self.assertEqual(results["aws-rds-public"].status, engine.SKIPPED)
        self.assertIn("AccessDenied", results["aws-rds-public"].reason)
        self.assertEqual(results["aws-iam-user-no-mfa"].status, engine.SKIPPED)
        self.assertEqual(results["aws-ec2-sg-open-admin-ports"].status, engine.FAIL)

    def test_identity_failure_is_fatal(self):
        fake = FakeTransport().add("POST", "sts", error_xml("InvalidClientTokenId", 403))
        with self.assertRaises(AwsError) as ctx:
            collect(AwsClient(fake.client(retries=0), EXAMPLE))
        self.assertTrue(ctx.exception.denied)


class HelperTests(unittest.TestCase):
    def test_error_parsing(self):
        self.assertEqual(error_from(400, '{"__type":"com.amazon#AccessDeniedException","message":"nope"}').code,
                         "AccessDeniedException")
        self.assertEqual(error_from(403, "<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>x"
                                         "</Message></Error></Errors></Response>").code, "UnauthorizedOperation")
        self.assertEqual(error_from(500, "garbage").code, "HTTP500")

    def test_xml_namespace_stripping(self):
        root = parse_xml(b'<A xmlns="urn:x"><B><C>1</C></B></A>')
        self.assertEqual((txt(root, "B/C"), txt(root, "B/missing", "d")), ("1", "d"))

    def test_policy_helpers(self):
        deny_http = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                                    "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        self.assertTrue(policy_enforces_tls(deny_http))
        self.assertFalse(policy_enforces_tls({"Statement": {"Effect": "Allow", "Action": "s3:GetObject"}}))
        self.assertFalse(policy_enforces_tls({"Statement": [{"Effect": "Deny", "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}))
        self.assertTrue(allows_everything({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}))
        self.assertFalse(allows_everything({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}))
        self.assertFalse(allows_everything({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}))
        self.assertFalse(allows_everything(None))


if __name__ == "__main__":
    unittest.main()
