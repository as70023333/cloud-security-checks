"""The check rules, run against the built-in demo accounts and small hand-made cases."""

import json
import unittest
from importlib import resources

from cloud_checks.core import engine
from cloud_checks.core.ports import exposure, is_internet, parse_port_range
from cloud_checks.gcp.checks import service_account_kind


def demo(cloud: str) -> dict:
    return json.loads(resources.files(f"cloud_checks.{cloud}").joinpath("demo.json").read_text(encoding="utf-8"))


def run(cloud: str, snapshot: dict | None = None) -> dict[str, engine.CheckResult]:
    return {r.check.id: r for r in engine.run(snapshot or demo(cloud), engine.checks_for(cloud))}


def resources_of(result: engine.CheckResult) -> dict[str, str]:
    """resource -> effective severity"""
    return {h.resource: h.severity or result.check.severity for h in result.hits}


def only(cloud: str, check_id: str, data: dict, captured_at: str = "2026-10-01T12:00:00Z") -> list[engine.Hit]:
    chk = next(c for c in engine.checks_for(cloud) if c.id == check_id)
    return engine.run({"cloud": cloud, "captured_at": captured_at, "data": data, "errors": {}}, [chk])[0].hits


class RegistryTests(unittest.TestCase):
    def test_registry_is_well_formed(self):
        engine.load_checks()
        self.assertGreaterEqual(len(engine.REGISTRY), 54)
        for chk in engine.REGISTRY.values():
            with self.subTest(check=chk.id):
                self.assertTrue(chk.id.startswith(chk.cloud + "-"))
                self.assertTrue(chk.title and chk.why and chk.fix and chk.needs)
                self.assertEqual(chk.id, chk.id.lower())
                self.assertFalse(chk.title.endswith("."))

    def test_every_check_fires_in_its_demo_account(self):
        # The demo accounts are the worked example for the whole catalog; AWS keeps one passing
        # check (no root access key) to show what a pass looks like.
        for cloud in engine.CLOUDS:
            results = run(cloud)
            passing = sorted(cid for cid, r in results.items() if r.status != engine.FAIL)
            self.assertEqual(passing, ["aws-iam-root-access-key"] if cloud == "aws" else [], cloud)

    def test_select(self):
        self.assertEqual({c.service for c in engine.select("aws", ["s3"])}, {"s3"})
        ids = [c.id for c in engine.select("aws", ["iam"], ["aws-iam-root-mfa"])]
        self.assertNotIn("aws-iam-root-mfa", ids)
        self.assertIn("aws-iam-user-no-mfa", ids)
        with self.assertRaisesRegex(ValueError, "unknown check or service"):
            engine.select("aws", ["azure-storage-https-only"])

    def test_missing_data_skips_with_reason(self):
        snap = demo("aws")
        snap["data"]["trails"] = None
        snap["errors"]["trails"] = "AccessDenied (permission missing)"
        del snap["data"]["instances"]
        results = run("aws", snap)
        self.assertEqual(results["aws-cloudtrail-multi-region"].status, engine.SKIPPED)
        self.assertIn("AccessDenied", results["aws-cloudtrail-multi-region"].reason)
        self.assertIn("not collected", results["aws-ec2-imdsv1"].reason)


class PortTests(unittest.TestCase):
    def test_is_internet(self):
        for value in ("0.0.0.0/0", "::/0", "*", "Internet", "any"):
            self.assertTrue(is_internet(value), value)
        for value in ("10.0.0.0/8", "203.0.113.5/32", "VirtualNetwork", "", "0.0.0.0/1"):
            self.assertFalse(is_internet(value), value)

    def test_parse_port_range(self):
        self.assertEqual(parse_port_range("22"), (22, 22))
        self.assertEqual(parse_port_range("1000-2000"), (1000, 2000))
        self.assertEqual(parse_port_range("*"), (0, 65535))
        self.assertIsNone(parse_port_range("http"))
        self.assertIsNone(parse_port_range("90-80"))

    def test_exposure(self):
        self.assertTrue(exposure("all", None, None)["all"])
        self.assertTrue(exposure("tcp", 0, 65535)["all"])
        self.assertTrue(exposure("tcp", None, None)["all"])
        self.assertEqual(exposure("tcp", 20, 25)["admin"], ["SSH (22)"])
        self.assertEqual(exposure("TCP", 3306, 3306)["sensitive"], ["MySQL (3306)"])
        self.assertEqual(exposure("*", 3389, 3389)["admin"], ["RDP (3389)"])
        self.assertEqual(exposure("icmp", None, None), {"all": False, "admin": [], "sensitive": []})
        self.assertEqual(exposure("tcp", 443, 443), {"all": False, "admin": [], "sensitive": []})


class AwsCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run("aws")

    def test_iam(self):
        self.assertEqual(self.r["aws-iam-root-access-key"].status, engine.PASS)
        self.assertEqual(resources_of(self.r["aws-iam-root-mfa"]), {"root user": "critical"})
        self.assertIn("password 11 day(s) ago", self.r["aws-iam-root-recently-used"].hits[0].detail)
        detail = self.r["aws-iam-password-policy"].hits[0].detail
        self.assertIn("minimum length is 8", detail.lower())
        self.assertIn("reuse prevention is off", detail)
        self.assertEqual(set(resources_of(self.r["aws-iam-user-no-mfa"])), {"bob"})
        self.assertEqual(set(resources_of(self.r["aws-iam-access-key-rotation"])),
                         {"ci-deploy (access key 1)", "old-contractor (access key 1)"})
        unused = {h.resource: h.detail for h in self.r["aws-iam-unused-credentials"].hits}
        self.assertEqual(set(unused), {"old-contractor"})
        self.assertIn("console password (214 days)", unused["old-contractor"])
        self.assertIn("access key 1 (223 days)", unused["old-contractor"])
        self.assertEqual(set(resources_of(self.r["aws-iam-admin-policy"])), {"LegacyFullAccess"})
        self.assertEqual(set(resources_of(self.r["aws-iam-user-admin-direct"])), {"bob"})

    def test_s3(self):
        self.assertIn("IgnorePublicAcls, RestrictPublicBuckets", self.r["aws-s3-account-public-access-block"].hits[0].detail)
        # contoso-old-site has a public policy but its own Block Public Access masks it -> low.
        self.assertEqual(resources_of(self.r["aws-s3-bucket-public"]),
                         {"contoso-customer-exports": "critical", "contoso-marketing-assets": "critical",
                          "contoso-old-site": "low"})
        self.assertEqual(set(resources_of(self.r["aws-s3-bucket-public-access-block"])),
                         {"contoso-customer-exports", "contoso-marketing-assets"})
        self.assertEqual(set(resources_of(self.r["aws-s3-bucket-tls"])),
                         {"contoso-customer-exports", "contoso-marketing-assets"})

    def test_account_block_covers_buckets(self):
        snap = demo("aws")
        snap["data"]["s3_account_block"] = {"configured": True, "BlockPublicAcls": True, "IgnorePublicAcls": True,
                                           "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        results = run("aws", snap)
        self.assertEqual(results["aws-s3-account-public-access-block"].status, engine.PASS)
        self.assertEqual(results["aws-s3-bucket-public-access-block"].status, engine.PASS)
        # public policies and ACLs are now masked by the account setting: reported, but low
        self.assertEqual(set(resources_of(results["aws-s3-bucket-public"]).values()), {"low"})

    def test_network(self):
        self.assertEqual(resources_of(self.r["aws-ec2-sg-open-all-ports"]), {"sg-0eee555 (test-anything)": "critical"})
        admin = {h.resource: h.detail for h in self.r["aws-ec2-sg-open-admin-ports"].hits}
        self.assertEqual(set(admin), {"sg-0ccc333 (bastion)", "sg-0ddd444 (legacy-db)"})
        self.assertIn("RDP (3389) open to ::/0", admin["sg-0ddd444 (legacy-db)"])
        self.assertEqual(set(resources_of(self.r["aws-ec2-sg-open-sensitive-ports"])), {"sg-0ddd444 (legacy-db)"})
        # the web group (80/443) and the internal group (10.0.0.0/8) are not findings
        everything = {h.resource for cid in self.r if cid.startswith("aws-ec2-sg") for h in self.r[cid].hits}
        self.assertFalse({r for r in everything if "web" in r or "internal" in r})
        # us-west-2's default group has no rules, us-east-1's does
        self.assertEqual(set(resources_of(self.r["aws-ec2-default-sg-rules"])), {"sg-0aaa111 (default)"})

    def test_compute_logging_and_data(self):
        self.assertEqual(set(resources_of(self.r["aws-ec2-ebs-default-encryption"])),
                         {"region eu-west-1", "region us-west-2"})
        self.assertEqual(resources_of(self.r["aws-ec2-imdsv1"]),
                         {"i-0aaa1111bbbb2222c (web-01)": "high", "i-0abc5555def66667a (batch-worker)": "medium"})
        self.assertIn("none is multi-region", self.r["aws-cloudtrail-multi-region"].hits[0].detail)
        self.assertEqual(set(resources_of(self.r["aws-rds-public"])), {"legacy-reporting"})
        self.assertEqual(set(resources_of(self.r["aws-rds-unencrypted"])), {"legacy-reporting"})
        self.assertEqual(set(resources_of(self.r["aws-guardduty-disabled"])), {"region eu-west-1", "region us-west-2"})

    def test_cloudtrail_stopped_and_unknown_status(self):
        trail = {"name": "t", "arn": "a", "home_region": "us-east-1", "multi_region": True, "log_validation": True,
                 "kms_key_id": "k", "is_logging": False}
        hits = only("aws", "aws-cloudtrail-multi-region", {"trails": [trail]})
        self.assertIn("logging is stopped: t", hits[0].detail)
        # an organization trail whose status a member account cannot read still counts as present
        self.assertEqual(only("aws", "aws-cloudtrail-multi-region", {"trails": [{**trail, "is_logging": None}]}), [])

    def test_never_used_credentials_use_creation_dates(self):
        row = {"user": "ghost", "password_enabled": "true", "password_last_used": "no_information",
               "password_last_changed": "2026-01-01T00:00:00+00:00", "mfa_active": "true",
               "access_key_1_active": "true", "access_key_1_last_rotated": "2026-09-20T00:00:00+00:00",
               "access_key_1_last_used_date": "N/A", "access_key_2_active": "false"}
        hits = only("aws", "aws-iam-unused-credentials", {"credential_report": [row]})
        self.assertEqual(len(hits), 1)
        self.assertIn("console password (273 days)", hits[0].detail)
        self.assertNotIn("access key", hits[0].detail)  # the key is only 11 days old


class AzureCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run("azure")

    def test_storage(self):
        self.assertEqual(set(resources_of(self.r["azure-storage-public-blob-access"])),
                         {"contosopublicweb (Contoso Production (demo))"})
        self.assertEqual(set(resources_of(self.r["azure-storage-https-only"])), {"contosodevscratch (Contoso Dev (demo))"})
        self.assertEqual(set(resources_of(self.r["azure-storage-min-tls"])), {"contosodevscratch (Contoso Dev (demo))"})
        # contosodevprivate has public network access disabled, so its Allow default is not a finding
        self.assertEqual(set(resources_of(self.r["azure-storage-network-default-allow"])),
                         {"contosopublicweb (Contoso Production (demo))", "contosodevscratch (Contoso Dev (demo))"})

    def test_network(self):
        # an unattached NSG is reported at low severity
        self.assertEqual(resources_of(self.r["azure-nsg-open-all-ports"]), {"nsg-dev-anything (Contoso Dev (demo))": "low"})
        admin = self.r["azure-nsg-open-admin-ports"].hits
        self.assertEqual([h.resource for h in admin], ["nsg-mgmt (Contoso Production (demo))"])
        self.assertIn("'allow-rdp' allows RDP (3389)", admin[0].detail)  # the office-only SSH rule is fine
        sensitive = self.r["azure-nsg-open-sensitive-ports"].hits
        self.assertIn("SQL Server (1433), PostgreSQL (5432)", sensitive[0].detail)

    def test_deny_and_outbound_rules_are_ignored(self):
        nsg = {"subscription": "s", "name": "n", "attached": True, "rules": [
            {"name": "deny", "direction": "Inbound", "access": "Deny", "protocol": "*", "sources": ["*"], "ports": ["*"]},
            {"name": "out", "direction": "Outbound", "access": "Allow", "protocol": "*", "sources": ["*"], "ports": ["*"]},
            {"name": "icmp", "direction": "Inbound", "access": "Allow", "protocol": "Icmp", "sources": ["*"], "ports": ["*"]}]}
        data = {"network_security_groups": [nsg], "subscriptions": []}
        for check_id in ("azure-nsg-open-all-ports", "azure-nsg-open-admin-ports", "azure-nsg-open-sensitive-ports"):
            self.assertEqual(only("azure", check_id, data), [], check_id)

    def test_data_services_and_subscription(self):
        self.assertEqual(resources_of(self.r["azure-sql-firewall-any-ip"]),
                         {"contoso-sql-dev (Contoso Dev (demo))": "critical",
                          "contoso-sql-prod (Contoso Production (demo))": "medium"})
        self.assertEqual(set(resources_of(self.r["azure-keyvault-purge-protection"])), {"kv-contoso-dev (Contoso Dev (demo))"})
        self.assertEqual(set(resources_of(self.r["azure-keyvault-public-network"])), {"kv-contoso-dev (Contoso Dev (demo))"})
        plans = set(resources_of(self.r["azure-defender-plan-off"]))
        self.assertIn("Defender for Azure SQL (Contoso Production (demo))", plans)
        self.assertNotIn("Defender for Servers (Contoso Production (demo))", plans)
        self.assertEqual(len(plans), 6)  # containers is not one of the plans this scanner tracks
        owners = self.r["azure-subscription-owner-count"].hits
        self.assertEqual([h.resource for h in owners], ["Contoso Production (demo)"])
        self.assertIn("5 Owner role assignments", owners[0].detail)
        self.assertIn("1 ServicePrincipal, 4 User", owners[0].detail)
        self.assertEqual(set(resources_of(self.r["azure-custom-owner-role"])),
                         {"Contoso Super Operator (Contoso Production (demo))"})
        self.assertEqual(set(resources_of(self.r["azure-activity-log-export"])), {"Contoso Dev (demo)"})

    def test_activity_log_not_flagged_when_subscription_was_not_read(self):
        data = {"subscriptions": [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}],
                "activity_log_settings": [{"subscription": "a", "name": ""}]}  # b failed to collect
        self.assertEqual([h.resource for h in only("azure", "azure-activity-log-export", data)], ["A"])


class GcpCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = run("gcp")

    def test_iam(self):
        self.assertIn("roles/storage.objectViewer is granted to allUsers", self.r["gcp-iam-public-member"].hits[0].detail)
        basic = resources_of(self.r["gcp-iam-service-account-basic-role"])
        self.assertEqual(basic, {"deployer@contoso-prod-demo.iam.gserviceaccount.com (contoso-prod-demo)": "high",
                                 "100000000001-compute@developer.gserviceaccount.com (contoso-prod-demo)": "medium"})
        self.assertEqual(resources_of(self.r["gcp-iam-personal-account"]),
                         {"dev.lead@gmail.com (contoso-dev-demo)": "high",
                          "freelancer.jane@gmail.com (contoso-prod-demo)": "medium"})
        keys = resources_of(self.r["gcp-iam-service-account-key"])  # the disabled key is not reported
        self.assertEqual(keys, {"deployer@contoso-prod-demo.iam.gserviceaccount.com (contoso-prod-demo)": "medium",
                                "ci@contoso-dev-demo.iam.gserviceaccount.com (contoso-dev-demo)": "low"})

    def test_service_account_kinds(self):
        self.assertEqual(service_account_kind("123-compute@developer.gserviceaccount.com"), "default")
        self.assertEqual(service_account_kind("proj@appspot.gserviceaccount.com"), "default")
        self.assertEqual(service_account_kind("app@proj.iam.gserviceaccount.com"), "user")
        self.assertEqual(service_account_kind("123@cloudservices.gserviceaccount.com"), "google")
        self.assertEqual(service_account_kind("service-1@gcp-sa-pubsub.iam.gserviceaccount.com"), "google")

    def test_storage_and_network(self):
        self.assertEqual(set(resources_of(self.r["gcp-storage-public-bucket"])), {"contoso-prod-static (contoso-prod-demo)"})
        self.assertEqual(set(resources_of(self.r["gcp-storage-uniform-access"])), {"contoso-dev-uploads (contoso-dev-demo)"})
        # the disabled rule and the ICMP rule are not findings
        self.assertEqual([h.resource for h in self.r["gcp-firewall-open-all-ports"].hits],
                         ["temp-open (contoso-dev-demo, network default)"])
        self.assertEqual({h.resource.split(" ")[0] for h in self.r["gcp-firewall-open-admin-ports"].hits},
                         {"default-allow-ssh", "default-allow-rdp"})
        self.assertIn("Redis (6379), Elasticsearch (9200)", self.r["gcp-firewall-open-sensitive-ports"].hits[0].detail)

    def test_compute_and_sql(self):
        # dev-batch uses the default account with narrow scopes; prod-api-1 uses a dedicated account
        self.assertEqual(resources_of(self.r["gcp-compute-default-sa-full-access"]), {"dev-box (contoso-dev-demo)": "high"})
        for check_id in ("gcp-sql-public-network", "gcp-sql-no-ssl", "gcp-sql-no-backups"):
            self.assertEqual(set(resources_of(self.r[check_id])), {"dev-mysql (contoso-dev-demo)"}, check_id)

    def test_unparseable_port_is_not_treated_as_all_ports(self):
        firewall = {"project": "p", "name": "f", "network": "n", "direction": "INGRESS", "disabled": False,
                    "source_ranges": ["0.0.0.0/0"], "allowed": [{"protocol": "tcp", "ports": ["http"]}]}
        self.assertEqual(only("gcp", "gcp-firewall-open-all-ports", {"firewalls": [firewall]}), [])


if __name__ == "__main__":
    unittest.main()
