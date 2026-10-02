"""Azure and Google Cloud collectors against fake APIs."""

import os
import unittest
from unittest import mock

from cloud_checks.azure.collect import ArmApi, collect as collect_azure
from cloud_checks.core import engine
from cloud_checks.core.http import HttpError, Response
from cloud_checks.gcp.auth import GcpAuthError, GcpCredential
from cloud_checks.gcp.collect import GcpApi, collect as collect_gcp
from tests.fakes import FakeTransport, StaticCredential, body_json, json_response, query_params

SUB = "11111111-2222-4333-8444-555555555555"
ARM = "https://management.azure.com"


def arm_resource(kind: str, name: str, properties: dict) -> dict:
    return {"id": f"/subscriptions/{SUB}/resourceGroups/rg/providers/{kind}/{name}", "name": name,
            "location": "eastus", "properties": properties}


class AzureCollectTests(unittest.TestCase):
    def fake(self) -> FakeTransport:
        t = FakeTransport()
        t.add("GET", r"/subscriptions\?", json_response({"value": [
            {"subscriptionId": SUB, "displayName": "Prod", "state": "Enabled"},
            {"subscriptionId": "disabled-sub", "displayName": "Old", "state": "Disabled"}]}))
        t.add("GET", r"storageAccounts\?.*skiptoken", json_response({"value": [arm_resource(
            "Microsoft.Storage/storageAccounts", "second", {"supportsHttpsTrafficOnly": False})]}))
        t.add("GET", r"Microsoft\.Storage/storageAccounts\?", json_response({
            "value": [arm_resource("Microsoft.Storage/storageAccounts", "first", {
                "allowBlobPublicAccess": True, "supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_0",
                "networkAcls": {"defaultAction": "Allow"}, "publicNetworkAccess": "Enabled"})],
            "nextLink": f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01&$skiptoken=abc"}))
        t.add("GET", r"networkSecurityGroups\?", json_response({"value": [arm_resource(
            "Microsoft.Network/networkSecurityGroups", "nsg1", {
                "subnets": [{"id": "x"}],
                "securityRules": [{"name": "rdp", "properties": {
                    "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "priority": 100,
                    "sourceAddressPrefix": "*", "destinationPortRanges": ["3389", "5985-5986"]}}]})]}))
        t.add("GET", r"/firewallRules\?", json_response({"value": [
            {"name": "all", "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}}]}))
        t.add("GET", r"Microsoft\.Sql/servers\?", json_response({"value": [arm_resource(
            "Microsoft.Sql/servers", "sql1", {"publicNetworkAccess": "Enabled"})]}))
        t.add("GET", r"Microsoft\.KeyVault/vaults\?", json_response({"value": [arm_resource(
            "Microsoft.KeyVault/vaults", "kv1", {"enableSoftDelete": True, "networkAcls": {"defaultAction": "Deny"}})]}))
        t.add("GET", r"Microsoft\.Security/pricings\?", json_response({"error": {
            "code": "AuthorizationFailed", "message": "no access"}}, 403))
        t.add("GET", r"roleAssignments\?", json_response({"value": [{"properties": {
            "principalId": "p1", "principalType": "User", "scope": f"/subscriptions/{SUB}",
            "roleDefinitionId": f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}]}))
        t.add("GET", r"roleDefinitions\?", json_response({"value": [{"properties": {
            "roleName": "God Mode", "permissions": [{"actions": ["*"]}], "assignableScopes": [f"/subscriptions/{SUB}"]}}]}))
        t.add("GET", r"Microsoft\.Insights/diagnosticSettings\?", json_response({"value": []}))
        return t

    def test_collect_normalizes_pages_and_isolates_failures(self):
        t = self.fake()
        credential = StaticCredential()
        snapshot = collect_azure(ArmApi(t.client(retries=0), credential))
        data = snapshot["data"]
        self.assertEqual(data["subscriptions"], [{"id": SUB, "name": "Prod"}])  # disabled subscription dropped
        self.assertEqual([s["name"] for s in data["storage_accounts"]], ["first", "second"])  # nextLink followed
        self.assertEqual(data["storage_accounts"][0]["minimum_tls"], "TLS1_0")
        rule = data["network_security_groups"][0]["rules"][0]
        self.assertEqual((rule["sources"], rule["ports"]), (["*"], ["3389", "5985-5986"]))
        self.assertTrue(data["network_security_groups"][0]["attached"])
        self.assertEqual(data["sql_servers"][0]["firewall_rules"], [{"name": "all", "start": "0.0.0.0", "end": "255.255.255.255"}])
        self.assertIsNone(data["key_vaults"][0]["purge_protection"])
        self.assertIsNone(data["defender_plans"])
        self.assertIn("assign the Reader role", snapshot["errors"]["defender_plans"])
        self.assertEqual(data["role_assignments"][0]["role_definition_id"], "8e3af657-a8ff-443c-a75c-2fe8c4bcb635")
        self.assertEqual(data["activity_log_settings"], [{"subscription": SUB, "name": ""}])
        self.assertEqual(credential.scopes[0], "https://management.azure.com/.default")
        self.assertEqual(query_params(t.requests_to("roleAssignments")[0])["$filter"], "atScope()")
        self.assertTrue(all(c.method == "GET" for c in t.calls))  # read-only

        results = {r.check.id: r for r in engine.run(snapshot, engine.checks_for("azure"))}
        self.assertEqual(results["azure-defender-plan-off"].status, engine.SKIPPED)
        for check_id in ("azure-storage-public-blob-access", "azure-storage-https-only", "azure-storage-min-tls",
                         "azure-nsg-open-admin-ports", "azure-nsg-open-sensitive-ports", "azure-sql-firewall-any-ip",
                         "azure-keyvault-purge-protection", "azure-custom-owner-role", "azure-activity-log-export"):
            self.assertEqual(results[check_id].status, engine.FAIL, check_id)
        self.assertEqual(results["azure-subscription-owner-count"].status, engine.PASS)
        self.assertIn("WinRM (5985)", results["azure-nsg-open-sensitive-ports"].hits[0].detail)

    def test_subscription_filter_and_unknown_subscription(self):
        snapshot = collect_azure(ArmApi(self.fake().client(retries=0), StaticCredential()), only_subscriptions=[SUB.upper()])
        self.assertEqual(len(snapshot["data"]["subscriptions"]), 1)
        with self.assertRaisesRegex(ValueError, "not visible"):
            collect_azure(ArmApi(self.fake().client(retries=0), StaticCredential()), only_subscriptions=["nope"])

    def test_paging_link_to_another_host_is_refused(self):
        t = FakeTransport().add("GET", "management.azure.com", json_response(
            {"value": [], "nextLink": "https://evil.example/steal"}))
        with self.assertRaises(HttpError):
            ArmApi(t.client(retries=0), StaticCredential()).get_all("/subscriptions", "2022-12-01")
        self.assertEqual(len(t.calls), 1)


class StaticToken:
    def get_token(self) -> str:
        return "gcp-token"


class GcpCollectTests(unittest.TestCase):
    def fake(self) -> FakeTransport:
        t = FakeTransport()
        t.add("GET", r"cloudresourcemanager.*/v1/projects\?", json_response({"projects": [
            {"projectId": "proj-a", "name": "A", "projectNumber": "1"}, {"projectId": "proj-b", "name": "B", "projectNumber": "2"}]}))
        t.add("POST", r"projects/proj-a:getIamPolicy", json_response({"bindings": [
            {"role": "roles/editor", "members": ["serviceAccount:1-compute@developer.gserviceaccount.com"]},
            {"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}]}))
        t.add("POST", r"projects/proj-b:getIamPolicy", json_response({"error": {"code": 403, "message": "denied"}}, 403))
        t.add("GET", r"iam\.googleapis\.com/v1/projects/proj-a/serviceAccounts\?", json_response({"accounts": [
            {"name": "projects/proj-a/serviceAccounts/app@proj-a.iam.gserviceaccount.com",
             "email": "app@proj-a.iam.gserviceaccount.com"}]}))
        t.add("GET", r"serviceAccounts/app@proj-a\.iam\.gserviceaccount\.com/keys", json_response({"keys": [
            {"name": "projects/proj-a/serviceAccounts/app@proj-a.iam.gserviceaccount.com/keys/abc123",
             "validAfterTime": "2020-01-01T00:00:00Z"}]}))
        t.add("GET", r"iam\.googleapis\.com/v1/projects/proj-b/serviceAccounts", json_response({}))
        t.add("GET", r"storage/v1/b\?.*pageToken=next", json_response({"items": [
            {"name": "locked", "location": "US", "iamConfiguration": {"publicAccessPrevention": "enforced",
                                                                    "uniformBucketLevelAccess": {"enabled": True}}}]}))
        t.add("GET", r"storage/v1/b\?.*project=proj-a", json_response({"nextPageToken": "next", "items": [
            {"name": "open", "location": "EU", "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}}]}))
        t.add("GET", r"storage/v1/b\?.*project=proj-b", json_response({}))
        t.add("GET", r"storage/v1/b/open/iam", json_response({"bindings": [
            {"role": "roles/storage.objectViewer", "members": ["allUsers", "user:a@example.com"]}]}))
        t.add("GET", r"projects/proj-a/global/firewalls", json_response({"items": [
            {"name": "ssh", "network": "https://www.googleapis.com/compute/v1/projects/proj-a/global/networks/default",
             "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]}))
        t.add("GET", r"projects/proj-a/aggregated/instances", json_response({"items": {
            "zones/us-central1-a": {"instances": [{"name": "vm1", "status": "RUNNING",
                                                   "networkInterfaces": [{"accessConfigs": [{"natIP": "203.0.113.4"}]}],
                                                   "serviceAccounts": [{"email": "1-compute@developer.gserviceaccount.com",
                                                                        "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}]},
            "zones/us-east1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}}}}))
        disabled = json_response({"error": {"code": 403, "message": "Compute Engine API has not been used in project 2 "
                                            "before or it is disabled.", "details": [
                                                {"reason": "SERVICE_DISABLED", "metadata": {"consumer": "projects/2"}}]}}, 403)
        t.add("GET", r"compute\.googleapis\.com/compute/v1/projects/proj-b/", disabled)
        t.add("GET", r"sqladmin.*projects/proj-a/instances", json_response({"items": [
            {"name": "db", "databaseVersion": "MYSQL_8_0", "region": "us-central1", "instanceType": "CLOUD_SQL_INSTANCE",
             "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "0.0.0.0/0"}]},
                          "backupConfiguration": {"enabled": True}}}]}))
        t.add("GET", r"sqladmin.*projects/proj-b/instances", json_response({}))
        return t

    def test_collect(self):
        t = self.fake()
        snapshot = collect_gcp(GcpApi(t.client(retries=0), StaticToken()))
        data, errors = snapshot["data"], snapshot["errors"]
        self.assertEqual([p["id"] for p in data["projects"]], ["proj-a", "proj-b"])
        self.assertEqual(len(data["iam_bindings"]), 2)
        self.assertIn("proj-b", errors["iam_bindings (partial)"])
        self.assertIn("roles/iam.securityReviewer", errors["iam_bindings (partial)"])
        self.assertEqual(data["service_account_keys"][0]["key_id"], "abc123")
        buckets = {b["name"]: b for b in data["buckets"]}
        self.assertEqual(buckets["open"]["public_bindings"], [{"role": "roles/storage.objectViewer", "member": "allUsers"}])
        self.assertEqual(buckets["locked"]["public_access_prevention"], "enforced")
        self.assertFalse(t.requests_to("b/locked/iam"))  # enforced prevention: no IAM lookup needed
        self.assertEqual(data["firewalls"][0]["network"], "default")
        self.assertEqual(data["instances"][0]["zone"], "us-central1-a")
        self.assertEqual(data["instances"][0]["public_ips"], ["203.0.113.4"])
        self.assertEqual(errors["firewalls (API not enabled)"], "nothing to check in proj-b")
        self.assertEqual(data["sql_instances"][0]["authorized_networks"], ["0.0.0.0/0"])
        self.assertEqual(t.calls[0].headers["Authorization"], "Bearer gcp-token")
        posts = [c for c in t.calls if c.method == "POST"]
        self.assertTrue(all(c.url.endswith(":getIamPolicy") for c in posts))  # the only POSTs are policy reads
        self.assertEqual(body_json(posts[0]), {"options": {"requestedPolicyVersion": 3}})

        results = {r.check.id: r for r in engine.run(snapshot, engine.checks_for("gcp"))}
        for check_id in ("gcp-iam-public-member", "gcp-iam-service-account-basic-role", "gcp-iam-service-account-key",
                         "gcp-storage-public-bucket", "gcp-storage-uniform-access", "gcp-firewall-open-admin-ports",
                         "gcp-compute-default-sa-full-access", "gcp-sql-public-network", "gcp-sql-no-ssl"):
            self.assertEqual(results[check_id].status, engine.FAIL, check_id)
        self.assertEqual(results["gcp-sql-no-backups"].status, engine.PASS)
        self.assertFalse([r for r in results.values() if r.status == engine.SKIPPED])

    def test_explicit_projects_skip_discovery_and_total_failure_skips_checks(self):
        t = self.fake()
        t.add("GET", r"cloudresourcemanager.*/v1/projects/proj-b$", json_response({"projectId": "proj-b", "name": "B",
                                                                                  "projectNumber": "2"}))
        snapshot = collect_gcp(GcpApi(t.client(retries=0), StaticToken(), quota_project="billing-proj"),
                               only_projects=["proj-b", "proj-b"])
        self.assertEqual(snapshot["data"]["projects"], [{"id": "proj-b", "name": "B", "number": "2"}])
        self.assertFalse(t.requests_to(r"v1/projects\?"))
        self.assertEqual(t.calls[0].headers["X-Goog-User-Project"], "billing-proj")
        self.assertIsNone(snapshot["data"]["iam_bindings"])
        self.assertEqual(snapshot["data"]["firewalls"], [])  # API disabled = nothing to check, not an error
        results = {r.check.id: r for r in engine.run(snapshot, engine.checks_for("gcp"))}
        self.assertEqual(results["gcp-iam-public-member"].status, engine.SKIPPED)
        self.assertEqual(results["gcp-firewall-open-all-ports"].status, engine.PASS)


    def test_api_disabled_in_the_quota_project_is_an_error_not_a_clean_result(self):
        # Signed in as a user, Google reports "disabled" for the gcloud CLI's own project. That must
        # never be read as "the scanned project has no firewalls".
        t = FakeTransport()
        t.add("GET", r"cloudresourcemanager.*/v1/projects/proj-a$", json_response({"projectId": "proj-a", "projectNumber": "1"}))
        t.add("POST", r"getIamPolicy", json_response({"bindings": []}))
        other = json_response({"error": {"code": 403, "message": "Compute Engine API has not been used in project "
                                         "32555940559 before or it is disabled.", "details": [
                                             {"reason": "SERVICE_DISABLED", "metadata": {"consumer": "projects/32555940559"}}]}}, 403)
        t.add("GET", r"googleapis\.com", other)
        snapshot = collect_gcp(GcpApi(t.client(retries=0), StaticToken()), only_projects=["proj-a"])
        self.assertIsNone(snapshot["data"]["firewalls"])
        self.assertIn("--quota-project", snapshot["errors"]["firewalls"])
        results = {r.check.id: r for r in engine.run(snapshot, engine.checks_for("gcp"))}
        self.assertEqual(results["gcp-firewall-open-all-ports"].status, engine.SKIPPED)
        self.assertEqual(results["gcp-iam-public-member"].status, engine.PASS)


class GcpAuthTests(unittest.TestCase):
    def test_environment_token(self):
        with mock.patch.dict(os.environ, {"GOOGLE_OAUTH_ACCESS_TOKEN": " tok \n"}, clear=True):
            credential = GcpCredential()
            self.assertEqual(credential.get_token(), "tok")
            self.assertIn("environment", credential.source)

    def test_gcloud_with_impersonation_and_failure(self):
        ok = mock.Mock(returncode=0, stdout="ya29.token\n", stderr="")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value="/usr/bin/gcloud"), \
                mock.patch("subprocess.run", return_value=ok) as run:
            self.assertEqual(GcpCredential("audit@p.iam.gserviceaccount.com").get_token(), "ya29.token")
            self.assertIn("--impersonate-service-account=audit@p.iam.gserviceaccount.com", run.call_args[0][0])
        bad = mock.Mock(returncode=1, stdout="", stderr="ERROR: (gcloud.auth.print-access-token) You do not have an active account.")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value="/usr/bin/gcloud"), \
                mock.patch("subprocess.run", return_value=bad):
            with self.assertRaisesRegex(GcpAuthError, "gcloud auth login"):
                GcpCredential().get_token()

    def test_metadata_server_and_nothing_available(self):
        t = FakeTransport().add("GET", "metadata.google.internal", json_response({"access_token": "md", "expires_in": 3000}))
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            credential = GcpCredential(metadata_http=t.client(retries=0))
            self.assertEqual(credential.get_token(), "md")
            self.assertEqual(credential.get_token(), "md")
            self.assertEqual(len(t.calls), 1)  # cached
            self.assertEqual(t.calls[0].headers["Metadata-Flavor"], "Google")
            down = FakeTransport().add("GET", "metadata", Response(404, b""))
            with self.assertRaisesRegex(GcpAuthError, "no Google Cloud credentials"):
                GcpCredential(metadata_http=down.client(retries=0)).get_token()
            with self.assertRaisesRegex(GcpAuthError, "needs the gcloud CLI"):
                GcpCredential("sa@p.iam.gserviceaccount.com").get_token()


if __name__ == "__main__":
    unittest.main()
