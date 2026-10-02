# Read-only access for cloud-security-checks

The scanner only reads. Give it the narrowest read-only identity each cloud offers. If a
permission is missing, the affected checks are reported as **skipped** with the reason; nothing
crashes and nothing is reported as passing.

## AWS

**Recommended:** an IAM role with the AWS-managed **`SecurityAudit`** policy
(`arn:aws:iam::aws:policy/SecurityAudit`). It covers every call the scanner makes.

### How the scanner finds credentials

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), unless
   `--profile` or `AWS_PROFILE` is set. This is what GitHub Actions OIDC provides.
2. The AWS CLI: `aws configure export-credentials`. This resolves everything the CLI can,
   including **IAM Identity Center (SSO)** and assumed roles. Run `aws sso login --profile <name>`
   first.
3. `~/.aws/credentials` for plain access-key profiles.
4. Container credentials (ECS, EKS Pod Identity) and the EC2 instance role.

### Calls made

| Service | Actions |
|---|---|
| STS | `GetCallerIdentity` |
| IAM | `GetAccountSummary`, `GetAccountPasswordPolicy`, `GenerateCredentialReport`, `GetCredentialReport`, `ListPolicies`, `GetPolicyVersion`, `ListEntitiesForPolicy` |
| S3 | `ListAllMyBuckets`, `GetAccountPublicAccessBlock`, `GetBucketPublicAccessBlock`, `GetBucketPolicyStatus`, `GetBucketAcl`, `GetBucketPolicy`, `HeadBucket` |
| EC2 | `DescribeRegions`, `DescribeSecurityGroups`, `GetEbsEncryptionByDefault`, `DescribeSnapshots`, `DescribeImages`, `DescribeInstances` |
| RDS | `DescribeDBInstances` |
| CloudTrail | `DescribeTrails`, `GetTrailStatus` |
| GuardDuty | `ListDetectors`, `GetDetector` |

`GenerateCredentialReport` is the only call that is not a pure read: it asks IAM to refresh its own
credential report (IAM does this at most once every four hours). It changes no resources.

To scan many accounts, create the same role in each (for example with a CloudFormation StackSet)
and run the scanner once per account with a profile that assumes it.

## Azure

**Recommended:** the built-in **Reader** role on each subscription (or on a management group above
them).

### How the scanner signs in

| Mode | Settings |
|---|---|
| Azure CLI | Run `az login`; nothing else needed |
| App registration | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Managed identity | `USE_MANAGED_IDENTITY=true` (and `AZURE_CLIENT_ID` for a user-assigned identity) |

Force one with `AZURE_AUTH=cli|secret|managed_identity`.

### Calls made (all `GET` on Azure Resource Manager)

`subscriptions`, `Microsoft.Storage/storageAccounts`, `Microsoft.Network/networkSecurityGroups`,
`Microsoft.Sql/servers` and their `firewallRules`, `Microsoft.KeyVault/vaults`,
`Microsoft.Security/pricings`, `Microsoft.Authorization/roleAssignments` and `roleDefinitions`,
`Microsoft.Insights/diagnosticSettings` (subscription scope).

Only the management plane is read. The scanner never reads blobs, secrets, keys or database
contents.

## Google Cloud

**Recommended:** a dedicated service account with **Viewer** (`roles/viewer`) and **Security
Reviewer** (`roles/iam.securityReviewer`) on each project, used through impersonation:

```bash
cloud-checks gcp --project my-project --impersonate auditor@my-project.iam.gserviceaccount.com
```

Your own user then only needs `roles/iam.serviceAccountTokenCreator` on that service account.

### How the scanner gets a token

1. `GOOGLE_OAUTH_ACCESS_TOKEN` (for example from workload identity federation in CI).
2. The gcloud CLI: `gcloud auth print-access-token`, with `--impersonate` if given.
3. The metadata server on Compute Engine, Cloud Run, GKE or Cloud Shell.

Service account key files are not supported on purpose.

### Signed in as yourself? Set a quota project

With user credentials, Google meters some APIs against the gcloud CLI's own project and answers
"API has not been used in project 32555940559". The scanner recognises this and reports the checks
as skipped rather than passed. Fix it with either:

* `--impersonate <service account>` (recommended), or
* `--quota-project <your project>`; your user needs `roles/serviceusage.serviceUsageConsumer` there.

### Calls made

| API | Calls |
|---|---|
| Cloud Resource Manager | `projects.list`, `projects.get`, `projects.getIamPolicy` |
| IAM | `serviceAccounts.list`, `serviceAccounts.keys.list` |
| Cloud Storage | `buckets.list`, `buckets.getIamPolicy` |
| Compute Engine | `firewalls.list`, `instances.aggregatedList` |
| Cloud SQL Admin | `instances.list` |

If one of these APIs is not enabled in a scanned project, there is nothing of that kind to check
there, and the report notes it.
