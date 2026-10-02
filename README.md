# cloud-security-checks

**Read-only misconfiguration scanners for AWS, Azure and Google Cloud.** 54 checks for the mistakes
that cause most cloud breaches: public storage, firewalls open to the internet, missing MFA, stale
keys, over-privileged identities, logging and threat detection switched off.

No SDKs and no third-party dependencies: the tool talks to the cloud REST APIs directly with the
Python standard library, including its own AWS request signing (verified against AWS's published
test vectors).

[![CI](https://github.com/as70023333/cloud-security-checks/actions/workflows/ci.yml/badge.svg)](https://github.com/as70023333/cloud-security-checks/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

```bash
pip install git+https://github.com/as70023333/cloud-security-checks
cloud-checks aws --demo      # try it now on a fictional account, no credentials needed
```

```text
Checks: 1 passed, 26 failed, 0 skipped
Findings: 5 critical, 10 high, 14 medium, 6 low
  [critical] EBS snapshot is public: snap-0123456789abcdef0
  [critical] Security group allows all ports from the internet: sg-0eee555 (test-anything)
  [critical] Root user has no MFA: root user
  [critical] S3 bucket is public: contoso-customer-exports
  [high    ] No multi-region CloudTrail trail is logging: account
  [high    ] Security group allows SSH or RDP from the internet: sg-0ccc333 (bastion)
  ...
Report: reports/aws-security-check-2026-10-01.md
```

---

## Who this is for

* **Cloud and security engineers** who want a quick, honest read on an account without deploying
  a platform.
* **Consultants and auditors** who are handed a read-only role and an afternoon.
* **Small teams without a CSPM product**, as a scheduled weekly check.
* **Teams that have a CSPM product**, as an independent second opinion or a CI gate.

## What it checks

| Cloud | Checks | Areas |
|---|---|---|
| **AWS** | 27 | IAM (root user, MFA, key age, unused credentials, admin policies), S3 (public buckets, Block Public Access, TLS), EC2 (security groups, public snapshots and AMIs, IMDSv1, EBS encryption), CloudTrail, RDS, GuardDuty |
| **Azure** | 14 | Storage (anonymous access, HTTPS, TLS, network rules), network security groups, Azure SQL firewall, Key Vault, Defender for Cloud plans, subscription owners and custom roles, activity log export |
| **Google Cloud** | 13 | Project IAM (public members, basic roles, personal accounts), service account keys, Cloud Storage, VPC firewall rules, Compute Engine default service account, Cloud SQL |

The full list, with why each check matters and how to fix it, is in **[docs/CHECKS.md](docs/CHECKS.md)**
(or run `cloud-checks list`). Where a check maps to a CIS benchmark control, the number is shown;
numbers are only cited where they were verified against the provider's published mapping.

### How results are reported

Every check ends in one of three states:

| State | Meaning |
|---|---|
| **PASS** | The data was read and nothing failed |
| **FAIL** | One finding per failing resource, each with a severity |
| **SKIPPED** | The data could not be read (missing permission, API error). The report says why. |

A skipped check is never reported as a pass. If your role cannot read RDS, the RDS checks say so
under **Coverage notes** instead of quietly showing green.

Severity adapts to context: an open security group rule is `critical` for all ports, `high` for
SSH or a database; a public S3 policy that is currently masked by Block Public Access is `low`
("one setting away from public") rather than `critical`; an instance allowing IMDSv1 is raised to
`high` if it has a public IP.

## When to use it

* **Before or after a migration**, to catch what was opened "temporarily".
* **Weekly, on a schedule**, with the Markdown report posted to the team (`--fail-on none`).
* **In CI for an infrastructure repository**, after `terraform apply` to a test account, with
  `--fail-on critical` as a gate.
* **During an incident**, to answer "what else is exposed in this account?" in a minute.
* **For an audit or customer questionnaire**, as evidence with CIS references.

## Where it runs

Anywhere with **Python 3.11+** and HTTPS to the cloud APIs: a laptop, a CI runner, a container, a
cloud shell. It keeps no state and sends nothing anywhere except the cloud provider's own APIs.

## Why it is built this way

* **Read-only, provably.** AWS calls are `Describe*`, `Get*`, `List*` (plus asking IAM to refresh
  its credential report). Azure calls are all `GET`. Google Cloud calls are `GET` plus
  `getIamPolicy`. The tests assert this. Nothing in the repository can change a cloud resource.
* **No SDKs.** boto3, the Azure SDK and the Google client libraries are hundreds of megabytes of
  dependencies for what is, here, a few dozen REST calls. Zero dependencies means nothing to
  audit, nothing to pin, and an install that takes a second.
* **Collect once, check offline.** A scan writes a snapshot of what it read (`--save-snapshot`).
  Checks are pure functions over that snapshot, so you can re-run them, add checks, or share the
  snapshot with a reviewer without touching the cloud again.
* **No false comfort.** Partial data is labelled as partial. A Google API that is disabled in the
  *credential's* project (a common trap when signed in as a user) is treated as an error, not as
  "this project has no firewalls".
* **No long-lived keys required.** AWS SSO and roles, Azure managed identity or `az login`, and
  gcloud or workload identity all work. Google service account key files are deliberately not
  supported: they are one of the things this tool reports.

## How to use it

### 1. Install

```bash
git clone https://github.com/as70023333/cloud-security-checks.git
cd cloud-security-checks
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install .
```

### 2. Try it offline

```bash
cloud-checks aws --demo
cloud-checks azure --demo
cloud-checks gcp --demo
```

Reports are written to `./reports` as Markdown, CSV and JSON.

### 3. Grant read-only access

| Cloud | Give the scanning identity | Details |
|---|---|---|
| AWS | The AWS-managed **SecurityAudit** policy | [docs/permissions.md](docs/permissions.md#aws) |
| Azure | The **Reader** role on each subscription | [docs/permissions.md](docs/permissions.md#azure) |
| Google Cloud | **Viewer** and **Security Reviewer** on each project | [docs/permissions.md](docs/permissions.md#google-cloud) |

### 4. Scan

```bash
# AWS: credentials from the environment, an AWS CLI profile (SSO works), or an IAM role
cloud-checks aws --profile audit
cloud-checks aws --region us-east-1,eu-west-1          # default: every enabled region

# Azure: 'az login', a client secret, or a managed identity (see .env.example)
cloud-checks azure --subscription 00000000-0000-0000-0000-000000000000

# Google Cloud: 'gcloud auth login', impersonation, or a token from workload identity
cloud-checks gcp --project my-project --impersonate auditor@my-project.iam.gserviceaccount.com
```

### Options (all three clouds)

| Option | Default | Meaning |
|---|---|---|
| `--checks LIST` | all | Only these check ids or services (`s3,iam`, `aws-iam-root-mfa`) |
| `--skip LIST` | none | Check ids or services to leave out |
| `--out DIR` | `reports` | Report folder |
| `--format LIST` | `md,csv,json` | Report formats |
| `--fail-on LEVEL` | `high` | Exit 1 when a finding is at or above this severity; `none` to always exit 0 |
| `--save-snapshot FILE` | | Also save the collected data |
| `--snapshot FILE` | | Check saved data instead of calling the cloud |
| `--demo` | | Use the built-in fictional account |
| `--quiet`, `--no-color`, `--env-file` | | Output and settings control |

Cloud-specific: `--profile`, `--region` (AWS); `--subscription` (Azure); `--project`,
`--impersonate`, `--quota-project` (Google Cloud). Most can also be set in `.env`
(see [.env.example](.env.example)).

**Exit codes:** `0` nothing at or above `--fail-on`, `1` findings at or above it, `2` error.

### The reports

* **`<cloud>-security-check-<date>.md`**: summary, a pass/fail/skipped table of every check, then
  each failed check with why it matters, how to fix it, and the affected resources.
* **`.csv`**: one row per finding, for a spreadsheet or ticket import.
* **`.json`**: everything, for automation (`checks[]`, `findings[]`, `coverage_notes`).

Reports and snapshots name your resources. Treat them as confidential (`reports/` is in
`.gitignore`).

### Use it as a CI gate (GitHub Actions, AWS via OIDC)

```yaml
permissions: { id-token: write, contents: read }
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with: { role-to-assume: arn:aws:iam::111122223333:role/SecurityAudit, aws-region: us-east-1 }
  - run: pip install git+https://github.com/as70023333/cloud-security-checks
  - run: cloud-checks aws --fail-on critical
  - uses: actions/upload-artifact@v4
    if: always()
    with: { name: cloud-security-report, path: reports/ }
```

## Tuning and false positives

| Situation | What to do |
|---|---|
| A bucket or image is public on purpose (static website, published AMI) | `--skip` the check for that run, or accept the finding in your tracker; per-resource exceptions are on the roadmap |
| Default security groups and EBS default encryption produce one finding per region | Scan only the regions you use with `--region`, or fix them once with the account-level settings |
| Defender for Cloud plans are off by decision (cost) | `--skip azure-defender-plan-off` |
| Google default network rules (`default-allow-ssh`, `default-allow-rdp`) | These are real findings; delete the default network in projects that do not use it |
| Service accounts that hold Editor by design | Replace with predefined roles; the default Compute Engine account is reported at `medium`, your own accounts at `high` |

## Limitations

* It reads configuration, not traffic or data: a public bucket is reported whether or not it
  holds anything sensitive.
* S3 "public" follows AWS's own `GetBucketPolicyStatus` and ACL grants; object-level ACLs are not
  enumerated. Google Cloud bucket checks read IAM, not per-object ACLs (which is why the tool
  flags buckets without uniform access).
* AWS commercial partition only (not GovCloud or China). Azure sovereign clouds work through
  `AZURE_ARM_BASE_URL` and `AZURE_AUTHORITY_HOST`.
* The cloud API calls are tested against simulated responses, not against live accounts in CI.
  Run it against a test account first.

## Repository layout

```
cloud-security-checks/
├── cloud_checks/
│   ├── core/            # HTTP with retries, Entra ID auth, check engine, ports logic, report helpers
│   ├── aws/             # sigv4.py (request signing), credentials.py, api.py, collect.py, checks.py
│   ├── azure/           # collect.py (Azure Resource Manager), checks.py
│   ├── gcp/             # auth.py, collect.py, checks.py
│   ├── report.py        # Markdown, CSV, JSON and the check catalog
│   └── cli.py
├── docs/
│   ├── CHECKS.md        # generated catalog of all 54 checks
│   └── permissions.md   # least-privilege access for each cloud
├── tests/               # 77 tests: signing vectors, fake AWS / Azure / Google Cloud APIs, every check
└── .github/workflows/ci.yml
```

## Adding a check

A check is one decorated function in `cloud_checks/<cloud>/checks.py`:

```python
@check(id="aws-rds-public", cloud="aws", service="rds", severity="high", cis="2.3.3",
       title="RDS instance is publicly accessible", needs=["rds_instances"],
       why="The database has a public address; only its security group and password protect it.",
       fix="Set PubliclyAccessible to false and reach the database through private networking.")
def rds_public(data):
    for db in data["rds_instances"]:
        if db.get("public"):
            yield Hit(db["id"], f"{db.get('engine')} instance has PubliclyAccessible enabled.", region=db["region"])
```

`needs` names the snapshot data the check reads; if that data could not be collected, the check is
skipped with the reason. Add a case to the demo snapshot and a test, then regenerate the catalog:

```bash
python -m unittest discover -s tests -t .
cloud-checks list --format md > docs/CHECKS.md
```

## Related projects

* [soc-toolkit](https://github.com/as70023333/soc-toolkit): KQL hunting library, Entra ID audit,
  IOC enrichment, Defender device health, secrets scanner.
* [cloud-guardrail-engine](https://github.com/as70023333/cloud-guardrail-engine): policy checks on
  Terraform plans *before* deployment; this tool checks what is actually deployed.

---

Developed by **Alex S., Security** · [MIT License](LICENSE)
