<div align="center">
 <p>
  <h1>
    Dredge - 0.1.1
  </h1>
 </p>
</div>

<div align="center">
  <h3>
   ⚡ Log collection, analysis, and rapid response in the cloud... pa' la hinchada⚡
  </h3>
</div>

---

### TL;DR

- This is a **rewritten / refactored** version of Dredge – still a work in progress.
- It currently focuses on:
  - **AWS Incident Response** (disable users/keys, isolate EC2, lock down S3, etc.).
  - **AWS Threat Hunting** via **CloudTrail lookup**.
  - **GitHub Threat Hunting** via **Org/Enterprise Audit Logs**.
- It’s implemented as:
  - A **Python library** (`dredge`) you can import.
  - A **CLI** (dredge) entrypoint you can run from the terminal.

Older features (GCP, Kubernetes, Shodan, VirusTotal, config-file log collection, etc.) are **not in prod right now** – they’re listed in the **Next steps / roadmap** section.

---

<div align="justify">
<p>
Dredge is a tool designed to identify and respond quickly to attacks in cloud environments, especially when you don’t have all the IR plumbing ready.
</p>

<p>
The new Dredge library focuses on a clean, composable API for:
</p>

<ul>
  <li><b>AWS Incident Response</b>: disable IAM users and access keys, lock down S3, and network-isolate EC2 instances.</li>
  <li><b>Log-centric Threat Hunting</b> for AWS (CloudTrail) and GitHub (Audit Logs).</li>
</ul>

<p>
It’s meant to be usable both as a library in your own IR tooling and as a CLI for “oh-shit-it’s-3AM” response.
</p>
</div>

---

## Current Features

### 🔥 Incident Response (AWS)

- Disable / delete IAM access keys.
- Disable / delete IAM users.
- Disable IAM roles (detach policies, break trust relationships).
- Block S3 public access (account-level, bucket-level, object-level).
- Network-isolate EC2 instances (forensic security group).

### 🎯 Threat Hunting

- AWS CloudTrail hunt:
  - Filter by `user_name`, `access_key_id`, `event_name`, `source_ip`, time ranges.
  - Handles pagination and AWS rate limiting.
- GitHub Audit Log hunt:
  - Org or Enterprise audit logs.
  - Filter by `actor`, `action`, `repo`, `source_ip`, time ranges or “today”.
  - Handles pagination and basic rate limiting.

---

# 📦 Installation

1. **Clone the repo**

```bash
git clone https://github.com/solidarity-labs/dredge-cli.git
cd dredge-cli
```

2. **Install via editable local development**
```bash
pip install -e .
```

3. **Run tests**
```bash
pytest -q
```

4. **See what’s available**

```bash
dredge --help
```

---

# 🐳 Docker Usage

## Build image
```bash
podman build -t dredge:latest .
```
OR
```bash
docker build -t dredge:latest .
```

---


## AWS Integration

### Authentication

Dredge uses standard AWS auth mechanisms via `boto3`:

- **Default credential chain** (env vars, `~/.aws/credentials`, EC2/ECS role, etc.).
- **Named profile** via `--aws-profile`.
- **Explicit keys** via CLI flags.
- **Assume role** via `--aws-role-arn` (optionally with `--aws-external-id`).

You can combine these in the usual way; precedence is:

1. Explicit keys  
2. Profile  
3. Default chain  

**Common setup in `~/.aws/credentials`:**

```ini
[dredge-role]
aws_access_key_id = AKIA...
aws_secret_access_key = SUPER_SECRET
```

**Region can be provided via:**

- `--aws-region`  
- `AWS_REGION` / `AWS_DEFAULT_REGION` env vars  
- Your AWS profile config (`~/.aws/config`)  

---

### Global AWS Flags (CLI)

- `--aws-region` or `--region` – AWS region, e.g. `us-east-1`.
- `--aws-profile` – AWS named profile.
- `--aws-access-key-id` – explicit key ID.
- `--aws-secret-access-key` – explicit secret.
- `--aws-session-token` – session token (if using STS).
- `--aws-role-arn` – role to assume.
- `--aws-external-id` – external ID for role assumption.
- `--dry-run` – simulate without making changes.

---

### AWS Incident Response – CLI Examples

#### Disable an IAM access key

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-disable-access-key   --user compromised-user   --access-key-id AKIA123456789
```

#### Disable an IAM user

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-disable-user   --user compromised-user
```

#### Disable an IAM role

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-disable-role   --role OldAccessRole
```

#### Block S3 public access

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-block-s3-account   --account-id 111122223333
```

#### Make a bucket private

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-block-s3-bucket   --bucket my-sus-bucket
```

#### Network-isolate EC2 instances

```bash
dredge --aws-profile dredge-role   --region us-east-1   aws-isolate-ec2   i-0123456789abcdef0 i-0abcdef1234567890
```

---

## GitHub Integration

### Authentication

Dredge uses a **GitHub personal access token**.

For **Org audit logs**, token requires:

- `admin:org`
- `audit_log` (or `read:audit_log`)

For **Enterprise audit logs**, token requires:

- `admin:enterprise`
- `audit_log`

Provide token via:

```bash
--github-token "$GITHUB_TOKEN"
```

Or rely on your environment variable via `GitHubIRConfig`.

Also specify either:

- `--github-org <org>`  
- `--github-enterprise <enterprise>`  

---

### GitHub Threat Hunting – CLI Examples

#### Today’s logs for a user

```bash
dredge --github-org solidarity-labs   --github-token "$GITHUB_TOKEN"   github-hunt-audit   --actor sabastante   --today   --include all
```

#### Hunt an action

```bash
dredge --github-enterprise solidaritylabs   --github-token "$GITHUB_TOKEN"   github-hunt-audit   --action repo.create   --start-time 2025-01-01T00:00:00Z   --end-time 2025-01-07T23:59:59Z   --include web
```

#### Hunt suspicious IP activity

```bash
dredge --github-org solidarity-labs   --github-token "$GITHUB_TOKEN"   github-hunt-audit   --source-ip 203.0.113.50   --today   --include all
```

---

## Library Usage

### AWS Example

```python
from dredge import Dredge
from dredge.auth import AwsAuthConfig

auth = AwsAuthConfig(profile_name="dredge-role", region_name="us-east-1")
d = Dredge(auth=auth)

result = d.aws_ir.response.disable_user("compromised-user")
print(result.success, result.details)
```

### GitHub Example

```python
from dredge import Dredge
from dredge.github_ir.config import GitHubIRConfig

cfg = GitHubIRConfig(org="solidarity-labs", token="ghp_xxx")
d = Dredge(github_config=cfg)

res = d.github_ir.hunt.search_today(actor="sabastante")
print(res.details["events"])
```

---

## 🧭 Next Steps / Roadmap

(Not yet implemented in the new architecture)

### Log Collection
- AWS EventHistory, GuardDuty, VPC Flow Logs, LB logs, WAF logs, S3 CloudTrail, CloudWatch Logs.
- GCP log retrieval.
- Kubernetes log retrieval.

### Threat Hunting
- IoC search, custom rules.
- Shodan + VirusTotal reintegration.
- AWS dangerous API heuristics.

### Incident Response
- Forensic imaging, tagging, deeper IR workflows.
- GitHub IR actions beyond hunting.
---

# ❤️ Contributing
PRs welcome!  
If you want help adding modules (Azure, Okta, Datadog, JumpCloud), open an issue.

---
