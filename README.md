# TeamCity OIDC Plugin

TeamCity plugin that enables builds to authenticate with cloud providers (AWS, GCP, Azure, etc.) using OpenID Connect tokens - no long-lived credentials required.

<!-- TOC -->
* [TeamCity OIDC Plugin](#teamcity-oidc-plugin)
  * [How It Works](#how-it-works)
  * [Installation](#installation)
  * [Usage](#usage)
    * [1. Configure Cloud Provider](#1-configure-cloud-provider)
    * [2. Add Build Feature](#2-add-build-feature)
    * [3. Use Token in Build](#3-use-token-in-build)
  * [Token Claims](#token-claims)
  * [Security](#security)
  * [Terraform Setup](#terraform-setup)
    * [AWS](#aws)
    * [GCP](#gcp)
  * [Endpoints](#endpoints)
  * [Development](#development)
  * [License](#license)
<!-- TOC -->

## How It Works

The plugin implements an [OpenID Connect Provider](https://openid.net/specs/openid-connect-core-1_0.html) within TeamCity:

1. **OIDC Discovery** - Exposes `/app/oidc/.well-known/openid-configuration` endpoint
2. **JWKS** – Publishes public keys for token verification
3. **Token Generation** – Signs JWTs with build context claims at build start

Cloud providers verify tokens by fetching the public key from TeamCity's JWKS endpoint and validating the signature.

```
┌─────────────┐     1. Request token      ┌─────────────┐
│   TeamCity  │ ◄──────────────────────── │    Build    │
│   Server    │ ─────────────────────────►│             │
└─────────────┘     2. JWT token          └──────┬──────┘
       │                                         │
       │ 3. Fetch JWKS                           │ 4. Present token
       ▼                                         ▼
┌─────────────┐                           ┌─────────────┐
│    Cloud    │ ◄─────────────────────────│    Cloud    │
│   Provider  │      5. Validate JWT      │   Service   │
└─────────────┘                           └─────────────┘
```

## Installation

1. Build: `mvn package`
2. Copy `target/teamcity-oidc.zip` to TeamCity's `plugins` directory
3. Restart TeamCity

## Usage

### 1. Configure Cloud Provider

Register TeamCity as an OIDC identity provider:

**AWS IAM Identity Provider:**
- Provider URL: `https://your-teamcity.com/app/oidc`
- Audience: Your AWS account ID or custom value

**GCP Workload Identity:**
- Issuer URI: `https://your-teamcity.com/app/oidc`

### 2. Add Build Feature

Add the "OIDC Token" build feature to your build configuration:
- **Audience**: Must match what you configured in the cloud provider
- **Environment Variable**: `TEAMCITY_OIDC_TOKEN` (default)

### 3. Use Token in Build

```bash
# AWS
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::ACCOUNT:role/ROLE \
  --role-session-name teamcity \
  --web-identity-token $TEAMCITY_OIDC_TOKEN

# GCP
gcloud auth login --cred-file=<(echo "{
  \"type\": \"external_account\",
  \"audience\": \"//iam.googleapis.com/projects/PROJECT/locations/global/workloadIdentityPools/POOL/providers/PROVIDER\",
  \"subject_token_type\": \"urn:ietf:params:oauth:token-type:jwt\",
  \"token_url\": \"https://sts.googleapis.com/v1/token\",
  \"credential_source\": {\"file\": \"/dev/stdin\"}
}" <<< "$TEAMCITY_OIDC_TOKEN")
```

## Token Claims

| Claim            | Example                                                  | Description                        |
|------------------|----------------------------------------------------------|------------------------------------|
| `iss`            | `https://teamcity.example.com/app/oidc`                  | Issuer URL                         |
| `sub`            | `project:MyProject:build_type:Build:ref:refs/heads/main` | Subject identifier                 |
| `aud`            | `sts.amazonaws.com`                                      | Audience                           |
| `project_id`     | `MyProject`                                              | TeamCity project ID                |
| `build_type_id`  | `MyProject_Build`                                        | Build configuration ID             |
| `build_id`       | `12345`                                                  | Build ID                           |
| `ref`            | `refs/heads/main`                                        | Git ref                            |
| `ref_type`       | `branch`                                                 | `branch`, `tag`, `pull_request`    |
| `default_branch` | `true`                                                   | Whether this is the default branch |

## Security

- Tokens are short-lived (max 2 hours, tied to build timeout)
- Private keys stored with restrictive file permissions
- Tokens masked in build logs
- Use `sub` claim conditions in IAM policies to restrict which builds can assume roles

Example AWS IAM trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/teamcity.example.com/app/oidc"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"teamcity.example.com/app/oidc:aud": "sts.amazonaws.com"},
      "StringLike": {"teamcity.example.com/app/oidc:sub": "project:Production*"}
    }
  }]
}
```

## Terraform Setup

### AWS

**1. Create OIDC Provider and IAM Role (one-time setup):**

```hcl
# OIDC Identity Provider
resource "aws_iam_openid_connect_provider" "teamcity" {
  url             = "https://teamcity.example.com/app/oidc"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]  # AWS ignores this for public CAs
}

# IAM Role for Terraform
resource "aws_iam_role" "terraform" {
  name = "teamcity-terraform"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.teamcity.arn }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "teamcity.example.com/app/oidc:aud" = "sts.amazonaws.com" }
        StringLike   = { "teamcity.example.com/app/oidc:sub" = "project:MyProject:build_type:*:ref:refs/heads/main" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "terraform" {
  role       = aws_iam_role.terraform.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # adjust as needed
}

output "role_arn" {
  value = aws_iam_role.terraform.arn
}
```

**2. TeamCity Build Feature:**
- Audience: `sts.amazonaws.com`

**3. Build Step:**

```bash
export AWS_ROLE_ARN="arn:aws:iam::123456789012:role/teamcity-terraform"
export AWS_WEB_IDENTITY_TOKEN_FILE=$(mktemp)
echo "$TEAMCITY_OIDC_TOKEN" > "$AWS_WEB_IDENTITY_TOKEN_FILE"

terraform init
terraform apply -auto-approve
```

### GCP

**1. Create Workload Identity Pool (one-time setup):**

```hcl
variable "project_id" {
  default = "my-gcp-project"
}

# Workload Identity Pool
resource "google_iam_workload_identity_pool" "teamcity" {
  project                   = var.project_id
  workload_identity_pool_id = "teamcity-pool"
  display_name              = "TeamCity"
}

# OIDC Provider
resource "google_iam_workload_identity_pool_provider" "teamcity" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.teamcity.workload_identity_pool_id
  workload_identity_pool_provider_id = "teamcity-oidc"
  display_name                       = "TeamCity OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.project_id" = "assertion.project_id"
    "attribute.ref"        = "assertion.ref"
  }

  # Only allow main branch
  attribute_condition = "assertion.ref == 'refs/heads/main'"

  oidc {
    issuer_uri = "https://teamcity.example.com/app/oidc"
  }
}

# Service Account
resource "google_service_account" "terraform" {
  project      = var.project_id
  account_id   = "teamcity-terraform"
  display_name = "TeamCity Terraform"
}

# Allow TeamCity to impersonate the service account
resource "google_service_account_iam_member" "terraform" {
  service_account_id = google_service_account.terraform.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.teamcity.name}/attribute.project_id/MyProject"
}

# Grant permissions to the service account
resource "google_project_iam_member" "terraform" {
  project = var.project_id
  role    = "roles/editor"  # adjust as needed
  member  = "serviceAccount:${google_service_account.terraform.email}"
}

output "workload_identity_provider" {
  value = google_iam_workload_identity_pool_provider.teamcity.name
}

output "service_account_email" {
  value = google_service_account.terraform.email
}
```

**2. TeamCity Build Feature:**
- Audience: `//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/teamcity-pool/providers/teamcity-oidc`

**3. Build Step:**

```bash
# Create credential config file
cat > /tmp/gcp-creds.json <<EOF
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/teamcity-pool/providers/teamcity-oidc",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "credential_source": {
    "file": "/tmp/oidc-token"
  },
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/teamcity-terraform@my-gcp-project.iam.gserviceaccount.com:generateAccessToken"
}
EOF

echo "$TEAMCITY_OIDC_TOKEN" > /tmp/oidc-token
export GOOGLE_APPLICATION_CREDENTIALS=/tmp/gcp-creds.json

terraform init
terraform apply -auto-approve
```

## Endpoints

| Endpoint                                     | Description             |
|----------------------------------------------|-------------------------|
| `/app/oidc/.well-known/openid-configuration` | OIDC Discovery document |
| `/app/oidc/.well-known/jwks.json`            | JSON Web Key Set        |

## Development

```bash
# Build
mvn package

# Run unit tests
mvn test

# Run integration tests (requires Docker)
mvn test -Dgroups=integration -P integration-tests
```

## License

Apache 2.0
