# Nutanix IAM API key creator

Create Nutanix Prism Central service accounts, API keys, authorization policies, and custom roles through the IAM v4 API.

The tool prompts for an existing administrator username and password. Credentials are not written to disk. Never commit generated API keys.

## Requirements

- Python 3.6 or newer
- `requests`

Install the dependency:

```bash
python3 -m pip install requests
```

Show help:

```bash
python3 nutanix_api_key_creator.py --help
```

## How the tool works

For a normal role, the tool:

1. Finds the requested built-in role.
2. Creates a `SERVICE_ACCOUNT`.
3. Creates an `API_KEY` for that service account.
4. Creates an authorization policy assigning the role to the service account.
5. Optionally writes the key to a mode `0600` environment file.

API versions are detected automatically. IAM versions are namespace-specific: a Prism Central release may support `clustermgmt/v4.2` while IAM supports `v4.0`, `v4.0.b3`, or `v4.1.b2`. Override detection with `--api-version` when necessary.

## Create a Super Admin API key

This creates a service account with full Prism Central permissions:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --service-account svc-full-administration \
  --display-name "Full administration automation" \
  --key-name full-administration \
  --role-name "Super Admin" \
  --write-env ./nutanix-api.env \
  --env-prefix pc \
  --insecure \
  --yes
```

Use `Super Admin` only when the automation genuinely needs unrestricted access. Prefer a narrower built-in or custom role for unattended tools.

## Create a Prism Admin API key

`Prism Admin` is suitable for broad day-to-day infrastructure automation:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --service-account svc-prism-automation \
  --display-name "Prism infrastructure automation" \
  --key-name prism-automation \
  --role-name "Prism Admin" \
  --write-env ./nutanix-api.env \
  --env-prefix pc \
  --insecure \
  --yes
```

## Create an SSL certificate updater API key

This creates a custom role containing only the certificate read and update operations:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --service-account svc-ssl-certificate-updater \
  --display-name "SSL certificate updater" \
  --key-name ssl-certificate-updater \
  --role-name "SSL Certificate Updater" \
  --role-description "Allows SSL certificate read and update operations only" \
  --operation-name View_Cluster_SSL_Certificate \
  --operation-name Update_Cluster_SSL_Certificate \
  --entity-type ssl_certificate \
  --write-env ./nutanix-api.env \
  --env-prefix pc_ssl \
  --insecure \
  --create-role \
  --yes
```

The resulting environment file contains variables similar to:

```bash
NUTANIX_PC_SSL_HOST="prismcentral.example.com"
NUTANIX_PC_SSL_API_KEY="REDACTED"
```

The `GET` operation is included because a safe certificate update reads the current ETag before sending `PUT`.

## Create another custom role

Use `--create-role` with one or more operation names and entity types:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --service-account svc-vm-readonly \
  --role-name "VM Inventory Reader" \
  --role-description "Read-only access to virtual machine inventory" \
  --operation-name View_AHV_VM \
  --entity-type ahv_vm \
  --write-env ./nutanix-api.env \
  --env-prefix pc_vm \
  --insecure \
  --create-role \
  --yes
```

Repeat either option for multiple values:

```bash
--operation-name View_Cluster \
--operation-name View_Host \
--entity-type cluster \
--entity-type host
```

The tool resolves operation display names to operation IDs using the IAM operation catalog, creates the custom role, and assigns it to the new service account.

## List available operations

The tool can fetch and format the IAM operation catalog without `curl` or `jq`:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-operations \
  --insecure
```

The default output shows client groups, operation names, and entity types. Add endpoint and HTTP method details:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-operations \
  --operation-filter ssl \
  --details \
  --insecure
```

Use JSON output for automation:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-operations \
  --json \
  --insecure
```

List unique entity types:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-entity-types \
  --insecure
```

Listing modes are read-only and do not require `--yes`.

## Relevant certificate operations

The operation names and IDs are release-dependent. The target Prism Central operation catalog is authoritative.

| Operation | Entity type | Method | Purpose |
| --- | --- | --- | --- |
| `View_Cluster_SSL_Certificate` | `ssl_certificate` | `GET` | Read the certificate and ETag |
| `Update_Cluster_SSL_Certificate` | `ssl_certificate` | `PUT` | Replace certificate, private key, and CA chain |

## Common built-in roles

| Role | Use |
| --- | --- |
| `Super Admin` | Full infrastructure, platform, tenant, and authorization administration |
| `Prism Admin` | Broad day-to-day infrastructure and platform administration |
| `Prism Viewer` | Read-only infrastructure and platform access |
| `Cluster Admin` | Full cluster-operation access |
| `Cluster Viewer` | Read-only cluster access |
| `Virtual Machine Admin` | Full virtual-machine access |
| `Virtual Machine Operator` | Day-to-day VM operations |
| `Virtual Machine Viewer` | Read-only VM access |
| `Storage Admin` / `Storage Viewer` | Full or read-only storage access |
| `Network Infra Admin` / `VPC Admin` | Network and VPC administration |
| `Security Admin` / `Security Viewer` | Security-feature administration or viewing |

The exact role list depends on the Prism Central release and installed services. The IAM role endpoint and `--list-operations` output should be treated as authoritative.

## Safety and reuse

- Do not pass passwords or API keys as command-line arguments.
- Store environment files with mode `0600`.
- `--insecure` disables TLS verification; use a trusted CA in production.
- Each normal execution creates a new API key and authorization policy.
- Use `--reuse-existing` only when intentionally creating another key for an existing service account.
- Review custom roles and authorization policies before using them in production.
