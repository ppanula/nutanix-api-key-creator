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

## Command-line options

### Connection and authentication

| Option | Description |
| --- | --- |
| `--pc PC` | Required Prism Central FQDN or IP address. |
| `--username USERNAME` | Administrator username. If omitted, the tool prompts for it. |
| `--api-version VERSION` | IAM API version. Defaults to `auto`, which probes supported versions. |
| `--insecure` | Disable TLS certificate verification. Use only for temporary testing. |

The administrator password is always requested interactively and is never accepted as a command-line argument.

### Service account and API key

| Option | Default | Description |
| --- | --- | --- |
| `--service-account NAME` | `svc-api-automation` | Service-account username to create or reuse. |
| `--display-name TEXT` | `Nutanix API automation` | Service-account display name. |
| `--first-name TEXT` | `Nutanix` | Service-account first name. |
| `--last-name TEXT` | `Automation` | Service-account last name. |
| `--email ADDRESS` | None | Optional service-account email address. |
| `--description TEXT` | `Service account for API automation` | Service-account description. |
| `--key-name NAME` | `api-automation` | Name of the generated API key. |
| `--reuse-existing` | Off | Reuse an existing service account with the requested username instead of failing. A new key is still created. |

### Built-in and custom roles

| Option | Default | Description |
| --- | --- | --- |
| `--role-name NAME` | `Prism Admin` | Existing role to assign, or the name of a new role with `--create-role`. |
| `--create-role` | Off | Create a custom role instead of finding an existing role. |
| `--role-description TEXT` | `Custom role for limited API automation` | Description for a custom role. |
| `--operation-name NAME` | None | Operation display name to include in a custom role. Repeat for multiple operations. Required with `--create-role`. |
| `--entity-type TYPE` | None | Entity type to include in a custom role. Repeat for multiple entity types. Required with `--create-role`. |

Example custom role options:

```bash
--create-role \
--role-name "SSL Certificate Updater" \
--operation-name View_Cluster_SSL_Certificate \
--operation-name Update_Cluster_SSL_Certificate \
--entity-type ssl_certificate
```

### Authorization policy

| Option | Default | Description |
| --- | --- | --- |
| `--policy-name NAME` | `<service-account> authorization policy` | Authorization-policy display name. |
| `--policy-description TEXT` | `Authorization policy for API automation` | Authorization-policy description. |
| `--entity-scope VALUE` | `*` | Entity scope written to the authorization policy. |

The default wildcard scope is convenient for API automation but should be reviewed when using custom roles.

### API-key output

| Option | Description |
| --- | --- |
| `--write-env PATH` | Write the Prism Central host and generated API key to a shell environment file. |
| `--env-prefix PREFIX` | Prefix for variables written with `--write-env`; required with that option. |
| `--yes` | Required confirmation before creating a service account, API key, role, or policy. |

When `--write-env` is used with `--env-prefix pc`, the tool writes:

```bash
NUTANIX_PC_HOST="prismcentral.example.com"
NUTANIX_PC_API_KEY="..."
```

The file is created with mode `0600`. Without `--write-env`, the generated API key is printed once.

### Read-only catalog listing

| Option | Description |
| --- | --- |
| `--list-operations` | Fetch and display IAM operations, then exit without changes. |
| `--list-entity-types` | Fetch and display unique IAM entity types, then exit without changes. |
| `--operation-filter TEXT` | Case-insensitive filter applied to operation listing results. |
| `--details` | Include endpoint paths and HTTP methods in operation listings. |
| `--json` | Output listing results as JSON. |

Listing modes do not require `--yes`. `--list-operations` and `--list-entity-types` are mutually exclusive.

### General

| Option | Description |
| --- | --- |
| `-h`, `--help` | Display command-line help and exit. |

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
  --details
```

The default output shows client groups, operation names, and entity types. Add endpoint and HTTP method details:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-operations \
  --operation-filter ssl \
  --details
```

Use JSON output for automation:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-operations \
  --json
```

List unique entity types:

```bash
python3 nutanix_api_key_creator.py \
  --pc prismcentral.example.com \
  --list-entity-types
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
- TLS verification is enabled by default. Use `--insecure` only for temporary testing with a known endpoint.
- Each normal execution creates a new API key and authorization policy.
- Use `--reuse-existing` only when intentionally creating another key for an existing service account.
- Review custom roles and authorization policies before using them in production.
