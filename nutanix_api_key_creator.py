#!/usr/bin/env python3
"""Create a Nutanix IAM service-account API key and authorization policy."""

import argparse
import getpass
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

import requests
import urllib3


class NutanixApiError(RuntimeError):
    """Raised when Prism Central rejects an API request."""


def request_json(session, method, url, **kwargs):
    try:
        response = session.request(method, url, timeout=30, **kwargs)
    except requests.RequestException as exc:
        raise NutanixApiError(f"{method} {url} failed: {exc}") from exc

    if not response.ok:
        detail = response.text[:1000].replace("\n", " ")
        raise NutanixApiError(
            f"{method} {url} returned HTTP {response.status_code}: {detail}"
        )

    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise NutanixApiError(f"{method} {url} returned invalid JSON") from exc


def detect_api_version(session, pc, requested_version):
    if requested_version != "auto":
        return requested_version

    candidates = (
        "v4.1.b2",
        "v4.1.b1",
        "v4.0.b3",
        "v4.0.b2",
        "v4.0.b1",
        "v4.0",
    )
    for version in candidates:
        url = f"https://{pc}:9440/api/iam/{version}/authz/roles"
        try:
            response = session.get(
                url,
                params={"$limit": "1"},
                headers={"Accept": "application/json"},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise NutanixApiError(
                f"could not probe IAM API version {version}: {exc}"
            ) from exc

        body = response.text.lower()
        unsupported_version = (
            response.status_code == 404
            or (
                response.status_code == 400
                and "invalid api version" in body
            )
        )
        if not unsupported_version:
            return version

    raise NutanixApiError(
        f"could not detect a supported IAM API version; tried {', '.join(candidates)}"
    )


def one_result(payload, description):
    data = payload.get("data", [])
    if isinstance(data, dict):
        data = [data]
    if len(data) != 1:
        raise NutanixApiError(
            f"expected one {description}, found {len(data)}"
        )
    return data[0]


def find_role(session, base_url, role_name):
    payload = request_json(
        session,
        "GET",
        f"{base_url}/authz/roles",
        params={"$filter": f"displayName eq '{role_name}'"},
        headers={"Accept": "application/json"},
    )
    role = one_result(payload, f"role named {role_name!r}")
    if not role.get("extId"):
        raise NutanixApiError(f"role {role_name!r} has no extId")
    return role


def find_operations(session, base_url, operation_names):
    found = {}
    for page in range(100):
        payload = request_json(
            session,
            "GET",
            f"{base_url}/authz/operations",
            params={"$page": page, "$limit": 100},
            headers={"Accept": "application/json"},
        )
        data = payload.get("data", [])
        if isinstance(data, dict):
            data = [data]
        for operation in data:
            name = operation.get("displayName")
            if name in operation_names:
                found[name] = operation
        if len(data) < 100 or len(found) == len(operation_names):
            break

    missing = [name for name in operation_names if name not in found]
    if missing:
        raise NutanixApiError(
            f"operation(s) not found: {', '.join(missing)}"
        )
    return [found[name] for name in operation_names]


def list_operations(session, base_url):
    operations = []
    for page in range(100):
        payload = request_json(
            session,
            "GET",
            f"{base_url}/authz/operations",
            params={"$page": page, "$limit": 100},
            headers={"Accept": "application/json"},
        )
        data = payload.get("data", [])
        if isinstance(data, dict):
            data = [data]
        operations.extend(data)
        if len(data) < 100:
            break
    return operations


def create_role(session, base_url, args):
    operations = find_operations(
        session, base_url, args.operation_name
    )
    payload = {
        "displayName": args.role_name,
        "description": args.role_description,
        "operations": [operation["extId"] for operation in operations],
        "accessibleEntityTypes": args.entity_type,
    }
    response = request_json(
        session,
        "POST",
        f"{base_url}/authz/roles",
        json=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    role = response.get("data", {})
    if not role.get("extId"):
        raise NutanixApiError("role response did not contain extId")
    return role


def find_service_account(session, base_url, username):
    payload = request_json(
        session,
        "GET",
        f"{base_url}/authn/users",
        params={"$filter": f"username eq '{username}'"},
        headers={"Accept": "application/json"},
    )
    users = payload.get("data", [])
    if isinstance(users, dict):
        users = [users]
    if not users:
        return None
    if len(users) > 1:
        raise NutanixApiError(
            f"found multiple users with username {username!r}"
        )
    user = users[0]
    if user.get("userType") != "SERVICE_ACCOUNT":
        raise NutanixApiError(
            f"{username!r} exists but is not a SERVICE_ACCOUNT"
        )
    return user


def create_service_account(session, base_url, args):
    existing = find_service_account(session, base_url, args.service_account)
    if existing:
        if not args.reuse_existing:
            raise NutanixApiError(
                f"service account {args.service_account!r} already exists; "
                "use --reuse-existing to use it"
            )
        return existing

    payload = {
        "username": args.service_account,
        "userType": "SERVICE_ACCOUNT",
        "displayName": args.display_name,
        "firstName": args.first_name,
        "lastName": args.last_name,
        "description": args.description,
        "creationType": "USERDEFINED",
        "status": "ACTIVE",
    }
    if args.email:
        payload["emailId"] = args.email

    response = request_json(
        session,
        "POST",
        f"{base_url}/authn/users",
        json=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    user = response.get("data", {})
    if not user.get("extId"):
        raise NutanixApiError("service-account response did not contain extId")
    return user


def create_api_key(session, base_url, user_id, args):
    response = request_json(
        session,
        "POST",
        f"{base_url}/authn/users/{quote(user_id, safe='')}/keys",
        json={"name": args.key_name, "keyType": "API_KEY"},
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    data = response.get("data", {})
    key = (data.get("keyDetails") or {}).get("apiKey")
    if not key:
        raise NutanixApiError(
            "API-key response did not contain data.keyDetails.apiKey"
        )
    return key


def create_authorization_policy(session, base_url, user_id, role_id, args):
    policy = {
        "displayName": args.policy_name,
        "description": args.policy_description,
        "entities": [{"$reserved": {"*": {"*": {"eq": args.entity_scope}}}}],
        "identities": [
            {
                "$reserved": {
                    "user": {"uuid": {"anyof": [user_id]}}
                }
            }
        ],
        "role": role_id,
    }
    return request_json(
        session,
        "POST",
        f"{base_url}/authz/authorization-policies",
        json=policy,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )


def write_env_file(path, variables):
    destination = Path(path).expanduser()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_content = destination.read_text() if destination.exists() else ""
    lines = old_content.splitlines()

    for name, value in variables.items():
        replacement = f"{name}={json.dumps(value)}"
        pattern = re.compile(rf"^{re.escape(name)}=")
        for index, line in enumerate(lines):
            if pattern.match(line):
                lines[index] = replacement
                break
        else:
            lines.append(replacement)

    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w") as output:
            output.write("\n".join(lines).rstrip("\n") + "\n")
        os.replace(temporary, destination)
        os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pc", required=True, help="Prism Central FQDN or IP")
    parser.add_argument("--username", help="Administrator username")
    parser.add_argument(
        "--api-version",
        default="auto",
        help="IAM API version, or auto (default: auto)",
    )
    parser.add_argument("--service-account", default="svc-api-automation")
    parser.add_argument("--display-name", default="Nutanix API automation")
    parser.add_argument("--first-name", default="Nutanix")
    parser.add_argument("--last-name", default="Automation")
    parser.add_argument("--email")
    parser.add_argument("--description", default="Service account for API automation")
    parser.add_argument("--key-name", default="api-automation")
    parser.add_argument("--role-name", default="Prism Admin")
    parser.add_argument(
        "--create-role",
        action="store_true",
        help="Create --role-name instead of using an existing role",
    )
    parser.add_argument(
        "--role-description",
        default="Custom role for limited API automation",
    )
    parser.add_argument(
        "--operation-name",
        action="append",
        default=[],
        help="Operation display name to include; repeat for multiple operations",
    )
    parser.add_argument(
        "--entity-type",
        action="append",
        default=[],
        help="Entity type for a custom role; repeat as needed",
    )
    parser.add_argument("--policy-name")
    parser.add_argument(
        "--policy-description",
        default="Authorization policy for API automation",
    )
    parser.add_argument(
        "--entity-scope",
        default="*",
        help="Authorization-policy entity scope (default: *)",
    )
    parser.add_argument(
        "--reuse-existing",
        action="store_true",
        help="Reuse an existing service account with the requested username",
    )
    parser.add_argument(
        "--write-env",
        help="Write the generated key to this shell environment file",
    )
    parser.add_argument(
        "--env-prefix",
        help="Prefix for environment variables written with --write-env",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm creation of the service account, key, and policy",
    )
    listing = parser.add_mutually_exclusive_group()
    listing.add_argument(
        "--list-operations",
        action="store_true",
        help="List IAM operations and exit without making changes",
    )
    listing.add_argument(
        "--list-entity-types",
        action="store_true",
        help="List IAM entity types and exit without making changes",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output listing results as JSON",
    )
    parser.add_argument(
        "--operation-filter",
        help="Case-insensitive text filter for operation listings",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Include endpoint and HTTP method details in operation listings",
    )
    return parser.parse_args()


def print_listing(
    operations,
    list_entity_types,
    output_json,
    operation_filter,
    show_details,
):
    if operation_filter:
        needle = operation_filter.lower()
        operations = [
            operation
            for operation in operations
            if needle in json.dumps(operation).lower()
        ]

    if list_entity_types:
        entity_types = sorted(
            {
                operation.get("entityType")
                for operation in operations
                if operation.get("entityType")
            }
        )
        if output_json:
            print(json.dumps(entity_types, indent=2))
        else:
            print("\n".join(entity_types))
        return

    if output_json:
        print(json.dumps(operations, indent=2, sort_keys=True))
        return

    grouped = {}
    for operation in operations:
        grouped.setdefault(operation.get("clientName") or "Unknown", []).append(
            operation
        )

    print(f"Operations: {len(operations)}")
    for client in sorted(grouped):
        print(f"\n[{client}] ({len(grouped[client])})")
        for operation in sorted(
            grouped[client], key=lambda item: item.get("displayName", "")
        ):
            name = operation.get("displayName", "")
            entity_type = operation.get("entityType", "")
            print(f"  {name} [{entity_type}]")
            if not show_details:
                continue
            endpoints = operation.get("associatedEndpointList", [])
            if not endpoints:
                print("    - no endpoint metadata")
                continue
            for endpoint in endpoints:
                method = endpoint.get("httpMethod", "")
                url = endpoint.get("endpointUrl", "")
                print(f"    {method} {url}")


def validate_args(args):
    listing_requested = args.list_operations or args.list_entity_types
    if not listing_requested and not args.yes:
        raise NutanixApiError("refusing changes without --yes")
    if not listing_requested and args.write_env and not args.env_prefix:
        raise NutanixApiError("--env-prefix is required with --write-env")
    if not listing_requested and args.create_role and not args.operation_name:
        raise NutanixApiError(
            "--operation-name is required when using --create-role"
        )
    if not listing_requested and args.create_role and not args.entity_type:
        raise NutanixApiError(
            "--entity-type is required when using --create-role"
        )
    return listing_requested


def main():
    args = parse_args()
    listing_requested = validate_args(args)
    if not args.policy_name:
        args.policy_name = f"{args.service_account} authorization policy"

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    username = args.username or input("Administrator username: ")
    password = getpass.getpass("Administrator password: ")
    if not username or not password:
        raise NutanixApiError("administrator username and password are required")

    session = requests.Session()
    session.auth = (username, password)
    session.verify = not args.insecure
    args.api_version = detect_api_version(session, args.pc, args.api_version)
    base_url = f"https://{args.pc}:9440/api/iam/{args.api_version}"
    print(f"Using IAM API version: {args.api_version}")

    if listing_requested:
        print_listing(
            list_operations(session, base_url),
            args.list_entity_types,
            args.json,
            args.operation_filter,
            args.details,
        )
        return

    if args.create_role:
        role = create_role(session, base_url, args)
        print(f"Created custom role: {role.get('displayName')}")
        print(f"Role extId: {role['extId']}")
    else:
        role = find_role(session, base_url, args.role_name)
    user = create_service_account(session, base_url, args)
    user_id = user["extId"]
    api_key = create_api_key(session, base_url, user_id, args)
    create_authorization_policy(session, base_url, user_id, role["extId"], args)

    print(f"Service account: {args.service_account}")
    print(f"Service-account extId: {user_id}")
    print(f"Authorization role: {args.role_name}")
    print("API key and authorization policy created.")

    if args.write_env:
        prefix = args.env_prefix.upper()
        write_env_file(
            args.write_env,
            {
                f"NUTANIX_{prefix}_HOST": args.pc,
                f"NUTANIX_{prefix}_API_KEY": api_key,
            },
        )
        print(f"API key written to {args.write_env}.")
    else:
        print("API key (shown once; store it securely):")
        print(api_key)


if __name__ == "__main__":
    try:
        main()
    except (NutanixApiError, requests.RequestException) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
