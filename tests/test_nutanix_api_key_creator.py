import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import nutanix_api_key_creator as tool


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text if text is not None else json.dumps(self._payload)
        self.content = self.text.encode()
        self.ok = status_code < 400

    def json(self):
        return self._payload


class ApiSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return next(self.responses)


class UtilityTests(unittest.TestCase):
    def test_detect_api_version_skips_unsupported_versions(self):
        session = Mock()
        session.get.side_effect = [
            FakeResponse(
                status_code=400,
                text="Invalid API version passed in the request",
            ),
            FakeResponse(status_code=404, text="not found"),
            FakeResponse({"data": []}),
        ]

        version = tool.detect_api_version(session, "pc.example.com", "auto")

        self.assertEqual(version, "v4.0.b3")
        self.assertEqual(session.get.call_count, 3)

    def test_detect_api_version_honors_explicit_version(self):
        session = Mock()

        version = tool.detect_api_version(session, "pc.example.com", "v4.0")

        self.assertEqual(version, "v4.0")
        session.get.assert_not_called()

    def test_create_role_resolves_operation_names_and_posts_ids(self):
        session = ApiSession(
            [
                FakeResponse(
                    {
                        "data": [
                            {
                                "displayName": "View_Cluster_SSL_Certificate",
                                "extId": "view-id",
                            },
                            {
                                "displayName": "Update_Cluster_SSL_Certificate",
                                "extId": "update-id",
                            },
                        ]
                    }
                ),
                FakeResponse({"data": {"extId": "role-id"}}),
            ]
        )
        args = SimpleNamespace(
            operation_name=[
                "View_Cluster_SSL_Certificate",
                "Update_Cluster_SSL_Certificate",
            ],
            role_name="SSL Certificate Updater",
            role_description="Certificate-only role",
            entity_type=["ssl_certificate"],
        )

        role = tool.create_role(session, "https://pc/api/iam/v4.0", args)

        self.assertEqual(role["extId"], "role-id")
        self.assertEqual(len(session.calls), 2)
        post_kwargs = session.calls[1][2]
        self.assertEqual(
            post_kwargs["json"]["operations"], ["view-id", "update-id"]
        )
        self.assertEqual(
            post_kwargs["json"]["accessibleEntityTypes"], ["ssl_certificate"]
        )

    def test_write_env_file_updates_values_and_restricts_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "api.env"
            tool.write_env_file(
                path,
                {"NUTANIX_PC_HOST": "pc.example.com", "NUTANIX_PC_API_KEY": "key"},
            )
            tool.write_env_file(path, {"NUTANIX_PC_API_KEY": "new-key"})

            self.assertEqual(
                path.read_text().splitlines(),
                [
                    'NUTANIX_PC_HOST="pc.example.com"',
                    'NUTANIX_PC_API_KEY="new-key"',
                ],
            )
            self.assertEqual(
                stat.S_IMODE(path.stat().st_mode),
                stat.S_IRUSR | stat.S_IWUSR,
            )

    def test_create_authorization_policy_contains_service_account_identity(self):
        session = ApiSession([FakeResponse({"data": {"extId": "policy-id"}})])
        args = SimpleNamespace(
            policy_name="certificate policy",
            policy_description="certificate policy",
            entity_scope="*",
        )

        response = tool.create_authorization_policy(
            session,
            "https://pc/api/iam/v4.0",
            "service-account-id",
            "role-id",
            args,
        )

        self.assertEqual(response["data"]["extId"], "policy-id")
        payload = session.calls[0][2]["json"]
        self.assertEqual(payload["role"], "role-id")
        self.assertEqual(
            payload["identities"][0]["$reserved"]["user"]["uuid"]["anyof"],
            ["service-account-id"],
        )

    def test_parse_args_supports_repeated_custom_role_options(self):
        with patch.object(
            sys,
            "argv",
            [
                "tool",
                "--pc",
                "pc.example.com",
                "--create-role",
                "--operation-name",
                "View_Cluster",
                "--operation-name",
                "View_Host",
                "--entity-type",
                "cluster",
                "--entity-type",
                "host",
                "--yes",
            ],
        ):
            args = tool.parse_args()

        self.assertEqual(
            args.operation_name, ["View_Cluster", "View_Host"]
        )
        self.assertEqual(args.entity_type, ["cluster", "host"])
        self.assertTrue(args.create_role)

    def test_validate_args_requires_confirmation_for_changes(self):
        args = SimpleNamespace(
            list_operations=False,
            list_entity_types=False,
            yes=False,
            write_env=None,
            env_prefix=None,
            create_role=False,
            operation_name=[],
            entity_type=[],
        )

        with self.assertRaisesRegex(tool.NutanixApiError, "--yes"):
            tool.validate_args(args)

    def test_validate_args_requires_env_prefix(self):
        args = SimpleNamespace(
            list_operations=False,
            list_entity_types=False,
            yes=True,
            write_env="api.env",
            env_prefix=None,
            create_role=False,
            operation_name=[],
            entity_type=[],
        )

        with self.assertRaisesRegex(tool.NutanixApiError, "--env-prefix"):
            tool.validate_args(args)

    def test_validate_args_requires_custom_role_inputs(self):
        base = {
            "list_operations": False,
            "list_entity_types": False,
            "yes": True,
            "write_env": None,
            "env_prefix": None,
            "create_role": True,
            "operation_name": [],
            "entity_type": [],
        }

        with self.assertRaisesRegex(tool.NutanixApiError, "--operation-name"):
            tool.validate_args(SimpleNamespace(**base))

        base["operation_name"] = ["View_Cluster"]
        with self.assertRaisesRegex(tool.NutanixApiError, "--entity-type"):
            tool.validate_args(SimpleNamespace(**base))

    def test_validate_args_allows_read_only_listing_without_confirmation(self):
        args = SimpleNamespace(
            list_operations=True,
            list_entity_types=False,
            yes=False,
            write_env=None,
            env_prefix=None,
            create_role=False,
            operation_name=[],
            entity_type=[],
        )

        self.assertTrue(tool.validate_args(args))


if __name__ == "__main__":
    unittest.main()
