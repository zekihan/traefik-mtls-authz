import json
import unittest

from check_docs_yaml import check_policy, find_plugin_blocks


FINGERPRINT = "0123456789abcdef" * 4


class PluginBlockDiscoveryTest(unittest.TestCase):
    def test_middleware_name_can_match_plugin_name(self):
        block = {"policyJSON": "{}"}
        document = {
            "http": {
                "middlewares": {
                    "traefik-mtls-authz": {"plugin": {"traefik-mtls-authz": block}},
                },
            },
        }
        self.assertEqual(list(find_plugin_blocks(document)), [block])

    def test_ignores_matching_kubernetes_label(self):
        block = {"policyJSON": "{}"}
        document = {
            "metadata": {"labels": {"traefik-mtls-authz": "enabled"}},
            "spec": {"plugin": {"traefik-mtls-authz": block}},
        }
        self.assertEqual(list(find_plugin_blocks(document)), [block])


class FingerprintValidationTest(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "schemaVersion": 1,
            "app": "test",
            "identityPrefix": "urn:noqer:mtls:clients:",
            "trustedIssuers": [FINGERPRINT],
            "blockedFingerprints": [{"fingerprint": FINGERPRINT}],
        }

    def errors(self):
        return check_policy({"policy": self.policy}, "fixture")

    def test_accepts_valid_fingerprints(self):
        self.assertEqual(self.errors(), [])
        del self.policy["blockedFingerprints"]
        self.assertEqual(self.errors(), [])

    def test_rejects_invalid_trusted_issuer_fingerprints(self):
        for value in (FINGERPRINT + "\n", FINGERPRINT.upper(), int("1" * 64)):
            with self.subTest(value=value):
                self.policy["trustedIssuers"] = [value]
                self.assertRegex("\n".join(self.errors()), "trustedIssuers")

    def test_rejects_invalid_blocked_fingerprints(self):
        for value in (FINGERPRINT + "\n", FINGERPRINT.upper(), int("1" * 64)):
            with self.subTest(value=value):
                self.policy["blockedFingerprints"] = [{"fingerprint": value}]
                self.assertRegex("\n".join(self.errors()), "blockedFingerprints")

    def test_rejects_non_list_blocked_fingerprints(self):
        for value in (None, {}, ""):
            with self.subTest(value=value):
                self.policy["blockedFingerprints"] = value
                self.assertRegex("\n".join(self.errors()), "blockedFingerprints must be a list")


class ForwardHeaderValidationTest(unittest.TestCase):
    def policy(self, **headers):
        body = {
            "schemaVersion": 1,
            "app": "test",
            "identityPrefix": "urn:noqer:mtls:clients:",
            "trustedIssuers": [FINGERPRINT],
        }
        body.update(headers)
        return body

    def test_rejects_underscore_alias_of_another_forward_header(self):
        policy = self.policy(
            forwardIdentityHeader="X-Mtls-Same-Name",
            forwardFingerprintHeader="x-mtls-SAME_NAME",
        )
        errors = check_policy({"policyJSON": json.dumps(policy)}, "fixture")
        self.assertRegex("\n".join(errors), "forwardFingerprintHeader duplicates")

    def test_accepts_distinct_forward_headers(self):
        policy = self.policy(
            forwardIdentityHeader="X-Mtls-Identity",
            forwardFingerprintHeader="X-Mtls-Fingerprint",
            forwardNotAfterHeader="X-Mtls-Not-After",
        )
        self.assertEqual(check_policy({"policy": policy}, "fixture"), [])


class ConstraintValidationTest(unittest.TestCase):
    def setUp(self):
        identity = "urn:noqer:mtls:clients:alice"
        self.rule = {"methods": ["POST"], "paths": ["/upload"]}
        self.policy = {
            "schemaVersion": 1,
            "app": "test",
            "identityPrefix": "urn:noqer:mtls:clients:",
            "trustedIssuers": [FINGERPRINT],
            "identities": [identity],
            "constraints": {identity: self.rule},
        }

    def errors(self):
        return check_policy({"policyJSON": json.dumps(self.policy)}, "fixture")

    def test_accepts_valid_constraint_lists(self):
        self.assertEqual(self.errors(), [])

    def test_rejects_invalid_constraint_lists(self):
        for field in ("methods", "paths"):
            valid = self.rule[field]
            for value in (valid[0], {"value": valid[0]}, [valid[0], None], [], None):
                with self.subTest(field=field, value=value):
                    self.rule[field] = value
                    self.assertIn(field, "\n".join(self.errors()))
            self.rule[field] = valid
