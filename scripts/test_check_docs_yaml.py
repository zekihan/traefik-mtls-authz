import unittest

from check_docs_yaml import check_policy


FINGERPRINT = "0123456789abcdef" * 4


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
