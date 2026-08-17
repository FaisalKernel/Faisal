import base64
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "faisal-journal-trust"))
import faisal_remote_kms_client as client


class RemoteKmsClientTests(unittest.TestCase):
    def test_vault_payload_and_versioned_response(self):
        captured = {}

        def fake_request(url, body, headers, timeout):
            captured.update(url=url, body=body, headers=headers, timeout=timeout)
            return {"data": {"signature": "vault:v7:" + base64.b64encode(b"sig").decode()}}

        with mock.patch.object(client, "_request", side_effect=fake_request):
            result = client.VaultTransitSigner(
                "https://vault.example", "token", "faisal-journal", timeout=3
            ).sign(b"journal-report")
        payload = json.loads(captured["body"])
        self.assertEqual(captured["url"], "https://vault.example/v1/transit/sign/faisal-journal")
        self.assertEqual(payload["input"], base64.b64encode(b"journal-report").decode())
        self.assertEqual(captured["headers"]["X-Vault-Token"], "token")
        self.assertEqual(result.signature, b"sig")
        self.assertEqual(result.key_generation, 7)

    def test_vault_rejects_insecure_or_malformed_responses(self):
        with self.assertRaises(ValueError):
            client.VaultTransitSigner("http://vault.example", "token", "key")
        with mock.patch.object(client, "_request", return_value={"data": {"signature": "bad"}}):
            with self.assertRaises(client.RemoteKmsError):
                client.VaultTransitSigner("https://vault.example", "token", "key").sign(b"x")
        with mock.patch.object(client, "_request", return_value={"data": {"signature": "vault:v0:eA=="}}):
            with self.assertRaises(client.RemoteKmsError):
                client.VaultTransitSigner("https://vault.example", "token", "key").sign(b"x")

    def test_aws_sigv4_payload_and_response(self):
        captured = {}

        def fake_request(url, body, headers, timeout):
            captured.update(url=url, body=body, headers=headers, timeout=timeout)
            return {
                "KeyId": "arn:aws:kms:us-east-1:123:key/faisal",
                "Signature": base64.b64encode(b"aws-signature").decode(),
                "SigningAlgorithm": "ED25519_SHA_512",
            }

        with mock.patch.object(client, "_request", side_effect=fake_request):
            result = client.AwsKmsSigner(
                "us-east-1", "arn:aws:kms:us-east-1:123:key/faisal",
                access_key="AKIA_TEST", secret_key="SECRET_TEST"
            ).sign(b"journal-report")
        payload = json.loads(captured["body"])
        self.assertEqual(captured["url"], "https://kms.us-east-1.amazonaws.com/")
        self.assertEqual(payload["KeyId"], "arn:aws:kms:us-east-1:123:key/faisal")
        self.assertEqual(payload["Message"], base64.b64encode(b"journal-report").decode())
        self.assertEqual(payload["MessageType"], "RAW")
        self.assertEqual(payload["SigningAlgorithm"], "ED25519_SHA_512")
        self.assertIn("AWS4-HMAC-SHA256 Credential=AKIA_TEST/", captured["headers"]["Authorization"])
        self.assertEqual(result.signature, b"aws-signature")

    def test_aws_rejects_missing_credentials_and_key_mismatch(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                client.AwsKmsSigner("us-east-1", "key")
        response = {
            "KeyId": "different-key",
            "Signature": base64.b64encode(b"sig").decode(),
            "SigningAlgorithm": "ED25519_SHA_512",
        }
        with mock.patch.object(client, "_request", return_value=response):
            signer = client.AwsKmsSigner("us-east-1", "key", "a", "b")
            with self.assertRaises(client.RemoteKmsError):
                signer.sign(b"x")

    def test_message_size_is_bounded(self):
        with mock.patch.object(client, "_request") as request:
            with self.assertRaises(ValueError):
                client.VaultTransitSigner("https://vault.example", "token", "key").sign(b"x" * 4097)
            with self.assertRaises(ValueError):
                client.AwsKmsSigner("us-east-1", "key", "a", "b").sign(b"x" * 4097)
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
