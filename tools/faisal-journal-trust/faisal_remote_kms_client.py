#!/usr/bin/env python3
"""Remote attestation signing clients for AWS KMS and Vault Transit.

The module never reads credentials from source files. AWS credentials use the
standard environment variables and Vault uses an explicitly supplied token.
The clients return signatures plus provider key/version metadata; callers must
still verify the signed journal report and freshness before admission.
"""
import base64
import hashlib
import hmac
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone


class RemoteKmsError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteSignature:
    signature: bytes
    key_id: str
    key_generation: int
    algorithm: str


def _request(url, body, headers, timeout=5):
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            payload = response.read()
            if response.status < 200 or response.status >= 300:
                raise RemoteKmsError(f"remote status {response.status}")
            return json.loads(payload.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
        raise RemoteKmsError(f"remote KMS request failed: {exc}") from exc


class VaultTransitSigner:
    def __init__(self, address, token, key_name, verify_tls=True, timeout=5):
        if not address.startswith("https://") or not token or not key_name:
            raise ValueError("Vault requires HTTPS, token, and key name")
        if not verify_tls:
            raise ValueError("disabling Vault TLS verification is not permitted")
        self.address = address.rstrip("/")
        self.token = token
        self.key_name = key_name
        self.verify_tls = verify_tls
        self.timeout = timeout

    def sign(self, message):
        if not message or len(message) > 4096:
            raise ValueError("Vault signing message must be 1..4096 bytes")
        body = json.dumps({"input": base64.b64encode(message).decode("ascii")}).encode()
        result = _request(
            f"{self.address}/v1/transit/sign/{urllib.parse.quote(self.key_name, safe='')}",
            body,
            {"Content-Type": "application/json", "X-Vault-Token": self.token},
            self.timeout,
        )
        data = result.get("data", {})
        raw = data.get("signature", "")
        if not raw.startswith("vault:v") or ":" not in raw:
            raise RemoteKmsError("Vault response lacks versioned signature")
        version_text, encoded = raw.rsplit(":", 1)
        try:
            version = int(version_text[6:])
            signature = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise RemoteKmsError("invalid Vault signature encoding") from exc
        if not signature or version < 1:
            raise RemoteKmsError("invalid Vault key version")
        return RemoteSignature(signature, self.key_name, version, "vault-transit")


class AwsKmsSigner:
    def __init__(self, region, key_id, access_key=None, secret_key=None, session_token=None, timeout=5):
        self.region = region
        self.key_id = key_id
        self.access_key = access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.session_token = session_token or os.environ.get("AWS_SESSION_TOKEN")
        self.timeout = timeout
        if not region or not key_id or not self.access_key or not self.secret_key:
            raise ValueError("AWS KMS requires region, key ID, and credentials")

    def sign(self, message):
        if not message or len(message) > 4096:
            raise ValueError("AWS KMS raw signing message must be 1..4096 bytes")
        service = "kms"
        host = f"kms.{self.region}.amazonaws.com"
        endpoint = f"https://{host}/"
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = now.strftime("%Y%m%d")
        target = "TrentService.Sign"
        payload = json.dumps({
            "KeyId": self.key_id,
            "Message": base64.b64encode(message).decode("ascii"),
            "MessageType": "RAW",
            "SigningAlgorithm": "ED25519_SHA_512",
        }, separators=(",", ":")).encode()
        payload_hash = hashlib.sha256(payload).hexdigest()
        canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\nx-amz-target:{target}\n"
        signed_headers = "host;x-amz-date;x-amz-target"
        canonical_request = "POST\n/\n\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash
        scope = f"{date}/{self.region}/{service}/aws4_request"
        string_to_sign = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + hashlib.sha256(canonical_request.encode()).hexdigest()
        def derive(key, value):
            return hmac.new(key, value.encode(), hashlib.sha256).digest()
        k_date = derive(("AWS4" + self.secret_key).encode(), date)
        k_region = derive(k_date, self.region)
        k_service = derive(k_region, service)
        signing_key = derive(k_service, "aws4_request")
        signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "Host": host,
            "X-Amz-Date": amz_date,
            "X-Amz-Target": target,
            "Authorization": f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        }
        if self.session_token:
            headers["X-Amz-Security-Token"] = self.session_token
        result = _request(endpoint, payload, headers, self.timeout)
        try:
            signature_bytes = base64.b64decode(result["Signature"], validate=True)
            returned_key = result["KeyId"]
        except (KeyError, ValueError, base64.binascii.Error) as exc:
            raise RemoteKmsError("invalid AWS KMS Sign response") from exc
        if not signature_bytes or returned_key != self.key_id:
            raise RemoteKmsError("AWS KMS key identity mismatch")
        return RemoteSignature(signature_bytes, returned_key, 1, result.get("SigningAlgorithm", "ED25519_SHA_512"))
