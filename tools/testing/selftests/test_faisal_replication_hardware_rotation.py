#!/usr/bin/env python3
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[2] / "faisal-replication"))
from faisal_replication_providers import (
    Ed25519AttestationVerifier,
    Ed25519Signer,
    Ed25519TrustStore,
    KmsTrustKeyRotationController,
    ProviderConfigurationError,
    ProviderUnavailable,
    RotationProposal,
    SecureEnclavePublicKeyProvider,
    TPM2PublicKeyProvider,
)


class HardwareRotationTest(unittest.TestCase):
    def test_missing_tpm_provider_is_unavailable_not_software_fallback(self):
        provider = TPM2PublicKeyProvider("0x81000001", "00" * 32, tool="/bin/false")
        with self.assertRaises(ProviderUnavailable):
            provider.load_public_key()

    def test_secure_enclave_digest_mismatch_is_rejected(self):
        provider = SecureEnclavePublicKeyProvider(("/bin/printf", "not-a-public-key"), "00" * 32)
        with self.assertRaises(ProviderUnavailable):
            provider.load_public_key()

    def test_rotation_activates_new_generation_and_revokes_old(self):
        old = Ed25519Signer.generate(7, 2, "old-key", 1)
        new = Ed25519Signer.generate(7, 2, "new-key", 2)
        store = Ed25519TrustStore({(7, 2, old.key_id, old.key_generation): old.public_key_bytes()})
        verifier = Ed25519AttestationVerifier(store)
        old_identity = old.identity(4, 0, b"\x00" * 32)
        self.assertTrue(verifier.verify(old_identity))
        controller = KmsTrustKeyRotationController(store, lambda: old.sign_rotation(new), interval_seconds=0.01)
        self.assertTrue(controller.rotate_once())
        self.assertEqual(store.active_generation(7, 2), ("new-key", 2))
        self.assertFalse(verifier.verify(old_identity))
        self.assertTrue(verifier.verify(new.identity(4, 0, b"\x00" * 32)))

    def test_invalid_rotation_preserves_active_key(self):
        old = Ed25519Signer.generate(7, 2, "old-key", 1)
        new = Ed25519Signer.generate(7, 2, "new-key", 2)
        store = Ed25519TrustStore({(7, 2, old.key_id, old.key_generation): old.public_key_bytes()})
        proposal = old.sign_rotation(new)
        invalid = RotationProposal(
            proposal.cluster_id,
            proposal.replica_id,
            proposal.previous_key_id,
            proposal.previous_generation,
            proposal.key_id,
            proposal.key_generation,
            proposal.public_key,
            b"invalid",
        )
        controller = KmsTrustKeyRotationController(store, lambda: invalid, interval_seconds=0.01)
        self.assertFalse(controller.rotate_once())
        self.assertEqual(store.active_generation(7, 2), ("old-key", 1))
        self.assertIsNotNone(controller.last_error)

    def test_background_rotation_changes_verification_without_restart(self):
        old = Ed25519Signer.generate(7, 2, "old-key", 1)
        new = Ed25519Signer.generate(7, 2, "new-key", 2)
        store = Ed25519TrustStore({(7, 2, old.key_id, old.key_generation): old.public_key_bytes()})
        pending = [old.sign_rotation(new)]
        controller = KmsTrustKeyRotationController(store, lambda: pending.pop(0) if pending else (_ for _ in ()).throw(ProviderUnavailable("no update")), interval_seconds=0.01)
        controller.start()
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and store.active_generation(7, 2) != ("new-key", 2):
            time.sleep(0.01)
        controller.stop()
        self.assertEqual(store.active_generation(7, 2), ("new-key", 2))


if __name__ == "__main__":
    unittest.main()
