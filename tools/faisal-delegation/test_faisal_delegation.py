#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_delegation import DelegationError, DelegationScope, Invocation, authorize_invocation, derive_child, issue_root, verify_chain


class DelegationTests(unittest.TestCase):
    def scope(self, tools=("read", "write"), resources=("repo", "issues"), max_calls=10, constraints=()):
        return DelegationScope(frozenset(tools), frozenset(resources), frozenset(constraints), max_calls)

    def chain(self):
        root = issue_root(delegation_id="root", issuer="user", delegatee="planner", issued_at=100, expires_at=1000, scope=self.scope(), max_depth=3, holder_proof_digest="sha256:" + "1" * 64, nonce="n-root")
        child = derive_child(root, delegation_id="child", delegatee="worker", issued_at=150, expires_at=800, scope=self.scope(tools=("read",), resources=("repo",), max_calls=4), holder_proof_digest="sha256:" + "2" * 64, nonce="n-child")
        return root, child

    def test_attenuated_chain_and_invocation(self):
        root, child = self.chain()
        leaf = verify_chain((root, child), now=200)
        self.assertEqual(leaf.delegation_id, "child")
        result = authorize_invocation((root, child), Invocation("read", "repo", None, "call-1"), now=200)
        self.assertTrue(result["authorized"])
        self.assertFalse(result["executed"])
        self.assertFalse(result["model_output_is_authority"])

    def test_amplification_and_ttl_depth_denied(self):
        root, _ = self.chain()
        with self.assertRaises(DelegationError):
            derive_child(root, delegation_id="wide", delegatee="worker", issued_at=150, expires_at=800, scope=self.scope(tools=("read", "write"), resources=("repo", "issues"), max_calls=11), holder_proof_digest="sha256:" + "3" * 64, nonce="n-wide")
        with self.assertRaises(DelegationError):
            derive_child(root, delegation_id="late", delegatee="worker", issued_at=150, expires_at=1001, scope=self.scope(tools=("read",), resources=("repo",), max_calls=4), holder_proof_digest="sha256:" + "4" * 64, nonce="n-late")
        depth1 = derive_child(root, delegation_id="d1", delegatee="a", issued_at=150, expires_at=800, scope=self.scope(tools=("read",), resources=("repo",), max_calls=4), holder_proof_digest="sha256:" + "5" * 64, nonce="n-d1")
        depth2 = derive_child(depth1, delegation_id="d2", delegatee="b", issued_at=200, expires_at=700, scope=self.scope(tools=("read",), resources=("repo",), max_calls=2), holder_proof_digest="sha256:" + "6" * 64, nonce="n-d2")
        depth3 = derive_child(depth2, delegation_id="d3", delegatee="c", issued_at=250, expires_at=600, scope=self.scope(tools=("read",), resources=("repo",), max_calls=1), holder_proof_digest="sha256:" + "7" * 64, nonce="n-d3")
        with self.assertRaises(DelegationError):
            derive_child(depth3, delegation_id="d4", delegatee="d", issued_at=300, expires_at=500, scope=self.scope(tools=("read",), resources=("repo",), max_calls=1), holder_proof_digest="sha256:" + "8" * 64, nonce="n-d4")

    def test_revocation_propagates_by_id_and_lineage(self):
        root, child = self.chain()
        with self.assertRaises(DelegationError):
            verify_chain((root, child), now=200, revoked_ids=frozenset({"root"}))
        with self.assertRaises(DelegationError):
            verify_chain((root, child), now=200, revoked_ids=frozenset({"child"}))
        with self.assertRaises(DelegationError):
            verify_chain((root, child), now=200, revoked_lineages=frozenset({root.record_digest()}))

    def test_expiry_and_invocation_scope_denied(self):
        root, child = self.chain()
        with self.assertRaises(DelegationError):
            verify_chain((root, child), now=800)
        with self.assertRaises(DelegationError):
            authorize_invocation((root, child), Invocation("write", "repo", None, "call-2"), now=200)
        with self.assertRaises(DelegationError):
            authorize_invocation((root, child), Invocation("read", "repo", None, "call-3", used_calls=4), now=200)

    def test_argument_constraint_attenuation(self):
        root_scope = self.scope(tools=("read",), resources=("repo",), max_calls=5, constraints=(("read", "path", "/safe",),))
        root = issue_root(delegation_id="arg-root", issuer="user", delegatee="worker", issued_at=100, expires_at=500, scope=root_scope, max_depth=2, holder_proof_digest="sha256:" + "a" * 64, nonce="arg-root-nonce")
        child = derive_child(root, delegation_id="arg-child", delegatee="leaf", issued_at=110, expires_at=400, scope=root_scope, holder_proof_digest="sha256:" + "b" * 64, nonce="arg-child-nonce")
        self.assertTrue(authorize_invocation((root, child), Invocation("read", "repo", ("read", "path", "/safe"), "arg-call"), now=200)["authorized"])
        with self.assertRaises(DelegationError):
            authorize_invocation((root, child), Invocation("read", "repo", ("read", "path", "/other"), "arg-bad"), now=200)

    def test_chain_linkage_and_proof_boundary(self):
        root, child = self.chain()
        self.assertNotEqual(root.record_digest(), child.record_digest())
        self.assertEqual(child.parent_digest, root.record_digest())
        tampered = type(child)(child.delegation_id, child.issuer, child.delegatee, root.record_digest(), child.depth, child.max_depth, child.issued_at, child.expires_at, self.scope(tools=("read",), resources=("outside",), max_calls=4), child.holder_proof_digest, child.nonce)
        with self.assertRaises(DelegationError):
            verify_chain((root, tampered), now=200)

    def test_invalid_windows_and_empty_scope_rejected(self):
        with self.assertRaises(DelegationError):
            DelegationScope(frozenset(), frozenset({"repo"}))
        with self.assertRaises(DelegationError):
            issue_root(delegation_id="bad", issuer="u", delegatee="a", issued_at=100, expires_at=100, scope=self.scope(), max_depth=1, holder_proof_digest="sha256:" + "c" * 64, nonce="bad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
