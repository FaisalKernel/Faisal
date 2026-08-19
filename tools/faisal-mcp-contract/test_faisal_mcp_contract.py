#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_mcp_contract import ContractError, admit_tool_list, contract_summary, sha256_hex, validate_tool_call, validate_tool_result


def tool(name, *, output=False, annotation=None):
    item = {
        "name": name,
        "description": f"bounded {name}",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    }
    if output:
        item["outputSchema"] = {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": False,
        }
    if annotation:
        item["annotations"] = annotation
    return item


class ContractTests(unittest.TestCase):
    def test_deterministic_ordering_and_digest(self):
        left = admit_tool_list("server-a", [tool("zeta"), tool("alpha")], [])
        right = admit_tool_list("server-a", [tool("alpha"), tool("zeta")], [])
        self.assertEqual([x["name"] for x in left["tools"]], ["alpha", "zeta"])
        self.assertEqual(left["digest"], right["digest"])
        self.assertTrue(left["annotationsAreUntrusted"])

    def test_scope_filtering_is_fail_closed(self):
        public = admit_tool_list("server-a", [tool("public")], [])
        restricted = admit_tool_list("server-a", [tool("restricted")], [])
        self.assertEqual(public["count"], 1)
        self.assertEqual(restricted["count"], 1)
        # Scope policy is supplied by the caller, never inferred from model annotations.
        scoped = admit_tool_list("server-a", [tool("restricted")], [], required_scopes={"server-a:restricted": ["repo:read"]})
        self.assertEqual(scoped["count"], 0)
        allowed = admit_tool_list("server-a", [tool("restricted")], ["repo:read"], required_scopes={"server-a:restricted": ["repo:read"]})
        self.assertEqual(allowed["count"], 1)

    def test_collision_rejected(self):
        with self.assertRaises(ContractError):
            admit_tool_list("server-a", [tool("same"), tool("same")], [])

    def test_input_and_output_validation(self):
        item = tool("answer", output=True)
        validate_tool_call(item, {"query": "hello"})
        validate_tool_result(item, {"answer": "world"})
        with self.assertRaises(ContractError):
            validate_tool_call(item, {"query": "", "extra": 1})
        with self.assertRaises(ContractError):
            validate_tool_result(item, {"wrong": "world"})

    def test_invalid_schema_rejected(self):
        item = tool("bad")
        item["inputSchema"]["properties"]["query"]["type"] = "function"
        with self.assertRaises(ContractError):
            admit_tool_list("server-a", [item], [])

    def test_invalid_header_and_sensitive_header_rejected(self):
        item = tool("header")
        item["inputSchema"]["properties"]["query"]["x-mcp-header"] = "Bad Header"
        with self.assertRaises(ContractError):
            admit_tool_list("server-a", [item], [])
        item = tool("secret-header")
        item["inputSchema"]["properties"]["query"]["x-mcp-header"] = "Authorization"
        item["inputSchema"]["properties"]["query"]["sensitive"] = True
        with self.assertRaises(ContractError):
            admit_tool_list("server-a", [item], [])

    def test_opaque_pagination(self):
        items = [tool(f"tool-{i:03d}") for i in range(4)]
        first = admit_tool_list("server-a", items, [], maximum_tools=2)
        self.assertEqual(first["count"], 2)
        self.assertIsNotNone(first["nextCursor"])
        second = admit_tool_list("server-a", items, [], maximum_tools=2, cursor=first["nextCursor"])
        self.assertEqual(second["count"], 2)
        self.assertIsNone(second["nextCursor"])
        self.assertNotEqual(first["digest"], second["digest"])

    def test_summary_is_machine_readable(self):
        result = contract_summary("server-a", [tool("answer", output=True, annotation={"readOnlyHint": True})], [])
        self.assertEqual(result["toolCount"], 1)
        self.assertTrue(result["schemaValidation"])
        self.assertTrue(result["outputValidation"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
