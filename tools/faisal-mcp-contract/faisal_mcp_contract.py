#!/usr/bin/env python3
"""FAISAL deterministic MCP-style tool contract validation.

This module is intentionally user-space control-plane code. It does not execute
models or tools and never treats model output, tool annotations, or provider
metadata as authorization. It validates a bounded MCP-compatible tool surface
before tool context admission and produces stable digests for audit/replay.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

MAX_TOOL_NAME = 128
MAX_DESCRIPTION = 4096
MAX_TOOLS = 1024
MAX_SCHEMA_DEPTH = 12
MAX_PROPERTIES = 128
MAX_ARRAY_ITEMS = 128
MAX_STRING_LENGTH = 4096
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_HTTP_FIELD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_RESERVED_SENSITIVE = re.compile(r"(?:pass(word)?|secret|token|api[_-]?key|credential|private[_-]?key|cookie)", re.I)
_ALLOWED_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}


class ContractError(ValueError):
    """Raised when a tool contract cannot be safely admitted."""


@dataclass(frozen=True)
class ValidatedTool:
    server_id: str
    name: str
    qualified_name: str
    definition: dict[str, Any]
    digest: str


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(value: Any) -> str:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    return hashlib.sha256(raw).hexdigest()


def _fail(path: str, message: str) -> None:
    raise ContractError(f"{path}: {message}")


def _check_schema(schema: Any, path: str = "schema", depth: int = 0) -> None:
    if not isinstance(schema, dict):
        _fail(path, "must be an object")
    if depth > MAX_SCHEMA_DEPTH:
        _fail(path, "maximum schema depth exceeded")
    schema_type = schema.get("type")
    if schema_type not in _ALLOWED_TYPES:
        _fail(path, "type must be a supported JSON Schema primitive")
    if "default" in schema and schema_type == "object":
        _fail(path, "object defaults are not admitted in the bounded contract")
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or len(enum) > MAX_ARRAY_ITEMS:
            _fail(path + ".enum", "must be a bounded list")
    if schema_type == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, dict) or len(properties) > MAX_PROPERTIES:
            _fail(path + ".properties", "must be a bounded object")
        required = schema.get("required", [])
        if not isinstance(required, list) or any(not isinstance(x, str) for x in required):
            _fail(path + ".required", "must be a list of strings")
        if len(set(required)) != len(required) or any(x not in properties for x in required):
            _fail(path + ".required", "must name unique declared properties")
        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, bool):
            _fail(path + ".additionalProperties", "must be boolean")
        for name, child in properties.items():
            if not isinstance(name, str) or not name or len(name) > MAX_TOOL_NAME:
                _fail(path + ".properties", "property names must be bounded strings")
            _check_schema(child, f"{path}.properties.{name}", depth + 1)
    elif schema_type == "array":
        if "items" not in schema:
            _fail(path, "array schema requires items")
        _check_schema(schema["items"], path + ".items", depth + 1)
    else:
        if "properties" in schema or "items" in schema:
            _fail(path, "non-container schema cannot declare properties or items")
    header_names: list[str] = []
    for name, child in schema.get("properties", {}).items() if schema_type == "object" else []:
        if "x-mcp-header" in child:
            header = child["x-mcp-header"]
            if not isinstance(header, str) or not _HTTP_FIELD.fullmatch(header):
                _fail(f"{path}.properties.{name}.x-mcp-header", "invalid HTTP field name")
            if child.get("type") not in {"string", "integer", "boolean"}:
                _fail(f"{path}.properties.{name}.x-mcp-header", "only string, integer, and boolean are allowed")
            if child.get("type") == "integer" and (child.get("minimum", -2**53) < -2**53 + 1 or child.get("maximum", 2**53 - 1) > 2**53 - 1):
                _fail(f"{path}.properties.{name}.x-mcp-header", "integer range exceeds safe JSON number range")
            if _RESERVED_SENSITIVE.search(name) or child.get("sensitive") is True:
                _fail(f"{path}.properties.{name}.x-mcp-header", "sensitive values cannot be mirrored into headers")
            folded = header.lower()
            if folded in {x.lower() for x in header_names}:
                _fail(path, "x-mcp-header values must be case-insensitively unique")
            header_names.append(header)


def _validate_tool(server_id: str, tool: Mapping[str, Any]) -> ValidatedTool:
    if not isinstance(server_id, str) or not server_id or not _SAFE_NAME.fullmatch(server_id):
        raise ContractError("server_id: must be a bounded ASCII identifier")
    if not isinstance(tool, Mapping):
        raise ContractError("tool: must be an object")
    name = tool.get("name")
    if not isinstance(name, str) or not _SAFE_NAME.fullmatch(name) or len(name) > MAX_TOOL_NAME:
        raise ContractError("tool.name: invalid deterministic tool name")
    description = tool.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION:
        raise ContractError("tool.description: must be a bounded string")
    input_schema = tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        raise ContractError("tool.inputSchema: required object")
    _check_schema(input_schema, "tool.inputSchema")
    output_schema = tool.get("outputSchema")
    if output_schema is not None:
        _check_schema(output_schema, "tool.outputSchema")
    annotations = tool.get("annotations", {})
    if annotations is not None and not isinstance(annotations, dict):
        raise ContractError("tool.annotations: must be an object when present")
    # Annotations are retained for audit but never interpreted as authority.
    definition = {
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    }
    if output_schema is not None:
        definition["outputSchema"] = output_schema
    if annotations:
        definition["annotations"] = annotations
    qualified = f"{server_id}:{name}"
    return ValidatedTool(server_id, name, qualified, definition, sha256_hex({"server": server_id, "tool": definition}))


def validate_tool_set(server_id: str, tools: Iterable[Mapping[str, Any]]) -> list[ValidatedTool]:
    raw = list(tools)
    if not raw or len(raw) > MAX_TOOLS:
        raise ContractError("tools: must contain between 1 and 1024 tools")
    validated = [_validate_tool(server_id, tool) for tool in raw]
    names = [tool.qualified_name for tool in validated]
    if len(set(names)) != len(names):
        raise ContractError("tools: duplicate qualified tool name")
    return sorted(validated, key=lambda item: item.qualified_name)


def admit_tool_list(server_id: str, tools: Iterable[Mapping[str, Any]], granted_scopes: Iterable[str], maximum_tools: int = MAX_TOOLS, cursor: str | None = None, required_scopes: Mapping[str, Iterable[str]] | None = None) -> dict[str, Any]:
    if maximum_tools <= 0 or maximum_tools > MAX_TOOLS:
        raise ContractError("maximum_tools: out of bounds")
    granted = {scope for scope in granted_scopes if isinstance(scope, str) and scope}
    policy = required_scopes or {}
    validated = validate_tool_set(server_id, tools)
    admitted: list[ValidatedTool] = []
    for item in validated:
        required_raw = policy.get(item.qualified_name, [])
        required = list(required_raw)
        if any(not isinstance(scope, str) or not scope for scope in required):
            raise ContractError(f"{item.qualified_name}: invalid required scope policy")
        if set(required).issubset(granted):
            admitted.append(item)
    start = 0
    if cursor is not None:
        if not isinstance(cursor, str) or not cursor.startswith("sha256:"):
            raise ContractError("cursor: invalid opaque cursor")
        try:
            start = int(cursor.removeprefix("sha256:"), 16)
        except ValueError as exc:
            raise ContractError("cursor: invalid hexadecimal offset") from exc
        if start < 0 or start > len(admitted):
            raise ContractError("cursor: out of range")
    page = admitted[start:start + maximum_tools]
    next_cursor = None if start + maximum_tools >= len(admitted) else f"sha256:{start + maximum_tools:x}"
    projection = [item.definition | {"qualifiedName": item.qualified_name} for item in page]
    return {
        "serverId": server_id,
        "tools": projection,
        "nextCursor": next_cursor,
        "count": len(page),
        "totalAdmitted": len(admitted),
        "digest": sha256_hex({"serverId": server_id, "tools": projection}),
        "annotationsAreUntrusted": True,
    }


def _validate_value(schema: Mapping[str, Any], value: Any, path: str) -> None:
    schema_type = schema["type"]
    valid = {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "string": isinstance(value, str) and len(value) <= MAX_STRING_LENGTH,
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "array": isinstance(value, list) and len(value) <= MAX_ARRAY_ITEMS,
    }[schema_type]
    if not valid:
        _fail(path, f"value does not match type {schema_type}")
    if "enum" in schema and value not in schema["enum"]:
        _fail(path, "value is not in enum")
    if schema_type == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            _fail(path, "string is shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            _fail(path, "string is longer than maxLength")
    if schema_type in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"]:
            _fail(path, "value is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            _fail(path, "value is above maximum")
    if schema_type == "object":
        props = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [name for name in required if name not in value]
        if missing:
            _fail(path, f"missing required properties: {','.join(missing)}")
        if schema.get("additionalProperties", True) is False:
            extra = [name for name in value if name not in props]
            if extra:
                _fail(path, f"unexpected properties: {','.join(sorted(extra))}")
        for name, child in props.items():
            if name in value:
                _validate_value(child, value[name], f"{path}.{name}")
    elif schema_type == "array":
        for index, item in enumerate(value):
            _validate_value(schema["items"], item, f"{path}[{index}]")


def validate_tool_call(tool: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    validated = _validate_tool("call", tool)
    if not isinstance(arguments, Mapping):
        raise ContractError("arguments: must be an object")
    _validate_value(validated.definition["inputSchema"], dict(arguments), "arguments")


def validate_tool_result(tool: Mapping[str, Any], result: Any) -> None:
    output = tool.get("outputSchema")
    if output is None:
        return
    _check_schema(output, "tool.outputSchema")
    _validate_value(output, result, "result")


def contract_summary(server_id: str, tools: Iterable[Mapping[str, Any]], granted_scopes: Iterable[str], required_scopes: Mapping[str, Iterable[str]] | None = None) -> dict[str, Any]:
    admitted = admit_tool_list(server_id, tools, granted_scopes, required_scopes=required_scopes)
    return {
        "serverId": server_id,
        "toolCount": admitted["count"],
        "totalAdmitted": admitted["totalAdmitted"],
        "digest": admitted["digest"],
        "deterministicOrdering": True,
        "schemaValidation": True,
        "scopeFiltering": True,
        "outputValidation": any("outputSchema" in tool for tool in admitted["tools"]),
        "annotationsAreUntrusted": True,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Validate a FAISAL MCP-style tool contract")
    parser.add_argument("contract", help="JSON object with serverId, tools, and optional grantedScopes")
    args = parser.parse_args()
    with open(args.contract, encoding="utf-8") as handle:
        payload = json.load(handle)
    print(json.dumps(contract_summary(payload["serverId"], payload["tools"], payload.get("grantedScopes", [])), sort_keys=True))
