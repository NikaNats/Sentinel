"""CONTRACT-001 tooling: regenerate the OpenAPI contract baseline snapshot.

This script is the PREVIEWED generator step of the contract pipeline
(see docs/CONTRACT_TESTING_STRATEGY.md, "OpenAPI contract suite").
It extracts the commit-binding facts from the current OpenAPI document
and snapshots them into v1-baseline.json, which the contract suite
asserts against on every execution.

Usage:
    python scripts/generate_openapi_baseline.py [path-to-openapi-yaml]

The YAML path defaults to docs/OPENAPI_3_1.yaml. The baseline is always
written to tests/Sentinel.Contracts/OpenApi/Baselines/v1-baseline.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOC = REPO_ROOT / "docs" / "OPENAPI_3_1.yaml"
BASELINE_OUT = (
    REPO_ROOT
    / "tests"
    / "Sentinel.Contracts"
    / "OpenApi"
    / "Baselines"
    / "v1-baseline.json"
)

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}
PARAMETER_LOCATIONS = ("header", "path", "query", "cookie")


def resolve_component(doc: dict, ref: str) -> dict | None:
    """Resolve a #/components/... reference within the document."""
    if not isinstance(ref, str) or not ref.startswith("#/components/"):
        return None
    node: dict = doc.get("components", {})
    for part in ref[len("#/components/"):].split("/"):
        if not isinstance(node, dict):
            return None
        node = node.get(part, {})
    return node if isinstance(node, dict) else None


def resolve_schema(doc: dict, ref: str) -> dict | None:
    """Resolve a #/components/schemas/... reference within the document."""
    return resolve_component(doc, ref)


def schema_required_props(
    doc: dict, schema: dict | str | None, seen: frozenset[str] = frozenset()
) -> list[str]:
    """Top-level required property names of a schema (following $ref chains)."""
    if schema is None:
        return []
    if isinstance(schema, str):
        if schema in seen:
            return []
        return schema_required_props(doc, resolve_schema(doc, schema), seen | {schema})
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if isinstance(ref, str):
            if ref in seen:
                return []
            return schema_required_props(doc, resolve_schema(doc, ref), seen | {ref})
        return sorted(schema.get("required", []))
    return []


def request_required_props(doc: dict, request_body: dict | None) -> list[str]:
    """Required properties of the request body's shape-defining media type."""
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content", {})
    if not isinstance(content, dict) or not content:
        return []
    for media_type in ("application/json", "application/*", "*/*"):
        if media_type in content:
            return schema_required_props(doc, content[media_type].get("schema"))
    for media_type in sorted(content):
        return schema_required_props(doc, content[media_type].get("schema"))
    return []


def request_parameters(doc: dict, path_item: dict, operation: dict) -> list[dict]:
    """Required path/query/header/cookie parameters (operation wins over path, $refs resolved)."""
    params: dict[tuple[str, str], dict] = {}

    def collect(container: object) -> None:
        if not isinstance(container, list):
            return
        for param in container:
            if not isinstance(param, dict):
                continue
            resolved = param
            ref = param.get("$ref")
            if isinstance(ref, str):
                resolved = resolve_component(doc, ref) or {}
            if (
                resolved.get("in") in PARAMETER_LOCATIONS
                and isinstance(resolved.get("name"), str)
            ):
                key = (resolved["in"], resolved["name"])
                params.setdefault(key, resolved)

    collect(operation.get("parameters"))
    collect(path_item.get("parameters"))
    return sorted(
        ({"in": kind, "name": name} for (kind, name), param in params.items() if param.get("required")),
        key=lambda item: (item["in"], item["name"]),
    )


def operation_snapshot(
    doc: dict, path_item: dict, operation: dict
) -> tuple[list[str], list[str], list[str], list[dict]]:
    """Return (response codes, security scheme names, required request props, required params)."""
    responses = sorted(
        str(code)
        for code in operation.get("responses", {}).keys()
    )
    security = sorted(
        scheme_name
        for requirement in operation.get("security", [])
        if isinstance(requirement, dict)
        for scheme_name in requirement.keys()
    )
    required = request_required_props(doc, operation.get("requestBody"))
    parameters = request_parameters(doc, path_item, operation)
    return responses, security, required, parameters


def security_scheme_snapshot(scheme: dict) -> dict:
    """The shape-defining keys of a security scheme."""
    keys = ("type", "in", "name", "scheme", "bearerFormat")
    return {k: scheme[k] for k in keys if k in scheme}


def generate(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)

    paths: dict[str, dict] = {}
    for path_name, path_item in sorted(doc.get("paths", {}).items()):
        if not isinstance(path_item, dict):
            continue
        methods: dict[str, dict] = {}
        for method, operation in sorted(path_item.items()):
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            responses, security, required, parameters = operation_snapshot(
                doc, path_item, operation
            )
            methods[method] = {
                "responses": responses,
                "security": security,
                "requestRequired": required,
                "parameters": parameters,
            }
        if methods:
            paths[path_name] = methods

    schemes = {
        name: security_scheme_snapshot(scheme)
        for name, scheme in doc.get("components", {}).get("securitySchemes", {}).items()
    }

    info = doc.get("info", {})
    return {
        "format": "SentinelOpenApiBaseline",
        "formatVersion": 1,
        "generatedFrom": path.name,
        "specVersion": str(info.get("version", "")),
        "contract": {"id": "CONTRACT-001", "version": "1.0"},
        "paths": paths,
        "securitySchemes": schemes,
    }


def main() -> None:
    doc_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DOC
    baseline = generate(doc_path)
    BASELINE_OUT.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_OUT.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {BASELINE_OUT.relative_to(REPO_ROOT)} ({len(baseline['paths'])} paths)")


if __name__ == "__main__":
    main()