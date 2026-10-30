"""Public API contract snapshot: every released `/api/*` operation keeps
accepting what it accepted before, and keeps answering with what it
answered before.

`tests/openapi_snapshot.json` holds the request contract of every `/api/*`
operation (query, path and header parameters, the body schema with every
model resolved) and the top-level response keys of the local read-only
endpoints whose answers do not depend on a tenant. It is compared with
`app.openapi()` and live answers on every run:

- a removed operation, parameter, body, content type or field fails;
- a field or parameter whose type narrowed fails (int -> number is a
  widening, number -> int a narrowing);
- a newly required field, parameter or body fails;
- a new or tightened limit (maxLength, maximum, maxItems, minLength,
  minimum, minItems, pattern), a new or smaller enum and a closed object
  (additionalProperties: false) fail;
- a response key the snapshot names that is gone, or changed JSON type, fails.

Additions (operations, optional fields, wider types, new response keys)
stay allowed. After an intended, documented additive change, refresh the
snapshot with `python tests/test_openapi_regression.py --write`: it
refuses to write while anything is incompatible, so the snapshot can only
grow. Operations in `UNRELEASED` are not held to a contract yet.
"""
from __future__ import annotations

import copy
import json
import os
import sys
from typing import Any, Dict, List, Optional

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SNAPSHOT = os.path.join(HERE, "openapi_snapshot.json")

# Never in a release: no contract yet (the brief's one exception). An
# operation listed here that later ships is taken in by --write.
UNRELEASED = ("POST /api/path-analyzer/full/start",)

# Local, tenant-free GET endpoints whose top-level answer keys are part of
# the contract (the UI, the browser extension and scripts read them).
RESPONSE_ENDPOINTS = (
    "/api/auth/status", "/api/change-queue", "/api/checks", "/api/deployments", "/api/detection-health/schedule",
    "/api/digests", "/api/dlp-packs", "/api/exports/columns", "/api/exports/plans", "/api/frameworks",
    "/api/guidance/sources", "/api/logs/catalogue", "/api/operations", "/api/pack-library", "/api/permissions/required",
    "/api/ping", "/api/posture/settings", "/api/reference", "/api/remediation/catalog", "/api/saas-apps",
    "/api/scope/prerequisites", "/api/secure-by-design", "/api/ssl-coverage/history", "/api/tenant-profiles",
    "/api/updates/sources", "/api/vendor-migrate/vendors", "/api/vertical-scope", "/api/write-mode",
)

_KEEP = ("type", "properties", "required", "items", "additionalProperties", "anyOf", "oneOf", "allOf", "enum", "const",
         "maxLength", "minLength", "maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum", "maxItems", "minItems",
         "pattern", "format", "$ref")
_UPPER = ("maxLength", "maximum", "exclusiveMaximum", "maxItems")
_LOWER = ("minLength", "minimum", "exclusiveMinimum", "minItems")


# ── extraction ─────────────────────────────────────────────────────────

def _norm(schema: Any) -> Any:
    """A schema with only what decides what is accepted (no titles,
    descriptions, defaults or examples)."""
    if isinstance(schema, list):
        return [_norm(s) for s in schema]
    if not isinstance(schema, dict):
        return schema
    out: Dict[str, Any] = {}
    for k in _KEEP:
        if k not in schema:
            continue
        v = schema[k]
        if k == "properties":
            out[k] = {name: _norm(s) for name, s in v.items()}
        elif k in ("items", "additionalProperties", "anyOf", "oneOf", "allOf"):
            out[k] = _norm(v)
        elif k == "required":
            out[k] = sorted(v)
        else:
            out[k] = v
    return out


def contract(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The request contract of every /api/* operation of an OpenAPI spec."""
    ops: Dict[str, Any] = {}
    for path, item in spec.get("paths", {}).items():
        if not path.startswith("/api/"):
            continue
        for method, op in item.items():
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            params = {f"{p['in']}:{p['name']}": {"required": bool(p.get("required")), "schema": _norm(p.get("schema") or {})}
                      for p in op.get("parameters") or []}
            body = op.get("requestBody")
            ops[f"{method.upper()} {path}"] = {
                "params": params,
                "body": None if body is None else {
                    "required": bool(body.get("required")),
                    "content": {ct: _norm(c.get("schema") or {}) for ct, c in (body.get("content") or {}).items()},
                },
            }
    schemas = {name: _norm(s) for name, s in (spec.get("components") or {}).get("schemas", {}).items()}
    return {"operations": ops, "schemas": schemas}


# ── compatibility ──────────────────────────────────────────────────────

class _Side:
    def __init__(self, schemas: Dict[str, Any]):
        self.schemas = schemas

    def res(self, s: Any) -> Any:
        seen = 0
        while isinstance(s, dict) and "$ref" in s and seen < 50:
            s = self.schemas.get(s["$ref"].rsplit("/", 1)[-1], {})
            seen += 1
        return s if isinstance(s, dict) else {}

    def types(self, s: Any) -> set:
        s = self.res(s)
        alts = s.get("anyOf") or s.get("oneOf")
        if alts:
            out: set = set()
            for a in alts:
                out |= self.types(a)
            return out
        if "type" in s:
            t = s["type"]
            got = set(t) if isinstance(t, list) else {t}
            return got | ({"number"} if "integer" in got else set())
        return {"any"}

    def object_view(self, s: Any) -> Dict[str, Any]:
        """The object a schema describes, looking through Optional[Model]."""
        s = self.res(s)
        alts = s.get("anyOf") or s.get("oneOf")
        if alts:
            objs = [self.res(a) for a in alts if self.res(a).get("type") != "null"]
            if len(objs) == 1:
                return objs[0]
        return s


def _schema_breaks(where: str, old: Any, new: Any, o: _Side, n: _Side, out: List[str], depth: int = 0) -> None:
    if depth > 12:
        return
    to, tn = o.types(old), n.types(new)
    if "any" not in tn and not to <= tn:
        out.append(f"{where}: type narrowed from {sorted(to)} to {sorted(tn)}")
        return
    so, sn = o.object_view(old), n.object_view(new)
    for k in _UPPER:
        if k in sn and (k not in so or sn[k] < so[k]):
            out.append(f"{where}: {k} tightened from {so.get(k)} to {sn[k]}")
    for k in _LOWER:
        if k in sn and (k not in so or sn[k] > so[k]):
            out.append(f"{where}: {k} tightened from {so.get(k)} to {sn[k]}")
    if "pattern" in sn and sn["pattern"] != so.get("pattern"):
        out.append(f"{where}: pattern added or changed")
    if "enum" in sn and ("enum" not in so or set(map(json.dumps, so["enum"])) - set(map(json.dumps, sn["enum"]))):
        out.append(f"{where}: enum narrowed")
    if "const" in sn and sn.get("const") != so.get("const"):
        out.append(f"{where}: const added or changed")
    if sn.get("additionalProperties") is False and so.get("additionalProperties") is not False:
        out.append(f"{where}: unknown fields now refused")
    po, pn = so.get("properties") or {}, sn.get("properties") or {}
    for name, sub in po.items():
        if name not in pn:
            out.append(f"{where}.{name}: field removed")
        else:
            _schema_breaks(f"{where}.{name}", sub, pn[name], o, n, out, depth + 1)
    for name in sorted(set(sn.get("required") or []) - set(so.get("required") or [])):
        out.append(f"{where}.{name}: newly required")
    if "items" in so and "items" in sn:
        _schema_breaks(f"{where}[]", so["items"], sn["items"], o, n, out, depth + 1)
    ao, an = so.get("additionalProperties"), sn.get("additionalProperties")
    if isinstance(ao, dict) and isinstance(an, dict):
        _schema_breaks(f"{where}{{}}", ao, an, o, n, out, depth + 1)


def operation_breaks(key: str, old: Dict[str, Any], new: Optional[Dict[str, Any]],
                     old_schemas: Dict[str, Any], new_schemas: Dict[str, Any]) -> List[str]:
    """Every way `new` refuses a request `old` accepted ([] = compatible)."""
    if new is None:
        return [f"{key}: operation removed"]
    o, n = _Side(old_schemas), _Side(new_schemas)
    out: List[str] = []
    for name, p in old["params"].items():
        q = new["params"].get(name)
        if q is None:
            out.append(f"{key} {name}: parameter removed")
            continue
        if q["required"] and not p["required"]:
            out.append(f"{key} {name}: parameter newly required")
        _schema_breaks(f"{key} {name}", p["schema"], q["schema"], o, n, out)
    for name, q in new["params"].items():
        if name not in old["params"] and q["required"]:
            out.append(f"{key} {name}: new required parameter")
    bo, bn = old["body"], new["body"]
    if bo is None:
        if bn is not None and bn["required"]:
            out.append(f"{key}: body newly required")
        return out
    if bn is None:
        out.append(f"{key}: body removed")
        return out
    if bn["required"] and not bo["required"]:
        out.append(f"{key}: body newly required")
    for ct, schema in bo["content"].items():
        if ct not in bn["content"]:
            out.append(f"{key}: content type {ct} removed")
        else:
            _schema_breaks(f"{key} body", schema, bn["content"][ct], o, n, out)
    return out


def contract_breaks(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key, op in sorted(old["operations"].items()):
        if key in UNRELEASED:
            continue
        out += operation_breaks(key, op, new["operations"].get(key), old["schemas"], new["schemas"])
    return out


def _json_type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    return {dict: "object", list: "array", str: "string"}.get(type(v), "other")


def response_shapes(client: Any) -> Dict[str, Dict[str, str]]:
    shapes = {}
    for path in RESPONSE_ENDPOINTS:
        r = client.get(path)
        assert r.status_code == 200, (path, r.status_code, r.text[:300])
        body = r.json()
        shapes[path] = {k: _json_type(v) for k, v in sorted(body.items())} if isinstance(body, dict) else {"": _json_type(body)}
    return shapes


def response_breaks(old: Dict[str, Dict[str, str]], new: Dict[str, Dict[str, str]]) -> List[str]:
    out = []
    for path, keys in sorted(old.items()):
        got = new.get(path)
        if got is None:
            out.append(f"GET {path}: no longer answered")
            continue
        for k, t in keys.items():
            if k not in got:
                out.append(f"GET {path}: response key {k!r} removed")
            elif t != got[k] and "null" not in (t, got[k]):
                out.append(f"GET {path}: response key {k!r} changed from {t} to {got[k]}")
    return out


# ── the live app ───────────────────────────────────────────────────────

def _load_snapshot() -> Dict[str, Any]:
    with open(SNAPSHOT, "r", encoding="utf-8") as f:
        return json.load(f)


_CACHE: Dict[str, Any] = {}


def _current() -> Dict[str, Any]:
    if "contract" not in _CACHE:
        import dlp_api_server as srv
        _CACHE["contract"] = contract(copy.deepcopy(srv.app.openapi()))
    return _CACHE["contract"]


_SNAP = _load_snapshot() if os.path.exists(SNAPSHOT) else {"operations": {}, "schemas": {}, "responses": {}}
_OPS = sorted(_SNAP["operations"])


def test_snapshot_covers_the_released_api():
    """SSDF PW.8.2 · CWE-1068: the committed contract snapshot exists and holds every released /api operation."""
    assert len(_SNAP["operations"]) >= 214 and _SNAP["schemas"], "tests/openapi_snapshot.json is missing or empty"
    assert set(_SNAP["responses"]) == set(RESPONSE_ENDPOINTS)
    assert not set(_SNAP["operations"]) & set(UNRELEASED)


@pytest.mark.parametrize("key", _OPS)
def test_operation_still_accepts_what_it_accepted(key):
    """SSDF PW.8.2 · CWE-1068: a released /api operation keeps every parameter, body and field with no narrower type, no new requirement and no tighter limit."""
    cur = _current()
    assert operation_breaks(key, _SNAP["operations"][key], cur["operations"].get(key), _SNAP["schemas"], cur["schemas"]) == []


def test_response_keys_are_kept():
    """SSDF PW.8.2 · CWE-1068: the local read endpoints still answer every top-level key, with the same JSON type."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    got = response_shapes(TestClient(srv.app, base_url="http://127.0.0.1"))
    assert response_breaks(_SNAP["responses"], got) == []


# The checker itself: each kind of break is caught, each addition passes.
def _mutant(fn):
    snap = {"operations": copy.deepcopy(_SNAP["operations"]), "schemas": copy.deepcopy(_SNAP["schemas"])}
    fn(snap)
    return snap


def _first_body_model(snap):
    for key, op in sorted(snap["operations"].items()):
        body = (op["body"] or {}).get("content", {}).get("application/json")
        if body and "$ref" in body:
            name = body["$ref"].rsplit("/", 1)[-1]
            props = snap["schemas"][name].get("properties") or {}
            for field, sub in props.items():
                if sub.get("type") == "string":
                    return key, name, field
    raise AssertionError("no JSON body model with a string field")


def _first_query(snap):
    for key, op in sorted(snap["operations"].items()):
        for name, p in op["params"].items():
            if name.startswith("query:") and not p["required"]:
                return key, name
    raise AssertionError("no optional query parameter")


BREAKS = {
    "operation removed": lambda s: s["operations"].pop(_first_body_model(s)[0]),
    "field removed": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"].pop(_first_body_model(s)[2]),
    "type narrowed": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"][_first_body_model(s)[2]].update(type="integer"),
    "newly required": lambda s: s["schemas"][_first_body_model(s)[1]].setdefault("required", []).append(_first_body_model(s)[2]),
    "tightened": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"][_first_body_model(s)[2]].update(maxLength=1),
    "enum narrowed": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"][_first_body_model(s)[2]].update(enum=["only"]),
    "unknown fields now refused": lambda s: s["schemas"][_first_body_model(s)[1]].update(additionalProperties=False),
    "parameter newly required": lambda s: s["operations"][_first_query(s)[0]]["params"][_first_query(s)[1]].update(required=True),
    "parameter removed": lambda s: s["operations"][_first_query(s)[0]]["params"].pop(_first_query(s)[1]),
    "body newly required": lambda s: s["operations"][_first_body_model(s)[0]]["body"].update(required=True)
    if not s["operations"][_first_body_model(s)[0]]["body"]["required"] else s["operations"][_first_body_model(s)[0]].update(body=None),
}


@pytest.mark.parametrize("kind", sorted(BREAKS))
def test_checker_catches_each_kind_of_break(kind):
    """SSDF PW.8.2 · CWE-1068: the compatibility checker reports each kind of incompatible change (negative control)."""
    assert contract_breaks(_SNAP, _mutant(BREAKS[kind])) != []


ADDITIONS = {
    "new operation": lambda s: s["operations"].__setitem__("POST /api/new-thing", {"params": {}, "body": None}),
    "new optional field": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"].__setitem__("brand_new", {"type": "string"}),
    "wider type": lambda s: s["schemas"][_first_body_model(s)[1]]["properties"].__setitem__(
        _first_body_model(s)[2], {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}),
    "new optional parameter": lambda s: s["operations"][_first_query(s)[0]]["params"].__setitem__(
        "query:brand_new", {"required": False, "schema": {"type": "string"}}),
}


@pytest.mark.parametrize("kind", sorted(ADDITIONS))
def test_checker_allows_additions(kind):
    """SSDF PW.8.2 · CWE-1068: additive changes pass the compatibility checker (positive control)."""
    assert contract_breaks(_SNAP, _mutant(ADDITIONS[kind])) == []


def test_response_checker_catches_a_removed_key_and_allows_a_new_one():
    """SSDF PW.8.2 · CWE-1068: a removed or retyped response key is reported, a new or nullable one is not."""
    old = {"/api/x": {"a": "object", "b": "string", "c": "null"}}
    assert response_breaks(old, {"/api/x": {"a": "object"}}) == ["GET /api/x: response key 'b' removed", "GET /api/x: response key 'c' removed"]
    assert response_breaks(old, {"/api/x": {"a": "array", "b": "string", "c": "string"}}) == ["GET /api/x: response key 'a' changed from object to array"]
    assert response_breaks(old, {"/api/x": {"a": "object", "b": "null", "c": "string", "d": "number"}}) == []


def _write() -> int:
    """Refresh the snapshot with the current contract; refuses while anything is incompatible."""
    os.environ.setdefault("ZSCALER_UI_AUTH", "0")
    sys.path.insert(0, os.path.dirname(HERE))
    import tempfile
    import conftest   # the test suite's isolated stores, so the answers are those of a fresh install
    os.environ.update(conftest.point_stores_at(tempfile.mkdtemp(prefix="openapi-snapshot-")))
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    cur = contract(copy.deepcopy(srv.app.openapi()))
    shapes = response_shapes(TestClient(srv.app, base_url="http://127.0.0.1"))
    problems = contract_breaks(_SNAP, cur) + response_breaks(_SNAP.get("responses") or {}, shapes) if _SNAP["operations"] else []
    if problems:
        print("Not written: incompatible with the snapshot:\n  " + "\n  ".join(problems))
        return 1
    cur["operations"] = {k: v for k, v in cur["operations"].items() if k not in UNRELEASED}
    cur["responses"] = shapes
    with open(SNAPSHOT, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"Wrote {SNAPSHOT}: {len(cur['operations'])} operations, {len(shapes)} response shapes.")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        raise SystemExit(_write())
    print(__doc__)
