"""Regenerate tenant_api_catalogue.json: every published GET endpoint of the installed zscaler-sdk-python.

Reads the SDK's source as text (ast), so it imports nothing from the SDK and never touches the network.
    python tools/build_tenant_api_catalogue.py            # rewrites tenant_api_catalogue.json
    python tools/build_tenant_api_catalogue.py --check    # exit 1 when the committed file differs from the installed SDK
tests/test_tenant_api_map.py runs the same check, so a new SDK release that adds or moves an endpoint fails CI until the
file is regenerated and its new endpoints reviewed."""
import ast, json, re, sys, pathlib, importlib.metadata

def resolve_root():
    import importlib.util
    spec = importlib.util.find_spec("zscaler")
    return pathlib.Path(spec.submodule_search_locations[0])

def const_str(node, env):
    """Evaluate a str expression to a template string; {name} kept for unknown names."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        out = ""
        for v in node.values:
            if isinstance(v, ast.Constant):
                out += str(v.value)
            else:
                out += fval(v.value, env)
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return const_str(node.left, env) + const_str(node.right, env)
    if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "format_url" and node.args:
        return const_str(node.args[0], env)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "upper":
        return const_str(node.func.value, env).upper()
    return "{?}"

def fval(n, env):
    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self":
        return env.get(n.attr, "{" + n.attr + "}")
    if isinstance(n, ast.Name):
        return env.get(n.id, "{" + n.id + "}")
    if isinstance(n, ast.Call):
        return "{?}"
    return "{?}"

# Endpoints never probed even though parameterless: secrets/credentials, bulk downloads/exports,
# or endpoints that need a mandatory query string.
SKIP_RE = re.compile(r"otp|password|secret|api-?key|credential|provurl|provisioningkey|download|export|"
                     r"cloudformationtemplate|/logs\b|/search$|getAppsByType", re.I)

def clean(s):
    return re.sub(r"\s+", "", s)

def build(root):
    cat = {}
    for f in sorted(root.rglob("*.py")):
        rel = f.relative_to(root)
        parts = rel.parts
        if len(parts) < 2 or parts[0] in ("cache", "config", "errors", "exceptions", "ratelimiter") or f.name == "__init__.py":
            continue
        product = parts[0]
        try:
            tree = ast.parse(f.read_text())
        except Exception:
            continue
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            env = {}
            for n in ast.walk(cls):  # class/instance attrs
                if isinstance(n, ast.Assign) and len(n.targets) == 1:
                    t = n.targets[0]
                    name = t.attr if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self" else (t.id if isinstance(t, ast.Name) and n in cls.body else None)
                    if name and isinstance(n.value, (ast.Constant, ast.JoinedStr)) and ("endpoint" in name.lower() or name in ("BASE",) or "path" in name.lower()):
                        s = const_str(n.value, {"customer_id": "{customerId}", "self.customer_id": "{customerId}"})
                        env[name] = s.replace("{customer_id}", "{customerId}")
            for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                method = None; url = None; local = dict(env)
                for st in ast.walk(fn):
                    if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                        nm = st.targets[0].id
                        if nm == "http_method":
                            method = const_str(st.value, local).upper()
                        elif nm == "api_url" and url is None:
                            url = clean(const_str(st.value, local))
                        elif isinstance(st.value, (ast.Constant, ast.JoinedStr)) and nm not in ("api_url",):
                            local[nm] = const_str(st.value, local)
                if method != "GET" or url is None:
                    continue
                params = re.findall(r"\{([^}]*)\}", url)
                params = [p for p in params if p]
                path_params = sorted(set(params) - {"customerId"})
                sensitive = bool(SKIP_RE.search(url))
                probeable = not path_params and "{?}" not in url and not sensitive
                cat.setdefault(product, []).append({
                    "module": ".".join(rel.with_suffix("").parts),
                    "class": cls.name, "method": fn.name,
                    "path": url, "path_params": path_params,
                    "needs_customer_id": "{customerId}" in url,
                    "probeable": probeable,
                    "skip_reason": None if probeable else ("path parameters: " + ", ".join(path_params) if path_params else ("sensitive/bulk/needs-query: skipped by design" if sensitive else "unresolved dynamic path")),
                })
    return cat

def catalogue():
    """The catalogue document for the installed SDK: {sdk, note, products}. One entry per distinct path
    (the other SDK methods that GET it are kept under "also")."""
    cat = build(resolve_root())
    products = {}
    for p, items in cat.items():
        seen = {}
        for it in items:
            key = it["path"]
            if key in seen:
                seen[key].setdefault("also", []).append(f'{it["module"]}.{it["class"]}.{it["method"]}')
            else:
                seen[key] = it
        products[p] = sorted(seen.values(), key=lambda x: x["path"])
    return {"sdk": "zscaler-sdk-python " + importlib.metadata.version("zscaler-sdk-python"),
            "note": "Generated by tools/build_tenant_api_catalogue.py from the SDK source. GET endpoints only.",
            "products": products}


DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / "tenant_api_catalogue.json"


def render(doc):
    return json.dumps(doc, indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    args = sys.argv[1:]
    doc = catalogue()
    if "--check" in args:
        ok = DEFAULT_OUT.is_file() and DEFAULT_OUT.read_text() == render(doc)
        print("tenant_api_catalogue.json matches the installed SDK" if ok else
              "tenant_api_catalogue.json is stale: run python tools/build_tenant_api_catalogue.py")
        sys.exit(0 if ok else 1)
    out = pathlib.Path(args[0]) if args else DEFAULT_OUT
    out.write_text(render(doc))
    for p, items in sorted(doc["products"].items()):
        print(p, sum(i["probeable"] for i in items), "/", len(items))
