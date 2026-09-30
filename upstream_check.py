"""Upstream contract check: is what this app sends still what the Zscaler
SDK, the Terraform provider and Zscaler's API reference expect?

Three upstreams move on their own schedule and each can silently break a
deploy: the Python SDK (`zscaler-sdk-python`, which carries the request
bodies to ZIA), the Terraform provider (`zscaler/zia`, which the hand-off
workspaces are written for) and the ZIA API itself (whose reference lives
at automate.zscaler.com and, machine-readably, in the 2.x SDK's service
definition). This module cross-checks all three against the app's own
configuration — every field the app puts in a dictionary, engine or rule
payload, on every channel, and every attribute the Terraform generator
emits — and reports drift in words.

Offline (no network; runs in `make check` and on every CI push):
  - every payload field the app sends is known to the installed SDK
    (its method signature, its documented keyword arguments, or its
    model's wire fields);
  - every attribute the committed Terraform workspaces carry is one the
    generator meant to emit (a parse sanity check).

Online (the daily GitHub Actions job, `python upstream_check.py`):
  - the installed SDK against PyPI's latest release and prerelease; the
    latest 1.x release is downloaded and the modules the app uses are
    diffed, so "a new version exists" is separated from "a new version
    touches what we call";
  - the 2.x SDK's machine-readable ZIA service definition against the
    app's payloads: is there still an operation for each endpoint the
    app writes to, and is every field the app sends a member of that
    operation's request body;
  - the Terraform provider's pinned constraint against the registry's
    latest, and every attribute the generator emits against the
    provider's current resource docs;
  - whether Zscaler's API reference answers at all (it is a JavaScript
    site; the SDK service definition is its machine-readable form).

Every outbound call goes through zscaler_update_check._safe_get and its
host allowlist. Findings are `drift` (something to act on; the process
exits 1) or `note` (worth knowing, nothing to do).
"""
from __future__ import annotations

import argparse
import glob
import importlib
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))

SDK_PACKAGE = "zscaler-sdk-python"
SDK_IMPORT = "zscaler"
SDK_REPO = "zscaler/zscaler-sdk-python"
PROVIDER = "zscaler/zia"
PROVIDER_REPO = "zscaler/terraform-provider-zia"
API_REFERENCE_URL = "https://automate.zscaler.com/docs/docs/api-reference-and-guides/api-reference/zia"
TERRAFORM_DIR = os.path.join(ROOT, "terraform")

# What the app writes to, per object kind or DLP channel: the ZIA path
# (matched against the 2.x service definition's requestUri), the 1.x SDK
# method it calls, the 1.x model whose wire fields describe the body, and
# the Terraform resource the generator emits for it.
ENDPOINTS: Dict[str, Dict[str, Any]] = {
    "dictionary": {"path": "/dlpDictionaries", "sdk": ("dlp_dictionary", "add_dict"), "model": "dlp_dictionary", "tf": "zia_dlp_dictionaries"},
    "engine": {"path": "/dlpEngines", "sdk": ("dlp_engine", "add_dlp_engine"), "model": "dlp_engine", "tf": "zia_dlp_engines"},
    "web": {"path": "/webDlpRules", "sdk": ("dlp_web_rules", "add_rule"), "model": "dlp_web_rules", "tf": "zia_dlp_web_rules"},
    "endpoint": {"path": "/endPointDlpRules", "sdk": ("endpoint_dlp_rules", "add_rule"), "model": "endpoint_dlp_rules", "tf": "zia_endpoint_dlp_rules"},
    "saas": {"path": "/casbDlpRules", "sdk": ("casb_dlp_rules", "add_rule"), "model": "casb_dlp_rules", "tf": "zia_casb_dlp_rules"},
    "email": {"path": "/emailDlpRules", "sdk": ("outbound_email_dlp_rules", "add_rule"), "model": "outbound_email_dlp_rules", "tf": "zia_outbound_email_dlp"},
    "activation": {"path": "/status/activate", "sdk": ("activate", "activate"), "model": None, "tf": "zia_activation_status"},
}
# The 1.x SDK modules a deploy, a removal and the Terraform hand-off go
# through; a new SDK release that changes none of these cannot change
# what reaches the tenant.
WATCHED_SDK_FILES = (
    "zia/dlp_dictionary.py", "zia/dlp_engine.py", "zia/dlp_web_rules.py", "zia/endpoint_dlp_rules.py",
    "zia/casb_dlp_rules.py", "zia/outbound_email_dlp_rules.py", "zia/saas_security_api.py", "zia/activate.py",
    "zia/dlp_resources.py", "zia/cloudappcontrol.py", "zia/file_type_control_rule.py", "zia/url_filtering.py",
    "zia/ssl_inspection_rules.py", "zia/rule_labels.py", "zia/dlp_templates.py",
    "zia/models/dlp_dictionary.py", "zia/models/dlp_engine.py", "zia/models/dlp_web_rules.py", "zia/models/endpoint_dlp_rules.py",
    "zia/models/casb_dlp_rules.py", "zia/models/outbound_email_dlp_rules.py",
    # ZscalerClient lives in oneapi_client.py; the classic ZIA API client
    # (tenant_auth.build_legacy_sdk_client) in zia/legacy.py.
    "request_executor.py", "utils.py", "oneapi_client.py", "zia/legacy.py",
)
# Wire fields ZIA accepts on a create that the 1.x SDK neither documents
# nor models, proven by real deploys (a clone of a predefined dictionary
# is created with dictTemplateId; the 2.x service definition lists it).
KNOWN_WIRE_EXTRAS: Dict[str, Set[str]] = {"dictionary": {"dictTemplateId"}}
# Keys the app puts in a payload for its own bookkeeping, never sent.
APP_ONLY_KEYS = {"rank_note"}
# The generator's variable-driven attributes that a provider doc lists
# under a block rather than as a flat attribute (dlp_engines { id = [...] }).
TF_BLOCK_ATTRS = {"id"}
# Terraform's own meta-arguments: valid on every resource, never in a
# provider's schema or docs.
TF_META_ARGS = {"count", "for_each", "depends_on", "lifecycle", "provider", "provisioner", "connection"}

Fetch = Callable[[str], Tuple[Optional[str], str]]


# ---------------------------------------------------------------------------
# What the app sends
# ---------------------------------------------------------------------------

def snake_to_camel(name: str) -> str:
    try:
        from zscaler.utils import snake_to_camel as sdk_conv
        return sdk_conv(name)
    except Exception:  # noqa: BLE001 — the SDK is not installed
        if "_" not in name:
            return name
        head, *rest = name.split("_")
        return head + "".join(p.title() for p in rest)


def app_payload_keys() -> Dict[str, Set[str]]:
    """The keyword arguments the app hands the SDK for each kind/channel,
    computed from the shipped packs through the same builders a deploy
    uses (pack_channels.build_payload, dlp_importer.build_dict_kwargs),
    with every channel selected so the extension rules are covered too."""
    import pack_channels as pc
    import pack_deploy as pd
    from dlp_importer import build_dict_kwargs, discover_packs

    packs = [{"id": p["id"], "dir": p["dir"]} for p in discover_packs()]
    targets = {p["id"]: [pc.WEB, pc.ENDPOINT, pc.SAAS, pc.EMAIL] for p in packs}
    merged = pd.merge_sources(pd.load_sources(packs, targets))
    keys: Dict[str, Set[str]] = {k: set() for k in ENDPOINTS}

    keys["dictionary"] |= {"name", "custom_phrase_match_type", "dictionary_type"}
    for item in merged["dictionary"].values():
        d = item["definition"]
        if d.get("predefined_clone"):
            # build_dict_kwargs resolves the template against a tenant; the
            # clone's kwargs are fixed (dlp_importer.build_dict_kwargs).
            keys["dictionary"] |= {"description", "dict_template_id", "custom", "confidence_threshold"}
            if d.get("confidence_level_for_predefined_dict"):
                keys["dictionary"].add("confidence_level_for_predefined_dict")
            if d.get("hierarchical_identifiers"):
                keys["dictionary"].add("hierarchical_identifiers")
            continue
        kwargs, _err = build_dict_kwargs(d, {})
        if kwargs:
            keys["dictionary"] |= set(kwargs)
    keys["engine"] |= {"name", "engine_expression", "custom_dlp_engine", "description"}   # pack_deploy: the engine payload

    resolved = {"tenants": [{"id": 1, "name": "tenant", "app": "BOX"}], "labels": [], "notification_template": None,
                "app_group_ids": [], "uc_template_id": None, "cloud_applications": []}
    for item in merged["policy"].values():
        p = item["definition"]
        ch = pc.channel_of(p)
        if ch not in ("web", "endpoint", "saas", "email"):
            continue
        for use_rank_0 in (False, True):
            try:
                payload = pc.build_payload(ch, p, [1], resolved, use_rank_0=use_rank_0)
            except Exception as e:  # noqa: BLE001 — a pack rule the builder refuses is a pack problem, not a contract one
                keys.setdefault("_errors", set()).add(f"{ch}:{p.get('name')}: {e}")
                continue
            keys[ch] |= {k for k in payload if k not in APP_ONLY_KEYS}
    return keys


# ---------------------------------------------------------------------------
# The installed 1.x SDK
# ---------------------------------------------------------------------------

def installed_sdk_version() -> Optional[str]:
    try:
        import importlib.metadata as md
        return md.version(SDK_PACKAGE)
    except Exception:  # noqa: BLE001
        return None


def installed_sdk_dir() -> Optional[str]:
    try:
        mod = importlib.import_module(SDK_IMPORT)
        return os.path.dirname(os.path.abspath(mod.__file__))
    except Exception:  # noqa: BLE001
        return None


def sdk_method(service: str, method: str) -> Optional[Callable[..., Any]]:
    """The installed SDK's method for a service, found on the API class in
    that service's module (the classes are not named uniformly)."""
    try:
        mod = importlib.import_module(f"{SDK_IMPORT}.zia.{service}")
    except Exception:  # noqa: BLE001
        return None
    for _n, cls in inspect.getmembers(mod, inspect.isclass):
        if cls.__module__ == mod.__name__ and hasattr(cls, method):
            return getattr(cls, method)
    return None


def documented_kwargs(fn: Optional[Callable[..., Any]]) -> Tuple[Set[str], Set[str]]:
    """(positional parameters, keyword arguments named in the docstring)."""
    if fn is None:
        return set(), set()
    sig = {p for p in inspect.signature(fn).parameters if p not in ("self", "kwargs", "args")}
    doc = inspect.getdoc(fn) or ""
    return sig, set(re.findall(r"^\s*([a-z_][a-z0-9_]*)\s*\(", doc, re.M))


def model_wire_fields(model: Optional[str], sdk_dir: Optional[str] = None) -> Set[str]:
    """The camelCase wire fields the installed SDK's model reads from a
    response body (`config["name"]`), the SDK's own picture of the object."""
    if not model:
        return set()
    base = sdk_dir or installed_sdk_dir()
    if not base:
        return set()
    path = os.path.join(base, "zia", "models", f"{model}.py")
    try:
        src = open(path, encoding="utf-8").read()
    except OSError:
        return set()
    return set(re.findall(r'config\["([A-Za-z0-9_]+)"\]', src))


def check_installed_sdk(keys: Dict[str, Set[str]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Every payload key the app sends is known to the installed SDK: the
    method exists, and the key is a positional parameter, a documented
    keyword argument, one of the model's wire fields, or a proven extra."""
    findings: List[Dict[str, Any]] = []
    detail: Dict[str, Any] = {"version": installed_sdk_version(), "endpoints": {}}
    for kind, spec in ENDPOINTS.items():
        service, method = spec["sdk"]
        fn = sdk_method(service, method)
        if fn is None:
            findings.append(_f("drift", "sdk", f"The installed SDK has no {service}.{method}: the app cannot write {kind} objects with it."))
            detail["endpoints"][kind] = {"method": None}
            continue
        sig, documented = documented_kwargs(fn)
        wire = model_wire_fields(spec["model"])
        known_camel = wire | {snake_to_camel(k) for k in sig | documented} | KNOWN_WIRE_EXTRAS.get(kind, set())
        unknown = sorted(k for k in keys.get(kind, set()) if snake_to_camel(k) not in known_camel and k not in sig | documented)
        detail["endpoints"][kind] = {"method": f"{service}.{method}", "sent": sorted(keys.get(kind, set())), "unknown": unknown,
                                     "documented": len(documented), "model_fields": len(wire)}
        if unknown:
            findings.append(_f("drift", "sdk", f"{kind}: the app sends {', '.join(unknown)} to {service}.{method}, which the installed SDK "
                                              f"{detail['version']} neither documents nor models — check the field against Zscaler's API reference."))
    return findings, detail


# ---------------------------------------------------------------------------
# Newer SDK releases: what changed, and the 2.x service definition
# ---------------------------------------------------------------------------

def _version_key(v: str) -> Tuple:
    parts = re.split(r"[.\-]", v)
    out: List[Any] = []
    for p in parts:
        m = re.match(r"(\d+)([a-zA-Z]+)?(\d+)?", p)
        if not m:
            out.append((0, p, 0))
            continue
        out.append((int(m.group(1)), m.group(2) or "~", int(m.group(3) or 0)))   # "~" sorts after letters: a final beats a beta
    return tuple(out)


def is_prerelease(v: str) -> bool:
    return bool(re.search(r"[a-zA-Z]", v))


def pypi_releases(fetch: Fetch) -> Tuple[Optional[Dict[str, Any]], str]:
    text, err = fetch(f"https://pypi.org/pypi/{SDK_PACKAGE}/json")
    if not text:
        return None, err or "no answer"
    try:
        d = json.loads(text)
    except ValueError as e:
        return None, f"PyPI answered something that is not JSON: {e}"
    rel = d.get("releases") or {}
    versions = sorted((v for v in rel if rel[v]), key=_version_key)
    stable = [v for v in versions if not is_prerelease(v)]
    pre = [v for v in versions if is_prerelease(v)]

    def uploaded(v: str) -> Optional[str]:
        files = rel.get(v) or []
        return max((f.get("upload_time_iso_8601") or f.get("upload_time") or "" for f in files), default=None) or None
    return {"latest": stable[-1] if stable else None, "latest_uploaded": uploaded(stable[-1]) if stable else None,
            "latest_prerelease": pre[-1] if pre else None, "prerelease_uploaded": uploaded(pre[-1]) if pre else None,
            "newest_on_index": versions[-1] if versions else None}, ""


def download_sdk(version: str, dest: str) -> Tuple[Optional[str], str]:
    """Download one release's wheel with pip (no dependencies) and unpack
    it under dest/<version>. Returns (directory, error)."""
    out_dir = os.path.join(dest, version)
    dl = os.path.join(dest, "dl")
    os.makedirs(dl, exist_ok=True)
    cp = subprocess.run([sys.executable, "-m", "pip", "download", "--no-deps", "-q", "-d", dl, f"{SDK_PACKAGE}=={version}"],
                        capture_output=True, text=True, timeout=300)
    if cp.returncode != 0:
        return None, (cp.stderr or cp.stdout or "pip download failed")[-400:]
    wheels = [f for f in os.listdir(dl) if f.endswith(".whl") and f"-{version}-" in f]
    if not wheels:
        return None, f"no wheel for {version} in {dl}"
    with zipfile.ZipFile(os.path.join(dl, wheels[0])) as z:
        z.extractall(out_dir)
    return out_dir, ""


def changed_watched_files(installed_dir: str, release_dir: str) -> Tuple[List[str], List[str]]:
    """(changed, missing) among WATCHED_SDK_FILES between the installed
    package and an unpacked release that still ships the `zscaler` package."""
    new_base = os.path.join(release_dir, SDK_IMPORT)
    changed, missing = [], []
    for rel in WATCHED_SDK_FILES:
        a, b = os.path.join(installed_dir, rel), os.path.join(new_base, rel)
        if not os.path.exists(a):
            continue   # not something this install has either
        if not os.path.exists(b):
            missing.append(rel)
            continue
        if open(a, "rb").read() != open(b, "rb").read():
            changed.append(rel)
    return changed, missing


def service_definition(release_dir: str) -> Optional[Dict[str, Any]]:
    """The 2.x SDK's machine-readable ZIA service definition, if the
    unpacked release carries one (zssdk/zscore/data/zia/v1/service-1.json)."""
    hits = glob.glob(os.path.join(release_dir, "**", "zscore", "data", "zia", "v1", "service-*.json"), recursive=True)
    if not hits:
        return None
    try:
        return json.load(open(sorted(hits)[-1], encoding="utf-8"))
    except (OSError, ValueError):
        return None


def operation_for(defn: Dict[str, Any], path: str, method: str = "POST") -> Optional[Tuple[str, Dict[str, Any]]]:
    """The operation whose requestUri ends with `path` for `method`."""
    for name, op in (defn.get("operations") or {}).items():
        http = op.get("http") or {}
        uri = str(http.get("requestUri") or "")
        if str(http.get("method") or "").upper() == method and (uri == path or uri.endswith(path)):
            return name, op
    return None


def body_members(defn: Dict[str, Any], op: Dict[str, Any]) -> Set[str]:
    """The request-body members of an operation: the `body` member's shape
    when the input wraps one, else the input shape's own members."""
    shapes = defn.get("shapes") or {}
    inp = shapes.get((op.get("input") or {}).get("shape") or "", {})
    members = inp.get("members") or {}
    if "body" in members:
        body = shapes.get(members["body"].get("shape") or "", {})
        return set((body.get("members") or {}).keys())
    return set(members.keys())


def check_service_definition(defn: Dict[str, Any], keys: Dict[str, Set[str]], label: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """The app's payloads against a machine-readable service definition:
    an operation must exist for every endpoint the app writes to, and
    every field the app sends must be a member of its request body."""
    findings: List[Dict[str, Any]] = []
    meta = defn.get("metadata") or {}
    detail: Dict[str, Any] = {"api_version": meta.get("apiVersion"), "operations": len(defn.get("operations") or {}), "endpoints": {}}
    for kind, spec in ENDPOINTS.items():
        found = operation_for(defn, spec["path"])
        if not found:
            detail["endpoints"][kind] = {"operation": None}
            findings.append(_f("drift", "sdk", f"{label}: no POST operation for {spec['path']} in its ZIA service definition "
                                              f"(apiVersion {meta.get('apiVersion')}) — the app's {kind} writes have no counterpart there."))
            continue
        name, op = found
        members = body_members(defn, op)
        sent = {snake_to_camel(k) for k in keys.get(kind, set()) if k not in APP_ONLY_KEYS}
        unknown = sorted(sent - members) if members else []
        unused = sorted(members - sent) if members else []
        detail["endpoints"][kind] = {"operation": name, "members": len(members), "unknown": unknown, "unused": len(unused)}
        if unknown:
            findings.append(_f("drift", "sdk", f"{label}: {kind} ({name}) does not list {', '.join(unknown)} in its request body; the app sends them."))
    return findings, detail


# ---------------------------------------------------------------------------
# Terraform: the provider and the generator's attributes
# ---------------------------------------------------------------------------

def pinned_provider_constraint(tf_dir: str = TERRAFORM_DIR) -> Optional[str]:
    for path in sorted(glob.glob(os.path.join(tf_dir, "*", "terraform.tf"))):
        src = open(path, encoding="utf-8").read()
        # The provider's own block, not Terraform's required_version.
        m = re.search(r'source\s*=\s*"' + re.escape(PROVIDER) + r'"\s*version\s*=\s*"([^"]+)"', src)
        if m:
            return m.group(1)
    return None


def constraint_allows(constraint: str, version: str) -> bool:
    """Terraform's pessimistic constraint (~> X.Y allows X.* >= X.Y; ~> X.Y.Z allows X.Y.* >= X.Y.Z), plus >= and =."""
    c = constraint.strip()
    v = [int(x) for x in re.findall(r"\d+", version)[:3]] + [0, 0, 0]
    m = re.match(r"~>\s*(\d+)\.(\d+)(?:\.(\d+))?$", c)
    if m:
        major, minor, patch = int(m.group(1)), int(m.group(2)), m.group(3)
        if patch is None:
            return v[0] == major and (v[1], v[2]) >= (minor, 0)
        return v[0] == major and v[1] == minor and v[2] >= int(patch)
    m = re.match(r">=\s*(\d+)\.(\d+)(?:\.(\d+))?$", c)
    if m:
        return tuple(v[:3]) >= (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
    m = re.match(r"=?\s*(\d+)\.(\d+)\.(\d+)$", c)
    if m:
        return tuple(v[:3]) == (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return True


def registry_latest(fetch: Fetch) -> Tuple[Optional[Dict[str, Any]], str]:
    text, err = fetch(f"https://registry.terraform.io/v1/providers/{PROVIDER}")
    if not text:
        return None, err or "no answer"
    try:
        d = json.loads(text)
    except ValueError as e:
        return None, f"the registry answered something that is not JSON: {e}"
    return {"latest": d.get("version"), "published": d.get("published_at"), "versions": len(d.get("versions") or [])}, ""


def emitted_attributes(tf_dir: str = TERRAFORM_DIR) -> Dict[str, Set[str]]:
    """resource type → the attribute and block names the committed
    workspaces carry for it (a brace-depth walk over every .tf file)."""
    out: Dict[str, Set[str]] = {}
    for path in sorted(glob.glob(os.path.join(tf_dir, "*", "*.tf"))):
        cur: Optional[str] = None
        depth = 0
        for raw in open(path, encoding="utf-8"):
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            m = re.match(r'^resource\s+"([a-z0-9_]+)"\s+"[^"]+"\s*\{', line)
            if m and depth == 0:
                cur, depth = m.group(1), 1
                out.setdefault(cur, set())
                continue
            if cur is None:
                continue
            if depth == 1:
                a = re.match(r"^\s+([a-z0-9_]+)\s*=", line)
                b = re.match(r"^\s+([a-z0-9_]+)\s*\{", line)
                if a:
                    out[cur].add(a.group(1))
                elif b:
                    out[cur].add(b.group(1))
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                cur, depth = None, 0
    return out


def doc_attributes(markdown: str) -> Set[str]:
    """Attribute names a provider resource doc lists (`* \\`name\\` - ...`),
    from its Schema / Argument Reference section on; nested block members
    are included, so a block's `id` counts too."""
    start = 0
    m = re.search(r"^## (Schema|Argument Reference|Arguments Reference)", markdown, re.M)
    if m:
        start = m.start()
    return set(re.findall(r"^\s*[*-] `([a-z0-9_]+)`", markdown[start:], re.M))


def check_terraform_docs(fetch: Fetch, emitted: Dict[str, Set[str]], accepted: Optional[Dict[str, Set[str]]] = None
                         ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """The generator's attributes against the provider's current resource
    docs. The docs lag the schema (zia_dlp_web_rules' doc omits `rank` and
    `protocols`, which the provider accepts), so an attribute the doc does
    not list is drift only when the provider schema (`accepted`, from
    provider_schema) does not accept it either; with no schema in hand it
    is a note."""
    findings: List[Dict[str, Any]] = []
    detail: Dict[str, Any] = {}
    for rtype, attrs in sorted(emitted.items()):
        text, err = fetch(f"https://raw.githubusercontent.com/{PROVIDER_REPO}/master/docs/resources/{rtype}.md")
        if not text:
            detail[rtype] = {"doc": None, "error": err}
            findings.append(_f("note", "terraform", f"{rtype}: the provider doc could not be read ({err}); its attributes were not cross-checked."))
            continue
        documented = doc_attributes(text)
        undocumented = sorted(a for a in attrs if a not in documented and a not in TF_BLOCK_ATTRS and a not in TF_META_ARGS)
        detail[rtype] = {"doc": True, "emitted": sorted(attrs), "documented": len(documented), "undocumented": undocumented}
        if not undocumented:
            continue
        if accepted is not None and rtype in accepted:
            rejected = [a for a in undocumented if a not in accepted[rtype]]
            if rejected:
                findings.append(_f("drift", "terraform", f"{rtype}: the generator emits {', '.join(rejected)}, which neither the provider's schema nor its doc knows."))
            else:
                findings.append(_f("note", "terraform", f"{rtype}: the provider's doc does not list {', '.join(undocumented)}, but its schema accepts them (docs lag)."))
        else:
            findings.append(_f("note", "terraform", f"{rtype}: the provider's doc does not list {', '.join(undocumented)}; no provider schema was available to settle it "
                                                   "(CI's terraform validate is the check that runs against the real provider)."))
    return findings, detail


def provider_schema(workspace: Optional[str] = None, terraform: str = "terraform") -> Tuple[Optional[Dict[str, Set[str]]], str]:
    """resource type → attributes and blocks the installed provider accepts,
    from `terraform providers schema -json` in one committed workspace
    (an init without backend pulls the provider the pin allows). None
    when terraform is not on PATH or the init fails."""
    import shutil
    if not shutil.which(terraform):
        return None, "terraform is not installed"
    ws = workspace or (sorted(glob.glob(os.path.join(TERRAFORM_DIR, "*", "terraform.tf")))[:1] or [""])[0]
    ws = os.path.dirname(ws) if ws.endswith("terraform.tf") else ws
    if not ws or not os.path.isdir(ws):
        return None, "no committed workspace"
    try:
        init = subprocess.run([terraform, f"-chdir={ws}", "init", "-backend=false", "-input=false", "-no-color"],
                              capture_output=True, text=True, timeout=600)
        if init.returncode != 0:
            return None, (init.stderr or init.stdout)[-300:]
        cp = subprocess.run([terraform, f"-chdir={ws}", "providers", "schema", "-json"], capture_output=True, text=True, timeout=300)
        if cp.returncode != 0:
            return None, (cp.stderr or cp.stdout)[-300:]
        data = json.loads(cp.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        return None, str(e)[:300]
    return parse_provider_schema(data), ""


def parse_provider_schema(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """The attribute and block-type names per resource from the JSON that
    `terraform providers schema -json` prints."""
    out: Dict[str, Set[str]] = {}
    for _prov, pdata in (data.get("provider_schemas") or {}).items():
        for rtype, rs in (pdata.get("resource_schemas") or {}).items():
            block = rs.get("block") or {}
            out[rtype] = set((block.get("attributes") or {}).keys()) | set((block.get("block_types") or {}).keys())
    return out


def check_terraform_schema(accepted: Dict[str, Set[str]], emitted: Dict[str, Set[str]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Every attribute the generator emits is one the provider's schema
    accepts — the authoritative form of what CI's terraform validate checks."""
    findings: List[Dict[str, Any]] = []
    detail: Dict[str, Any] = {}
    for rtype, attrs in sorted(emitted.items()):
        if rtype not in accepted:
            findings.append(_f("drift", "terraform", f"{rtype}: the provider's schema has no such resource."))
            detail[rtype] = {"resource": False}
            continue
        unknown = sorted(a for a in attrs if a not in accepted[rtype] and a not in TF_BLOCK_ATTRS and a not in TF_META_ARGS)
        detail[rtype] = {"resource": True, "unknown": unknown, "accepted": len(accepted[rtype])}
        if unknown:
            findings.append(_f("drift", "terraform", f"{rtype}: the generator emits {', '.join(unknown)}, which the provider's schema does not accept."))
    return findings, detail


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------

def _f(level: str, area: str, text: str) -> Dict[str, Any]:
    return {"level": level, "area": area, "text": text}


def default_fetch(url: str) -> Tuple[Optional[str], str]:
    """Allowlisted, short-timeout GET through zscaler_update_check."""
    from zscaler_update_check import _safe_get
    body, status, err = _safe_get(url)
    if err:
        return None, err
    if status != 200:
        return None, f"HTTP {status}"
    try:
        return body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body), ""
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def run(offline: bool = False, fetch: Optional[Fetch] = None, workdir: Optional[str] = None) -> Dict[str, Any]:
    fetch = fetch or default_fetch
    started = time.time()
    report: Dict[str, Any] = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "offline": offline,
                              "findings": [], "sdk": {}, "terraform": {}, "api_reference": {}}
    findings = report["findings"]

    keys = app_payload_keys()
    report["app"] = {"payload_keys": {k: sorted(v) for k, v in keys.items() if not k.startswith("_")}}
    for e in sorted(keys.get("_errors", set())):
        findings.append(_f("note", "app", f"a pack rule could not be turned into a payload: {e}"))

    f, d = check_installed_sdk(keys)
    findings.extend(f)
    report["sdk"]["installed"] = d

    emitted = emitted_attributes()
    report["terraform"]["pinned"] = pinned_provider_constraint()
    report["terraform"]["emitted"] = {k: sorted(v) for k, v in emitted.items()}
    if not emitted:
        findings.append(_f("drift", "terraform", "No committed Terraform workspace could be parsed under terraform/."))

    if not offline:
        # SDK releases on PyPI
        rel, err = pypi_releases(fetch)
        report["sdk"]["pypi"] = rel or {"error": err}
        if not rel:
            findings.append(_f("note", "sdk", f"PyPI could not be read ({err}); the SDK release check did not run."))
        else:
            installed = installed_sdk_version()
            tmp = workdir or tempfile.mkdtemp(prefix="upstream_sdk_")
            if rel["latest"] and installed and _version_key(rel["latest"]) > _version_key(installed):
                rdir, derr = download_sdk(rel["latest"], tmp)
                if not rdir:
                    findings.append(_f("note", "sdk", f"{SDK_PACKAGE} {rel['latest']} is newer than the installed {installed}; it could not be downloaded to diff ({derr})."))
                else:
                    sdk_dir = installed_sdk_dir() or ""
                    changed, missing = changed_watched_files(sdk_dir, rdir)
                    report["sdk"]["latest_diff"] = {"version": rel["latest"], "changed": changed, "missing": missing}
                    if missing:
                        findings.append(_f("drift", "sdk", f"{SDK_PACKAGE} {rel['latest']} no longer ships {', '.join(missing)} — the app's calls would break on it."))
                    elif changed:
                        findings.append(_f("drift", "sdk", f"{SDK_PACKAGE} {rel['latest']} (installed: {installed}) changes modules the app calls: "
                                                          f"{', '.join(changed)}. Read its changelog before re-locking (make lock)."))
                    else:
                        findings.append(_f("note", "sdk", f"{SDK_PACKAGE} {rel['latest']} is newer than the installed {installed} but changes none of the "
                                                         f"{len(WATCHED_SDK_FILES)} modules the app calls."))
            elif rel["latest"] and installed:
                findings.append(_f("note", "sdk", f"{SDK_PACKAGE} {installed} is the latest release."))
            pre = rel.get("latest_prerelease")
            if pre and (not rel["latest"] or _version_key(pre) > _version_key(rel["latest"])):
                rdir, derr = download_sdk(pre, tmp)
                if not rdir:
                    findings.append(_f("note", "sdk", f"{SDK_PACKAGE} prerelease {pre} exists; it could not be downloaded to check ({derr})."))
                else:
                    defn = service_definition(rdir)
                    if defn is None:
                        changed, missing = changed_watched_files(installed_sdk_dir() or "", rdir)
                        report["sdk"]["prerelease"] = {"version": pre, "service_definition": False, "changed": changed, "missing": missing}
                        findings.append(_f("note", "sdk", f"{SDK_PACKAGE} prerelease {pre}: {len(changed)} watched module(s) changed, {len(missing)} missing."))
                    else:
                        f, d = check_service_definition(defn, keys, f"{SDK_PACKAGE} {pre}")
                        d["version"] = pre
                        report["sdk"]["prerelease"] = d
                        findings.extend(f)
                        findings.append(_f("note", "sdk", f"{SDK_PACKAGE} {pre} is a new package layout (zssdk) with a machine-readable ZIA service "
                                                         f"definition (apiVersion {d.get('api_version')}); the checks above ran against it."))
            # The SDK's changelog, newest entry
            text, cerr = fetch(f"https://raw.githubusercontent.com/{SDK_REPO}/master/CHANGELOG.md")
            if text:
                m = re.search(r"^## ([^\n]+)", text, re.M)
                report["sdk"]["changelog_head"] = m.group(1) if m else None

        # Terraform provider
        reg, rerr = registry_latest(fetch)
        report["terraform"]["registry"] = reg or {"error": rerr}
        pinned = report["terraform"]["pinned"]
        if not reg:
            findings.append(_f("note", "terraform", f"The Terraform registry could not be read ({rerr}); the provider version check did not run."))
        elif pinned and reg.get("latest"):
            if constraint_allows(pinned, reg["latest"]):
                findings.append(_f("note", "terraform", f"Provider {PROVIDER} {reg['latest']} is the latest and satisfies the pinned \"{pinned}\"; "
                                                       f"CI's terraform validate already runs against it."))
            else:
                findings.append(_f("drift", "terraform", f"Provider {PROVIDER} {reg['latest']} is outside the pinned \"{pinned}\": the workspaces "
                                                        f"install an older provider than the latest. Test against {reg['latest']} and raise the pin."))
        text, cerr = fetch(f"https://raw.githubusercontent.com/{PROVIDER_REPO}/master/CHANGELOG.md")
        if text:
            m = re.search(r"^## ([^\n]+)", text, re.M)
            report["terraform"]["changelog_head"] = m.group(1) if m else None
        # The provider's real schema when terraform is on PATH (the daily
        # runner), the docs otherwise; the docs alone only produce notes.
        accepted, serr = provider_schema()
        if accepted is None:
            report["terraform"]["schema"] = {"available": False, "error": serr}
            findings.append(_f("note", "terraform", f"The provider schema was not read ({serr}); attributes were checked against the docs only."))
        else:
            f, d = check_terraform_schema(accepted, emitted)
            findings.extend(f)
            report["terraform"]["schema"] = {"available": True, "resources": d}
            if not f:
                findings.append(_f("note", "terraform", f"Every attribute the generator emits is accepted by the provider's schema ({len(accepted)} resource types read)."))
        f, d = check_terraform_docs(fetch, emitted, accepted)
        findings.extend(f)
        report["terraform"]["docs"] = d

        # Zscaler's API reference (a JavaScript site; reachability only)
        text, aerr = fetch(API_REFERENCE_URL)
        report["api_reference"] = {"url": API_REFERENCE_URL, "reachable": bool(text), "error": aerr or None}
        if text:
            findings.append(_f("note", "api", "Zscaler's API reference (automate.zscaler.com) answers; its machine-readable form is the 2.x SDK service definition checked above."))
        else:
            findings.append(_f("note", "api", f"Zscaler's API reference (automate.zscaler.com) could not be fetched ({aerr}); the 2.x SDK service definition stands in for it."))

    report["drift"] = [x for x in findings if x["level"] == "drift"]
    report["ok"] = not report["drift"]
    report["seconds"] = round(time.time() - started, 1)
    return report


def to_markdown(report: Dict[str, Any]) -> str:
    lines = [f"# Upstream contract check — {'OK' if report.get('ok') else 'DRIFT'}",
             "", f"Generated {report.get('generated')} ({'offline' if report.get('offline') else 'online'}).", ""]
    sdk = report.get("sdk") or {}
    inst = (sdk.get("installed") or {}).get("version")
    pypi = sdk.get("pypi") or {}
    tf = report.get("terraform") or {}
    reg = tf.get("registry") or {}
    lines.append("| Upstream | This app | Latest | Newest prerelease |")
    lines.append("|---|---|---|---|")
    lines.append(f"| {SDK_PACKAGE} | {inst or '?'} | {pypi.get('latest') or '?'} ({(pypi.get('latest_uploaded') or '')[:10]}) | {pypi.get('latest_prerelease') or '—'} |")
    lines.append(f"| Terraform provider {PROVIDER} | pinned {tf.get('pinned') or '?'} | {reg.get('latest') or '?'} ({(reg.get('published') or '')[:10]}) | — |")
    api = report.get("api_reference") or {}
    lines.append(f"| Zscaler API reference | — | {'reachable' if api.get('reachable') else 'not fetched'} | — |")
    lines.append("")
    for level, title in (("drift", "Drift — act on these"), ("note", "Notes")):
        items = [f for f in report.get("findings") or [] if f["level"] == level]
        lines.append(f"## {title}" + ("" if items else " — none"))
        for f in items:
            lines.append(f"- **{f['area']}** {f['text']}")
        lines.append("")
    keys = (report.get("app") or {}).get("payload_keys") or {}
    if keys:
        lines.append("## What the app sends (payload fields per endpoint)")
        for k, v in keys.items():
            lines.append(f"- `{k}` ({ENDPOINTS[k]['path']}): {', '.join(v) if v else '—'}")
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Cross-check the SDK, the Terraform provider and Zscaler's API reference against what this app sends.")
    ap.add_argument("--offline", action="store_true", help="no network: the installed SDK and the committed Terraform only")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--md", metavar="FILE", help="write the report as Markdown")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    report = run(offline=args.offline)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
    md = to_markdown(report)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if not args.quiet:
        print(md)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
