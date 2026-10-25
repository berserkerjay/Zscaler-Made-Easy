"""
Policy pack library: the packs the app ships with plus the ones an operator
adds from the Advanced settings tab.

An uploaded pack arrives as one or more files (JSON, Terraform `.tf`, or a
ZIP of either) and becomes an ordinary pack directory under `user_packs/`,
so Deploy Policy Packs, the Data Flow Map, the Terraform hand-off and the
detection validator all see it without knowing where it came from.

Accepted layouts
----------------
* one JSON "bundle": {"name", "description", "dictionaries": [...],
  "engines": [...], "policies": [...], "app_groups": [...]}
* the three pack files: dlp_dictionaries.json, dlp_engines.json,
  dlp_policies.json (plus optional pack.json and
  endpoint_application_groups.json), named or recognised by content
* Terraform for the zscaler/zia provider: resource "zia_dlp_dictionaries",
  "zia_dlp_engines", the DLP and containment rule resources, and the
  data lookups that name predefined dictionaries and engines. The
  workspace this app exports round-trips; a workspace exported from a
  tenant with zscaler-terraformer works for everything that references
  objects by name (tenant ids inside engine expressions cannot travel
  between tenants and are reported).
* a ZIP of any of the above (a pack directory, for example)
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import zipfile

from native_zscaler import convert_parts, is_native, kind_of
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pack_channels as pc
import pack_ops as ops
from dlp_importer import PACKS_ROOT, template_candidates

USER_PACKS_DIRNAME = "user_packs"
_SLUG_RE = re.compile(r"[^a-z0-9_]+")
MAX_UPLOAD_BYTES = 8 * 1024 * 1024


def user_packs_dir(root: Optional[str] = None) -> str:
    """Where uploaded packs live. `DLP_CHECK_USER_PACKS` overrides the
    default `<app>/user_packs` (a mounted volume in the container) for the
    app's own root, however it is passed: the server and pack discovery
    pass PACKS_ROOT explicitly, and in the container that folder is
    read-only, so ignoring the setting there hid and refused every upload.
    Another root (a test's scratch folder) keeps its own user_packs."""
    own_root = root is None or os.path.realpath(root) == os.path.realpath(PACKS_ROOT)
    if own_root and os.environ.get("DLP_CHECK_USER_PACKS"):
        return os.path.abspath(os.environ["DLP_CHECK_USER_PACKS"])
    return os.path.join(root or PACKS_ROOT, USER_PACKS_DIRNAME)


def slugify(name: str) -> str:
    return _SLUG_RE.sub("_", (name or "").lower().strip()).strip("_")[:64]


def pack_slug(name: str) -> str:
    """The id a pack gets from its name: slugify(name), or, for a name with
    no Latin letters or digits ("名前", "..."), 'pack_' and a short hash of
    the name, so such a pack still gets an id and the same name always the
    same one. Empty only for an empty name."""
    slug = slugify(name)
    if slug or not (name or "").strip():
        return slug
    return "pack_" + hashlib.sha1(name.strip().encode("utf-8")).hexdigest()[:10]


# ---------------------------------------------------------------------------
# HCL (Terraform) reader: enough of the language for provider resources.
# ---------------------------------------------------------------------------

class Ref:
    """An unquoted expression (a reference, a function call, arithmetic)."""

    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text.strip()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Ref({self.text!r})"


class HCLError(ValueError):
    pass


_TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r]+)
  | (?P<nl>\n)
  | (?P<comment>\#[^\n]*|//[^\n]*|/\*.*?\*/)
  | (?P<heredoc><<-?(?P<hd>[A-Za-z_][A-Za-z0-9_]*)\n(?P<hdbody>.*?)\n[ \t]*(?P=hd)(?=\n|$))
  | (?P<string>"(?:\\.|\$\$\{|%%\{|[^"\\])*")
  | (?P<number>-?\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_\-]*(?:\.[A-Za-z_*][A-Za-z0-9_\-*]*|\[[^\]]*\])*)
  | (?P<punct>==|!=|<=|>=|&&|\|\||[{}\[\]()=,:?+\-*/%!<>.])
""", re.S | re.X)


def _unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}.get(n, "\\" + n))
            i += 2
            continue
        if c == "$" and s[i:i + 3] == "$${":
            out.append("${"); i += 3; continue
        if c == "%" and s[i:i + 3] == "%%{":
            out.append("%{"); i += 3; continue
        out.append(c)
        i += 1
    return "".join(out)


def _tokenize(text: str) -> List[Tuple[str, Any]]:
    pos, out = 0, []
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise HCLError(f"unexpected character {text[pos]!r} at offset {pos}")
        pos = m.end()
        if m.group("ws") is not None or m.group("comment") is not None:
            continue
        if m.group("heredoc") is not None:
            out.append(("string", m.group("hdbody")))
        elif m.group("string") is not None:
            out.append(("string", _unescape(m.group()[1:-1])))
        elif m.group("number") is not None:
            v = m.group()
            out.append(("number", float(v) if "." in v else int(v)))
        elif m.group("nl") is not None:
            out.append(("nl", None))
        elif m.group("ident") is not None:
            out.append(("ident", m.group()))
        else:
            out.append(("punct", m.group()))
    return out


class _Parser:
    def __init__(self, tokens: List[Tuple[str, Any]]):
        self.t = tokens
        self.i = 0

    def peek(self, k: int = 0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else ("eof", None)

    def next(self):
        tok = self.peek()
        self.i += 1
        return tok

    def skip_nl(self):
        while self.peek()[0] == "nl":
            self.i += 1

    def body(self, closer: Optional[str] = "}") -> Dict[str, Any]:
        """Attributes and blocks until `closer` (or EOF at top level).
        Repeated keys become lists; blocks are dicts carrying `_labels`."""
        out: Dict[str, Any] = {}
        while True:
            self.skip_nl()
            kind, val = self.peek()
            if kind == "eof":
                if closer:
                    raise HCLError("unexpected end of file: a block is not closed")
                return out
            if closer and kind == "punct" and val == closer:
                self.i += 1
                return out
            if kind == "punct" and val == ",":
                self.i += 1
                continue
            if kind not in ("ident", "string"):
                raise HCLError(f"expected an attribute or block name, found {val!r}")
            self.i += 1
            key = str(val)
            kind2, val2 = self.peek()
            if kind2 == "punct" and val2 in ("=", ":"):
                self.i += 1
                self.skip_nl()
                value = self.expr()
            else:
                labels = []
                while self.peek()[0] == "string":
                    labels.append(self.next()[1])
                k3, v3 = self.peek()
                if not (k3 == "punct" and v3 == "{"):
                    raise HCLError(f"expected '{{' after block {key!r}")
                self.i += 1
                value = self.body("}")
                value["_labels"] = labels
            if isinstance(value, dict) and "_labels" in value:
                existing = out.get(key)
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    out[key] = [value]
            else:
                out[key] = value

    def expr(self):
        kind, val = self.peek()
        if kind == "string":
            self.i += 1
            return self._maybe_binary(val)
        if kind == "number":
            self.i += 1
            return self._maybe_binary(val)
        if kind == "punct" and val == "[":
            self.i += 1
            items = []
            while True:
                self.skip_nl()
                k, v = self.peek()
                if k == "punct" and v == "]":
                    self.i += 1
                    break
                if k == "punct" and v == ",":
                    self.i += 1
                    continue
                if k == "ident" and v == "for":
                    return self._raw_until_closer("]", "[")
                items.append(self.expr())
            return self._maybe_binary(items)
        if kind == "punct" and val == "{":
            self.i += 1
            j = self.i
            while self.peek(j - self.i)[0] == "nl":
                j += 1
            if self.peek(j - self.i) == ("ident", "for"):
                return self._raw_until_closer("}", "{")
            return self.body("}")
        if kind == "ident" and val in ("true", "false", "null"):
            self.i += 1
            return {"true": True, "false": False, "null": None}[val]
        if kind == "eof":
            raise HCLError("unexpected end of file")
        return self._raw_expr()

    def _maybe_binary(self, value):
        """`"a" + "b"`, `1 + 2`, `[..] : ..` etc. become a Ref carrying the source."""
        k, v = self.peek()
        if k == "punct" and v in ("+", "-", "*", "/", "?", "==", "!=", "<", ">", "<=", ">=", "&&", "||"):
            rest = self._raw_expr()
            return Ref(f"{json.dumps(value) if isinstance(value, str) else value} {rest.text}")
        return value

    def _raw_expr(self) -> Ref:
        """Collect an unquoted expression up to the end of the line, a comma
        or a closer at depth 0."""
        parts: List[str] = []
        depth = 0
        while True:
            k, v = self.peek()
            if k == "eof":
                break
            if k == "nl":
                if depth == 0:
                    break
                self.i += 1
                continue
            if k == "punct":
                if v in ("(", "[", "{"):
                    depth += 1
                elif v in (")", "]", "}"):
                    if depth == 0:
                        break
                    depth -= 1
                elif v == "," and depth == 0:
                    break
            self.i += 1
            parts.append(json.dumps(v) if k == "string" else str(v))
        return Ref(" ".join(parts))

    def _raw_until_closer(self, closer: str, opener: str) -> Ref:
        parts: List[str] = [opener]
        depth = 1
        while depth:
            k, v = self.next()
            if k == "eof":
                raise HCLError("unterminated expression")
            if k == "punct" and v == opener:
                depth += 1
            elif k == "punct" and v == closer:
                depth -= 1
            if k != "nl":
                parts.append(json.dumps(v) if k == "string" else str(v))
        return Ref(" ".join(parts))


def parse_hcl(text: str) -> Dict[str, Any]:
    """Parse a Terraform file into {"resource": [...], "data": [...], ...};
    each block is a dict of attributes plus `_labels`."""
    return _Parser(_tokenize(text)).body(None)


def _blocks(doc: Dict[str, Any], kind: str) -> List[Dict[str, Any]]:
    v = doc.get(kind)
    if not v:
        return []
    return v if isinstance(v, list) else [v]


# ---------------------------------------------------------------------------
# Terraform -> pack objects
# ---------------------------------------------------------------------------

RULE_CHANNEL_BY_RESOURCE = {
    "zia_dlp_web_rules": pc.WEB,
    "zia_endpoint_dlp_rules": pc.ENDPOINT,
    "zia_endpoint_dlp_sub_rules": pc.ENDPOINT,
    "zia_casb_dlp_rules": pc.SAAS,
    "zia_outbound_email_dlp": pc.EMAIL,
    "zia_cloud_app_control_rule": pc.CLOUD_APP,
    "zia_file_type_control_rules": pc.FILE_TYPE,
    "zia_url_filtering_rules": pc.URL,
    "zia_ssl_inspection_rules": pc.SSL,
}
_SKIP_RULE_ATTRS = {"order", "rank", "lifecycle", "depends_on", "provider", "_labels", "timeouts"}
# "[<assessor> pack <id> v1] Terraform-managed." ("[DLP-Check ...]" when no assessor was named).
_PROVENANCE_RE = re.compile(r"\s*\[[^\[\]\r\n]{1,60}? (?:baseline|pack) [^\]]*\] Terraform-managed\.?\s*$")
_ID_REF_RE = re.compile(r"D\$\{([^}]+)\}\.S")
_NUMERIC_REF_RE = re.compile(r"\bD(\d+)\.S\b")


def _strip_provenance(s: Any) -> str:
    return _PROVENANCE_RE.sub("", str(s or "")).strip()


def _plain(v: Any) -> Any:
    """Scalars and lists of scalars pass through; references are dropped;
    a single unlabelled nested block becomes a plain object."""
    if isinstance(v, Ref):
        return None
    if isinstance(v, list):
        if len(v) == 1 and isinstance(v[0], dict) and v[0].get("_labels") == []:
            return _plain(v[0])
        out = [_plain(x) for x in v]
        return [x for x in out if x is not None]
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items() if k != "_labels" and not isinstance(x, Ref)}
    return v


def _ref_list(v: Any, labels: Dict[Tuple[str, str], str], warnings: List[str], owner: str, what: str) -> List[str]:
    """Names for a list of references. The zscaler/zia provider writes
    engines and application groups either as a list attribute or as a
    block holding an `id` / `group_id` list; both are read."""
    items: List[Any] = []
    if isinstance(v, list) and v and isinstance(v[0], dict) and "_labels" in v[0]:
        for blk in v:
            for key in ("id", "group_id"):
                inner = blk.get(key)
                if isinstance(inner, list):
                    items.extend(inner)
                elif inner is not None:
                    items.append(inner)
    elif isinstance(v, list):
        items = v
    elif v is not None:
        items = [v]
    out: List[str] = []
    for ref in items:
        n = _ref_name(ref, labels)
        if n:
            out.append(n)
        elif isinstance(ref, (int, float)) and not isinstance(ref, bool):
            warnings.append(f"{owner}: references {what} id {int(ref)} from another tenant; name the {what} instead")
        elif isinstance(ref, str):
            out.append(ref)
    return out


_VERB_LIST_RE = re.compile(r"for v in \[ ((?:\"[^\"]*\" ?,? ?)*) \] : endswith")
_DEFAULT_RE = re.compile(r'startswith \( a , "([A-Z]+)_" \)')


def _actions_by_verb(ref: Ref) -> Optional[Dict[str, str]]:
    """Reverse the Cloud App Control `actions` comprehension this app
    exports into the pack's {"UPLOAD": "BLOCK", "*": "ALLOW"} form."""
    lists = [[s.strip('" ') for s in m.group(1).split(",") if s.strip('" ')] for m in _VERB_LIST_RE.finditer(ref.text)]
    if not lists:
        return None
    out: Dict[str, str] = {}
    for verb in lists[0]:
        out[verb.lstrip("_")] = "BLOCK"
    if len(lists) > 1:
        for verb in lists[1]:
            out[verb.lstrip("_")] = "ALLOW"
    defaults = _DEFAULT_RE.findall(ref.text)
    out["*"] = defaults[-1] if defaults else "ALLOW"
    return out


def _ref_name(ref: Any, labels: Dict[Tuple[str, str], str]) -> Optional[str]:
    """`zia_dlp_engines.foo.id` / `data.zia_dlp_dictionaries.bar.id` -> the
    object's name, using the labels seen in the same upload."""
    if not isinstance(ref, Ref):
        return None
    # tostring(x.y.group_id) and friends: look through the wrapper.
    m = re.search(r"(?<![A-Za-z0-9_.])(data\.)?([a-z_]+)\.([A-Za-z0-9_\-]+)\.(id|rule_id|group_id|name)(?![A-Za-z0-9_.])", ref.text)
    if not m:
        return None
    return labels.get((("data." if m.group(1) else "") + m.group(2), m.group(3)))


def pack_from_terraform(files: Dict[str, str]) -> Tuple[Dict[str, Any], List[str]]:
    """Read every .tf file into pack objects. Returns (pack, warnings)."""
    warnings: List[str] = []
    docs = []
    for name, text in files.items():
        try:
            docs.append((name, parse_hcl(text)))
        except HCLError as e:
            raise ValueError(f"{name}: {e}") from e

    labels: Dict[Tuple[str, str], str] = {}         # (resource type or data.type, label) -> name
    app_class_lookups: Dict[str, List[str]] = {}    # data.zia_cloud_applications label -> app classes
    resources: List[Tuple[str, str, Dict[str, Any], str]] = []
    for fname, doc in docs:
        for blk in _blocks(doc, "data"):
            lab = blk.get("_labels") or []
            if len(lab) >= 2:
                if isinstance(blk.get("name"), str):
                    labels[("data." + lab[0], lab[1])] = blk["name"]
                if lab[0] == "zia_cloud_applications":
                    app_class_lookups[lab[1]] = [str(c) for c in (_plain(blk.get("app_class")) or [])]
        for blk in _blocks(doc, "resource"):
            lab = blk.get("_labels") or []
            if len(lab) >= 2:
                if isinstance(blk.get("name"), str):
                    labels[(lab[0], lab[1])] = blk["name"]
                resources.append((lab[0], lab[1], blk, fname))

    dicts: List[Dict[str, Any]] = []
    engines: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []
    app_groups: List[Dict[str, Any]] = []
    ignored: Dict[str, set] = {}
    unsupported: Dict[str, int] = {}

    for rtype, label, blk, fname in resources:
        if rtype == "zia_dlp_dictionaries":
            d: Dict[str, Any] = {"name": blk.get("name"), "description": _strip_provenance(blk.get("description"))}
            mt = blk.get("custom_phrase_match_type")
            if isinstance(mt, str):
                d["custom_phrase_match_type"] = mt
            tpl_id, tpl_name = blk.get("dict_template_id"), None
            if isinstance(tpl_id, Ref):
                tpl_name = _ref_name(tpl_id, labels)
                tpl_id = None
            if tpl_id or tpl_name:
                d["predefined_clone"] = True
                if tpl_name:
                    d["dict_template_name"] = tpl_name
                if tpl_id:
                    d["dict_template_id"] = int(tpl_id)
                    warnings.append(f"{d['name']}: clones predefined dictionary id {int(tpl_id)}; ids differ between tenants, name the template instead")
            for k in ("confidence_level_for_predefined_dict", "confidence_threshold"):
                if isinstance(blk.get(k), str):
                    d[k] = blk[k]
            if blk.get("proximity"):
                d["proximity"] = int(blk["proximity"])
            for k in ("include_bin_numbers", "include_ssn_numbers"):
                if blk.get(k) is True:
                    d[k] = True
            if isinstance(blk.get("hierarchical_identifiers"), list):
                d["hierarchical_identifiers"] = _plain(blk["hierarchical_identifiers"])
            d["patterns"] = [{"action": p.get("action", "PATTERN_COUNT_TYPE_ALL"), "pattern": p.get("pattern", "")}
                             for p in _blocks(blk, "patterns") if isinstance(p, dict)]
            d["phrases"] = [{"action": p.get("action", "PHRASE_COUNT_TYPE_ALL"), "phrase": p.get("phrase", "")}
                            for p in _blocks(blk, "phrases") if isinstance(p, dict)]
            dicts.append(d)
        elif rtype == "zia_dlp_engines":
            expr = blk.get("engine_expression")
            if not isinstance(expr, str):
                warnings.append(f"{blk.get('name') or label}: engine_expression is not a plain string; skipped")
                continue

            def _sub(m):
                name = _ref_name(Ref(m.group(1)), labels)
                return f"D:{name}" if name else m.group(0)
            expr = _ID_REF_RE.sub(_sub, expr)
            for m in _NUMERIC_REF_RE.finditer(expr):
                warnings.append(f"{blk.get('name') or label}: expression references dictionary id {m.group(1)} from another tenant; replace it with D:<dictionary name>")
            engines.append({"name": blk.get("name"), "description": _strip_provenance(blk.get("description")), "expression": expr})
        elif rtype == "zia_endpoint_dlp_application_group":
            app_groups.append({"name": blk.get("name"), "description": _strip_provenance(blk.get("description")),
                               "resources": _plain(blk.get("resources")) or []})
        elif rtype in RULE_CHANNEL_BY_RESOURCE:
            channel = RULE_CHANNEL_BY_RESOURCE[rtype]
            p: Dict[str, Any] = {"name": blk.get("name"), "description": _strip_provenance(blk.get("description")), "channel": channel}
            if rtype == "zia_endpoint_dlp_sub_rules":
                parent = _ref_name(blk.get("parent_rule"), labels)
                if parent:
                    p["parent_rule"] = parent
            owner = str(p["name"] or label)
            eng_names = _ref_list(blk.get("dlp_engines", blk.get("engines")), labels, warnings, owner, "engine")
            if eng_names or channel in (pc.WEB, pc.ENDPOINT, pc.SAAS, pc.EMAIL):
                p["engines"] = eng_names
            groups = _ref_list(blk.get("end_point_application_groups", blk.get("endpoint_application_groups")), labels, warnings, owner, "application group")
            if groups:
                p["endpoint_application_groups"] = groups
            for k, v in blk.items():
                if k in _SKIP_RULE_ATTRS or k in ("name", "description", "dlp_engines", "engines", "parent_rule",
                                                  "end_point_application_groups", "endpoint_application_groups", "uc_template_id"):
                    continue
                if k == "type" and channel == pc.SAAS:
                    p["saas_type"] = _plain(v)
                    continue
                if isinstance(v, Ref):
                    # cloud_applications built from data.zia_cloud_applications lookups -> app classes
                    used = [lbl for lbl in app_class_lookups if f"data.zia_cloud_applications.{lbl}." in v.text]
                    if k in ("cloud_applications", "applications") and used:
                        p["cloud_app_classes"] = sorted({c for lbl in used for c in app_class_lookups[lbl]})
                        continue
                    if k == "actions" and channel == pc.CLOUD_APP:
                        verbs = _actions_by_verb(v)
                        if verbs:
                            p["actions_by_verb"] = verbs
                            continue
                    ignored.setdefault(rtype, set()).add(k)
                    continue
                if isinstance(v, list) and v and isinstance(v[0], dict) and "_labels" in v[0]:
                    # nested blocks such as ssl `action { ... }`
                    if k == "action" and channel == pc.SSL:
                        p["action"] = _plain(v)
                    else:
                        ignored.setdefault(rtype, set()).add(k)
                    continue
                p[k] = _plain(v)
            policies.append(p)
        else:
            unsupported[rtype] = unsupported.get(rtype, 0) + 1

    # Endpoint sub-rules live inside their parent in a pack.
    parents = {p["name"]: p for p in policies if not p.get("parent_rule")}
    nested: List[Dict[str, Any]] = []
    for p in policies:
        parent = p.pop("parent_rule", None)
        if parent and parent in parents:
            p.pop("channel", None)
            parents[parent].setdefault("sub_rules", []).append(p)
        elif parent:
            warnings.append(f"{p['name']}: parent rule '{parent}' is not in the upload; kept as a top-level rule")
            nested.append(p)
        else:
            nested.append(p)
    policies = nested

    for rtype, keys in ignored.items():
        warnings.append(f"{rtype}: computed attributes left for the tenant to decide ({', '.join(sorted(keys))})")
    for rtype, n in unsupported.items():
        warnings.append(f"{n} {rtype} resource(s) are not part of a policy pack and were skipped")
    return {"dictionaries": dicts, "engines": engines, "policies": policies, "app_groups": app_groups}, warnings


# ---------------------------------------------------------------------------
# Upload assembly: files -> pack
# ---------------------------------------------------------------------------

def _looks_like(items: List[Any]) -> Optional[str]:
    if not items or not all(isinstance(x, dict) for x in items):
        return None
    keys = set().union(*(x.keys() for x in items))
    native = {kind_of(x) for x in items if is_native(x)}
    if len(native) == 1 and None not in native:
        return next(iter(native))
    if "expression" in keys:
        return "engines"
    if keys & {"patterns", "phrases", "predefined_clone", "dict_template_name"}:
        return "dictionaries"
    if keys & {"engines", "channel", "action", "state", "protocols", "url_categories", "filtering_action"}:
        return "policies"
    if "resources" in keys:
        return "app_groups"
    return None


def _decode(entry: Dict[str, Any]) -> bytes:
    content = entry.get("content") or ""
    if entry.get("encoding") == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8") if isinstance(content, str) else bytes(content)


def _expand(files: List[Dict[str, Any]]) -> List[Tuple[str, bytes]]:
    """Flatten ZIPs into (name, bytes); skip directories and junk."""
    out: List[Tuple[str, bytes]] = []
    total = 0
    for f in files:
        name = os.path.basename(str(f.get("name") or "upload"))
        data = _decode(f)
        total += len(data)
        if total > MAX_UPLOAD_BYTES:
            raise ValueError(f"upload is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
        if name.lower().endswith(".zip") or data[:2] == b"PK":
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile as e:
                raise ValueError(f"{name}: not a valid ZIP file") from e
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_UPLOAD_BYTES:
                    continue
                base = os.path.basename(info.filename)
                if not base or base.startswith(".") or "__MACOSX" in info.filename:
                    continue
                if base.lower().endswith((".json", ".tf", ".md", ".txt", ".tfvars")):
                    total += info.file_size
                    if total > MAX_UPLOAD_BYTES:
                        raise ValueError("ZIP contents are larger than the upload limit")
                    out.append((info.filename, zf.read(info)))
        else:
            out.append((name, data))
    return out


def assemble_pack(files: List[Dict[str, Any]], *, pack_name: str = "", description: str = "") -> Dict[str, Any]:
    """Turn uploaded files into a pack dict:
    {"meta": {...}, "dictionaries", "engines", "policies", "app_groups",
     "format": "json"|"terraform"|"mixed", "sources": [...], "warnings": [...]}"""
    entries = _expand(files)
    if not entries:
        raise ValueError("no files were uploaded")
    meta: Dict[str, Any] = {}
    parts: Dict[str, List[Dict[str, Any]]] = {"dictionaries": [], "engines": [], "policies": [], "app_groups": []}
    tf_files: Dict[str, str] = {}
    warnings: List[str] = []
    sources: List[str] = []
    formats = set()
    native_hints: Dict[str, List[str]] = {}
    for path, data in entries:
        base = os.path.basename(path)
        low = base.lower()
        if low.endswith(".tf"):
            tf_files[path] = data.decode("utf-8", "replace")
            sources.append(path)
            formats.add("terraform")
            continue
        if not low.endswith(".json"):
            continue   # README, tfvars examples and the like
        try:
            obj = json.loads(data.decode("utf-8-sig"))
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"{base}: not valid JSON ({e})") from e
        sources.append(path)
        formats.add("json")
        if low == "pack.json" and isinstance(obj, dict) and not any(k in obj for k in ("dictionaries", "engines", "policies")):
            meta.update({k: v for k, v in obj.items() if k not in ("dir", "id")})
            continue
        if isinstance(obj, dict) and any(k in obj for k in ("dictionaries", "engines", "policies")):
            for k in parts:
                v = obj.get(k) or obj.get({"app_groups": "endpoint_application_groups"}.get(k, k)) or []
                if not isinstance(v, list):
                    raise ValueError(f"{base}: '{k}' must be a list")
                parts[k].extend(v)
            for k in ("name", "version", "description", "references", "baseline"):
                if obj.get(k) is not None and k not in meta:
                    meta[k] = obj[k]
            continue
        if isinstance(obj, list):
            kind = None
            for key, needle in (("dictionaries", "dictionar"), ("engines", "engine"), ("policies", "polic"), ("policies", "rule"), ("app_groups", "application_group")):
                if needle in low:
                    kind = key
                    break
            kind = kind or _looks_like(obj)
            if kind == "policies":
                hint = "endpoint" if "endpoint" in low else ("saas" if ("casb" in low or "saas" in low) else ("email" if "email" in low else ""))
                if hint:
                    native_hints.setdefault(hint, []).extend(str(x.get("name")) for x in obj if isinstance(x, dict) and x.get("name"))
            if not kind:
                if not obj:
                    continue
                raise ValueError(f"{base}: cannot tell whether this list holds dictionaries, engines or rules; name the file dlp_dictionaries.json, dlp_engines.json or dlp_policies.json")
            parts[kind].extend(obj)
            continue
        raise ValueError(f"{base}: expected a pack bundle object or a list of dictionaries / engines / rules")
    if tf_files:
        tf_pack, tf_warn = pack_from_terraform(tf_files)
        warnings.extend(tf_warn)
        for k in parts:
            parts[k].extend(tf_pack.get(k) or [])
    # Native Zscaler API exports (dlpDictionaries, dlpEngines, webDlpRules,
    # endpointDlpRules, casbDlpRules, emailDlpRules) are rewritten into the
    # pack schema: ids become names, D<id>.S becomes D:<name>.
    native_counts = {}
    if any(is_native(x) for part in parts.values() for x in part):
        parts, nwarn, native_counts = convert_parts(parts, hints=native_hints)
        warnings.extend(nwarn)
        formats.discard("json")
        formats.add("zscaler")
    if not any(parts.values()):
        raise ValueError("no dictionaries, engines or rules were found in the upload")
    # Proximity is a number of characters. Uploaded packs are untrusted, so
    # anything else is refused here rather than carried to the preview page.
    for d in parts["dictionaries"]:
        if isinstance(d, dict) and d.get("proximity") not in (None, ""):
            try:
                if isinstance(d["proximity"], bool):
                    raise TypeError
                d["proximity"] = int(d["proximity"])
            except (TypeError, ValueError):
                raise ValueError(f"dictionary '{str(d.get('name') or '')[:80]}': proximity must be a whole number of characters") from None
    name = (pack_name or meta.get("name") or "").strip()
    if not name:
        first = sources[0] if sources else "uploaded pack"
        name = os.path.splitext(os.path.basename(first))[0].replace("_", " ").replace("-", " ").strip().title() or "Uploaded Pack"
        if name.lower() in ("dlp dictionaries", "dlp engines", "dlp policies", "dictionaries", "engines", "rules", "main"):
            name = "Uploaded Pack"
    meta["name"] = name
    if description.strip():
        meta["description"] = description.strip()
    meta.setdefault("description", f"Uploaded pack: {name}")
    meta.setdefault("version", "1.0")
    fmt = "mixed" if len(formats) > 1 else (next(iter(formats)) if formats else "json")
    return {"meta": meta, "format": fmt, "sources": sources, "warnings": warnings, "native": native_counts, **parts}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_REF_NAME_RE = re.compile(r"D:(.+?)(?=\s*(?:[<>=]|\bAND\b|\bOR\b|\)\s*(?:AND\b|OR\b|\)|$)|$))")   # find_refs is the paren-aware reader


def _without_known_refs(expr: str, names: Any) -> Tuple[str, List[str]]:
    """(the expression with every D:<name> reference to one of `names` taken
    out, the names found). Longest names first, as the deploy resolves
    them, and only where the name ends as a reference ends."""
    found: List[str] = []
    for name in sorted(names, key=len, reverse=True):
        pat = re.compile(re.escape(f"D:{name}") + r"(?=\s*(?:[<>=+)]|AND\b|OR\b|$))")
        if pat.search(expr):
            expr = pat.sub("\x00", expr)
            found.append(name)
    return expr, found


def validate_pack(pack: Dict[str, Any]) -> Dict[str, Any]:
    """Problems block the upload; warnings are shown and allowed."""
    problems: List[str] = []
    warnings: List[str] = list(pack.get("warnings") or [])
    dicts = pack.get("dictionaries") or []
    engines = pack.get("engines") or []
    policies = pack.get("policies") or []
    groups = pack.get("app_groups") or []

    seen: set = set()
    for d in dicts:
        if not isinstance(d, dict) or not str(d.get("name") or "").strip():
            problems.append("a dictionary has no name")
            continue
        n = d["name"]
        if n in seen:
            problems.append(f"dictionary '{n}' appears twice")
        seen.add(n)
        for p in d.get("patterns") or []:
            pat = p.get("pattern") if isinstance(p, dict) else str(p)
            try:
                re.compile(pat or "")
            except re.error as e:
                problems.append(f"dictionary '{n}': pattern does not compile ({e}): {str(pat)[:60]}")
        # The same validator the deploy plan runs (pack_ops.validate), so an
        # upload and a preflight never disagree about what ZIA refuses.
        for msg in ops.validate("dictionary", d):
            problems.append(f"dictionary '{n}': {msg}")
        for msg in ops.notes("dictionary", d):
            warnings.append(f"dictionary '{n}': {msg}")
        if d.get("predefined_clone") and not (d.get("dict_template_name") or d.get("dict_template_id")):
            problems.append(f"dictionary '{n}': predefined clone without a template name")
        if not d.get("predefined_clone") and not (d.get("patterns") or d.get("phrases")):
            problems.append(f"dictionary '{n}': has neither patterns nor phrases")
    dict_names = {d.get("name") for d in dicts if isinstance(d, dict)}
    known_predefined = set()
    for d in dicts:
        if isinstance(d, dict) and d.get("dict_template_name"):
            known_predefined.update(template_candidates(d["dict_template_name"]))

    ref_names = {x for x in dict_names | known_predefined if isinstance(x, str) and x.strip()}
    meta_predefined = (pack.get("meta") or {}).get("predefined_dictionaries")
    if isinstance(meta_predefined, list):
        ref_names.update(x for x in meta_predefined if isinstance(x, str) and x.strip())

    eng_seen: set = set()
    for e in engines:
        if not isinstance(e, dict) or not str(e.get("name") or "").strip():
            problems.append("an engine has no name")
            continue
        n = e["name"]
        if n in eng_seen:
            problems.append(f"engine '{n}' appears twice")
        eng_seen.add(n)
        expr = str(e.get("expression") or "")
        if not expr.strip():
            problems.append(f"engine '{n}': empty expression")
            continue
        for msg in ops.validate("engine", e):
            problems.append(f"engine '{n}': {msg}")
        # A dictionary name ZIA accepts may hold a lone parenthesis or a
        # "D7.S"; the references to names the pack knows are taken out
        # before the checks that read the expression as a whole.
        rest, named = _without_known_refs(expr, ref_names)
        if rest.count("(") != rest.count(")"):
            problems.append(f"engine '{n}': unbalanced parentheses in expression")
        for m in _NUMERIC_REF_RE.finditer(rest):
            problems.append(f"engine '{n}': references dictionary id {m.group(1)}; use D:<dictionary name> so the pack works on any tenant")
        from dlp_importer import find_refs
        refs = set(named) | set(find_refs(rest))
        if not refs and "D:" not in expr and not _NUMERIC_REF_RE.search(expr):
            problems.append(f"engine '{n}': expression references no dictionary (expected D:<name> terms)")
        for r in refs:
            if r not in dict_names:
                warnings.append(f"engine '{n}': '{r}' is not in this pack, so it must be a predefined Zscaler dictionary or already exist in the tenant")
    engine_names = {e.get("name") for e in engines if isinstance(e, dict)}

    pol_seen: set = set()
    enabled = 0
    enforcing: List[str] = []
    try:
        flat = pc.expand_sub_rules([p for p in policies if isinstance(p, dict)])
    except Exception:  # noqa: BLE001 - malformed sub_rules are reported below as rules without names
        flat = policies
    for p in flat:
        if not isinstance(p, dict) or not str(p.get("name") or "").strip():
            problems.append("a rule has no name")
            continue
        n = p["name"]
        if n in pol_seen:
            problems.append(f"rule '{n}' appears twice")
        pol_seen.add(n)
        for err in ops.validate("policy", p):
            problems.append(f"rule '{n}': {err}")
        ch = pc.channel_of(p)
        if ch in (pc.WEB, pc.ENDPOINT, pc.SAAS, pc.EMAIL):
            for en in p.get("engines") or []:
                if en not in engine_names:
                    warnings.append(f"rule '{n}': engine '{en}' is not in this pack, so it must already exist in the tenant")
            if not (p.get("engines") or p.get("without_content_inspection")):
                warnings.append(f"rule '{n}': no engines listed; the rule would match on nothing")
        if str(p.get("state") or "ENABLED").upper() != "DISABLED":
            enabled += 1
        if pc.has_engines(ch) and pc.is_enforcing(ch, pc.policy_action(p)):
            enforcing.append(f"{n} ({pc.policy_action(p)})")
        for g in p.get("endpoint_application_groups") or []:
            if g not in {x.get("name") for x in groups if isinstance(x, dict)}:
                warnings.append(f"rule '{n}': application group '{g}' is not in this pack")
    if enabled:
        warnings.append(f"{enabled} rule(s) would be created ENABLED; Zscaler Made Easy's convention is to ship every rule DISABLED and enable it after review (Deploy Policy Packs still creates them disabled)")
    if enforcing:
        warnings.append(f"{len(enforcing)} rule(s) carry an enforcing action: {', '.join(enforcing[:6])}{'…' if len(enforcing) > 6 else ''}. "
                        "Zscaler Made Easy ships every DLP rule monitor-only (ALLOW, or report incident on SaaS) and DISABLED; the designed action is kept as "
                        "target_action and the data-governance journey names it as the hardening step (Deploy Policy Packs and the Terraform hand-off apply this)")

    return {
        "ok": not problems,
        "problems": problems,
        "warnings": warnings,
        "native": pack.get("native") or {},
        "counts": {"dictionaries": len(dicts), "engines": len(engines), "policies": len(policies), "app_groups": len(groups),
                   "clones": sum(1 for d in dicts if isinstance(d, dict) and d.get("predefined_clone"))},
        "channels": sorted({pc.channel_of(p) for p in policies if isinstance(p, dict)}),
    }


# ---------------------------------------------------------------------------
# Library on disk
# ---------------------------------------------------------------------------

def _pack_id_taken(slug: str, root: Optional[str] = None) -> bool:
    from dlp_importer import discover_packs
    return any(p["id"] == slug for p in discover_packs(root))


def save_pack(pack: Dict[str, Any], *, pack_id: str = "", root: Optional[str] = None) -> Dict[str, Any]:
    """Write the pack under the user library. Returns the pack metadata."""
    v = validate_pack(pack)
    if not v["ok"]:
        raise ValueError("; ".join(v["problems"][:5]))
    slug = pack_slug(pack_id or pack["meta"].get("name") or "")
    if not slug:
        raise ValueError("the pack needs a name")
    if slug == USER_PACKS_DIRNAME or _pack_id_taken(slug, root):
        raise FileExistsError(f"a pack with id '{slug}' already exists; choose another id or remove the existing pack first")
    lib = user_packs_dir(root)
    pack_dir = os.path.join(lib, slug)
    if os.path.exists(pack_dir):
        raise FileExistsError(f"'{slug}' already exists in the library")
    configs = os.path.join(pack_dir, "configs")
    os.makedirs(configs)
    meta = dict(pack["meta"])
    meta.update({
        "source": "uploaded",
        "uploaded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "upload_format": pack.get("format", "json"),
        "upload_files": list(pack.get("sources") or []),
    })
    with open(os.path.join(pack_dir, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    for fname, key in (("dlp_dictionaries.json", "dictionaries"), ("dlp_engines.json", "engines"), ("dlp_policies.json", "policies")):
        with open(os.path.join(configs, fname), "w", encoding="utf-8") as f:
            json.dump(pack.get(key) or [], f, indent=2)
    if pack.get("app_groups"):
        with open(os.path.join(configs, "endpoint_application_groups.json"), "w", encoding="utf-8") as f:
            json.dump(pack["app_groups"], f, indent=2)
    from dlp_importer import load_pack_metadata
    out = load_pack_metadata(pack_dir)
    out["id"] = slug
    out["dir"] = pack_dir
    out["source"] = "uploaded"
    out["validation"] = v
    return out


def delete_pack(pack_id: str, root: Optional[str] = None) -> str:
    """Remove an uploaded pack. Built-in packs cannot be removed here."""
    lib = os.path.realpath(user_packs_dir(root))
    slug = slugify(pack_id)
    target = os.path.realpath(os.path.join(lib, slug))
    if not slug or not target.startswith(lib + os.sep) or not os.path.isdir(target):
        raise FileNotFoundError(f"'{pack_id}' is not an uploaded pack (built-in packs stay; remove their folder on disk if you must)")
    shutil.rmtree(target)
    return target


def pack_bundle(pack_dir: str) -> Dict[str, Any]:
    """A single-file JSON copy of a pack: the upload format, and the
    starting point for a customer's own pack."""
    from dlp_importer import _load_json, _resolve_configs, load_pack_metadata
    meta = load_pack_metadata(pack_dir)
    configs = _resolve_configs(pack_dir)
    out = {k: meta[k] for k in ("name", "version", "description", "references", "baseline") if meta.get(k) is not None}
    out["dictionaries"] = _load_json(configs, "dlp_dictionaries.json")
    out["engines"] = _load_json(configs, "dlp_engines.json")
    out["policies"] = _load_json(configs, "dlp_policies.json")
    groups = _load_json(configs, "endpoint_application_groups.json")
    if groups:
        out["app_groups"] = groups
    return out


def library(root: Optional[str] = None) -> Dict[str, Any]:
    from dlp_importer import discover_packs
    packs = []
    for p in discover_packs(root):
        packs.append({k: p.get(k) for k in ("id", "name", "version", "description", "dictionaries", "engines", "policies", "app_groups", "channels", "source", "uploaded_at", "upload_format")})
    return {"packs": packs, "user_packs_dir": user_packs_dir(root)}
