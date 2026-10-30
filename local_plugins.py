"""Local plugins: an opt-in way to add Bulk changes operations and read-only
pages from Python packages the admin puts in a folder on this computer.

Off by default, and it stays off unless all of these hold:

1. DLP_CHECK_PLUGINS_DIR names a folder (local_settings); nothing is
   looked for anywhere else, and nothing is ever downloaded or installed.
2. Plugins are switched on in Advanced settings > Local plugins (a writer
   under SSO), saved in plugins.json beside the other local settings.
3. The plugin's SHA-256 (over every file of its folder, see package_hash)
   is on the allow-list: an admin approved that exact hash in Advanced
   settings after seeing its name, version, hash and the permissions it
   asks for, and typed its name to confirm. A plugin that is not listed,
   or whose files changed since it was approved (another hash), is refused
   and never imported. The files are read once, hashed, and the same bytes
   are executed from memory, so a file swapped after the check is not run.

A plugin package is a folder <name>/ holding plugin.json (name, version,
description, permissions: "operations" and/or "pages") and __init__.py
with register(api). Only .py, .json, .md and .txt files directly in the
folder are allowed (no sub-folders, no links, at most 32 files of 256 KB).

The narrow API (PluginAPI) offers exactly two things:

* add_operation(): one more Bulk changes operation type, registered on the
  engine as plugin_<plugin>_<name>. Its plan and object reader get a
  read-only client (only list_/get_/search_/lookup_/read_ calls, no private
  attributes); its write handlers run only inside the engine's apply, after
  the Scope rule, write mode, a writer, the named assessor, the typed
  confirmation and the plan hash were checked, and write only through
  run.create / run.update / run.delete (pack_ops: re-read guards, audit
  log, Stop). The engine still re-plans before writing, reads back and
  records the change; the plugin's scope check is ANDed with the product's.
* add_page(): a read-only page under /report/plugin?page=<slug>: a title
  and a table the app renders as text (no HTML or script from the plugin).

Per-user enablement: an approval may name the people (their sign-in
names) allowed to use the plugin; under SSO anyone else gets 403 on its
operations and pages, and does not see them listed.

The security cost, stated plainly in SECURITY.md: a plugin is Python code
running inside the app's process, with the app's privileges. The API is
narrow by contract and the read-only client and write wrappers enforce it
for the objects they hand over, but nothing in a Python process can stop
code that sets out to bypass them (it can import any module). The hash
allow-list and the admin's review of the code are the control.
"""
from __future__ import annotations

import hashlib
import importlib.abc
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import safe_files

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_DIR = "DLP_CHECK_PLUGINS_DIR"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,24}$")
PART_RE = re.compile(r"^[a-z][a-z0-9_]{1,12}$")
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
USER_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,120}$")
PERMISSIONS = {"operations": "add Bulk changes operations (planned, previewed and applied through the app's gates)",
               "pages": "add read-only pages (a title and a table the app renders)"}
ALLOWED_EXT = (".py", ".json", ".md", ".txt")
MAX_FILES = 32
MAX_FILE_BYTES = 256 * 1024
MAX_PLUGINS = 50
MAX_ROWS = 2000
MAX_COLS = 30
MAX_CELL = 500
_LOCK = threading.RLock()

# What is loaded in this process: {plugin name: {sha256, version, types, pages}}
LOADED: Dict[str, Dict[str, Any]] = {}
PAGES: Dict[str, Dict[str, Any]] = {}
TYPE_OWNER: Dict[str, str] = {}   # operation type -> plugin name


class PluginError(ValueError):
    """A plugin that is refused (the reason is shown to the admin)."""


# ---------------------------------------------------------------------------
# Settings (plugins.json: switch and allow-list)
# ---------------------------------------------------------------------------

def settings_path() -> str:
    env = os.environ.get("DLP_CHECK_PLUGINS_FILE")
    if env:
        return env
    try:
        import posture_plus
        folder = os.path.dirname(os.path.abspath(posture_plus.settings_path()))
    except Exception:  # noqa: BLE001
        folder = _APP_DIR
    return os.path.join(folder, "plugins.json")


def _clean_users(v: Any) -> List[str]:
    return sorted({str(u).strip() for u in (v if isinstance(v, list) else []) if USER_RE.match(str(u).strip() or "\x00")})[:100]


def settings() -> Dict[str, Any]:
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001 - missing or unreadable: off, nothing approved
        data = {}
    data = data if isinstance(data, dict) else {}
    approved = {}
    for name, a in (data.get("approved") or {}).items() if isinstance(data.get("approved"), dict) else []:
        if NAME_RE.match(str(name)) and isinstance(a, dict) and HASH_RE.match(str(a.get("sha256") or "")):
            approved[str(name)] = {"sha256": a["sha256"], "version": str(a.get("version") or "")[:32],
                                   "permissions": [p for p in a.get("permissions") or [] if p in PERMISSIONS],
                                   "approved_by": str(a.get("approved_by") or "")[:120], "approved_at": str(a.get("approved_at") or "")[:40],
                                   "users": _clean_users(a.get("users"))}
    return {"enabled": data.get("enabled") is True, "approved": approved}


def _save(data: Dict[str, Any]) -> Dict[str, Any]:
    p = settings_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    safe_files.private_makedirs(folder)
    fd, tmp = tempfile.mkstemp(prefix=".plugins-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"enabled": data.get("enabled") is True, "approved": data.get("approved") or {}}, f, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return settings()


def plugins_dir() -> Optional[str]:
    d = (os.environ.get(ENV_DIR) or "").strip()
    return os.path.abspath(d) if d else None


def enabled() -> bool:
    """On only with a configured folder and the switch on (both)."""
    return bool(plugins_dir()) and settings()["enabled"]


def set_enabled(on: bool) -> Dict[str, Any]:
    with _LOCK:
        s = settings()
        s["enabled"] = on is True
        return _save(s)


# ---------------------------------------------------------------------------
# Reading a package (never importing it)
# ---------------------------------------------------------------------------

def read_package(path: str) -> Tuple[Dict[str, bytes], str]:
    """({file name: bytes}, sha256) of a plugin folder, refusing anything but
    plain small files of the allowed kinds. The hash covers every file's
    name and content, so adding, removing or editing any file changes it."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise PluginError("not a folder (links are not followed)")
    files: Dict[str, bytes] = {}
    for fn in sorted(os.listdir(path)):
        if fn.startswith(".") or fn == "__pycache__":
            continue
        full = os.path.join(path, fn)
        st = os.lstat(full)
        if not stat.S_ISREG(st.st_mode):
            raise PluginError(f"'{fn[:60]}' is not a plain file (sub-folders and links are not allowed)")
        if not fn.endswith(ALLOWED_EXT) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", fn):
            raise PluginError(f"'{fn[:60]}' is not an allowed file ({', '.join(ALLOWED_EXT)})")
        if st.st_size > MAX_FILE_BYTES:
            raise PluginError(f"'{fn}' is larger than {MAX_FILE_BYTES // 1024} KB")
        if len(files) >= MAX_FILES:
            raise PluginError(f"more than {MAX_FILES} files")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(full, flags)
        try:
            with os.fdopen(fd, "rb") as f:
                files[fn] = f.read(MAX_FILE_BYTES + 1)
        except Exception:
            raise
        if len(files[fn]) > MAX_FILE_BYTES:
            raise PluginError(f"'{fn}' is larger than {MAX_FILE_BYTES // 1024} KB")
    return files, package_hash(files)


def package_hash(files: Dict[str, bytes]) -> str:
    h = hashlib.sha256()
    for fn in sorted(files):
        name = fn.encode("utf-8")
        h.update(len(name).to_bytes(4, "big") + name + len(files[fn]).to_bytes(8, "big") + files[fn])
    return h.hexdigest()


def manifest(files: Dict[str, bytes], folder: str) -> Dict[str, Any]:
    if "plugin.json" not in files or "__init__.py" not in files:
        raise PluginError("needs plugin.json and __init__.py")
    try:
        m = json.loads(files["plugin.json"].decode("utf-8"))
    except Exception:  # noqa: BLE001
        raise PluginError("plugin.json is not valid JSON") from None
    if not isinstance(m, dict):
        raise PluginError("plugin.json must be an object")
    name, version = str(m.get("name") or ""), str(m.get("version") or "")
    if not NAME_RE.match(name) or name != folder:
        raise PluginError("plugin.json 'name' must be the folder's name (a-z, 0-9, _; 2 to 25 characters)")
    if not VERSION_RE.match(version):
        raise PluginError("plugin.json 'version' is missing or not a version")
    perms = m.get("permissions")
    if not isinstance(perms, list) or not perms or any(p not in PERMISSIONS for p in perms):
        raise PluginError(f"plugin.json 'permissions' must list some of: {', '.join(PERMISSIONS)}")
    desc = re.sub(r"[\x00-\x1f\x7f]", " ", str(m.get("description") or ""))[:300]
    return {"name": name, "version": version, "description": desc, "permissions": sorted(set(perms))}


def discover() -> List[Dict[str, Any]]:
    """Every folder in the plugins directory with its manifest, hash and
    status (approved, not approved, changed since approval, refused). Reads
    files only; imports nothing."""
    d = plugins_dir()
    if not d or not os.path.isdir(d):
        return []
    approved = settings()["approved"]
    out = []
    for fn in sorted(os.listdir(d))[:MAX_PLUGINS]:
        if fn.startswith((".", "_")):
            continue
        row: Dict[str, Any] = {"folder": fn[:64], "name": fn[:64], "version": "", "description": "", "permissions": [], "sha256": ""}
        try:
            files, sha = read_package(os.path.join(d, fn))
            row.update(manifest(files, fn), sha256=sha, files=sorted(files))
            a = approved.get(row["name"])
            if a is None:
                row["status"], row["reason"] = "not_approved", "not on the allow-list: approve it after reviewing its code"
            elif a["sha256"] != sha:
                row["status"], row["reason"] = "changed", "its files changed since it was approved (another SHA-256): refused until approved again"
            else:
                row["status"], row["reason"], row["users"] = "approved", "", a["users"]
        except (PluginError, OSError) as e:
            row["status"], row["reason"] = "refused", str(e)[:200]
        row["loaded"] = row["name"] in LOADED
        out.append(row)
    return out


def approve(name: str, sha256: str, *, by: str, confirm: str, users: Any = None) -> Dict[str, Any]:
    """Put a plugin's current hash on the allow-list. The admin passes the
    hash they saw (it must still be the folder's hash) and types the name."""
    if not NAME_RE.match(str(name or "")):
        raise PluginError("Unknown plugin name.")
    if str(confirm or "").strip() != name:
        raise PluginError(f"Type the plugin's name ({name}) to confirm.")
    d = plugins_dir()
    if not d:
        raise PluginError(f"No plugins folder is configured ({ENV_DIR}).")
    files, sha = read_package(os.path.join(d, name))
    m = manifest(files, name)
    if not HASH_RE.match(str(sha256 or "")) or sha != sha256:
        raise PluginError("The plugin's files changed since you looked at them (another SHA-256). Reload and review it again.")
    with _LOCK:
        s = settings()
        s["approved"][name] = {"sha256": sha, "version": m["version"], "permissions": m["permissions"], "approved_by": str(by or "")[:120],
                               "approved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "users": _clean_users(users)}
        return _save(s)


def revoke(name: str) -> Dict[str, Any]:
    with _LOCK:
        s = settings()
        s["approved"].pop(str(name), None)
        saved = _save(s)
        unload(str(name))
        return saved


# ---------------------------------------------------------------------------
# Loading: the same bytes that were hashed, from memory
# ---------------------------------------------------------------------------

class _MemoryFinder(importlib.abc.MetaPathFinder, importlib.abc.InspectLoader):
    """Serves the plugin's modules from the bytes that were hashed (never
    from the folder again). The standard loader runs the code it compiles."""

    def __init__(self, pkg: str, files: Dict[str, bytes]):
        self.pkg = pkg
        self.files = files

    def _file(self, fullname: str) -> Optional[str]:
        if fullname == self.pkg:
            return "__init__.py"
        rest = fullname[len(self.pkg) + 1:] if fullname.startswith(self.pkg + ".") else ""
        return f"{rest}.py" if rest and "." not in rest and f"{rest}.py" in self.files else None

    def find_spec(self, fullname, path=None, target=None):
        fn = self._file(fullname)
        if fn is None:
            return None
        spec = importlib.util.spec_from_loader(fullname, self, origin=f"<plugin {self.pkg}/{fn}>", is_package=fullname == self.pkg)
        if fullname == self.pkg and spec is not None:
            spec.submodule_search_locations = []
        return spec

    def is_package(self, fullname: str) -> bool:
        return fullname == self.pkg

    def get_source(self, fullname: str) -> str:
        fn = self._file(fullname)
        if fn is None:
            raise ImportError(fullname)
        return self.files[fn].decode("utf-8")

    def get_code(self, fullname: str):
        fn = self._file(fullname)
        if fn is None:
            raise ImportError(fullname)
        return compile(self.files[fn], f"<plugin {self.pkg}/{fn}>", "exec", dont_inherit=True)


def load(name: str) -> Dict[str, Any]:
    """Load one plugin if, and only if, plugins are on and its current hash
    is approved. Raises PluginError with the reason it is refused."""
    if not enabled():
        raise PluginError("Local plugins are off (Advanced settings > Local plugins, and DLP_CHECK_PLUGINS_DIR).")
    if not NAME_RE.match(str(name or "")):
        raise PluginError("Unknown plugin name.")
    a = settings()["approved"].get(name)
    if a is None:
        raise PluginError(f"{name}: not on the allow-list; it is not loaded.")
    files, sha = read_package(os.path.join(plugins_dir() or "", name))
    m = manifest(files, name)
    if sha != a["sha256"]:
        raise PluginError(f"{name}: its files changed since it was approved (SHA-256 {sha[:12]}…, approved {a['sha256'][:12]}…); it is not loaded.")
    with _LOCK:
        if name in LOADED:
            return LOADED[name]
        pkg = f"zme_plugin_{name}"
        finder = _MemoryFinder(pkg, files)
        sys.meta_path.insert(0, finder)
        api = PluginAPI(name, set(m["permissions"]) & set(a["permissions"] or m["permissions"]))
        try:
            mod = importlib.import_module(pkg)
            reg = getattr(mod, "register", None)
            if not callable(reg):
                raise PluginError(f"{name}: __init__.py has no register(api).")
            reg(api)
        except PluginError:
            api.rollback()
            raise
        except Exception as e:  # noqa: BLE001 - a broken plugin is refused, the app keeps running
            api.rollback()
            raise PluginError(f"{name}: failed while registering ({type(e).__name__}: {str(e)[:160]})") from None
        finally:
            if finder in sys.meta_path:
                sys.meta_path.remove(finder)
        LOADED[name] = {"name": name, "version": m["version"], "sha256": sha, "types": list(api.types), "pages": list(api.pages),
                        "users": a["users"]}
        return LOADED[name]


def load_enabled(log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """At start-up: every approved plugin whose hash still matches. Each
    refusal is reported, never raised."""
    say = log or (lambda m: None)
    out: Dict[str, Any] = {"loaded": [], "refused": []}
    if not enabled():
        return out
    for row in discover():
        if row["status"] != "approved":
            if row["status"] == "changed":
                out["refused"].append({"name": row["name"], "reason": row["reason"]})
            continue
        try:
            load(row["name"])
            out["loaded"].append(row["name"])
            say(f"Local plugin loaded: {row['name']} {row['version']}")
        except (PluginError, OSError) as e:
            out["refused"].append({"name": row["name"], "reason": str(e)[:200]})
            say(f"Local plugin refused: {row['name']}: {e}")
    return out


def unload(name: str) -> None:
    import admin_ops as ao
    with _LOCK:
        info = LOADED.pop(name, None)
        if not info:
            return
        for t in info["types"]:
            reg = ao.PLUGINS.pop(t, None)
            if reg:
                ao.PLUGIN_FAMILIES.pop(reg["family"], None)
            TYPE_OWNER.pop(t, None)
        for h in [h for h in ao.PLUGIN_HANDLERS if h.startswith(f"plg_{name}_")]:
            ao.PLUGIN_HANDLERS.pop(h, None)
        for slug in info["pages"]:
            PAGES.pop(slug, None)


# ---------------------------------------------------------------------------
# Who may use a plugin (per-user enablement)
# ---------------------------------------------------------------------------

def owner_of(type_or_family: Any) -> Optional[str]:
    t = type_or_family if isinstance(type_or_family, str) else str((type_or_family or {}).get("type") or "") if isinstance(type_or_family, dict) else ""
    if t in TYPE_OWNER:
        return TYPE_OWNER[t]
    for typ, owner in TYPE_OWNER.items():
        if t == f"{typ}_f":
            return owner
    return None


def user_allowed(plugin: Optional[str], actor: Optional[str]) -> bool:
    if not plugin:
        return True
    info = LOADED.get(plugin)
    if info is None:
        return False
    users = info.get("users") or []
    return not users or str(actor or "") in users


def check_user(what: Any, actor: Optional[str]) -> Optional[str]:
    """Why `actor` may not use the plugin behind `what` (an operation spec,
    a type or a family), or None."""
    p = owner_of(what)
    if p and not user_allowed(p, actor):
        return f"The local plugin '{p}' is not enabled for you. An admin can add you in Advanced settings > Local plugins."
    return None


# ---------------------------------------------------------------------------
# The narrow API a plugin gets
# ---------------------------------------------------------------------------

_READ_PREFIXES = ("list", "get", "search", "lookup", "read")


class ReadOnly:
    """A view of the SDK client that can only read: attribute chains are
    followed, private attributes refused, and only calls whose name starts
    with list/get/search/lookup/read go through."""

    __slots__ = ("_t", "_path")

    def __init__(self, target: Any, path: str = "client"):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_path", path)

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("_"):
            raise PermissionError(f"a plugin may not reach {self._path}.{attr}")
        v = getattr(self._t, attr)
        if callable(v):
            if not attr.lower().startswith(_READ_PREFIXES):
                def refused(*a: Any, **k: Any) -> Any:
                    raise PermissionError(f"{self._path}.{attr} is not a read: a plugin writes only through run.create / run.update / run.delete")
                return refused
            return lambda *a, **k: v(*a, **k)
        if isinstance(v, (str, int, float, bool, type(None))):
            return v
        return ReadOnly(v, f"{self._path}.{attr}")

    def __setattr__(self, k: str, v: Any) -> None:
        raise PermissionError("a plugin may not change the client")

    def __call__(self, *a: Any, **k: Any) -> Any:
        raise PermissionError(f"{self._path} is not callable by a plugin")


class PluginRun:
    """What a plugin's write handler gets instead of the engine's run: the
    read-only client, the units and marks, and the three write calls, which
    go through pack_ops (audited, Stop-aware) and only inside the engine's
    apply."""

    def __init__(self, run: Any, product: str):
        self._run, self._product = run, product
        self.client = ReadOnly(run.client)
        self.zia = ReadOnly(run.zia) if run.zia is not None else None
        self.zpa = ReadOnly(run.zpa) if run.zpa is not None else None
        self.log, self.assessor, self.units = run.log, run.assessor, run.units

    def _target(self) -> Any:
        import pack_ops as ops
        if not ops.in_run():
            raise PermissionError("a plugin writes only inside an apply the engine started")
        return self._run.zpa if self._product == "zpa" else self._run.zia

    def mark(self, units: Sequence[Dict[str, Any]], status: str, reason: str = "", **extra: Any) -> None:
        self._run.mark(units, status, reason, **extra)

    def outcome(self, units: Sequence[Dict[str, Any]], out: Any, verb: str) -> bool:
        ok = self._run.outcome(units, out, verb)
        if ok and self._product == "zia":
            self._run.wrote_zia = True
        if ok and verb == "create":
            self._run.created.append({"type": "plugin", "id": str(getattr(out, "id", "") or ""), "name": units[0]["object"].get("name") if units else ""})
        return ok

    def create(self, kind: str, payload: Dict[str, Any], *, name: str = "", channel: Optional[str] = None) -> Any:
        import pack_ops as ops
        return ops.create(self._target(), kind, dict(payload), channel=channel, name=name, log=self.log)

    def update(self, kind: str, oid: Any, payload: Dict[str, Any], *, name: str = "", channel: Optional[str] = None) -> Any:
        import pack_ops as ops
        return ops.update(self._target(), kind, oid, dict(payload), channel=channel, name=name, log=self.log)

    def delete(self, item: Dict[str, Any]) -> Any:
        import pack_ops as ops
        return ops.delete(self._target(), dict(item), log=self.log)


def _product_scope(product: str, scope: Dict[str, Any]) -> Optional[str]:
    if product == "zpa":
        return None if scope.get("zpa") else "Not in scope: ZPA is not ticked on the Scope page."
    if product == "zia":
        return None if scope.get("policies") else "Not in scope: no ZIA policy is in scope on the Scope page."
    return None if product in (scope.get("scopes") or []) else f"Not in scope: {product} is not ticked on the Scope page."


class PluginAPI:
    """The only object a plugin's register(api) receives."""

    def __init__(self, plugin: str, permissions: set):
        self.plugin = plugin
        self.permissions = frozenset(permissions)
        self.types: List[str] = []
        self.pages: List[str] = []

    def _need(self, perm: str) -> None:
        if perm not in self.permissions:
            raise PluginError(f"{self.plugin}: '{perm}' was not asked for in plugin.json or not approved")

    def add_operation(self, name: str, *, label: str, hint: str, product: str, plan: Callable[..., Dict[str, Any]],
                      read_objects: Callable[..., Dict[str, Any]], handlers: Dict[str, Callable[..., None]],
                      in_scope: Optional[Callable[[Dict[str, Any]], Optional[str]]] = None,
                      verify: Optional[Callable[..., Dict[str, Any]]] = None, inverse: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None) -> str:
        import admin_ops as ao
        self._need("operations")
        if not PART_RE.match(str(name or "")) or product not in ("zia", "zpa", "zcc", "zdx"):
            raise PluginError(f"{self.plugin}: operation name must be a-z, 0-9, _ (2-13 characters) and product zia, zpa, zcc or zdx")
        type_name = f"plugin_{self.plugin}_{name}"[:41]
        family = f"{type_name}_f"[:41]
        hmap = {}
        for h, fn in (handlers or {}).items():
            if not PART_RE.match(str(h)) or not callable(fn):
                raise PluginError(f"{self.plugin}: handler names must be a-z, 0-9, _ (2-13 characters)")
            hmap[h] = f"plg_{self.plugin}_{h}"[:41]

        def scope_ok(scope: Dict[str, Any]) -> Optional[str]:
            why = _product_scope(product, scope)
            if why or in_scope is None:
                return why
            return in_scope(scope)

        def plan_ro(client, spec, scope, say, cancel):
            prepared = plan(ReadOnly(client), spec, scope, say, cancel)
            if not isinstance(prepared, dict):
                raise ao.OperationError(f"The plugin {self.plugin} returned no plan.")
            prepared["product"] = product   # the plugin cannot pose as another product
            for g in prepared.get("groups") or []:
                g["handler"] = hmap.get(g.get("handler"), f"unknown:{str(g.get('handler'))[:40]}")
            prepared.setdefault("notes", []).append(f"Planned by the local plugin {self.plugin}.")
            return prepared

        def objects_ro(client, scope, say, cancel):
            return read_objects(ReadOnly(client), scope, say, cancel)

        def wrap(fn):
            return lambda run, g, units: fn(PluginRun(run, product), g, units)

        ao.register(type_name, family=family, product=product, label=f"{str(label)[:80]} (plugin)", hint=str(hint)[:300], in_scope=scope_ok,
                    plan=plan_ro, read_objects=objects_ro, handlers={hmap[h]: wrap(fn) for h, fn in handlers.items()},
                    verify=(lambda run: verify(PluginRun(run, product))) if verify else None, inverse=inverse, group="Local plugins", script="")
        self.types.append(type_name)
        TYPE_OWNER[type_name] = self.plugin
        return type_name

    def add_page(self, slug: str, *, title: str, render: Callable[[], Dict[str, Any]]) -> str:
        self._need("pages")
        if not SLUG_RE.match(str(slug or "")) or not callable(render):
            raise PluginError(f"{self.plugin}: a page slug is a-z, 0-9 and -")
        full = f"{self.plugin.replace('_', '-')}-{slug}"[:60]
        if full in PAGES:
            raise PluginError(f"{self.plugin}: page {slug} is already registered")
        PAGES[full] = {"slug": full, "plugin": self.plugin, "title": re.sub(r"[\x00-\x1f\x7f]", " ", str(title))[:120], "render": render}
        self.pages.append(full)
        return full

    def rollback(self) -> None:
        LOADED.setdefault(self.plugin, {"types": self.types, "pages": self.pages})
        unload(self.plugin)


def _cell(v: Any) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", str(v if v is not None else ""))[:MAX_CELL]


def render_page(slug: str, actor: Optional[str]) -> Dict[str, Any]:
    """A plugin page's data, reduced to text (the page escapes it again)."""
    p = PAGES.get(str(slug))
    if p is None:
        raise KeyError(slug)
    if not user_allowed(p["plugin"], actor):
        raise PermissionError(f"The local plugin '{p['plugin']}' is not enabled for you.")
    try:
        data = p["render"]()
    except Exception as e:  # noqa: BLE001
        return {"slug": slug, "title": p["title"], "plugin": p["plugin"], "error": f"the plugin failed: {type(e).__name__}", "columns": [], "rows": []}
    data = data if isinstance(data, dict) else {}
    cols = [_cell(c)[:80] for c in (data.get("columns") or [])][:MAX_COLS]
    rows = [[_cell(c) for c in (r if isinstance(r, (list, tuple)) else [r])][:MAX_COLS] for r in (data.get("rows") or [])][:MAX_ROWS]
    notes = [_cell(n) for n in (data.get("notes") or []) if n][:20]
    return {"slug": slug, "title": p["title"], "plugin": p["plugin"], "columns": cols, "rows": rows, "notes": notes}


def overview(actor: Optional[str] = None) -> Dict[str, Any]:
    """What Advanced settings shows (no path beyond the folder's name)."""
    d = plugins_dir()
    s = settings()
    return {"enabled": enabled(), "switch": s["enabled"], "folder_configured": bool(d), "folder": os.path.basename(d) if d else "",
            "env": ENV_DIR, "permissions": PERMISSIONS, "plugins": discover(),
            "loaded": [dict(v, users=v.get("users") or []) for v in LOADED.values()],
            "pages": [{"slug": k, "title": v["title"], "plugin": v["plugin"]} for k, v in PAGES.items() if user_allowed(v["plugin"], actor)],
            "note": "Approved plugins are loaded when the app starts; revoking one unloads it at once."}
