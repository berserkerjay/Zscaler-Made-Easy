"""The SaaS tenant capability matrix, kept as data.

The SaaS Security API and Email DLP channels only work through onboarded
application tenants, and each application supports a different set of
capabilities (DLP and malware scanning, App Governance, SSPM, Workflow
Automation). Zscaler documents the matrix on two help pages; this module
keeps it in saas_apps.json (shipped with the app), refreshes it from the
pages on the continuous-evaluation schedule, and compares it with the
tenants a customer has onboarded: which applications could be onboarded
for DLP and are not, which onboarded tenants are not ACTIVE, and which
applications are at the 16-tenant limit.

A refreshed copy is written to saas_apps.local.json (git-ignored) so the
shipped seed is never modified in place.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
SEED_FILE = os.path.join(ROOT, "saas_apps.json")
LOCAL_FILE = os.path.join(ROOT, "saas_apps.local.json")
TENANT_LIMIT = 16
PAGES = [
    "https://help.zscaler.com/zia/adding-saas-application-tenants",
    "https://help.zscaler.com/zia/understanding-saas-security-supported-capabilities",
]
CAPABILITY_WORDS = {"dlp": "DLP", "malware": "Malware", "app governance": "App Governance", "governance": "App Governance",
                    "sspm": "SSPM", "workflow automation": "Workflow Automation", "scan": "DLP"}
TYPE_WORDS = [("file", "OFLCASB_DLP_FILE"), ("email", "OFLCASB_DLP_EMAIL"), ("mail", "OFLCASB_DLP_EMAIL"), ("collab", "OFLCASB_DLP_COLLAB"),
              ("crm", "OFLCASB_DLP_CRM"), ("itsm", "OFLCASB_DLP_ITSM"), ("repo", "OFLCASB_DLP_REPO"), ("storage", "OFLCASB_DLP_STORAGE"),
              ("gen", "OFLCASB_DLP_GENAI"), ("ai", "OFLCASB_DLP_GENAI")]


def _local_path() -> str:
    return os.environ.get("DLP_CHECK_SAAS_MATRIX") or LOCAL_FILE


def load() -> Dict[str, Any]:
    """The refreshed matrix when one exists, else the shipped seed."""
    for path in (_local_path(), SEED_FILE):
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and d.get("applications"):
                d["path"] = path
                return d
        except Exception:  # noqa: BLE001
            continue
    return {"types": {}, "applications": [], "path": None}


def apps_for_type(saas_type: str, matrix: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    m = matrix or load()
    return [a for a in m.get("applications") or [] if a.get("type") == saas_type]


def dlp_capable(matrix: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    m = matrix or load()
    return [a for a in m.get("applications") or [] if "DLP" in (a.get("capabilities") or [])]


# ── Parsing the help pages ───────────────────────────────────────────
class _Tables(HTMLParser):
    """Collect every table as rows of cell text."""
    def __init__(self) -> None:
        super().__init__()
        self.tables: List[List[List[str]]] = []
        self._row: Optional[List[str]] = None
        self._cell: Optional[List[str]] = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.tables.append([])
        elif tag == "tr" and self.tables:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None and self.tables:
            if self._row:
                self.tables[-1].append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def parse_matrix(html: str) -> List[Dict[str, Any]]:
    """Applications with their SaaS type and capabilities from a help
    page's tables. Tolerant: a table qualifies when its header names an
    application column and at least one capability column; a cell that
    reads yes / ✓ / supported counts as supported."""
    p = _Tables()
    p.feed(html)
    apps: Dict[str, Dict[str, Any]] = {}
    for table in p.tables:
        if len(table) < 2:
            continue
        header = [h.lower() for h in table[0]]
        try:
            app_col = next(i for i, h in enumerate(header) if "application" in h or h in ("app", "saas application", "name"))
        except StopIteration:
            continue
        cap_cols = {i: CAPABILITY_WORDS[w] for i, h in enumerate(header) for w in CAPABILITY_WORDS if w in h and i != app_col}
        type_col = next((i for i, h in enumerate(header) if "type" in h or "category" in h), None)
        if not cap_cols and type_col is None:
            continue
        for row in table[1:]:
            if len(row) <= app_col or not row[app_col]:
                continue
            name = row[app_col]
            rec = apps.setdefault(name, {"name": name, "type": None, "capabilities": []})
            for i, cap in cap_cols.items():
                if i < len(row) and re.search(r"yes|✓|✔|supported|available|x$", row[i].strip().lower()):
                    if cap not in rec["capabilities"]:
                        rec["capabilities"].append(cap)
            if type_col is not None and type_col < len(row):
                low = row[type_col].lower()
                for w, t in TYPE_WORDS:
                    if w in low:
                        rec["type"] = t
                        break
    return list(apps.values())


def refresh(safe_get, *, pages: Sequence[str] = PAGES) -> Dict[str, Any]:
    """Fetch the help pages through the app's allowlisted fetcher and, when
    they parse into at least as many applications as the seed knows,
    write the refreshed matrix. Otherwise keep what we have and say why."""
    seed = load()
    found: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    for url in pages:
        try:
            body, status, err = safe_get(url)
        except Exception as e:  # noqa: BLE001
            body, status, err = None, 0, str(e)
        if not body or status != 200:
            errors.append(f"{url}: {err or f'HTTP {status}'}")
            continue
        for a in parse_matrix(body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)):
            rec = found.setdefault(a["name"], {"name": a["name"], "type": a.get("type"), "capabilities": []})
            rec["type"] = rec["type"] or a.get("type")
            for c in a.get("capabilities") or []:
                if c not in rec["capabilities"]:
                    rec["capabilities"].append(c)
    known = {a["name"].lower(): a for a in seed.get("applications") or []}
    if len(found) >= 8:   # a real capability table, not a stray table on the page
        merged = []
        for name, rec in found.items():
            old = known.get(name.lower()) or {}
            merged.append({"name": name, "type": rec.get("type") or old.get("type") or _guess_type(name),
                           "capabilities": rec["capabilities"] or old.get("capabilities") or [], "vendor_sources": old.get("vendor_sources") or []})
        new_names = sorted(n for n in found if n.lower() not in known)
        out = {"source": "Zscaler help pages (refreshed)", "pages": list(pages), "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "refreshed_from_pages": True, "types": seed.get("types") or {}, "applications": merged, "new_since_seed": new_names}
        try:
            with open(_local_path(), "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
        except OSError as e:
            errors.append(f"could not write the refreshed matrix: {e}")
        return {"ok": True, "applications": len(merged), "new_since_seed": new_names, "errors": errors}
    return {"ok": False, "applications": len(found), "errors": errors or ["the pages did not parse into a capability table; the shipped matrix is kept"]}


def _guess_type(name: str) -> Optional[str]:
    low = name.lower()
    for w, t in (("drive", "OFLCASB_DLP_FILE"), ("sharepoint", "OFLCASB_DLP_FILE"), ("box", "OFLCASB_DLP_FILE"), ("mail", "OFLCASB_DLP_EMAIL"), ("exchange", "OFLCASB_DLP_EMAIL"),
                 ("teams", "OFLCASB_DLP_COLLAB"), ("slack", "OFLCASB_DLP_COLLAB"), ("salesforce", "OFLCASB_DLP_CRM"), ("servicenow", "OFLCASB_DLP_ITSM"), ("jira", "OFLCASB_DLP_ITSM"),
                 ("git", "OFLCASB_DLP_REPO"), ("s3", "OFLCASB_DLP_STORAGE"), ("blob", "OFLCASB_DLP_STORAGE"), ("gpt", "OFLCASB_DLP_GENAI"), ("copilot", "OFLCASB_DLP_GENAI"), ("gemini", "OFLCASB_DLP_GENAI")):
        if w in low:
            return t
    return None


# ── Tenants in the customer's ZIA ─────────────────────────────────────
def list_tenants(client) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Onboarded SaaS application tenants: {id, name, app, status, type}."""
    zia = getattr(client, "zia", client)
    svc = getattr(zia, "saas_security_api", None)
    if svc is None:
        return [], "the API client has no SaaS Security API service"
    try:
        ret = svc.list_casb_tenant_lite(query_params={"active_only": False})
    except TypeError:
        ret = svc.list_casb_tenant_lite()
    except Exception as e:  # noqa: BLE001
        return [], str(e)[:200]
    if isinstance(ret, tuple):
        data = ret[0]
        err = ret[2] if len(ret) == 3 else (ret[1] if len(ret) == 2 else None)
    else:
        data, err = ret, None
    if err:
        return [], str(err)[:200]
    out = []
    for t in data or []:
        g = (lambda *ks: next((getattr(t, k) if hasattr(t, k) else t.get(k) for k in ks if (hasattr(t, k) and getattr(t, k) is not None) or (isinstance(t, dict) and t.get(k) is not None)), None))
        name = str(g("tenant_name", "tenantName", "name") or "").strip()
        if not name:
            continue
        status = g("status")
        if isinstance(status, (list, tuple)):
            status = ",".join(str(s) for s in status)
        out.append({"id": g("tenant_id", "tenantId", "id"), "name": name, "app": str(g("saas_application", "saasApplication", "enterprise_tenant_id") or "").upper(),
                    "status": str(status or "").upper(), "type": str(g("saas_type", "saasType", "type") or "").upper() or None})
    return out, None


def tenant_findings(tenants: Sequence[Dict[str, Any]], *, pack_channels: Sequence[str] = ("saas", "email"), matrix: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What the loop tells about the customer's tenants: which need
    re-authorisation, which applications sit at the limit, and which
    DLP-capable applications are not onboarded at all."""
    m = matrix or load()
    apps = m.get("applications") or []
    by_app: Dict[str, List[Dict[str, Any]]] = {}
    for t in tenants:
        by_app.setdefault(t.get("app") or "?", []).append(t)
    not_active = [t for t in tenants if t.get("status") and "ACTIVE" not in t["status"]]
    at_limit = [app for app, ts in by_app.items() if len(ts) >= TENANT_LIMIT]
    onboarded = {(t.get("app") or "").lower() for t in tenants} | {t["name"].lower() for t in tenants}
    def _is_onboarded(app_name: str) -> bool:
        key = app_name.lower()
        return any(key in o or o in key for o in onboarded if o)
    candidates = [{"name": a["name"], "type": a.get("type"), "type_label": (m.get("types") or {}).get(a.get("type"), a.get("type"))}
                  for a in apps if "DLP" in (a.get("capabilities") or []) and not _is_onboarded(a["name"])]
    types_present = {t.get("type") for t in tenants if t.get("type")}
    has_email = any((t.get("type") or "").endswith("EMAIL") or "MAIL" in (t.get("app") or "") or "EXCHANGE" in (t.get("app") or "") for t in tenants)
    gaps = []
    if "saas" in pack_channels and not tenants:
        gaps.append("The packs' SaaS mirrors have no onboarded SaaS application tenant to run in.")
    if "email" in pack_channels and not has_email:
        gaps.append("The packs' Email mirrors have no onboarded email tenant (Microsoft 365 or Gmail) to run in.")
    return {"tenants": len(tenants), "active": len(tenants) - len(not_active), "not_active": not_active, "at_limit": at_limit,
            "onboard_candidates": candidates, "types_present": sorted(t for t in types_present if t), "gaps": gaps, "matrix_updated_at": m.get("updated_at"),
            "matrix_refreshed": bool(m.get("refreshed_from_pages"))}
