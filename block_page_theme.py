"""Block page (end-user notification) theme builder: a local, read-only
preview and generator.

A theme is a few validated settings kept in this app's own store: the
organisation name, a logo (PNG, JPEG or GIF, stored locally), colours and
the words end users read when a page is blocked. From a theme this module
produces, without touching a tenant:

  * a self-contained HTML preview of the page (sample values for the blocked
    address and reason; every value escaped; no script; a CSP that allows
    only the inline style and the stored logo);
  * the end-user notification settings that carry the same words and
    switches (settings_for), which ops_zia_eun.py can send to ZIA, and only
    through Bulk changes: plan, hash, the four gates, read-back, Undo, audit.

The logo never travels to ZIA from here: the SDK's end-user notification
settings have no logo field (assumed, the SDK lists none), so the logo
appears in the generated HTML (for a page the organisation hosts itself)
and the display-logo switch is sent, but the image is uploaded in the ZIA
Admin Portal.

The store is block_page_theme.json beside the tenant profiles (owner-only,
atomic, sealed by store_crypto when encryption is on); DLP_CHECK_BLOCK_PAGE_THEME
overrides the path. A theme name is a short slug used only as a dictionary
key, never as a file name. Every change is audited with who made it; theme
text is not (it may name the organisation).
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import html
import json
import os
import re
import tempfile
import threading
from typing import Any, Dict, List, Optional, Tuple

import safe_files
import store_crypto

STORE_FILE = "block_page_theme.json"
_LOCK = threading.RLock()

MAX_THEMES = 20
MAX_LOGO_BYTES = 200 * 1024
MAX_STORE_BYTES = 8 * 1024 * 1024
LIMITS = {"org_name": 80, "title": 80, "message": 600, "support_email": 254, "support_phone": 30, "policy_link": 300}

DEFAULTS: Dict[str, Any] = {
    "org_name": "", "title": "This page is blocked", "message": "Access to this page was blocked by your organization's security policy.",
    "support_email": "", "support_phone": "", "policy_link": "",
    "background": "#f3f4f6", "card": "#ffffff", "text": "#1f2937", "accent": "#0b5cab",
    "show_reason": True, "show_company_name": True, "show_logo": True,
}
COLOR_KEYS = ("background", "card", "text", "accent")
BOOL_KEYS = ("show_reason", "show_company_name", "show_logo")
TEXT_KEYS = ("org_name", "title", "message", "support_email", "support_phone", "policy_link")

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_EMAIL_RE = re.compile(r"^[^\s@<>\"'`]+@[^\s@<>\"'`]+\.[^\s@<>\"'`]+$")
_PHONE_RE = re.compile(r"^[0-9+()\-. ]{3,30}$")
_LINK_RE = re.compile(r"^https://[^\s\"'<>`\\]+$")
# C1 controls, line/paragraph separators and bidirectional overrides never stay in text (CWE-451).
_INVISIBLE = {chr(c) for c in range(0x80, 0xA0)} | {" ", " "} | {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}

EUN_FIELDS = ("displayReason", "displayCompName", "displayCompLogo", "customText", "supportEmail", "supportPhone", "orgPolicyLink")


class ThemeError(ValueError):
    """A refusal the page can show as it is. `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── validation ──────────────────────────────────────────────────────────
def clean_name(name: Any) -> str:
    n = str(name if name is not None else "default").strip().lower() or "default"
    if not _NAME_RE.match(n):
        raise ThemeError("a theme name is 1 to 40 lower-case letters, digits, - or _")
    return n


def _text(value: Any, key: str, *, multiline: bool = False) -> str:
    s = "".join(ch for ch in str(value if value is not None else "")
                if (multiline and ch == "\n") or (ch >= " " and ch != "\x7f" and ch not in _INVISIBLE)).strip()
    if len(s) > LIMITS[key]:
        raise ThemeError(f"{key.replace('_', ' ')} is too long: at most {LIMITS[key]} characters")
    return s


def _color(value: Any, key: str) -> str:
    c = str(value or "").strip()
    if not _COLOR_RE.match(c):
        raise ThemeError(f"{key} must be a colour such as #0b5cab")
    c = c.lower()
    return "#" + "".join(ch * 2 for ch in c[1:]) if len(c) == 4 else c


def clean_theme(raw: Any) -> Dict[str, Any]:
    """A validated theme (without its logo) from untrusted input; unknown keys are refused, not ignored."""
    if not isinstance(raw, dict):
        raise ThemeError("a theme is an object of settings")
    known = set(DEFAULTS)
    extra = sorted(str(k)[:30] for k in raw if k not in known)
    if extra:
        raise ThemeError(f"unknown theme setting(s): {', '.join(extra[:3])}")
    t = dict(DEFAULTS)
    for k in TEXT_KEYS:
        if k in raw:
            t[k] = _text(raw[k], k, multiline=(k == "message"))
    for k in COLOR_KEYS:
        if k in raw:
            t[k] = _color(raw[k], k)
    for k in BOOL_KEYS:
        if k in raw:
            if not isinstance(raw[k], bool):
                raise ThemeError(f"{k} must be true or false")
            t[k] = raw[k]
    if t["support_email"] and not _EMAIL_RE.match(t["support_email"]):
        raise ThemeError("support email is not an email address")
    if t["support_phone"] and not _PHONE_RE.match(t["support_phone"]):
        raise ThemeError("support phone may hold digits, spaces and + ( ) - . only")
    if t["policy_link"] and not _LINK_RE.match(t["policy_link"]):
        raise ThemeError("the policy link must be an https:// address")
    if not t["title"]:
        raise ThemeError("the page needs a title")
    return t


_MAGIC = ((b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"), (b"GIF87a", "image/gif"), (b"GIF89a", "image/gif"))


def clean_logo(data: Any) -> Dict[str, Any]:
    """A logo from a base64 string or a data: URI. Only PNG, JPEG and GIF are kept, recognised by their first bytes (the
    declared type is not trusted), at most MAX_LOGO_BYTES. SVG is refused: it can carry script."""
    s = str(data or "").strip()
    if s.startswith("data:"):
        head, _, s = s.partition(",")
        if ";base64" not in head:
            raise ThemeError("the logo must be base64 encoded")
    if not s:
        raise ThemeError("no logo was sent")
    if len(s) > MAX_LOGO_BYTES * 4 // 3 + 16:
        raise ThemeError(f"the logo is too large: at most {MAX_LOGO_BYTES // 1024} KB")
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise ThemeError("the logo is not valid base64")
    if len(raw) > MAX_LOGO_BYTES:
        raise ThemeError(f"the logo is too large: at most {MAX_LOGO_BYTES // 1024} KB")
    mime = next((m for sig, m in _MAGIC if raw.startswith(sig)), "")
    if not mime:
        raise ThemeError("the logo must be a PNG, JPEG or GIF image (SVG is not accepted)")
    return {"mime": mime, "b64": base64.b64encode(raw).decode("ascii"), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


# ── the store ───────────────────────────────────────────────────────────
def store_path() -> str:
    env = os.environ.get("DLP_CHECK_BLOCK_PAGE_THEME")
    if env:
        return env
    try:
        import tenant_profiles
        folder = os.path.dirname(os.path.abspath(tenant_profiles.store_path()))
    except Exception:  # noqa: BLE001
        folder = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(folder, STORE_FILE)


def _read() -> Dict[str, Any]:
    try:
        with open(store_path(), "r", encoding="utf-8") as f:
            data = store_crypto.load_json(f)
        if isinstance(data, dict) and isinstance(data.get("themes"), dict):
            return {"version": 1, "themes": {k: v for k, v in data["themes"].items() if isinstance(k, str) and isinstance(v, dict)}}
    except (OSError, ValueError, RecursionError):
        pass
    return {"version": 1, "themes": {}}


def _write(data: Dict[str, Any]) -> None:
    if len(json.dumps(data, separators=(",", ":"))) > MAX_STORE_BYTES:
        raise ThemeError("the theme store is full")
    p = store_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    safe_files.private_makedirs(folder)
    fd, tmp = tempfile.mkstemp(prefix=".block_page_theme.", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            store_crypto.dump_json(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _audit(action: str, name: str, by: str) -> None:
    try:
        import audit
        audit.record("block_page_theme", actor=by or None, action=action, theme=name)
    except Exception as e:  # noqa: BLE001 - the change stands; the lost audit line is reported loudly
        with contextlib.suppress(Exception):
            import audit
            audit.report_failure(f"the block page theme step '{action}'", e)


def _public(name: str, rec: Dict[str, Any]) -> Dict[str, Any]:
    """A stored theme as the page sees it: the logo's facts, never its bytes."""
    logo = rec.get("logo") if isinstance(rec.get("logo"), dict) else None
    return {"name": name, "settings": {**DEFAULTS, **{k: v for k, v in (rec.get("settings") or {}).items() if k in DEFAULTS}},
            "logo": {"mime": logo.get("mime"), "bytes": logo.get("bytes"), "sha256": logo.get("sha256")} if logo else None}


def names() -> List[str]:
    with _LOCK:
        return sorted(_read()["themes"])


def get(name: Any) -> Optional[Dict[str, Any]]:
    n = clean_name(name)
    with _LOCK:
        rec = _read()["themes"].get(n)
    return _public(n, rec) if rec else None


def _raw(name: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        return _read()["themes"].get(name)


def save(name: Any, settings: Any, *, logo: Any = None, by: str = "") -> Dict[str, Any]:
    """Create or replace a theme's settings; `logo` (base64 or data URI) replaces its logo when given."""
    n = clean_name(name)
    s = clean_theme(settings)
    new_logo = clean_logo(logo) if logo else None
    with _LOCK:
        data = _read()
        if n not in data["themes"] and len(data["themes"]) >= MAX_THEMES:
            raise ThemeError(f"at most {MAX_THEMES} themes are kept; delete one first")
        old = data["themes"].get(n) or {}
        data["themes"][n] = {"settings": s, "logo": new_logo or old.get("logo")}
        _write(data)
        out = _public(n, data["themes"][n])
    _audit("save", n, by)
    return out


def remove_logo(name: Any, *, by: str = "") -> Dict[str, Any]:
    n = clean_name(name)
    with _LOCK:
        data = _read()
        if n not in data["themes"]:
            raise ThemeError("there is no such theme", 404)
        data["themes"][n]["logo"] = None
        _write(data)
        out = _public(n, data["themes"][n])
    _audit("remove_logo", n, by)
    return out


def delete(name: Any, *, by: str = "") -> bool:
    n = clean_name(name)
    with _LOCK:
        data = _read()
        if n not in data["themes"]:
            return False
        del data["themes"][n]
        _write(data)
    _audit("delete", n, by)
    return True


# ── colour ──────────────────────────────────────────────────────────────
def _lum(color: str) -> float:
    def ch(v: int) -> float:
        x = v / 255.0
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a: str, b: str) -> float:
    """WCAG 2.2 contrast ratio of two #rrggbb colours (1 to 21)."""
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return round((hi + 0.05) / (lo + 0.05), 2)


def readable_on(bg: str) -> str:
    """Black or white, whichever reads better on `bg` (used for button text)."""
    return "#ffffff" if contrast("#ffffff", bg) >= contrast("#000000", bg) else "#000000"


def review(settings: Dict[str, Any]) -> List[str]:
    """Plain-word warnings about legibility (WCAG AA) and missing pieces."""
    s = {**DEFAULTS, **settings}
    out: List[str] = []
    r = contrast(s["text"], s["card"])
    if r < 4.5:
        out.append(f"Text on the card has contrast {r}:1; WCAG AA asks for at least 4.5:1.")
    r2 = contrast(readable_on(s["accent"]), s["accent"])
    if r2 < 4.5:
        out.append(f"Button text on the accent colour has contrast {r2}:1; pick a darker or lighter accent.")
    r3 = contrast(s["card"], s["background"])
    if r3 < 1.1:
        out.append("The card and the page background are almost the same colour.")
    if not (s["support_email"] or s["support_phone"]):
        out.append("No support contact: blocked users have nobody to ask.")
    if not s["policy_link"]:
        out.append("No link to the acceptable-use policy.")
    return out


# ── the page ────────────────────────────────────────────────────────────
SAMPLE = {"url": "https://example.com/blocked-page", "reason": "Category: Gambling (sample)", "user": "sam.lee@example.com"}
CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def render_html(settings: Dict[str, Any], logo: Optional[Dict[str, Any]] = None, *, sample: bool = True) -> str:
    """A self-contained block page. Every value is escaped; there is no script and no external resource. The logo (when the
    theme shows one) is a data: URI of the stored image. `sample` fills the blocked address and reason with made-up values and
    says so."""
    s = {**DEFAULTS, **settings}
    e = html.escape
    btn = readable_on(s["accent"])
    logo_html = ""
    if s["show_logo"] and logo and logo.get("b64") and logo.get("mime") in ("image/png", "image/jpeg", "image/gif"):
        logo_html = f'<img class="logo" alt="{e(s["org_name"] or "Organization")} logo" src="data:{logo["mime"]};base64,{logo["b64"]}">'
    org = f'<p class="org">{e(s["org_name"])}</p>' if s["show_company_name"] and s["org_name"] else ""
    reason = f'<p class="reason"><strong>Reason:</strong> {e(SAMPLE["reason"])}</p>' if s["show_reason"] else ""
    contact = []
    if s["support_email"]:
        contact.append(f'<a href="mailto:{e(s["support_email"], quote=True)}">{e(s["support_email"])}</a>')
    if s["support_phone"]:
        contact.append(e(s["support_phone"]))
    contact_html = f'<p class="contact">Need help? {" or ".join(contact)}</p>' if contact else ""
    policy = f'<p><a class="btn" href="{e(s["policy_link"], quote=True)}" rel="noopener noreferrer">Read the policy</a></p>' if s["policy_link"] else ""
    note = '<p class="sample">Preview with sample values.</p>' if sample else ""
    msg = "".join(f"<p>{e(line)}</p>" for line in s["message"].split("\n") if line.strip())
    css = (f"body{{margin:0;font:16px/1.5 system-ui,sans-serif;background:{s['background']};color:{s['text']}}}"
           f"main{{max-width:34rem;margin:3rem auto;padding:2rem;background:{s['card']};border-top:6px solid {s['accent']};border-radius:6px}}"
           f"h1{{margin:.5rem 0;font-size:1.5rem}}.logo{{max-height:64px;max-width:240px}}.org{{margin:0;font-weight:600}}"
           f".btn{{display:inline-block;padding:.5rem 1rem;background:{s['accent']};color:{btn};border-radius:4px;text-decoration:none}}"
           f"a{{color:{s['accent']}}}.btn:focus,a:focus{{outline:3px solid {s['text']};outline-offset:2px}}"
           f".sample,.url{{font-size:.85rem;opacity:.85;word-break:break-all}}")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>{e(s['title'])}</title><style>{css}</style></head><body><main>"
            f"{logo_html}{org}<h1>{e(s['title'])}</h1>{msg}"
            f'<p class="url">{e(SAMPLE["url"])}</p>{reason}{policy}{contact_html}{note}</main></body></html>\n')


def settings_for(settings: Dict[str, Any], logo: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The end-user notification settings (ZIA field names) that carry this theme's words and switches. Empty text is not sent
    (a blank would erase what ZIA holds). The logo image is never part of it (see the module docstring)."""
    s = {**DEFAULTS, **settings}
    out: Dict[str, Any] = {"displayReason": bool(s["show_reason"]), "displayCompName": bool(s["show_company_name"]),
                           "displayCompLogo": bool(s["show_logo"] and logo)}
    for ours, theirs in (("message", "customText"), ("support_email", "supportEmail"), ("support_phone", "supportPhone"),
                         ("policy_link", "orgPolicyLink")):
        if s[ours]:
            out[theirs] = s[ours]
    return out


def generate(name: Any = "default", settings: Any = None) -> Dict[str, Any]:
    """Everything a theme produces, read-only. `settings` (unsaved edits) override the stored theme's. Nothing is sent or saved."""
    n = clean_name(name)
    rec = _raw(n) or {}
    s = clean_theme(settings) if settings is not None else {**DEFAULTS, **(rec.get("settings") or {})}
    logo = rec.get("logo") if isinstance(rec.get("logo"), dict) else None
    notes = ["Nothing was sent to the tenant. Applying the settings is a separate Bulk changes operation that asks for write mode, "
             "a named assessor and a typed phrase.",
             "The logo image is not part of the settings: ZIA's API lists no logo field (assumed), so upload it in the ZIA Admin Portal; "
             "the generated HTML below embeds it for a page you host yourself."]
    return {"name": n, "html": render_html(s, logo), "settings": s, "eun_settings": settings_for(s, logo), "warnings": review(s),
            "has_logo": bool(logo), "notes": notes, "csp": CSP}
