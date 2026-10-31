"""POV planner: one proof of value per tenant, planned, run and reported.

A POV (proof of value) holds what the customer and the engineer agreed and
what actually ran:

* the intake: customer name, internal domain, a short prefix generated from
  the name, a vertical preset (Healthcare, Financial services, General
  enterprise, Education) and the products in scope;
* the customer's success criteria, each linked to the tests that prove it;
* a runbook of tests per product (URL filtering, threat, cloud apps,
  firewall, DNS, DLP, SSL, ZPA, ZDX), each with pass or fail, notes and
  evidence;
* a timeline (kickoff, check-ins, end), notes and follow-ups.

Where it is kept. A POV belongs to a saved tenant profile and lives in the
profile's folder: povs/<profile id>.json beside the tenant profiles
(tenant_profiles.pov_path; /data in the container), owner-only, replaced
atomically under a lock, the same convention as workspace_notes.py, and
deleted with its profile. A POV never holds a secret: the tenant is named
by its label ("acme (production)") and, for a classic-API tenant, by its
keyed fingerprint (tenant_fingerprint), never by a client secret,
password, API key or admin login; a secret pasted into its text is masked.

Bound to its tenant. A POV opens only for the tenant it was made for: an
import, an evidence update or a report against another tenant is refused.

Read-only. Nothing here writes to a tenant. "Prove it" asks the Path
analyzer for the verdict the configuration gives a test's destination, and
ZIA Insights for counts, both through the app's existing read-only, scoped
readers; any change to the tenant goes through Deploy policy packs or Bulk
changes, whose deployment records the customer report lists.

The test kit is synthetic: published card-network test numbers (Luhn
valid, never real accounts), Social Security numbers from the block the
Social Security Administration reserved for examples (987-65-4320 to
987-65-4329, never issued), the published specimen Medicare Beneficiary
Identifier and specimen IBANs, invented names on example.com, phone
numbers in the 555-0100 to 555-0199 range set aside for fiction, the
industry-standard EICAR antivirus test string (assembled at run time, so
this source file never carries it) and a harmless PDF that is new every
time it is downloaded. The identifiers come from corpus_engines.sample,
and tests/test_pov.py checks them with corpus_engines' own validators.
"""
from __future__ import annotations

import contextlib
import io
import json
import math
import os
import random
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import safe_files
import store_crypto

try:  # POSIX
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore
try:  # Windows
    import msvcrt  # type: ignore
except ImportError:
    msvcrt = None  # type: ignore

FORMAT = "zscaler-made-easy-pov"
TEMPLATE_FORMAT = "zscaler-made-easy-pov-template"
VERSION = 1
TEMPLATES_FILE = "templates.json"
_LOCK = threading.RLock()

# ── Limits (every field is validated and capped) ────────────────────────
MAX_NAME = 120
MAX_DOMAIN = 253
MAX_TEXT = 2000          # a note, a test's notes
MAX_SHORT = 300          # a criterion, a follow-up, an evidence line
MAX_LABEL = 80
MAX_CRITERIA = 50
MAX_NOTES = 200
MAX_FOLLOW_UPS = 100
MAX_CHECKINS = 30
MAX_EVIDENCE = 20        # per test
MAX_INSIGHTS_RUNS = 5
MAX_TEMPLATES = 50
MAX_POV_BYTES = 1024 * 1024          # one POV, as stored JSON
MAX_IMPORT_BYTES = 1024 * 1024       # an imported POV file
MAX_IMPORT_DEPTH = 12
MAX_TENANT_LABEL = 200

TEST_STATUSES = ("not_run", "pass", "fail", "skipped")
CRITERION_STATUSES = ("pending", "met", "not_met")
POV_STATUSES = ("planning", "testing", "wrapping_up", "closed")
STATUS_WORDS = {"not_run": "Not run", "pass": "Pass", "fail": "Fail", "skipped": "Skipped",
                "pending": "Pending", "met": "Met", "not_met": "Not met",
                "planning": "Planning", "testing": "Testing", "wrapping_up": "Wrapping up", "closed": "Closed"}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_ITEM_ID_RE = re.compile(r"^[a-f0-9]{8,32}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_PREFIX_RE = re.compile(r"^[A-Z0-9]{2,8}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class PovError(ValueError):
    """A refusal the page can show as it is. `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# ── What a POV covers ───────────────────────────────────────────────────
PRODUCTS: Dict[str, str] = {
    "url_filtering": "URL filtering",
    "threat": "Threat protection",
    "cloud_apps": "Cloud apps",
    "firewall": "Firewall",
    "dns": "DNS",
    "dlp": "DLP",
    "ssl": "SSL inspection",
    "zpa": "ZPA",
    "zdx": "ZDX",
}

VERTICALS: Dict[str, Dict[str, Any]] = {
    "healthcare": {
        "label": "Healthcare",
        "description": "Hospital or health system: patient data (PHI) under HIPAA, clinical apps on ZPA, clinicians' experience in ZDX.",
        "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "zpa", "zdx"],
        "criteria": ["Patient records (PHI) uploaded to personal cloud storage or webmail are detected and blocked.",
                     "Known malware and first-seen files are stopped before they reach a clinician's device.",
                     "Clinical web apps keep working: health and banking sites stay private (not inspected) where policy says so.",
                     "Clinical apps are reached through ZPA only, never exposed to the internet."],
    },
    "financial": {
        "label": "Financial services",
        "description": "Bank, insurer or payments: card data (PCI DSS) and customer financial records (GLBA), strict threat and SaaS controls.",
        "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "firewall", "dns"],
        "criteria": ["Card numbers and customer account records leaving through the web or generative AI are detected and blocked.",
                     "Uploads to unsanctioned file sharing and generative AI apps are controlled while reading stays allowed.",
                     "Known malware, phishing and DNS tunnels are blocked and logged.",
                     "Every block names the policy that decided it, for the audit trail."],
    },
    "general": {
        "label": "General enterprise",
        "description": "Any organisation: a balanced baseline across web, threat, SaaS and data protection.",
        "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "firewall"],
        "criteria": ["Risky web categories are blocked and the user sees a block page that names the policy.",
                     "Known malware and first-seen files are stopped.",
                     "Personal data (names with Social Security or card numbers) is detected when it is uploaded.",
                     "Most web traffic is inspected; the exemptions are deliberate and listed."],
    },
    "education": {
        "label": "Education",
        "description": "School district, college or university: student records (FERPA), content filtering, generative AI controls.",
        "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "dns"],
        "criteria": ["Student records uploaded to personal accounts or generative AI are detected.",
                     "Content filtering blocks the categories the district's policy names.",
                     "Malware and phishing are blocked on student and staff devices.",
                     "Learning platforms keep working with inspection on."],
    },
    "federal": {
        "label": "Federal and public sector",
        "description": "Federal agency, contractor or state agency: CUI or federal tax information, a federal compliance profile "
                       "(FedRAMP, CMMC, zero trust, IRS 1075), strict inspection and DNS controls.",
        "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "firewall", "dns", "zpa"],
        "criteria": ["Documents marked CUI (or labelled federal tax information) leaving through the web, webmail or generative AI are "
                     "detected and logged.",
                     "Traffic is denied by default and only approved applications leave; the firewall log names the rule.",
                     "All web traffic is inspected (no privacy exemptions under FedRAMP High) and QUIC is blocked so it stays inspectable.",
                     "DNS goes to the protective resolver and DNS tunnels and risky DNS over HTTPS lookups are blocked.",
                     "Every rule the build creates is mapped to a control of the compliance profile, or says why none applies."],
    },
}
DEFAULT_VERTICAL = "general"
# The one compliance choice (compliance_profiles.py) each vertical starts with.
VERTICAL_COMPLIANCE = {"healthcare": "HIPAA", "financial": "PCI", "general": "", "education": "FERPA", "federal": "FEDRAMP_MOD"}

# Checks a "Prove it" verdict is compared with (path_analyzer.derive_verdict):
CHECKS: Dict[str, str] = {
    "blocked": "The configuration blocks this destination.",
    "inspected": "Traffic reaches Zscaler and is decrypted, so threat and data controls can see it.",
    "reachable": "The site works: traffic reaches Zscaler, is decrypted so the controls can see it, and is not blocked.",
    "dlp": "Traffic is decrypted and a DLP rule inspects uploads to it.",
    "exempt": "Traffic reaches Zscaler but is deliberately not decrypted (a privacy exemption).",
}
# Path analyzer outcomes that cannot agree or disagree: the answer is not known.
_UNDECIDED = ("unknown", "out_of_scope", "conditional")

# Insights sections a test's counts come from (insights.SECTIONS / EXTRA_SECTIONS keys).
INSIGHTS_FOR = {"url_filtering": ["web_action"], "threat": ["web_action"], "ssl": ["web_action"],
                "dlp": ["web_action"], "cloud_apps": ["cloud_apps", "casb_apps"], "firewall": ["fw_action"]}
INSIGHTS_SECTIONS = ("web_action", "cloud_apps", "casb_apps", "fw_action")

EICAR_LINKS = [
    {"label": "EICAR test file download page", "url": "https://www.eicar.org/download-anti-malware-testfile/"},
    {"label": "eicar.com.txt over HTTPS", "url": "https://secure.eicar.org/eicar.com.txt"},
    {"label": "eicar_com.zip (zipped)", "url": "https://secure.eicar.org/eicar_com.zip"},
    {"label": "eicar_com2.zip (a zip inside a zip)", "url": "https://secure.eicar.org/eicar_com2.zip"},
]
AMTSO_LINKS = [
    {"label": "AMTSO security features check (all tests)", "url": "https://www.amtso.org/security-features-check/"},
    {"label": "Download of malware", "url": "https://www.amtso.org/feature-settings-check-download-of-malware/"},
    {"label": "Drive-by download", "url": "https://www.amtso.org/feature-settings-check-drive-by-download-test/"},
    {"label": "Potentially unwanted application", "url": "https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/"},
    {"label": "Phishing page", "url": "https://www.amtso.org/feature-settings-check-phishing-page/"},
]


def _t(tid: str, product: str, title: str, steps: Sequence[str], expect: str, destination: str = "", check: Optional[str] = None,
       prove_note: str = "") -> Dict[str, Any]:
    return {"id": tid, "product": product, "title": title, "steps": list(steps), "expect": expect, "destination": destination,
            "check": check, "insights": list(INSIGHTS_FOR.get(product, [])), "prove_note": prove_note}


_NO_PATH_FW = "The Path analyzer models web traffic; firewall rules for other ports and protocols are proved by the steps and the firewall counts."
_NO_PATH_DNS = "The Path analyzer models web traffic; DNS control is proved by the steps and ZIA's DNS logs."
_NO_PATH_ZPA = "The Path analyzer models internet web traffic; for a private app use ZPA analysis, Diagnose (/report/zpa)."
_NO_PATH_ZDX = "ZDX measures experience, not policy: prove it with the ZDX score and path for the app."

RUNBOOK: List[Dict[str, Any]] = [
    _t("url-block", "url_filtering", "Blocked web category",
       ["On a POV device with Client Connector, browse to a site in a category the policy blocks (for example a gambling site)."],
       "The Zscaler block page appears and names the URL filtering rule.", "www.pokerstars.com", "blocked"),
    _t("url-allowed", "url_filtering", "Business sites keep working",
       ["Browse to a few everyday business sites (news, the customer's own website, a supplier portal)."],
       "Each site opens normally and the visit appears in the web logs.", "www.wikipedia.org", "reachable"),
    _t("threat-eicar", "threat", "Known malware blocked (EICAR)",
       ["Through ZIA, open the EICAR links in the test kit: eicar.com.txt, the zip and the zip inside a zip.",
        "Note the policy each block page names."],
       "Every EICAR download is blocked by malware protection, the zipped ones too.", "secure.eicar.org", "inspected",
       "Malware protection can only see inside HTTPS downloads that are decrypted, so the check is that this site is inspected."),
    _t("threat-amtso", "threat", "Phishing and drive-by pages blocked",
       ["Through ZIA, open the AMTSO security features check pages from the test kit."],
       "Advanced Threat Protection blocks the phishing and drive-by checks; the block page names the policy.", "www.amtso.org", "inspected"),
    _t("threat-sandbox", "threat", "First-seen file held by Cloud Sandbox",
       ["Download the unique sandbox PDF from the test kit (every download is a new file nobody has seen).",
        "Upload it to a file share (OneDrive, Box or Google Drive), then download it again from there through ZIA.",
        "Open the sandbox report in the ZIA admin portal."],
       "The first download is held until the sandbox verdict, then allowed as benign; the sandbox report shows the analysis.",
       "www.dropbox.com", "inspected"),
    _t("apps-genai", "cloud_apps", "Generative AI: chat allowed, uploads controlled",
       ["Open a generative AI app (for example ChatGPT) and send a harmless prompt.", "Try to upload a document to it."],
       "Chat works; the upload is blocked or cautioned as the Cloud App Control rule says.", "chatgpt.com", "reachable"),
    _t("apps-fileshare", "cloud_apps", "File sharing: view, but no upload",
       ["Open a personal file-sharing app and browse files.", "Try to upload a file."],
       "Viewing works; the upload is blocked by the Cloud App Control rule.", "www.dropbox.com", "reachable"),
    _t("fw-nonweb", "firewall", "Non-web traffic to a blocked destination dropped",
       ["From a POV device, try a non-web connection the firewall policy blocks (for example SSH or RDP to an internet host)."],
       "The connection fails and the firewall log shows the rule that dropped it.", prove_note=_NO_PATH_FW),
    _t("fw-quic", "firewall", "QUIC blocked so web traffic stays inspectable",
       ["Open a video site in Chrome and look at chrome://net-internals/#quic (or the protocol column of the Network tab)."],
       "Sessions fall back to HTTP/2 over TCP; no QUIC sessions are made.", prove_note=_NO_PATH_FW),
    _t("dns-tunnel", "dns", "DNS tunnels blocked",
       ["Run a DNS tunnel test tool from a POV device (only with the customer's written approval)."],
       "The tunnel lookups are blocked and logged as DNS tunnel traffic.", prove_note=_NO_PATH_DNS),
    _t("dns-doh", "dns", "DNS over HTTPS controlled",
       ["In a browser, turn on DNS over HTTPS and browse to a few sites."],
       "DNS over HTTPS is blocked or inspected as the DNS control policy says, and the lookups appear in the DNS logs.",
       prove_note=_NO_PATH_DNS),
    _t("dlp-upload", "dlp", "Sensitive data upload detected",
       ["Download the DLP test file for the customer's vertical from the test kit.",
        "Through ZIA, upload it (or paste a few lines) to a test upload page such as https://dlptest.com/http-post/."],
       "Block mode: the upload is blocked and the DLP incident names the engine. Monitor mode: it goes through and the incident is logged.",
       "dlptest.com", "dlp"),
    _t("dlp-genai", "dlp", "Sensitive data pasted into a generative AI prompt",
       ["Paste two or three rows of the DLP test file into a generative AI prompt."],
       "The prompt is blocked or logged by the DLP rule, as the policy says.", "chatgpt.com", "dlp"),
    _t("dlp-webmail", "dlp", "Sensitive data attached to personal webmail",
       ["Attach the DLP test file to a draft in a personal webmail account."],
       "The attachment upload is blocked or logged by the DLP rule.", "mail.google.com", "dlp"),
    _t("ssl-inspect", "ssl", "General web traffic is inspected",
       ["Open a general site and look at its certificate in the browser."],
       "The certificate is issued by Zscaler (the traffic is inspected).", "www.wikipedia.org", "inspected"),
    _t("ssl-exempt", "ssl", "Banking and health sites stay private",
       ["Open an online banking site and look at its certificate."],
       "The bank's own certificate is shown: the site is deliberately not inspected.", "www.chase.com", "exempt"),
    _t("ssl-old-tls", "ssl", "Old TLS versions refused",
       ["Open https://tls-v1-1.badssl.com:1011/ through ZIA."],
       "The connection is refused: TLS 1.0 and 1.1 are below the minimum.", "tls-v1-1.badssl.com",
       prove_note="The Path analyzer shows whether the site is inspected; the TLS version check itself is proved by the steps."),
    _t("zpa-access", "zpa", "Private app reachable through ZPA only",
       ["With Client Connector signed in, open an internal application.",
        "Turn off Private Access in Client Connector and try again."],
       "Reachable with ZPA on, unreachable with it off; the app is never exposed to the internet.", prove_note=_NO_PATH_ZPA),
    _t("zpa-posture", "zpa", "Device posture decides access",
       ["From a device that fails the posture check the access rule needs, open the internal application."],
       "Access is denied for the failing device and allowed for a compliant one.", prove_note=_NO_PATH_ZPA),
    _t("zdx-score", "zdx", "Experience score for a key application",
       ["Use a key SaaS application or join a Teams or Zoom meeting from a POV device.", "Open ZDX and look at the application."],
       "ZDX shows the application's score and the network path, hop by hop.", prove_note=_NO_PATH_ZDX),
]
RUNBOOK_BY_ID: Dict[str, Dict[str, Any]] = {t["id"]: t for t in RUNBOOK}


def _compliance_choices() -> List[Dict[str, str]]:
    import compliance_profiles as cp
    return [{"key": p["key"], "label": p["label"], "group": p["group"]} for p in cp.catalog()["profiles"]]


def catalog() -> Dict[str, Any]:
    """What the page needs to draw the planner (no tenant data)."""
    return {"products": [{"key": k, "label": v} for k, v in PRODUCTS.items()],
            "verticals": [{"key": k, "label": v["label"], "description": v["description"], "products": list(v["products"]),
                           "criteria": list(v["criteria"]), "compliance_profile": VERTICAL_COMPLIANCE.get(k, "")} for k, v in VERTICALS.items()],
            "compliance_profiles": _compliance_choices(),
            "runbook": RUNBOOK, "checks": CHECKS, "test_statuses": list(TEST_STATUSES), "criterion_statuses": list(CRITERION_STATUSES),
            "pov_statuses": list(POV_STATUSES), "status_words": STATUS_WORDS, "kit": kit_catalog(),
            "limits": {"criteria": MAX_CRITERIA, "notes": MAX_NOTES, "follow_ups": MAX_FOLLOW_UPS, "text": MAX_TEXT, "short": MAX_SHORT,
                       "evidence": MAX_EVIDENCE, "import_bytes": MAX_IMPORT_BYTES}}


# ── Validation ──────────────────────────────────────────────────────────
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(text: Any, limit: int, *, multiline: bool = False, what: str = "text") -> str:
    """Printable text (a newline kept where `multiline`), trimmed; longer
    than `limit` is refused rather than silently cut."""
    if text is None:
        return ""
    if not isinstance(text, (str, int, float)) or isinstance(text, bool):
        raise PovError(f"{what} must be text")
    s = "".join(ch for ch in str(text) if (multiline and ch == "\n") or (ch >= " " and ch != "\x7f" and not 0xD800 <= ord(ch) <= 0xDFFF))
    s = s.strip()
    if len(s) > limit:
        raise PovError(f"{what} is too long: at most {limit} characters")
    return s


def _date(value: Any, what: str) -> Optional[str]:
    if value in (None, ""):
        return None
    s = _clean(value, 10, what=what)
    if not _DATE_RE.match(s):
        raise PovError(f"{what} must be a date as YYYY-MM-DD")
    try:
        datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        raise PovError(f"{what} is not a real date")
    return s


def _item_id(value: Any = None) -> str:
    v = str(value or "")
    return v if _ITEM_ID_RE.match(v) else secrets.token_hex(6)


def _list(value: Any, what: str, limit: int) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PovError(f"{what} must be a list")
    if len(value) > limit:
        raise PovError(f"too many {what}: at most {limit}")
    return value


def _obj(value: Any, what: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PovError(f"{what} must be an object")
    return value


def suggest_prefix(name: Any) -> str:
    """A short prefix from the customer name: the initials of a name of
    several words (the first letters of a one-word name), letters and
    digits only, upper case, 2 to 6 characters. "" when nothing fits."""
    words = re.sub(r"[^A-Za-z0-9 ]+", " ", str(name or "")).split()
    words = [w for w in words if w.lower() not in ("the", "of", "and", "inc", "llc", "ltd", "co", "corp", "plc", "gmbh")] or words
    if not words:
        return ""
    initials = "".join(w[0] for w in words)
    s = (initials if len(initials) >= 3 else (initials + words[-1][1:]) if len(words) > 1 else words[0]).upper()[:6]
    return s if len(s) >= 2 else (s + "POV")[:6] if s else ""


def clean_intake(raw: Any) -> Dict[str, Any]:
    d = _obj(raw, "intake")
    customer = _clean(d.get("customer"), MAX_NAME, what="the customer name")
    if not customer:
        raise PovError("enter the customer name")
    domain = _clean(d.get("domain"), MAX_DOMAIN, what="the internal domain").lower().rstrip(".")
    if domain and not _DOMAIN_RE.match(domain):
        raise PovError("the internal domain must be a domain name such as corp.example.com")
    prefix = _clean(d.get("prefix"), 8, what="the prefix").upper() or suggest_prefix(customer)
    if not _PREFIX_RE.match(prefix):
        raise PovError("the prefix must be 2 to 8 letters or digits")
    vertical = str(d.get("vertical") or DEFAULT_VERTICAL)
    if vertical not in VERTICALS:
        raise PovError("pick a vertical: " + ", ".join(v["label"] for v in VERTICALS.values()))
    products = d.get("products")
    products = list(VERTICALS[vertical]["products"]) if products is None else _list(products, "products", len(PRODUCTS))
    bad = [p for p in products if p not in PRODUCTS]
    if bad:
        raise PovError("unknown product: " + ", ".join(str(b)[:40] for b in bad[:3]))
    products = [p for p in PRODUCTS if p in products]
    if not products:
        raise PovError("pick at least one product for the POV")
    import compliance_profiles as cp
    raw_cp = d.get("compliance_profile")
    try:
        compliance = cp.key_of(raw_cp) if raw_cp is not None else VERTICAL_COMPLIANCE.get(vertical, "")
    except cp.ProfileError:
        raise PovError("pick a compliance profile from the list") from None
    return {"customer": customer, "domain": domain, "prefix": prefix, "vertical": vertical, "products": products,
            "compliance_profile": compliance}


def _clean_criteria(raw: Any) -> List[Dict[str, Any]]:
    out = []
    for c in _list(raw, "success criteria", MAX_CRITERIA):
        c = _obj(c, "a success criterion")
        text = _clean(c.get("text"), MAX_SHORT, what="a success criterion")
        if not text:
            continue
        status = str(c.get("status") or "pending")
        if status not in CRITERION_STATUSES:
            raise PovError("a success criterion's status must be pending, met or not met")
        tests = [t for t in _list(c.get("tests"), "linked tests", len(RUNBOOK)) if isinstance(t, str) and t in RUNBOOK_BY_ID]
        out.append({"id": _item_id(c.get("id")), "text": text, "status": status, "tests": sorted(set(tests), key=list(RUNBOOK_BY_ID).index),
                    "note": _clean(c.get("note"), MAX_SHORT, what="a criterion's note")})
    return out


def _clean_evidence_item(e: Any, *, manual_only: bool) -> Optional[Dict[str, Any]]:
    e = _obj(e, "an evidence item")
    kind = str(e.get("kind") or "note")
    if kind not in ("note", "prove", "insights"):
        raise PovError("evidence must be a note, a Prove it verdict or Insights counts")
    if manual_only and kind != "note":
        return None   # system evidence is only ever written by the app itself
    item = {"id": _item_id(e.get("id")), "kind": kind, "at": _clean(e.get("at"), 40, what="a date") or _now(),
            "by": _clean(e.get("by"), MAX_LABEL, what="a name"), "text": _clean(e.get("text"), MAX_SHORT, what="an evidence line")}
    if kind == "note" and not item["text"]:
        return None
    if kind == "prove":
        item["verdict"] = _clean_verdict(e.get("verdict"))
        if e.get("imported"):
            item["imported"] = True
    if kind == "insights":
        item["counts"] = _clean_counts(e.get("counts"))
    return item


def _clean_verdict(v: Any) -> Dict[str, Any]:
    v = _obj(v, "a verdict")
    agrees = v.get("agrees")
    return {"destination": _clean(v.get("destination"), 300, what="a destination"),
            "outcome": _clean(v.get("outcome"), 40, what="an outcome"),
            "headline": _clean(v.get("headline"), 500, what="a headline"),
            "stops_at": _clean(v.get("stops_at"), 120, what="a hop"),
            "decided_by": _clean(v.get("decided_by"), 200, what="a rule name"),
            "decrypted": bool(v.get("decrypted")), "reaches_zscaler": bool(v.get("reaches_zscaler")),
            "categories": [_clean(c, 80, what="a category") for c in _list(v.get("categories"), "categories", 20)],
            "check": v.get("check") if v.get("check") in CHECKS else None,
            "agrees": agrees if isinstance(agrees, bool) else None,
            "not_in_scope": [_clean(c, 80, what="a hop") for c in _list(v.get("not_in_scope"), "hops", 20)]}


def _clean_counts(c: Any) -> Dict[str, Any]:
    c = _obj(c, "counts")
    out: Dict[str, Any] = {"window": _clean(c.get("window"), 80, what="a window"), "sections": {}}
    for key, sec in _obj(c.get("sections"), "sections").items():
        if key not in INSIGHTS_SECTIONS:
            continue
        sec = _obj(sec, "a section")
        rows = []
        for r in _list(sec.get("rows"), "rows", 10):
            r = _obj(r, "a row")
            total = r.get("total")
            rows.append({"name": _clean(r.get("name"), 120, what="a name"),
                         "total": total if isinstance(total, (int, float)) and not isinstance(total, bool)
                         and (isinstance(total, int) or math.isfinite(total)) else None})
        out["sections"][key] = {"title": _clean(sec.get("title"), 120, what="a title"), "status": _clean(sec.get("status"), 20, what="a status"),
                                "rows": rows}
    return out


def _clean_tests(raw: Any, *, keep: Optional[Dict[str, Any]] = None, manual_only: bool = True) -> Dict[str, Any]:
    """Per test: status, notes and evidence. With `keep` (the stored tests),
    the app's own evidence (Prove it, Insights) is kept as it was: a page
    can add or remove notes, never forge a verdict."""
    out: Dict[str, Any] = {}
    for tid, t in _obj(raw, "tests").items():
        if tid not in RUNBOOK_BY_ID:
            continue
        t = _obj(t, "a test")
        status = str(t.get("status") or "not_run")
        if status not in TEST_STATUSES:
            raise PovError("a test's result must be not run, pass, fail or skipped")
        ev = [x for x in (_clean_evidence_item(e, manual_only=manual_only) for e in _list(t.get("evidence"), "evidence items", MAX_EVIDENCE * 2)) if x]
        if keep is not None:
            ev = [e for e in (keep.get(tid) or {}).get("evidence", []) if e.get("kind") != "note"] + ev
        out[tid] = {"status": status, "notes": _clean(t.get("notes"), MAX_TEXT, multiline=True, what="a test's notes"),
                    "evidence": ev[-MAX_EVIDENCE:], "updated_at": _clean(t.get("updated_at"), 40, what="a date") or None,
                    "updated_by": _clean(t.get("updated_by"), MAX_LABEL, what="a name")}
    return out


def _clean_timeline(raw: Any) -> Dict[str, Any]:
    t = _obj(raw, "timeline")
    checkins = []
    for c in _list(t.get("checkins"), "check-ins", MAX_CHECKINS):
        c = _obj(c, "a check-in")
        d = _date(c.get("date"), "a check-in date")
        if d:
            checkins.append({"id": _item_id(c.get("id")), "date": d, "label": _clean(c.get("label"), MAX_LABEL, what="a check-in label") or "Check-in"})
    checkins.sort(key=lambda c: c["date"])
    kickoff, end = _date(t.get("kickoff"), "the kickoff date"), _date(t.get("end"), "the end date")
    if kickoff and end and end < kickoff:
        raise PovError("the POV ends before it starts: pick an end date after the kickoff")
    return {"kickoff": kickoff, "end": end, "checkins": checkins}


def _clean_notes(raw: Any) -> List[Dict[str, Any]]:
    out = []
    for n in _list(raw, "notes", MAX_NOTES):
        n = _obj(n, "a note")
        text = _clean(n.get("text"), MAX_TEXT, multiline=True, what="a note")
        if text:
            out.append({"id": _item_id(n.get("id")), "at": _clean(n.get("at"), 40, what="a date") or _now(),
                        "by": _clean(n.get("by"), MAX_LABEL, what="a name"), "text": text})
    return out


def _clean_follow_ups(raw: Any) -> List[Dict[str, Any]]:
    out = []
    for f in _list(raw, "follow-ups", MAX_FOLLOW_UPS):
        f = _obj(f, "a follow-up")
        text = _clean(f.get("text"), MAX_SHORT, what="a follow-up")
        if text:
            out.append({"id": _item_id(f.get("id")), "text": text, "done": bool(f.get("done")), "due": _date(f.get("due"), "a due date"),
                        "owner": _clean(f.get("owner"), MAX_LABEL, what="an owner")})
    return out


def _clean_insights(raw: Any) -> List[Dict[str, Any]]:
    out = []
    for r in _list(raw, "Insights runs", MAX_INSIGHTS_RUNS * 2):
        r = _obj(r, "an Insights run")
        out.append({"at": _clean(r.get("at"), 40, what="a date") or _now(), "by": _clean(r.get("by"), MAX_LABEL, what="a name"),
                    "counts": _clean_counts(r.get("counts")), **({"imported": True} if r.get("imported") is True else {})})
    return out[-MAX_INSIGHTS_RUNS:]


# ── Tenant binding ──────────────────────────────────────────────────────
def binding(creds: Dict[str, Any]) -> Dict[str, str]:
    """What a POV keeps to know its tenant: the label and, for the classic
    API, the keyed fingerprint. Never a secret or the admin login. Needs
    no sign-in."""
    import tenant_auth
    import tenant_fingerprint
    c = tenant_auth.normalize(creds)
    if c["auth_method"] == tenant_auth.LEGACY:
        fp = tenant_fingerprint.fingerprint(c)
        if not fp:
            raise PovError("This classic API sign-in names no tenant yet: enter the admin login in the tenant profile.")
        return {"label": tenant_auth.record_label(c), "fp": fp}
    if not c["vanity_domain"]:
        raise PovError("This tenant profile has no vanity domain: a POV is kept per tenant, so add it to the profile first.")
    label = tenant_auth.record_label(c)
    if len(label) > MAX_TENANT_LABEL or any(ch < " " for ch in label):
        raise PovError("The vanity domain is not one a tenant can have.")
    return {"label": label}


def same_tenant(stored: Dict[str, Any], current: Dict[str, Any]) -> bool:
    """Whether the POV's binding names the tenant of `current` (a binding)."""
    import hmac
    if not isinstance(stored, dict) or stored.get("label") != current.get("label"):
        return False
    if stored.get("fp") or current.get("fp"):
        return bool(stored.get("fp")) and bool(current.get("fp")) and hmac.compare_digest(str(stored["fp"]), str(current["fp"]))
    return True


# ── The store: the tenant profile's folder ──────────────────────────────
def _profile(profile_id: Any) -> Tuple[str, Dict[str, Any]]:
    """(the profile's POV file, the profile). A POV belongs to a saved
    tenant profile: 400 without one, 404 for one that does not exist."""
    import tenant_profiles
    pid = str(profile_id or "").strip()
    if not pid:
        raise PovError("Choose a saved tenant profile: a POV belongs to a tenant profile (save the tenant on the assessment page first).")
    try:
        path = tenant_profiles.pov_path(pid)
    except ValueError:
        raise PovError("That tenant profile cannot hold a POV: its id is not a profile id.", 404)
    prof = tenant_profiles.get(pid)
    if not prof:
        raise PovError("That tenant profile no longer exists: choose another.", 404)
    return path, prof


def _bind(profile_id: Any, creds: Optional[Dict[str, Any]]) -> Tuple[str, Dict[str, str]]:
    """(POV file, the profile's tenant binding). When the request carries
    sign-in details of its own (`creds`, resolved), they must name the
    profile's tenant: a POV is never opened against another tenant."""
    import tenant_profiles
    path, prof = _profile(profile_id)
    b = binding(tenant_profiles.creds_from(prof))
    if creds is not None and (creds.get("vanity_domain") or creds.get("username")) and not same_tenant(binding(creds), b):
        raise PovError(f"This POV belongs to {b['label']}, but the sign-in names another tenant: a POV opens only for its own tenant.", 409)
    return path, b


@contextlib.contextmanager
def _locked(path: str) -> Iterator[None]:
    """This process's lock, then an exclusive lock on <folder>/.lock."""
    with _LOCK:
        folder = os.path.dirname(path)
        safe_files.private_makedirs(folder)
        fd = os.open(os.path.join(folder, ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no cover - Windows
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            yield
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no cover - Windows
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(fd)


def _read_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        if os.path.getsize(path) > MAX_POV_BYTES * 2:
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = store_crypto.load_json(f)
    except (OSError, ValueError, store_crypto.StoreLocked):
        return None
    return data if isinstance(data, dict) else None


def _write_file(path: str, data: Dict[str, Any]) -> None:
    text = json.dumps(data, indent=1, ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_POV_BYTES:
        raise PovError(f"the POV is larger than {MAX_POV_BYTES // 1024} KB: remove old notes or evidence first", 413)
    with contextlib.suppress(Exception):   # a last-good copy for self_heal; never stops a write
        import self_heal
        self_heal.keep_last_good(path)
    safe_files.write_private_atomic(path, store_crypto.seal_text(text))


def _audit(action: str, label: str, by: str, **extra: Any) -> None:
    try:
        import audit
        audit.record("pov", actor=by or None, action=action, tenant=label, **extra)
    except Exception as e:  # noqa: BLE001 - the POV stands; the lost audit line is reported loudly
        try:
            import audit
            audit.report_failure(f"the POV step '{action}'", e)
        except Exception:  # noqa: BLE001
            pass


def _load(path: str, b: Dict[str, str]) -> Optional[Dict[str, Any]]:
    data = _read_file(path)
    if data is None:
        return None
    if not same_tenant(data.get("tenant") or {}, b):
        raise PovError("This POV was made for another tenant than the profile now names: it opens only for the tenant it was made for. "
                       "Put the profile's tenant back, or delete the POV and start a new one.", 409)
    return data


def get(profile_id: Any, creds: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, str], Optional[Dict[str, Any]]]:
    """(binding, the profile's POV or None). Never reads the tenant."""
    path, b = _bind(profile_id, creds)
    return b, _load(path, b)


def require(profile_id: Any, creds: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """(binding, POV) or PovError 404 when the profile has none."""
    b, pov = get(profile_id, creds)
    if pov is None:
        raise PovError("This tenant profile has no POV yet: open the POV planner and start one first.", 404)
    return b, pov


def _mask(text: str, creds: Optional[Dict[str, Any]]) -> str:
    if not creds or not text:
        return text
    import tenant_auth
    return tenant_auth.mask_secrets(text, creds)


def _mask_tree(value: Any, creds: Optional[Dict[str, Any]]) -> Any:
    """Every string in `value` with any form of the sign-in's secrets masked."""
    if isinstance(value, str):
        return _mask(value, creds)
    if isinstance(value, list):
        return [_mask_tree(v, creds) for v in value]
    if isinstance(value, dict):
        return {k: _mask_tree(v, creds) for k, v in value.items()}
    return value


def _masked(value: Any, profile_id: Any, creds: Optional[Dict[str, Any]]) -> Any:
    """`value` with every form of the request's and the profile's
    remembered secrets masked: a POV never keeps a secret, even pasted."""
    import tenant_profiles
    value = _mask_tree(value, creds)
    try:
        prof = tenant_profiles.get(str(profile_id), with_secret=True) or {}
    except Exception:  # noqa: BLE001 - no remembered secret to look for
        prof = {}
    return _mask_tree(value, tenant_profiles.creds_from(prof)) if prof else value


def _new(b: Dict[str, str], intake: Dict[str, Any], by: str, template: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    v = VERTICALS[intake["vertical"]]
    texts = (template or {}).get("criteria") or v["criteria"]
    now = _now()
    return {"format": FORMAT, "version": VERSION, "tenant": dict(b), "rev": 1, "created_at": now, "updated_at": now, "created_by": by,
            "status": "planning", "intake": intake, "template": (template or {}).get("name") or "",
            "criteria": [{"id": _item_id(), "text": t, "status": "pending", "tests": [], "note": ""} for t in texts][:MAX_CRITERIA],
            "tests": {}, "timeline": {"kickoff": None, "end": None, "checkins": []}, "notes": [], "follow_ups": [], "insights": []}


def _bump(pov: Dict[str, Any]) -> None:
    pov["rev"] = int(pov.get("rev") or 0) + 1
    pov["updated_at"] = _now()


def create(profile_id: Any, creds: Optional[Dict[str, Any]], intake: Any, *, by: str, template_id: str = "") -> Dict[str, Any]:
    """Start the profile's POV (refused when it already has one)."""
    path, b = _bind(profile_id, creds)
    raw = intake if isinstance(intake, dict) else {}
    template = _usable_template(get_template(template_id)) if template_id else None
    if template:
        raw = dict(raw, vertical=raw.get("vertical") or template["vertical"],
                   products=raw.get("products") if raw.get("products") is not None else template["products"])
    clean = _masked(clean_intake(raw if isinstance(intake, dict) else intake), profile_id, creds)
    with _locked(path):
        if _load(path, b) is not None:
            raise PovError("This tenant profile already has a POV: open it, or delete it first.", 409)
        pov = _new(b, clean, by, template)
        _write_file(path, pov)
    _audit("create", b["label"], by, vertical=clean["vertical"], products=len(clean["products"]))
    return pov


EDITABLE = ("intake", "criteria", "tests", "timeline", "notes", "follow_ups", "status")


def update(profile_id: Any, creds: Optional[Dict[str, Any]], rev: Any, changes: Any, *, by: str) -> Dict[str, Any]:
    """Replace the sections in `changes` (intake, criteria, tests, timeline,
    notes, follow_ups, status) after validating them, when `rev` is the
    revision the page last read (409 otherwise: someone else saved)."""
    changes = _obj(changes, "changes")
    unknown = [k for k in changes if k not in EDITABLE]
    if unknown:
        raise PovError("these parts of a POV cannot be edited: " + ", ".join(str(k)[:40] for k in unknown[:5]))
    path, b = _bind(profile_id, creds)
    with _locked(path):
        pov = _load(path, b)
        if pov is None:
            raise PovError("This tenant profile has no POV yet: start one first.", 404)
        if not isinstance(rev, int) or isinstance(rev, bool) or rev != pov.get("rev"):
            raise PovError("The POV was changed in another tab or by someone else since you opened it: reload it and make the change again.", 409)
        clean: Dict[str, Any] = {}
        if "intake" in changes:
            clean["intake"] = clean_intake(changes["intake"])
        if "criteria" in changes:
            clean["criteria"] = _clean_criteria(changes["criteria"])
        if "tests" in changes:
            clean["tests"] = _merge_tests(pov.get("tests") or {}, changes["tests"], by)
        if "timeline" in changes:
            clean["timeline"] = _clean_timeline(changes["timeline"])
        if "notes" in changes:
            clean["notes"] = _attribute(_clean_notes(changes["notes"]), pov.get("notes") or [], by)
        if "follow_ups" in changes:
            clean["follow_ups"] = _clean_follow_ups(changes["follow_ups"])
        if "status" in changes:
            if changes["status"] not in POV_STATUSES:
                raise PovError("the POV status must be planning, testing, wrapping up or closed")
            clean["status"] = changes["status"]
        pov.update(_masked(clean, profile_id, creds))
        if pov["status"] == "planning" and any(t.get("status") not in (None, "not_run") for t in (pov.get("tests") or {}).values()):
            pov["status"] = "testing"
        _bump(pov)
        _write_file(path, pov)
    _audit("update", b["label"], by, parts=sorted(clean))
    return pov


def _merge_tests(stored: Dict[str, Any], raw: Any, by: str) -> Dict[str, Any]:
    """The tests a page sent, merged into the stored ones: status, notes
    and note evidence from the page; the app's own evidence (Prove it)
    kept as stored, so a page can never forge a verdict."""
    tests = _clean_tests(raw, keep=stored)
    for tid, t in tests.items():
        old = stored.get(tid) or {}
        old_ids = [e.get("id") for e in old.get("evidence") or []]
        if (t["status"], t["notes"], [e["id"] for e in t["evidence"]]) != (old.get("status"), old.get("notes"), old_ids):
            t["updated_at"], t["updated_by"] = _now(), by
        else:
            t["updated_at"], t["updated_by"] = old.get("updated_at"), old.get("updated_by", "")
        notes = _attribute([e for e in t["evidence"] if e["kind"] == "note"], old.get("evidence") or [], by)
        t["evidence"] = [e for e in t["evidence"] if e["kind"] != "note"] + notes
    for tid, old in stored.items():   # a test the page did not send stays as it was
        if tid not in tests and tid in RUNBOOK_BY_ID:
            tests[tid] = old
    return tests


def _attribute(notes: List[Dict[str, Any]], stored: Sequence[Any], by: str) -> List[Dict[str, Any]]:
    """Who wrote a note and when come from the app, never from the page: a
    note the page kept as it was keeps its stored author and time, a new or
    edited one is the editor's, now. A note that reuses the id of another
    item (a verdict, a second copy) gets an id of its own."""
    old = {e.get("id"): e for e in stored if isinstance(e, dict)}
    seen = set()
    for n in notes:
        prev = old.get(n["id"])
        if n["id"] in seen or (prev is not None and prev.get("kind", "note") != "note"):
            n["id"], prev = _item_id(), None
        seen.add(n["id"])
        if prev is not None and prev.get("text") == n["text"]:
            n["by"], n["at"] = prev.get("by", ""), prev.get("at") or _now()
        else:
            n["by"], n["at"] = by, _now()
    return notes


def delete(profile_id: Any, creds: Optional[Dict[str, Any]], *, by: str) -> bool:
    path, b = _bind(profile_id, creds)
    with _locked(path):
        if _load(path, b) is None:
            return False
        os.unlink(path)
    _audit("delete", b["label"], by)
    return True


def add_system_evidence(profile_id: Any, creds: Optional[Dict[str, Any]], test_id: str, item: Dict[str, Any], *, by: str) -> Dict[str, Any]:
    """Record a Prove it verdict on a test (the app's own evidence; the
    latest one replaces the one before)."""
    if test_id not in RUNBOOK_BY_ID:
        raise PovError("unknown runbook test", 404)
    path, b = _bind(profile_id, creds)
    with _locked(path):
        pov = _load(path, b)
        if pov is None:
            raise PovError("This tenant profile has no POV yet: start one first.", 404)
        ev = _masked(_clean_evidence_item(dict(item, by=by, at=_now()), manual_only=False), profile_id, creds)
        t = pov.setdefault("tests", {}).setdefault(test_id, {"status": "not_run", "notes": "", "evidence": [], "updated_at": None, "updated_by": ""})
        t["evidence"] = ([e for e in t.get("evidence") or [] if e.get("kind") != "prove"] + [ev])[-MAX_EVIDENCE:]
        _bump(pov)
        _write_file(path, pov)
    _audit("prove", b["label"], by, test=test_id, outcome=(ev or {}).get("verdict", {}).get("outcome"))
    return pov


def add_insights(profile_id: Any, creds: Optional[Dict[str, Any]], counts: Dict[str, Any], *, by: str) -> Dict[str, Any]:
    """Record an Insights counts read on the POV (the latest few are kept)."""
    path, b = _bind(profile_id, creds)
    with _locked(path):
        pov = _load(path, b)
        if pov is None:
            raise PovError("This tenant profile has no POV yet: start one first.", 404)
        pov["insights"] = _clean_insights((pov.get("insights") or []) + [{"at": _now(), "by": by, "counts": counts}])
        pov["insights"][-1] = _masked(pov["insights"][-1], profile_id, creds)
        _bump(pov)
        _write_file(path, pov)
    _audit("insights", b["label"], by)
    return pov


# ── Export and import ───────────────────────────────────────────────────
def export(pov: Dict[str, Any]) -> Dict[str, Any]:
    """The POV as a file: everything it holds (there is no secret in it)."""
    out = json.loads(json.dumps(pov))
    out["format"], out["version"], out["exported_at"] = FORMAT, VERSION, _now()
    return out


def _depth(value: Any, limit: int) -> int:
    """Nesting depth, iteratively (a hostile file cannot recurse the parser's caller)."""
    stack = [(value, 1)]
    deepest = 0
    while stack:
        v, d = stack.pop()
        deepest = max(deepest, d)
        if deepest > limit:
            return deepest
        if isinstance(v, dict):
            stack.extend((x, d + 1) for x in v.values())
        elif isinstance(v, list):
            stack.extend((x, d + 1) for x in v)
    return deepest


def parse_import(text: Any) -> Dict[str, Any]:
    """An exported POV file, untrusted: size, JSON, depth, format, version,
    then every field through the same validators as an edit. Unknown
    fields are dropped. Raises PovError in plain words."""
    if not isinstance(text, str) or not text.strip():
        raise PovError("choose an exported POV file (.json) to import")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_IMPORT_BYTES:
        raise PovError(f"the file is larger than {MAX_IMPORT_BYTES // 1024} KB, more than any exported POV", 413)
    try:
        data = safe_files.strict_json_loads(text)   # NaN or Infinity kept would break every later read of the POV
    except (ValueError, RecursionError):
        raise PovError("the file is not JSON: export the POV again and import that file")
    if not isinstance(data, dict):
        raise PovError("the file is not an exported POV")
    if _depth(data, MAX_IMPORT_DEPTH) > MAX_IMPORT_DEPTH:
        raise PovError(f"the file is nested more than {MAX_IMPORT_DEPTH} levels deep, which no exported POV is")
    if data.get("format") != FORMAT:
        raise PovError("the file is not an exported POV (its format is not " + FORMAT + ")")
    if data.get("version") != VERSION:
        raise PovError("the file was exported by a version of the POV planner this app does not read")
    tenant = _obj(data.get("tenant"), "the tenant")
    label = _clean(tenant.get("label"), MAX_TENANT_LABEL, what="the tenant")
    if not label:
        raise PovError("the file does not say which tenant the POV is for")
    fp = _clean(tenant.get("fp"), 64, what="the tenant")
    status = data.get("status") if data.get("status") in POV_STATUSES else "planning"
    created = _start_time(data.get("created_at"))
    return {"format": FORMAT, "version": VERSION, "tenant": {"label": label, **({"fp": fp} if fp else {})},
            "created_at": created, "created_by": _clean(data.get("created_by"), MAX_LABEL, what="a name"),
            "status": status, "intake": clean_intake(data.get("intake")), "template": _clean(data.get("template"), MAX_LABEL, what="a template"),
            "criteria": _clean_criteria(data.get("criteria")), "tests": _imported(_clean_tests(data.get("tests"), manual_only=False)),
            "timeline": _clean_timeline(data.get("timeline")), "notes": _clean_notes(data.get("notes")),
            "follow_ups": _clean_follow_ups(data.get("follow_ups")),
            "insights": [dict(r, imported=True) for r in _clean_insights(data.get("insights"))]}


def _start_time(value: Any) -> str:
    """An imported POV's start: a real time no later than now. It decides
    which of this app's changes the customer report lists, so a start set
    in the future (every change hidden) or not a time is refused."""
    s = _clean(value, 40, what="the start time")
    if not s:
        return _now()
    try:
        when = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise PovError("the file's start time (created_at) is not a date and time: export the POV again and import that file")
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    if when > datetime.fromisoformat(_now()):
        raise PovError("the file's start time (created_at) is in the future, which no exported POV is")
    return when.astimezone(timezone.utc).isoformat(timespec="seconds")


def _imported(tests: Dict[str, Any]) -> Dict[str, Any]:
    """A verdict in an imported file is marked as imported: this app did
    not record it, so the report says where it came from."""
    for t in tests.values():
        for e in t.get("evidence") or []:
            if e.get("kind") == "prove":
                e["imported"] = True
    return tests


def import_pov(profile_id: Any, creds: Optional[Dict[str, Any]], text: Any, *, replace: bool, by: str) -> Dict[str, Any]:
    """Import an exported POV into a tenant profile. A file made for
    another tenant is refused (409); a profile that has a POV keeps it
    unless `replace` is set."""
    path, b = _bind(profile_id, creds)
    data = parse_import(text)
    if not same_tenant(data["tenant"], b):
        raise PovError(f"This POV was made for {data['tenant']['label']}, not for {b['label']}: a POV opens only for its own tenant. "
                       "Choose that tenant's profile to import it, or start a new POV here (a template carries the plan without the customer).", 409)
    data = _masked(data, profile_id, creds)
    with _locked(path):
        existing = _load(path, b)
        if existing is not None and not replace:
            raise PovError("This tenant profile already has a POV: tick Replace to overwrite it with the file.", 409)
        data["rev"] = int((existing or {}).get("rev") or 0) + 1
        data["updated_at"] = _now()
        data["tenant"] = dict(b)
        _write_file(path, data)
    _audit("import", b["label"], by, replaced=existing is not None)
    return data


# ── Templates (the plan without the customer) ───────────────────────────
def _templates_path() -> str:
    """templates.json in the POV folder beside the tenant profiles."""
    import tenant_profiles
    return os.path.join(os.path.dirname(os.path.abspath(tenant_profiles.store_path())), tenant_profiles.POV_DIR, TEMPLATES_FILE)


def _read_templates() -> List[Dict[str, Any]]:
    data = _read_file(_templates_path()) or {}
    rows = data.get("templates") if isinstance(data.get("templates"), list) else []
    return [t for t in rows if isinstance(t, dict) and _ID_RE.match(str(t.get("id") or ""))]


def list_templates() -> List[Dict[str, Any]]:
    return sorted(_read_templates(), key=lambda t: str(t.get("name") or "").lower())


def get_template(tid: Any) -> Dict[str, Any]:
    tid = str(tid or "")
    for t in _read_templates():
        if t.get("id") == tid:
            return t
    raise PovError("No such template.", 404)


def _usable_template(t: Dict[str, Any]) -> Dict[str, Any]:
    """A stored template as a POV starts from it: templates.json is a file
    on disk, so its vertical, products and criteria are checked like any
    input (an unknown vertical is the default, a bad criterion dropped)."""
    texts = []
    for c in t.get("criteria") if isinstance(t.get("criteria"), list) else []:
        with contextlib.suppress(PovError):
            c = _clean(c, MAX_SHORT, what="a success criterion") if isinstance(c, str) else ""
            if c:
                texts.append(c)
    return {"name": _clean(t.get("name"), MAX_LABEL, what="the template name") if isinstance(t.get("name"), str) else "",
            "vertical": t.get("vertical") if t.get("vertical") in VERTICALS else DEFAULT_VERTICAL,
            "products": [p for p in t.get("products") if isinstance(p, str) and p in PRODUCTS] or None
            if isinstance(t.get("products"), list) else None,
            "criteria": texts[:MAX_CRITERIA]}


def save_template(pov: Dict[str, Any], name: Any, description: Any, *, by: str) -> Dict[str, Any]:
    """A template from a POV: its vertical, products and success criteria
    texts. Never the customer, domain, prefix, tenant, results or notes."""
    name = _clean(name, MAX_LABEL, what="the template name")
    if not name:
        raise PovError("name the template")
    intake = pov.get("intake") or {}
    tpl = {"format": TEMPLATE_FORMAT, "id": re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] + "-" + secrets.token_hex(3),
           "name": name, "description": _clean(description, MAX_SHORT, what="the description"),
           "vertical": intake.get("vertical") if intake.get("vertical") in VERTICALS else DEFAULT_VERTICAL,
           "products": [p for p in intake.get("products") or [] if p in PRODUCTS],
           "criteria": [c["text"] for c in pov.get("criteria") or [] if c.get("text")][:MAX_CRITERIA],
           "created_at": _now(), "created_by": by}
    if not _ID_RE.match(tpl["id"]):
        tpl["id"] = "template-" + secrets.token_hex(3)
    with _locked(_templates_path()):
        rows = _read_templates()
        if len(rows) >= MAX_TEMPLATES:
            raise PovError(f"there are already {MAX_TEMPLATES} templates: delete one first")
        rows.append(tpl)
        _write_file(_templates_path(), {"version": 1, "templates": rows})
    _audit("template_save", "", by, template=tpl["id"])
    return tpl


def delete_template(tid: Any, *, by: str) -> bool:
    tid = str(tid or "")
    with _locked(_templates_path()):
        rows = _read_templates()
        keep = [t for t in rows if t.get("id") != tid]
        if len(keep) == len(rows):
            return False
        _write_file(_templates_path(), {"version": 1, "templates": keep})
    _audit("template_delete", "", by, template=tid[:60])
    return True


# ── Prove it (Path analyzer) and Insights counts ───────────────────────
def prove_evidence(test: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """The evidence item a Path analyzer result gives a runbook test: the
    verdict in a few fields and whether the configuration agrees with
    what the test expects (None when the analyzer could not tell)."""
    v = result.get("verdict") or {}
    d = result.get("destination") or {}
    outcome = str(v.get("outcome") or "")
    check = test.get("check")
    agrees: Optional[bool] = None
    if check and outcome not in _UNDECIDED:
        decrypted = bool(v.get("decrypted")) and bool(v.get("reaches_zscaler"))
        agrees = {"blocked": outcome == "blocked",
                  "inspected": outcome == "blocked" or (decrypted and outcome != "bypassed"),
                  # a site that must keep working: a block is a failure, not proof of inspection
                  "reachable": decrypted and outcome not in ("blocked", "bypassed"),
                  "dlp": outcome in ("enforce", "monitor"),
                  "exempt": outcome == "blind"}[check]
    verdict = {"destination": str(d.get("host") or d.get("input") or test.get("destination") or "")[:300],
               "outcome": outcome, "headline": str(v.get("headline") or "")[:500], "stops_at": str(v.get("stops_at") or "")[:120],
               "decided_by": str(v.get("blocked_by") or "")[:200], "decrypted": bool(v.get("decrypted")),
               "reaches_zscaler": bool(v.get("reaches_zscaler")), "categories": [str(c)[:80] for c in (v.get("categories") or [])[:20]],
               "check": check, "agrees": agrees,
               "not_in_scope": [str(x.get("label") or "")[:80] for x in (v.get("not_in_scope") or [])[:20] if isinstance(x, dict)]}
    words = {True: "The configuration agrees with the expected result.", False: "The configuration does not give the expected result.",
             None: "The analyzer could not tell whether the configuration gives the expected result." if check else "No expected verdict to compare."}
    return {"kind": "prove", "text": f"Path analyzer: {verdict['headline']} {words[agrees]}"[:MAX_SHORT], "verdict": verdict}


def insights_counts(result: Dict[str, Any], window_label: str = "") -> Dict[str, Any]:
    """Counts only (names and totals, at most ten rows a section) from an
    insights.read result; never a user row."""
    out: Dict[str, Any] = {"window": str(window_label or "")[:80], "sections": {}}
    for key, sec in (result.get("sections") or {}).items():
        if key not in INSIGHTS_SECTIONS or not isinstance(sec, dict):
            continue
        rows = []
        for r in (sec.get("rows") or [])[:10]:
            if isinstance(r, dict):
                name = r.get("name") if r.get("name") is not None else r.get("application")
                total = r.get("total") if r.get("total") is not None else r.get("data_consumed")
                rows.append({"name": str(name or "")[:120], "total": total if isinstance(total, (int, float)) and not isinstance(total, bool) else None})
        out["sections"][key] = {"title": str(sec.get("title") or key)[:120], "status": str(sec.get("status") or "")[:20], "rows": rows}
    return out


# ── The test kit (synthetic data only) ──────────────────────────────────
# The values come from corpus_engines' sample generator (published test
# card numbers, reserved SSNs, specimen identifiers), the same module whose
# validators the DLP efficacy corpus test runs; nothing here invents an
# identifier that could belong to someone.
BANNER = ("SYNTHETIC TEST DATA for a Zscaler proof of value, made by Zscaler Made Easy. Not real people or accounts: "
          "card numbers are published card-network test numbers, Social Security numbers are from the block reserved for examples "
          "(987-65-4320 to 987-65-4329, never issued), e-mail addresses are on example.com and phone numbers are in the 555-0100 to "
          "555-0199 range set aside for fiction.")
_STREETS = ("100 Example Street", "22 Sample Avenue", "7 Test Road", "415 Demo Lane")
_CITIES = ("Springfield, IL 62701", "Portland, ME 04101", "Austin, TX 78701", "Denver, CO 80202")
_ICD10 = (("E11.9", "Type 2 diabetes mellitus without complications"), ("I10", "Essential (primary) hypertension"),
          ("J45.909", "Unspecified asthma, uncomplicated"), ("M54.5", "Low back pain"), ("F41.1", "Generalized anxiety disorder"),
          ("K21.9", "Gastro-esophageal reflux disease without esophagitis"), ("N18.3", "Chronic kidney disease, stage 3"))
SSN_NOTE = ("The Social Security numbers are from the reserved block 987-65-4320 to 987-65-4329. A strict SSN dictionary that "
            "checks the area number does not count them; if the SSN rule does not fire on this file, the card numbers and the other "
            "identifiers still prove detection.")

KIT_FILES: Dict[str, Dict[str, str]] = {
    "dlp-healthcare.csv": {"vertical": "healthcare", "label": "Healthcare: patient records (PHI)",
                           "why": "Names with dates of birth, medical record numbers, the specimen Medicare identifier, ICD-10 diagnoses and reserved SSNs."},
    "dlp-financial.csv": {"vertical": "financial", "label": "Financial services: card and account records (PCI DSS, GLBA)",
                          "why": "Card-network test card numbers with expiry, a test routing number, account numbers, specimen IBANs and reserved SSNs."},
    "dlp-education.csv": {"vertical": "education", "label": "Education: student records (FERPA)",
                          "why": "Student IDs, dates of birth, grades, accommodations and reserved SSNs."},
    "dlp-federal.csv": {"vertical": "federal", "label": "Federal and public sector: CUI and federal tax information",
                        "why": "Documents with CUI banner and category markings and the federal tax information label, with names, "
                               "reserved SSNs and dates of birth."},
    "dlp-general.csv": {"vertical": "general", "label": "General enterprise: personal data (PII)",
                        "why": "Names with reserved SSNs, dates of birth, addresses, test card numbers, phone numbers and e-mail addresses."},
    "eicar.com.txt": {"vertical": "", "label": "EICAR antivirus test file",
                      "why": "The industry-standard, harmless antivirus test string. Your own antivirus may remove this download at once: that "
                             "proves the device's antivirus, not ZIA. To test ZIA, open the EICAR links below through ZIA."},
    "sandbox-unique.pdf": {"vertical": "", "label": "Unique harmless PDF for Cloud Sandbox",
                           "why": "A small PDF that is new on every download (its hash has never been seen), to show first-seen quarantine."},
}


def kit_catalog() -> Dict[str, Any]:
    return {"files": [{"id": k, **v} for k, v in KIT_FILES.items()], "eicar_links": EICAR_LINKS, "amtso_links": AMTSO_LINKS,
            "ssn_note": SSN_NOTE,
            "how": ("Downloads from this app never pass through Zscaler: they come from this computer. Upload the DLP files to a test "
                    "page or a personal account through ZIA, and upload the sandbox PDF to a file share and download it again through ZIA.")}


def eicar() -> str:
    """The EICAR antivirus test string, assembled from reversed parts so
    this source file never carries it (a scanner on the machine the app is
    installed on would otherwise quarantine pov.py)."""
    parts = ("$}7)CC7)^P(45XZP\\4[PA@%P!O5X", "-DRADNATS-RACIE", "*H+H$!ELIF-TSET-SURIVITNA")
    return "".join(p[::-1] for p in parts)


def _csv(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> bytes:
    import csv_safe
    buf = io.StringIO()
    buf.write(f"# {BANNER}\r\n")
    w = csv_safe.writer(buf, lineterminator="\r\n")   # no cell starts a spreadsheet formula
    w.writerow(header)
    for row in rows:
        w.writerow(row)
    return buf.getvalue().encode("utf-8")


def dlp_rows(vertical: str, rng: Optional[random.Random] = None, n: int = 12) -> Tuple[List[str], List[List[Any]]]:
    """(header, rows) of synthetic records for a vertical, from
    corpus_engines.sample. `rng` (random.Random) is injected in tests."""
    import corpus_engines as ce
    r = rng if rng is not None else random.SystemRandom()
    s = lambda key, i: ce.sample(key, i, r)  # noqa: E731
    if vertical == "healthcare":
        header = ["Patient", "Date of birth", "Medical record number", "Medicare MBI", "SSN", "ICD-10 diagnosis", "Diagnosis", "Phone"]
        rows = [[s("name", i), s("date_of_birth", i), f"MRN-TEST-{r.randint(100000, 999999)}", s("mbi", i), s("ssn", i),
                 _ICD10[i % len(_ICD10)][0], _ICD10[i % len(_ICD10)][1], s("phone", i)] for i in range(n)]
    elif vertical == "financial":
        header = ["Customer", "Card number", "Expiry", "CVV", "Routing number", "Account number", "IBAN", "SSN", "Balance (USD)"]
        rows = [[s("name", i), s("credit_card", i), f"{r.randint(1, 12):02d}/{r.randint(30, 35)}", f"{r.randint(0, 999):03d}",
                 s("aba", i), f"TEST{r.randint(10 ** 7, 10 ** 8 - 1)}", s("iban", i), s("ssn", i),
                 f"{r.randint(100, 250000)}.{r.randint(0, 99):02d}"] for i in range(n)]
    elif vertical == "education":
        header = ["Student", "Student ID", "Date of birth", "SSN", "GPA", "Course", "Grade", "Accommodation", "Parent e-mail"]
        rows = [[s("name", i), f"STU-TEST-{r.randint(100000, 999999)}", f"{r.randint(2004, 2012)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                 s("ssn", i), f"{r.randint(150, 400) / 100:.2f}", r.choice(("MATH-101", "BIO-210", "HIST-150", "ENG-120")),
                 r.choice(("A", "B+", "C", "F")), r.choice(("None", "Extended time", "Reader")), s("email", i + 3)] for i in range(n)]
    elif vertical == "federal":
        header = ["Name", "SSN", "Date of birth", "Marking", "Document"]
        marks = ("CUI//SP-PRVCY", "CUI", "CONTROLLED UNCLASSIFIED INFORMATION", "FEDERAL TAX INFORMATION - IRC 6103")
        docs = ("Personnel record (synthetic)", "Form W-2 (synthetic)", "Account Transcript (synthetic)", "Case file (synthetic)")
        rows = [[s("name", i), s("ssn", i), s("date_of_birth", i), marks[i % len(marks)], docs[i % len(docs)]] for i in range(n)]
    elif vertical == "general":
        header = ["Name", "SSN", "Date of birth", "Street", "City", "Card number", "Phone", "E-mail"]
        rows = [[s("name", i), s("ssn", i), s("date_of_birth", i), r.choice(_STREETS), r.choice(_CITIES), s("credit_card", i),
                 s("phone", i), s("email", i)] for i in range(n)]
    else:
        raise PovError("No such test file.", 404)
    return header, rows


def sandbox_pdf(nonce: Optional[str] = None) -> bytes:
    """A harmless one-page PDF, built with the app's PDF writer, whose
    nonce makes its hash new on every download."""
    import pdf_writer
    nonce = nonce or secrets.token_hex(16)
    doc = pdf_writer.PdfDocument(title="Cloud Sandbox test file", footer=f"Sandbox test {nonce[:12]}", subject="Harmless test file")
    doc.heading("Cloud Sandbox test file")
    doc.paragraph("This is a harmless PDF for a Zscaler proof of value. It contains only this text and a random value, so every "
                  "download is a file no sandbox has seen before: the first download through ZIA is held until the Cloud Sandbox "
                  "verdict, then allowed as benign.")
    doc.key_values([("Unique value", nonce)])
    return doc.to_bytes()


def kit_file(file_id: str, *, rng: Optional[random.Random] = None, nonce: Optional[str] = None) -> Tuple[bytes, str, str]:
    """(content, media type, download name) of one test kit file."""
    spec = KIT_FILES.get(str(file_id or ""))
    if spec is None:
        raise PovError("No such test file.", 404)
    if file_id == "eicar.com.txt":
        return eicar().encode("ascii"), "text/plain; charset=us-ascii", "eicar.com.txt"
    if file_id == "sandbox-unique.pdf":
        nonce = nonce or secrets.token_hex(16)
        return sandbox_pdf(nonce), "application/pdf", f"zscaler-pov-sandbox-{nonce[:8]}.pdf"
    header, rows = dlp_rows(spec["vertical"], rng)
    return _csv(header, rows), "text/csv; charset=utf-8", f"zscaler-pov-{file_id}"


# ── The customer report ─────────────────────────────────────────────────
def changes_made(creds: Dict[str, Any], since: str) -> List[Dict[str, Any]]:
    """What this app changed in the tenant during the POV, from its own
    records: policy-pack deployments and bulk changes recorded for this
    tenant (tenant_fingerprint.same_tenant) at or after `since`."""
    import deployments
    import tenant_auth
    import tenant_fingerprint
    label = tenant_auth.record_label(creds)
    out: List[Dict[str, Any]] = []
    for s in deployments.list_all(label):
        raw = deployments.get(s["id"]) or {}
        if not tenant_fingerprint.same_tenant(raw, creds) or str(s.get("at") or "") < since:
            continue
        kinds = ", ".join(f"{n} {k}{'s' if n != 1 else ''}" for k, n in sorted((s.get("created_by_kind") or {}).items()))
        out.append({"at": s.get("at"), "kind": "Policy pack deployment", "what": ", ".join(s.get("packs") or []) or "policy pack",
                    "detail": f"Created {kinds or 'nothing'}" + (f"; undone {str(s.get('undone_at'))[:10]}" if s.get("undone_at") else ""),
                    "by": s.get("by") or ""})
    for s in deployments.list_operations(label):
        raw = deployments.get_operation(s["id"]) or {}
        if not tenant_fingerprint.same_tenant(raw, creds) or str(s.get("at") or "") < since:
            continue
        counts = s.get("counts") or {}
        n = counts.get("applied") if isinstance(counts, dict) else None
        out.append({"at": s.get("at"), "kind": "Bulk change", "what": str(s.get("title") or s.get("type") or "bulk change"),
                    "detail": (f"{n} item(s) applied" if isinstance(n, int) else str(s.get("status") or ""))
                    + (f"; undone {str(s.get('undone_at'))[:10]}" if s.get("undone_at") else ""), "by": s.get("by") or s.get("actor") or ""})
    out.sort(key=lambda r: str(r.get("at") or ""))
    return out


def report_model(pov: Dict[str, Any], changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What the customer report says, from what actually ran: the tests
    with a result, the criteria, the evidence and the changes made."""
    intake = pov.get("intake") or {}
    tests = pov.get("tests") or {}
    ran, not_run = [], []
    for t in RUNBOOK:
        if t["product"] not in (intake.get("products") or []):
            continue
        res = tests.get(t["id"]) or {}
        status = res.get("status") or "not_run"
        if status == "not_run":
            not_run.append(t)
            continue
        ran.append({"test": t, "status": status, "notes": res.get("notes") or "",
                    "evidence": [e for e in res.get("evidence") or [] if isinstance(e, dict)]})
    counts = {s: sum(1 for r in ran if r["status"] == s) for s in ("pass", "fail", "skipped")}
    crit = pov.get("criteria") or []
    return {"customer": intake.get("customer") or "", "tenant": (pov.get("tenant") or {}).get("label") or "",
            "vertical": VERTICALS.get(intake.get("vertical"), {}).get("label", ""), "prefix": intake.get("prefix") or "",
            "domain": intake.get("domain") or "",
            "products": [PRODUCTS[p] for p in intake.get("products") or [] if p in PRODUCTS], "status": STATUS_WORDS.get(pov.get("status"), ""),
            "timeline": pov.get("timeline") or {}, "criteria": crit, "ran": ran, "not_run": not_run, "counts": counts,
            "criteria_met": sum(1 for c in crit if c.get("status") == "met"),
            "follow_ups": [f for f in pov.get("follow_ups") or [] if not f.get("done")], "changes": changes,
            "insights": (pov.get("insights") or [])[-1:] or [], "generated_at": _now()}


def _evidence_lines(r: Dict[str, Any]) -> List[str]:
    lines = []
    for e in r["evidence"]:
        when = str(e.get("at") or "")[:10]
        if e.get("kind") == "prove":
            v = e.get("verdict") or {}
            agree = {True: "agrees with the expected result", False: "does not give the expected result"}.get(v.get("agrees"), "")
            lines.append(f"Path analyzer ({when}), {v.get('destination', '')}: {v.get('headline', '')}" + (f" The configuration {agree}." if agree else "")
                         + (" (Recorded elsewhere and imported.)" if e.get("imported") else ""))
        elif e.get("kind") == "note":
            lines.append(f"{e.get('text', '')} ({e.get('by') or 'unknown'}, {when})")
    return lines


def _summary_sentence(m: Dict[str, Any]) -> str:
    c = m["counts"]
    total = len(m["ran"])
    s = (f"{total} test{'s' if total != 1 else ''} ran: {c['pass']} passed, {c['fail']} failed"
         + (f", {c['skipped']} skipped" if c["skipped"] else "") + ". ")
    s += f"{m['criteria_met']} of {len(m['criteria'])} success criteria are met. "
    s += (f"{len(m['changes'])} change{'s' if len(m['changes']) != 1 else ''} to the tenant were made through the app during the POV."
          if m["changes"] else "No change to the tenant was made through the app during the POV.")
    return s


def _criterion_tests(m: Dict[str, Any], c: Dict[str, Any]) -> str:
    by = {r["test"]["id"]: r for r in m["ran"]}
    parts = []
    for tid in c.get("tests") or []:
        t = RUNBOOK_BY_ID.get(tid)
        if t:
            parts.append(f"{t['title']}: {STATUS_WORDS.get(by[tid]['status'], '') if tid in by else 'not run'}")
    return "; ".join(parts) or "No test linked"


def _counts_lines(m: Dict[str, Any]) -> List[str]:
    out = []
    for run in m["insights"]:
        counts = run.get("counts") or {}
        for sec in (counts.get("sections") or {}).values():
            rows = ", ".join(f"{r.get('name')}: {r.get('total'):,}" if isinstance(r.get("total"), (int, float)) else str(r.get("name"))
                             for r in sec.get("rows") or [])
            out.append(f"{sec.get('title')}: {rows or 'no data in this window'}")
        if out:
            out.insert(0, f"ZIA Insights, {counts.get('window') or 'window not recorded'}, read {str(run.get('at') or '')[:10]}."
                       + (" (Recorded elsewhere and imported.)" if run.get("imported") else ""))
    return out


def report_document(m: Dict[str, Any]) -> Dict[str, Any]:
    """The customer report as title, summary, details and sections (a
    heading, paragraphs, a table, bullets, sub-items), the shape the Word
    writer (report_docx.pov_report) and the PDF writer
    (report_exports.pov_pdf) both draw."""
    tl = m["timeline"] or {}
    secs: List[Dict[str, Any]] = []
    crit = {"heading": "Success criteria"}
    if m["criteria"]:
        crit["table"] = {"columns": ["Criterion", "Status", "Proved by"], "widths": [4.5, 1.2, 4],
                         "rows": [[c.get("text", ""), STATUS_WORDS.get(c.get("status"), ""), _criterion_tests(m, c)] for c in m["criteria"]]}
    else:
        crit["paragraphs"] = ["No success criteria were recorded."]
    secs.append(crit)
    tests: Dict[str, Any] = {"heading": "Tests that ran"}
    if m["ran"]:
        tests["table"] = {"columns": ["Product", "Test", "Result", "Expected"], "widths": [1.5, 3, 1, 4.5],
                          "rows": [[PRODUCTS[r["test"]["product"]], r["test"]["title"], STATUS_WORDS[r["status"]], r["test"]["expect"]] for r in m["ran"]]}
        tests["items"] = [{"title": f"{r['test']['title']} ({STATUS_WORDS[r['status']]})",
                           "bullets": ([f"Notes: {r['notes']}"] if r["notes"] else []) + _evidence_lines(r)} for r in m["ran"]]
        tests["items"] = [i for i in tests["items"] if i["bullets"]]
    else:
        tests["paragraphs"] = ["No test has a result yet."]
    if m["not_run"]:
        tests["note"] = "Not run: " + "; ".join(t["title"] for t in m["not_run"]) + "."
    secs.append(tests)
    counts = _counts_lines(m)
    if counts:
        secs.append({"heading": "Traffic counts", "bullets": counts})
    ch: Dict[str, Any] = {"heading": "Changes made to the tenant during the POV"}
    if m["changes"]:
        ch["table"] = {"columns": ["Date", "Change", "What", "Detail", "By"], "widths": [1.3, 1.8, 2.5, 3.5, 1.5],
                       "rows": [[str(c.get("at") or "")[:10], c["kind"], c["what"], c["detail"], c["by"]] for c in m["changes"]]}
    else:
        ch["paragraphs"] = ["No change was made through Zscaler Made Easy's deploy or bulk-change flows during the POV."]
    secs.append(ch)
    if m["follow_ups"]:
        secs.append({"heading": "Open follow-ups", "bullets": [f["text"] + (f" (due {f['due']})" if f.get("due") else "")
                                                               + (f", {f['owner']}" if f.get("owner") else "") for f in m["follow_ups"]]})
    return {"title": f"Proof of value: {m['customer'] or 'customer'}", "summary": _summary_sentence(m),
            "footer": f"Zscaler proof of value · {m['customer']} · {m['generated_at'][:10]}",
            "details": [("Customer", m["customer"]), ("Tenant", m["tenant"]), ("Vertical", m["vertical"]),
                        ("Products in scope", ", ".join(m["products"]) or "None"), ("Status", m["status"]),
                        ("Kickoff", tl.get("kickoff") or "Not set"), ("End", tl.get("end") or "Not set"),
                        ("Report made", m["generated_at"][:16].replace("T", " ") + " UTC")],
            "sections": secs}


def report_pdf(m: Dict[str, Any]) -> bytes:
    import report_exports
    return report_exports.pov_pdf(report_document(m))


def report_docx(m: Dict[str, Any]) -> bytes:
    import report_docx as rd
    return rd.pov_report(report_document(m))


def report_filename(m: Dict[str, Any], ext: str) -> str:
    import report_exports
    return f"zscaler_pov_{report_exports.safe_filename_part(m.get('customer'), 'customer', 40)}_{m['generated_at'][:10]}.{ext}"
