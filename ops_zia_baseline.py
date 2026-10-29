"""ZIA security baseline builder and SSL certificate manager: two operation
types on the Bulk changes engine (admin_ops.register), so they share its
scope check before any read, preview with a plan hash, the four gates,
the re-plan before writing, writes through pack_ops, one ZIA activation,
read-back and a recorded Undo.

zia_baseline
    Builds a ZIA security baseline from a tier (Strict, Balanced,
    Permissive, Healthcare zero trust) across URL filtering, Cloud
    Firewall, SSL inspection, Sandbox, DNS Control (Trusted Resolver, DoH
    inspection, geo-blocking), File Type Control, Cloud App Control and the
    Advanced Threat Protection settings, or from a framework captured from
    another tenant (capture(), offered by Export from tenant as the "ZIA
    policy framework" part). Optional compliance overlays (HIPAA, HITRUST,
    NIST 800-53 / 800-171, PCI DSS, CJIS, SOX, FERPA, GDPR) add the
    framework controls each rule supports; every control and every rule
    cites its source. The overlays never change a rule.

    Rule review: each rule can be switched off and its action set to
    Allow, Block or (URL filtering) Isolate; the whole baseline can take
    the tier's defaults, allow all or block all. A rule weaker than its
    tier default is flagged. The Cloud Firewall Allow-Web and Allow-NTP
    rules are locked (always on, always Allow), the DNS Trusted Resolver
    rule's redirect is locked. Names fit ZIA's 31-character limit.
    URL categories, network and cloud applications, isolation profiles,
    the Trusted Resolver gateway and certificates the tenant does not have
    are dropped with a warning; a rule left with nothing to match is
    dropped (it would otherwise match everything). The SSL catch-all (and
    the firewall default deny) always goes last.

    Re-runs match rules by name and update them in place (field by field,
    the preview shows each field before and after). Rules are created
    DISABLED unless the operator ticks "Create the rules enabled"; the ATP
    settings are changed only when that area is picked explicitly (they
    have no disabled state). Every apply that creates a rule, turns one on
    or changes ATP needs the typed phrase, whatever the number of changes
    (admin_ops._finish `confirm_always`): ATP is live as soon as ZIA
    activates, which the app does right after the writes.

ssl_certificate_move
    Lists the SSL inspection rules with the intermediate certificate each
    uses (zia.intermediate_certificates.list_ready_to_use, GET
    /intermediateCaCertificate/readyToUse) and moves the picked Inspect
    (DECRYPT) rules to another ready-to-use certificate. Every move needs
    the typed phrase: inspected sites show certificate errors until devices
    trust the new certificate's root.

Verified against zscaler-sdk-python 1.11.3: services url_filtering,
cloud_firewall_rules, ssl_inspection_rules, sandbox_rules,
cloud_firewall_dns, file_type_control_rule, cloudappcontrol (list_rules,
get_rule, add_rule, update_rule, delete_rule), atp_policy
(get_atp_settings, update_atp_settings), url_categories.list_categories_lite,
cloud_browser_isolation.list_isolation_profiles, cloud_firewall.list_network_apps,
cloud_applications.list_cloud_app_policy, dns_gatways.list_dns_gateways
(natZtrGateway), intermediate_certificates.list_ready_to_use, and the
model fields used below. Enum values (URL categories, network apps, DNS
tunnel apps, file types, Cloud App Control actions) come from Zscaler's
published lists and are checked against the tenant where the SDK can
read them; the others are assumed and the tenant refuses what it lacks.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import pack_channels as pc
import pack_ops as ops

LogFn = Optional[Callable[[str], None]]

TYPE = "zia_baseline"
FAMILY = "zia_baseline_catalog"
CERT_TYPE = "ssl_certificate_move"
CERT_FAMILY = "ssl_certificates"
MAX_NAME = 31            # ZIA rejects rule names longer than 31 characters
DESC_MAX = 255           # bytes; ZIA refuses longer descriptions on several objects
MAX_FRAMEWORK_RULES = 200
FRAMEWORK_FORMAT = "zia-policy-framework"
FRAMEWORK_VERSION = 1
_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$")
_ENUM_RE = re.compile(r"^[A-Za-z0-9_]{1,80}$")

# ---------------------------------------------------------------------------
# Areas: label, how they are read and written, and what puts them in scope
# ---------------------------------------------------------------------------
# policy: the admin_ops.POLICIES key read with admin_ops.read_rules (None:
# read here); channel: the pack_ops channel its writes go through;
# action: the field that holds the rule's action; choose: the actions the
# review offers; domain: compliance_mapping.CONTROL_DOMAINS key(s).
AREAS: Dict[str, Dict[str, Any]] = {
    "firewall": {"label": "Cloud Firewall", "policy": "firewall", "channel": "firewall", "service": "cloud_firewall_rules",
                 "action": "action", "choose": ("ALLOW", "BLOCK"), "domain": ("firewall",)},
    "url": {"label": "URL filtering", "policy": "url_filtering", "channel": pc.URL, "service": "url_filtering",
            "action": "action", "choose": ("ALLOW", "BLOCK", "ISOLATE"), "domain": ("url_filtering",)},
    "ssl": {"label": "SSL inspection", "policy": "ssl_inspection", "channel": pc.SSL, "service": "ssl_inspection_rules",
            "action": None, "choose": (), "domain": ("ssl_inspection",)},
    "sandbox": {"label": "Sandbox", "policy": None, "channel": "sandbox", "service": "sandbox_rules",
                "action": None, "choose": (), "domain": ("malware_threat",)},
    "dns": {"label": "DNS Control", "policy": None, "channel": "dns", "service": "cloud_firewall_dns",
            "action": "action", "choose": ("ALLOW", "BLOCK"), "domain": ("firewall", "malware_threat")},
    "ftc": {"label": "File Type Control", "policy": "file_type_control", "channel": pc.FILE_TYPE, "service": "file_type_control_rule",
            "action": "filtering_action", "choose": ("ALLOW", "BLOCK"), "domain": ("malware_threat", "dlp")},
    "cac": {"label": "Cloud App Control", "policy": "cloud_app_control", "channel": pc.CLOUD_APP, "service": "cloudappcontrol",
            "action": "actions", "choose": ("ALLOW", "BLOCK"), "domain": ("dlp", "url_filtering")},
    "atp": {"label": "Advanced Threat Protection", "policy": None, "channel": None, "service": "atp_policy",
            "action": None, "choose": (), "domain": ("malware_threat",)},
}
AREA_ORDER = ("firewall", "url", "ssl", "sandbox", "dns", "ftc", "cac", "atp")
RULE_AREAS = tuple(a for a in AREA_ORDER if a != "atp")
# Areas the Scope page must put in scope: the admin_ops policy, or ZIA platform.
_PLATFORM_AREAS = ("sandbox", "dns", "atp")
DEFAULT_AREAS = tuple(a for a in AREA_ORDER if a != "atp")   # ATP only when picked: it has no disabled state

TIERS: Dict[str, Dict[str, str]] = {
    "strict": {"label": "Strict", "what": "Maximum protection: blocks high-risk and non-business categories, inspects all TLS (TLS 1.2 minimum), "
                                          "default-deny firewall, full Advanced Threat Protection."},
    "balanced": {"label": "Balanced", "what": "Blocks high-risk categories, cautions on bandwidth and productivity loss, exempts health and "
                                              "finance sites from TLS inspection for privacy, inspects the rest."},
    "permissive": {"label": "Permissive", "what": "Blocks only legal-liability, privacy and security risks; no TLS inspection (the weakest "
                                                  "tier: most inline controls cannot see encrypted traffic)."},
    "healthcare": {"label": "Healthcare zero trust", "what": "For hospitals and clinics: global rules only (no user or group targeting), "
                                                             "blocks file hosting and personal webmail, isolates unknown sites, exempts "
                                                             "finance, health and government sites from TLS inspection, inspects the rest."},
}

# ---------------------------------------------------------------------------
# Sources: every rule and every control cites one
# ---------------------------------------------------------------------------
SOURCES: Dict[str, Dict[str, str]] = {
    "cis": {"title": "CIS Critical Security Controls v8", "url": "https://www.cisecurity.org/controls/v8"},
    "nistcsf": {"title": "NIST Cybersecurity Framework 2.0", "url": "https://www.nist.gov/cyberframework"},
    "sp80052": {"title": "NIST SP 800-52 Rev. 2: Guidelines for TLS implementations (TLS 1.2 or later)",
                "url": "https://csrc.nist.gov/pubs/sp/800/52/r2/final"},
    "cisadns": {"title": "CISA: Protective Domain Name System resolver",
                "url": "https://www.cisa.gov/resources-tools/services/protective-domain-name-system-resolver"},
    "zssandbox": {"title": "Zscaler: Recommended Sandbox policy", "url": "https://help.zscaler.com/zia/recommended-sandbox-policy"},
    # Overlay documents
    "hipaa": {"title": "HIPAA Security Rule, 45 CFR Part 164 Subpart C",
              "url": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C"},
    "hitrust": {"title": "HITRUST CSF", "url": "https://hitrustalliance.net/hitrust-framework"},
    "sp80053": {"title": "NIST SP 800-53 Rev. 5", "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
    "sp800171": {"title": "NIST SP 800-171 Rev. 3", "url": "https://csrc.nist.gov/pubs/sp/800/171/r3/final"},
    "pci": {"title": "PCI DSS v4.0", "url": "https://www.pcisecuritystandards.org/document_library/"},
    "cjis": {"title": "FBI CJIS Security Policy", "url": "https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center"},
    "sox": {"title": "Sarbanes-Oxley Act of 2002, Section 404", "url": "https://www.govinfo.gov/content/pkg/PLAW-107publ204/pdf/PLAW-107publ204.pdf"},
    "ferpa": {"title": "FERPA, 34 CFR Part 99", "url": "https://www.ecfr.gov/current/title-34/subtitle-A/part-99"},
    "gdpr": {"title": "GDPR, Regulation (EU) 2016/679", "url": "https://eur-lex.europa.eu/eli/reg/2016/679/oj"},
}

# Overlays: the framework's key in compliance_mapping.CONTROL_DOMAINS
# (cm_key) or its own controls per control domain here (HITRUST, CJIS, SOX
# and FERPA are not in compliance_mapping).
OVERLAYS: Dict[str, Dict[str, Any]] = {
    "HIPAA": {"label": "HIPAA", "source": "hipaa", "cm_key": "HIPAA"},
    "HITRUST": {"label": "HITRUST CSF", "source": "hitrust", "controls": {
        "url_filtering": ["01.v (Information Access Restriction)", "09.m (Network Controls)"],
        "firewall": ["01.n (Network Connection Control)", "09.m (Network Controls)"],
        "ssl_inspection": ["09.m (Network Controls)"],
        "malware_threat": ["09.j (Controls Against Malicious Code)"],
        "dlp": ["01.v (Information Access Restriction)", "09.s (Information Exchange Policies and Procedures)"]}},
    "NIST_800_53": {"label": "NIST 800-53", "source": "sp80053", "cm_key": "NIST_800_53"},
    "NIST_800_171": {"label": "NIST 800-171", "source": "sp800171", "cm_key": "NIST_800_171"},
    "PCI": {"label": "PCI DSS", "source": "pci", "cm_key": "PCI_DSS"},
    "CJIS": {"label": "CJIS", "source": "cjis", "controls": {
        "url_filtering": ["5.10.1.1 (Boundary Protection)"],
        "firewall": ["5.10.1.1 (Boundary Protection)"],
        "ssl_inspection": ["5.10.1.2 (Encryption)", "5.10.1.1 (Boundary Protection)"],
        "malware_threat": ["5.10.4.2 (Malicious Code Protection)"],
        "dlp": ["5.10.1.1 (Boundary Protection)"]}},
    "SOX": {"label": "SOX", "source": "sox", "controls": {
        "url_filtering": ["Section 404 (internal control: IT general controls, logical access)"],
        "firewall": ["Section 404 (internal control: IT general controls, network security)"],
        "ssl_inspection": ["Section 404 (internal control: IT general controls, monitoring)"],
        "malware_threat": ["Section 404 (internal control: IT general controls, malware protection)"],
        "dlp": ["Section 404 (internal control: protection of financial data)"]}},
    "FERPA": {"label": "FERPA", "source": "ferpa", "controls": {
        "url_filtering": ["34 CFR 99.31(a)(1)(ii) (reasonable methods to limit access to education records)"],
        "dlp": ["34 CFR 99.31(a)(1)(ii) (reasonable methods to limit access to education records)"]}},
    "GDPR": {"label": "GDPR", "source": "gdpr", "cm_key": "GDPR"},
}

# ---------------------------------------------------------------------------
# The rule catalog
# ---------------------------------------------------------------------------
LEGAL_LIABILITY = ["OTHER_ADULT_MATERIAL", "ADULT_THEMES", "LINGERIE_BIKINI", "NUDITY", "PORNOGRAPHY", "SEXUALITY", "ADULT_SEX_EDUCATION",
                   "K_12_SEX_EDUCATION", "SOCIAL_ADULT", "OTHER_DRUGS", "MARIJUANA", "GAMBLING", "OTHER_ILLEGAL_OR_QUESTIONABLE",
                   "COPYRIGHT_INFRINGEMENT", "COMPUTER_HACKING", "QUESTIONABLE", "PROFANITY", "MATURE_HUMOR", "ANONYMIZER",
                   "MILITANCY_HATE_AND_EXTREMISM", "TASTELESS", "VIOLENCE", "WEAPONS_AND_BOMBS"]
PRIVACY_RISK = ["OTHER_SECURITY", "ADWARE_OR_SPYWARE", "ENCR_WEB_CONTENT", "DYNAMIC_DNS", "NEWLY_REVIVED_DOMAINS"]
BANDWIDTH_LOSS = ["STREAMING_MEDIA", "RADIO_STATIONS", "TELEVISION_AND_MOVIES", "MUSIC", "ENTERTAINMENT",
                  "OTHER_ENTERTAINMENT_AND_RECREATION", "NEWS_AND_MEDIA"]
PRODUCTIVITY_LOSS = ["OTHER_GAMES", "SOCIAL_NETWORKING_GAMES", "SPECIALIZED_SHOPPING", "ONLINE_AUCTIONS", "OTHER_SHOPPING_AND_AUCTIONS",
                     "SOCIAL_NETWORKING", "SPORTS"]
SECURITY_RISK = ["NEWLY_REG_DOMAINS", "NON_CATEGORIZABLE", "P2P_COMMUNICATION", "REMOTE_ACCESS"]
MISC_UNKNOWN = ["MISCELLANEOUS_OR_UNKNOWN", "OTHER_MISCELLANEOUS"]
HIGH_RISK_COUNTRIES = ["COUNTRY_CN", "COUNTRY_RU", "COUNTRY_KP", "COUNTRY_IR"]
ALL_METHODS = ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE"]
BROWSERS = ["OPERA", "FIREFOX", "MSIE", "MSEDGE", "CHROME", "SAFARI", "MSCHREDGE"]
SANDBOX_PROTOCOLS = ["FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
SANDBOX_CATEGORIES = ["ADWARE_BLOCK", "BOTMAL_BLOCK", "ANONYP2P_BLOCK", "RANSOMWARE_BLOCK", "OFFSEC_TOOLS_BLOCK", "SUSPICIOUS_BLOCK"]
ALL = ("strict", "balanced", "permissive", "healthcare")


def _tiers(value: Any, tiers: Sequence[str] = ALL, **per_tier: Any) -> Dict[str, Any]:
    out = {t: copy.deepcopy(value) for t in tiers}
    out.update({k: copy.deepcopy(v) for k, v in per_tier.items()})
    return {k: v for k, v in out.items() if v is not None}


def _r(key: str, area: str, suffix: str, title: str, tiers: Dict[str, Any], fields: Dict[str, Any], sources: Sequence[str], **flags: Any) -> Dict[str, Any]:
    return {"key": key, "area": area, "suffix": suffix, "title": title, "tiers": tiers, "fields": fields, "sources": list(sources),
            "locked": flags.get("locked", ""), "action_locked": flags.get("action_locked", ""), "catch_all": bool(flags.get("catch_all")),
            "default_on": flags.get("default_on", True), "risky": flags.get("risky", "")}


CATALOG: List[Dict[str, Any]] = [
    # Cloud Firewall (evaluated in this order; the default deny goes last)
    _r("fw.geo_out", "firewall", "FW-Geo-Block-Out", "Drop SSH, RDP and FTP to high-risk countries (China, Russia, North Korea, Iran)",
       _tiers("BLOCK_DROP"), {"nw_applications": ["SSH", "RDP", "FTP"], "dest_countries": HIGH_RISK_COUNTRIES}, ["cis"]),
    _r("fw.geo_in", "firewall", "FW-Geo-Block-In", "Drop SSH, RDP and FTP coming from high-risk countries",
       _tiers("BLOCK_DROP"), {"nw_applications": ["SSH", "RDP", "FTP"], "source_countries": HIGH_RISK_COUNTRIES}, ["cis"]),
    _r("fw.quic", "firewall", "FW-Block-QUIC", "Block QUIC so browsers fall back to TLS over TCP, which SSL inspection can see",
       _tiers("BLOCK_DROP"), {"nw_applications": ["QUIC"]}, ["cis", "nistcsf"]),
    _r("fw.allow_web", "firewall", "FW-Allow-Web", "Allow HTTP, HTTPS, HTTP/2, DNS and SSL",
       _tiers("ALLOW"), {"nw_applications": ["HTTP", "HTTPS", "HTTP2", "DNS", "SSL"]}, ["cis"],
       locked="keeps the internet working: always on, always Allow"),
    _r("fw.allow_ntp", "firewall", "FW-Allow-NTP", "Allow NTP for time synchronisation",
       _tiers("ALLOW"), {"nw_applications": ["NTP"]}, ["cis"], locked="keeps clocks in sync (authentication and logs depend on it): always on, always Allow"),
    _r("fw.collab", "firewall", "FW-Allow-Collab", "Allow collaboration apps (Zoom, Webex, GoTo, Skype, SIP and RTP)",
       _tiers("ALLOW"), {"nw_applications": ["ZOOM", "WEBEX", "GOTOMEETING", "SKYPE", "SKYPE_FOR_BUSINESS", "SIP", "RTP", "RTCP"]}, ["cis"]),
    _r("fw.enterprise", "firewall", "FW-Allow-Enterprise", "Allow enterprise services (LDAP, Kerberos, RADIUS, SNMP, DHCP, ICMP, SSH, RDP, OCSP)",
       _tiers("ALLOW"), {"nw_applications": ["LDAP", "LDAPS", "KRB5", "RADIUS", "SNMP", "DHCP", "ICMP", "SSH", "RDP", "OCSP"]}, ["cis"]),
    _r("fw.p2p", "firewall", "FW-Block-P2P", "Block peer-to-peer file sharing applications",
       _tiers("BLOCK_DROP", ("strict", "healthcare")),
       {"nw_applications": ["BITTORRENT", "EDONKEY", "GNUTELLA", "KAZAA", "ARES", "DIRECTCONNECT", "THUNDER", "SLSK", "PANDO", "IMESH", "APPLEJUICE"]},
       ["cis"]),
    _r("fw.tunnels", "firewall", "FW-Block-Tunnels", "Block tunnelling and proxy-evasion applications (Tor, Ultrasurf, Psiphon, OpenVPN ...)",
       _tiers("BLOCK_DROP", ("strict", "healthcare")),
       {"nw_applications": ["TOR", "ULTRASURF", "PSIPHON", "OPENVPN", "HTTPTUNNEL", "SOCKS2HTTP", "TEREDO"]}, ["cis", "nistcsf"]),
    _r("fw.default_deny", "firewall", "FW-Default-Deny", "Default deny: drop all traffic the rules above do not allow",
       _tiers("BLOCK_DROP", ("strict",)), {}, ["cis"], catch_all=True),
    # URL filtering
    _r("url.legal", "url", "URL-Legal-Liability", "Legal-liability class: adult content, gambling, drugs, hate, violence, anonymizers",
       _tiers("BLOCK"), {"url_categories": LEGAL_LIABILITY}, ["cis"]),
    _r("url.privacy", "url", "URL-Privacy-Risk", "Privacy-risk class: spyware and adware, dynamic DNS, revived domains",
       _tiers("BLOCK", ("strict", "balanced", "permissive")), {"url_categories": PRIVACY_RISK}, ["cis"]),
    _r("url.security", "url", "URL-Security-Risk", "Security-risk sites: newly registered domains, uncategorisable, P2P and remote access",
       _tiers("BLOCK", ("strict", "balanced", "permissive")), {"url_categories": SECURITY_RISK}, ["cis"]),
    _r("url.security_global", "url", "URL-Security-Global", "Critical security categories, including newly registered domains",
       _tiers("BLOCK", ("healthcare",)), {"url_categories": PRIVACY_RISK + ["NEWLY_REG_DOMAINS"]}, ["cis"]),
    _r("url.misc", "url", "URL-Misc-Unknown", "Miscellaneous and unknown sites open in Cloud Browser Isolation (Caution without an isolation profile)",
       _tiers("ISOLATE"), {"url_categories": MISC_UNKNOWN}, ["cis", "nistcsf"]),
    _r("url.bandwidth", "url", "URL-Bandwidth-Loss", "Streaming media and entertainment",
       _tiers(None, (), strict="BLOCK", balanced="CAUTION"), {"url_categories": BANDWIDTH_LOSS}, ["cis"]),
    _r("url.productivity", "url", "URL-Productivity-Loss", "Games, shopping, social networking and sports",
       _tiers(None, (), strict="BLOCK", balanced="CAUTION"), {"url_categories": PRODUCTIVITY_LOSS}, ["cis"]),
    _r("url.filehost_webmail", "url", "URL-FileHost-Webmail", "File hosting and personal webmail (approved services are allowed in Cloud App Control)",
       _tiers("BLOCK", ("healthcare",)), {"url_categories": ["FILE_HOST", "EMAIL_HOST"]}, ["cis"]),
    _r("url.new_domains", "url", "URL-New-Domains", "Caution page for newly registered or revived domains (phishing risk)",
       _tiers("CAUTION", ("healthcare",)), {"url_categories": ["NEWLY_REG_DOMAINS", "NEWLY_REVIVED_DOMAINS"]}, ["cis"]),
    _r("url.remote_access", "url", "URL-Remote-Access", "Remote access tools and anonymizers often used in ransomware attacks",
       _tiers("BLOCK", ("healthcare",)), {"url_categories": ["REMOTE_ACCESS", "ANONYMIZER"]}, ["cis"]),
    _r("url.genai", "url", "URL-GenAI-Caution", "Caution page for AI and ML applications",
       _tiers("CAUTION", ("healthcare",)), {"url_categories": ["AI_ML_APPS"]}, ["nistcsf"]),
    _r("url.translation", "url", "URL-Translation", "Public translation services, where pasted text (patient data) leaves the organisation",
       _tiers("BLOCK", ("healthcare",)), {"url_categories": ["TRANSLATORS"]}, ["nistcsf"]),
    _r("url.p2p", "url", "URL-P2P", "Peer-to-peer communication sites",
       _tiers("BLOCK", ("healthcare",)), {"url_categories": ["P2P_COMMUNICATION"]}, ["cis"]),
    # SSL inspection (the catch-all always goes last)
    _r("ssl.exempt_health", "ssl", "SSL-Exempt-Health", "Do not inspect health sites (patient privacy)",
       _tiers("DO_NOT_DECRYPT", ("balanced",)), {"url_categories": ["HEALTH"]}, ["nistcsf"]),
    _r("ssl.exempt_finance", "ssl", "SSL-Exempt-Finance", "Do not inspect financial institutions (user privacy)",
       _tiers("DO_NOT_DECRYPT", ("balanced",)), {"url_categories": ["FINANCE"]}, ["nistcsf"]),
    _r("ssl.exempt_fhg", "ssl", "SSL-Exempt-Fin-Health-Gov", "Do not inspect finance, health and government sites",
       _tiers("DO_NOT_DECRYPT", ("healthcare",)), {"url_categories": ["FINANCE", "HEALTH", "GOVERNMENT", "OTHER_GOVERNMENT_AND_POLITICS"]}, ["nistcsf"]),
    _r("ssl.catch_all", "ssl", "SSL-Catch-All", "Inspect all remaining TLS traffic, TLS 1.2 minimum, OCSP check, block undecryptable traffic",
       _tiers("DECRYPT", permissive="DO_NOT_DECRYPT"), {"url_categories": [], "min_tls": "TLS_1_2"}, ["sp80052", "nistcsf"], catch_all=True,
       risky="Permissive: no TLS inspection, so URL filtering, DLP, sandbox and malware scanning cannot see encrypted traffic."),
    # Sandbox
    _r("sb.office_pdf", "sandbox", "SB-Office-PDF", "Office and PDF files: quarantine and isolate while the sandbox analyses them",
       _tiers("QUARANTINE_ISOLATE"),
       {"file_types": ["FTCATEGORY_MS_EXCEL", "FTCATEGORY_MS_WORD", "FTCATEGORY_MS_RTF", "FTCATEGORY_MS_POWERPOINT", "FTCATEGORY_PDF_DOCUMENT"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"], "ml_action_enabled": True}, ["zssandbox", "cis"]),
    _r("sb.executables", "sandbox", "SB-Executables", "Executables and scripts: allow and scan on first download, AI Instant Verdict on",
       _tiers("ALLOW_SCAN", ("strict", "balanced", "healthcare")),
       {"file_types": ["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_WINDOWS_LIBRARY", "FTCATEGORY_POWERSHELL", "FTCATEGORY_VISUAL_BASIC_SCRIPT"],
        "protocols": ["HTTPS_RULE", "HTTP_RULE"], "ml_action_enabled": True}, ["zssandbox", "cis"]),
    _r("sb.archives", "sandbox", "SB-Archives-Other", "Archives and other risky file types: quarantine on first download",
       _tiers("QUARANTINE"),
       {"file_types": ["FTCATEGORY_ZIP", "FTCATEGORY_RAR", "FTCATEGORY_TAR", "FTCATEGORY_BZIP2", "FTCATEGORY_P7Z", "FTCATEGORY_ISO",
                       "FTCATEGORY_HTA", "FTCATEGORY_MICROSOFT_INSTALLER", "FTCATEGORY_BAT", "FTCATEGORY_WINDOWS_SCRIPT_FILES",
                       "FTCATEGORY_APK", "FTCATEGORY_PYTHON"], "protocols": SANDBOX_PROTOCOLS, "ml_action_enabled": True}, ["zssandbox", "cis"]),
    # DNS Control
    _r("dns.tunnels_critical", "dns", "DNS-Tunnels-Critical", "Block known malicious DNS tunnels",
       _tiers("BLOCK"), {"applications": ["DNSTUN_MALICIOUS"], "protocols": ["ANY_RULE"]}, ["cisadns", "cis"]),
    _r("dns.tunnels_high", "dns", "DNS-Tunnels-High", "Block the other DNS tunnel categories",
       _tiers("BLOCK", ("strict", "balanced", "healthcare")),
       {"applications": ["DNSTUN_UNKNOWN", "DNSTUN_SOCIAL", "DNSTUN_IM", "DNSTUN_P2P", "DNSTUN_STREAMING", "DNSTUN_MALWARE",
                         "DNSTUN_TUNNELING", "DNSTUN_FILESERVER_TRANSFER", "DNSTUN_REMOTE"], "protocols": ["ANY_RULE"]}, ["cisadns", "cis"]),
    _r("dns.doh", "dns", "DNS-DoH-Inspect", "Inspect DNS over HTTPS: block DoH lookups of newly registered, dynamic DNS and spyware domains",
       _tiers("BLOCK"), {"protocols": ["DOHTTPS_RULE"],
                         "dest_ip_categories": ["NEWLY_REG_DOMAINS", "NEWLY_REVIVED_DOMAINS", "DYNAMIC_DNS", "ADWARE_OR_SPYWARE", "OTHER_SECURITY"]},
       ["cisadns"]),
    _r("dns.geo", "dns", "DNS-Geo-Block", "Block DNS requests sent to resolvers in high-risk countries",
       _tiers("BLOCK", ("strict", "balanced", "healthcare")), {"dest_countries": HIGH_RISK_COUNTRIES, "protocols": ["ANY_RULE"]}, ["cisadns"]),
    _r("dns.resolver", "dns", "DNS-Trusted-Resolver", "Send DNS requests to the Zscaler Trusted Resolver, whatever resolver a device is set to",
       _tiers("REDIR_REQ_KEEP_SENDER"), {"protocols": ["TCP_RULE", "UDP_RULE"], "trusted_resolver": True}, ["cisadns", "cis"],
       action_locked="a redirect, not an allow or block rule: blocking it would block all DNS"),
    # File Type Control
    _r("ftc.db_upload", "ftc", "FTC-DB-Upload", "Block upload of database files (mass exfiltration through exports)",
       _tiers("BLOCK"), {"file_types": ["FTCATEGORY_ACCDB", "FTCATEGORY_SQL", "FTCATEGORY_DBF", "FTCATEGORY_DB", "FTCATEGORY_SDB", "FTCATEGORY_DB2"],
                         "operation": "UPLOAD", "protocols": ["HTTPS_RULE", "HTTP_RULE"]}, ["cis"]),
    _r("ftc.pw_archives", "ftc", "FTC-PW-Archives", "Block password-protected archives, which no scanner can inspect",
       _tiers("BLOCK", ("strict", "healthcare")), {"file_types": ["FTCATEGORY_ZIP", "FTCATEGORY_RAR", "FTCATEGORY_P7Z"],
                                                  "operation": "UPLOAD_DOWNLOAD", "protocols": ["ANY_RULE"], "password_protected": True}, ["cis"]),
    _r("ftc.exe_download", "ftc", "FTC-Exe-Download", "Block download of executables and installers (approved software sources go above)",
       _tiers("BLOCK"), {"file_types": ["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_MICROSOFT_INSTALLER", "FTCATEGORY_APPX"],
                         "operation": "DOWNLOAD", "protocols": ["HTTPS_RULE", "HTTP_RULE"]}, ["cis"]),
    _r("ftc.scripts", "ftc", "FTC-Scripts", "Block upload and download of script files (PowerShell, VBS, BAT, Python, Bash)",
       _tiers("BLOCK", ("strict", "balanced", "healthcare")),
       {"file_types": ["FTCATEGORY_POWERSHELL", "FTCATEGORY_VISUAL_BASIC_SCRIPT", "FTCATEGORY_BAT", "FTCATEGORY_WINDOWS_SCRIPT_FILES",
                       "FTCATEGORY_PYTHON", "FTCATEGORY_BASH_SCRIPTS"], "operation": "UPLOAD_DOWNLOAD", "protocols": ["HTTPS_RULE", "HTTP_RULE"]}, ["cis"]),
    # Cloud App Control: app-specific rules first, so they win over the category-wide ones
    _r("cac.fileshare_view", "cac", "CAC-FileShare-ViewOnly", "Google Drive, Dropbox and Box: open and download, no upload",
       _tiers(["ALLOW_FILE_SHARE_VIEW", "DENY_FILE_SHARE_UPLOAD"]), {"type": "FILE_SHARE", "applications": ["GDRIVE", "DROPBOX", "BOXNET"]}, ["nistcsf"]),
    _r("cac.social_view", "cac", "CAC-Social-ViewNoPost", "Facebook and X: reading allowed, posting blocked",
       _tiers(["ALLOW_SOCIAL_NETWORKING_VIEW", "BLOCK_SOCIAL_NETWORKING_POST"]), {"type": "SOCIAL_NETWORKING", "applications": ["FACEBOOK", "TWITTER"]}, ["nistcsf"]),
    _r("cac.genai_noupload", "cac", "CAC-GenAI-NoUpload", "ChatGPT, Gemini and Copilot: prompts allowed, file uploads blocked",
       _tiers(["ALLOW_AI_ML_WEB_USE", "DENY_AI_ML_UPLOAD"]), {"type": "AI_ML", "applications": ["CHATGPT_AI", "GOOGLE_GEMINI", "MICROSOFT_COPILOT"]}, ["nistcsf"]),
    _r("cac.slack_noupload", "cac", "CAC-Slack-NoUpload", "Slack: chat allowed, file uploads blocked",
       _tiers(["ALLOW_ENTERPRISE_COLLABORATION_CHAT", "BLOCK_ENTERPRISE_COLLABORATION_UPLOAD"]),
       {"type": "ENTERPRISE_COLLABORATION", "applications": ["SLACK"]}, ["nistcsf"]),
    _r("cac.doh", "cac", "CAC-Block-DoH-Apps", "Block every DNS over HTTPS app outright (off by default: DNS Control inspects DoH instead)",
       _tiers(["DENY_DNS_OVER_HTTPS_USE"]), {"type": "DNS_OVER_HTTPS"}, ["cisadns"], default_on=False),
    _r("cac.fileshare", "cac", "CAC-FileShare", "Every other file-sharing app: no viewing, no upload",
       _tiers(["DENY_FILE_SHARE_VIEW", "DENY_FILE_SHARE_UPLOAD"]), {"type": "FILE_SHARE"}, ["cis", "nistcsf"]),
    _r("cac.im", "cac", "CAC-Instant-Messaging", "Instant messaging: block chat (Strict) or file transfer in chat (Balanced)",
       _tiers(["BLOCK_CHAT", "BLOCK_FILE_TRANSFER_IN_CHAT"], ("strict", "healthcare"), balanced=["BLOCK_FILE_TRANSFER_IN_CHAT"]),
       {"type": "INSTANT_MESSAGING"}, ["nistcsf"]),
    _r("cac.social", "cac", "CAC-Social", "Social networking: block (Strict) or read-only",
       _tiers(["ALLOW_SOCIAL_NETWORKING_VIEW", "BLOCK_SOCIAL_NETWORKING_POST"], strict=["BLOCK_SOCIAL_NETWORKING_VIEW", "BLOCK_SOCIAL_NETWORKING_POST"],
              healthcare=["BLOCK_SOCIAL_NETWORKING_VIEW", "BLOCK_SOCIAL_NETWORKING_POST"]), {"type": "SOCIAL_NETWORKING"}, ["nistcsf"]),
    _r("cac.webmail", "cac", "CAC-Webmail", "Personal webmail: no viewing, sending or attachments",
       _tiers(["BLOCK_WEBMAIL_VIEW", "BLOCK_WEBMAIL_ATTACHMENT_SEND", "BLOCK_WEBMAIL_SEND"]), {"type": "WEBMAIL"}, ["cis", "nistcsf"]),
    _r("cac.streaming", "cac", "CAC-Streaming", "Streaming media: block (Strict) or block uploads (Balanced)",
       _tiers(["BLOCK_STREAMING_VIEW_LISTEN"], ("strict", "healthcare"), balanced=["BLOCK_STREAMING_UPLOAD"]), {"type": "STREAMING_MEDIA"}, ["cis"]),
    _r("cac.collab", "cac", "CAC-Collab", "Every other collaboration app (approved ones are allowed above)",
       _tiers(["BLOCK_ENTERPRISE_COLLABORATION_APPS"], ("strict", "healthcare")), {"type": "ENTERPRISE_COLLABORATION"}, ["nistcsf"]),
    _r("cac.ai_ml", "cac", "CAC-AI-ML", "AI and ML apps: block (Strict) or a caution page",
       _tiers(["CAUTION_AI_ML_WEB_USE"], strict=["DENY_AI_ML_WEB_USE"], healthcare=["DENY_AI_ML_WEB_USE"]), {"type": "AI_ML"}, ["nistcsf"]),
]
CATALOG_BY_KEY = {r["key"]: r for r in CATALOG}

# Advanced Threat Protection settings (zscaler-sdk-python
# models/advanced_threat_settings.py), all "block" switches.
ATP_SETTINGS: List[Tuple[str, str]] = [
    ("cmd_ctl_server_blocked", "Block connections to known command-and-control servers"),
    ("cmd_ctl_traffic_blocked", "Block botnet command-and-control traffic to unknown servers"),
    ("malware_sites_blocked", "Block known malicious and compromised sites"),
    ("active_x_blocked", "Block vulnerable ActiveX controls"),
    ("browser_exploits_blocked", "Block known browser exploits"),
    ("file_format_vunerabilites_blocked", "Block file format vulnerabilities (Office, PDF)"),
    ("known_phishing_sites_blocked", "Block known phishing sites"),
    ("suspected_phishing_sites_blocked", "Block suspected phishing sites"),
    ("suspect_adware_spyware_sites_blocked", "Block spyware callback traffic"),
    ("ad_spyware_sites_blocked", "Block adware and spyware sites"),
    ("webspam_blocked", "Block web spam"),
    ("crypto_mining_blocked", "Block cryptomining"),
    ("irc_tunnelling_blocked", "Block IRC tunnelling"),
    ("anonymizer_blocked", "Block anonymizers"),
    ("cookie_stealing_blocked", "Block cookie stealing"),
    ("potential_malicious_requests_blocked", "Block cross-site scripting (XSS) requests"),
    ("bit_torrent_blocked", "Block BitTorrent"),
    ("tor_blocked", "Block Tor"),
    ("ssh_tunnelling_blocked", "Block SSH tunnelling"),
    ("dga_domains_blocked", "Block domains made by domain generation algorithms"),
]
ATP_KEYS = {k for k, _ in ATP_SETTINGS}
# What a rule matches on, per area: a rule other than a catch-all that names
# none of these would match all traffic, so it is dropped (fit).
MATCH_FIELDS: Dict[str, Tuple[str, ...]] = {
    "firewall": ("nw_applications", "dest_countries", "source_countries"), "url": ("url_categories",), "ssl": ("url_categories",),
    "sandbox": ("file_types",), "dns": ("applications", "dest_ip_categories", "dest_countries", "trusted_resolver"),
    "ftc": ("file_types",), "cac": ("type",)}
ATP_TIER_OFF = {"permissive": {"ssh_tunnelling_blocked"}}

# Cloud App Control action bases that take DENY_ rather than BLOCK_ (the
# webApplicationRules action enum).
CAC_DENY_BASES = {"AI_ML_CHAT", "AI_ML_CREATE", "AI_ML_DELETE", "AI_ML_DOWNLOAD", "AI_ML_INVITE", "AI_ML_RENAME", "AI_ML_SHARE",
                  "AI_ML_UPLOAD", "AI_ML_WEB_USE", "DNS_OVER_HTTPS_USE", "FILE_SHARE_CREATE", "FILE_SHARE_DELETE", "FILE_SHARE_DOWNLOAD",
                  "FILE_SHARE_EDIT", "FILE_SHARE_FORM_SHARE", "FILE_SHARE_INVITE", "FILE_SHARE_RENAME", "FILE_SHARE_SHARE",
                  "FILE_SHARE_UPLOAD", "FILE_SHARE_VIEW"}
_CAC_PREFIX = re.compile(r"^(ALLOW|BLOCK|DENY|CAUTION|ISOLATE)_")

NAME_ABBREV = [(r"Exempt", "Ex"), (r"Health", "Hlth"), (r"Finance", "Fin"), (r"Instant-Messaging", "IM"), (r"Productivity", "Prod"),
               (r"Bandwidth", "BW"), (r"Security", "Sec"), (r"Unknown", "Unk"), (r"Archives", "Arch"), (r"Collab", "Colb"),
               (r"Default", "Dflt"), (r"Block", "Blk"), (r"Allow", "Alw"), (r"Trusted", "Trust")]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _snake(key: Any) -> str:
    """camelCase (acronyms included: minClientTLSVersion) -> snake_case."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", str(key))
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def _deep_snake(v: Any) -> Any:
    if isinstance(v, dict):
        return {_snake(k): _deep_snake(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_deep_snake(x) for x in v]
    if hasattr(v, "as_dict"):
        return _deep_snake(v.as_dict())
    return v


def _empty(v: Any) -> bool:
    return v is None or v is False or v == "" or v == [] or v == {}


def _canon(v: Any) -> Any:
    """A comparable form: references by id, lists sorted, empties as None."""
    if _empty(v):
        return None
    if isinstance(v, dict):
        if v.get("id") not in (None, ""):
            return f"id:{v['id']}"
        out = {k: _canon(x) for k, x in sorted(v.items())}
        out = {k: x for k, x in out.items() if x is not None}
        return out or None
    if isinstance(v, (list, tuple, set)):
        items = [_canon(x) for x in v]
        items = [x for x in items if x is not None]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str)) or None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return str(v)
    return str(v)


def same(a: Any, b: Any) -> bool:
    return _canon(a) == _canon(b)


def _flat(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Nested dicts as dotted paths; a reference ({id, ...}) stays one value."""
    out: Dict[str, Any] = {}
    for k, v in (obj or {}).items():
        path = f"{prefix}{k}"
        if isinstance(v, dict) and v.get("id") in (None, "") and v:
            out.update(_flat(v, path + "."))
        else:
            out[path] = v
    return out


def _set_path(body: Dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = body
    for p in parts[:-1]:
        if not isinstance(cur.get(p), dict):
            cur[p] = {}
        cur = cur[p]
    if value is None:
        cur.pop(parts[-1], None)
    else:
        cur[parts[-1]] = copy.deepcopy(value)


def _show(v: Any) -> Any:
    """A value as the preview shows it: short, never a whole object."""
    if isinstance(v, dict):
        if v.get("name") or v.get("id") is not None:
            return str(v.get("name") or v.get("id"))
        return json.dumps(v, sort_keys=True, default=str)[:140]
    if isinstance(v, (list, tuple, set)):
        vals = [str(_show(x)) for x in v]
        txt = ", ".join(sorted(vals))
        return txt if len(txt) <= 140 else txt[:137] + "…"
    return v


def _fit_bytes(text: str, limit: int = DESC_MAX) -> str:
    t = " ".join(str(text or "").split())
    if len(t.encode("utf-8")) <= limit:
        return t
    # Every character is at least one byte: nothing past `limit` characters
    # can fit, so cut there first and the loop below stays bounded (an
    # uploaded framework's title may be megabytes long).
    t = t[:limit]
    while len((t + "…").encode("utf-8")) > limit:
        t = t[:-1]
    return t.rstrip() + "…"


def short_name(prefix: str, suffix: str) -> str:
    """'<prefix>-<suffix>' within ZIA's 31 characters: abbreviate the suffix
    word by word, then cut, so every name keeps the prefix."""
    head = f"{prefix}-" if prefix else ""
    room = MAX_NAME - len(head)
    n = suffix
    for pat, to in NAME_ABBREV:
        if len(n) <= room:
            break
        n = re.sub(pat, to, n)
    if len(n) > room:
        n = n[:room].rstrip("-_ ")
    return head + n


def _unique_names(rows: List[Dict[str, Any]]) -> None:
    used: Dict[str, Set[str]] = {}
    for r in rows:
        bucket = used.setdefault(r["area"] + ":" + str(r["fields"].get("type") or ""), set())
        n, i = r["name"], 2
        while n in bucket:
            tail = f"-{i}"
            n = r["name"][:MAX_NAME - len(tail)].rstrip("-_ ") + tail
            i += 1
        r["name"] = n
        bucket.add(n)


def _is_restrictive(action: Any) -> bool:
    acts = action if isinstance(action, list) else [action]
    return any(re.match(r"^(BLOCK|DENY|CAUTION|ISOLATE|DECRYPT|QUARANTINE)", str(a or "")) for a in acts)


def _cac_base(a: str) -> str:
    return _CAC_PREFIX.sub("", str(a))


def _cac_to(choice: str, actions: List[str]) -> List[str]:
    out = []
    for a in actions:
        base = _cac_base(a)
        new = f"ALLOW_{base}" if choice == "ALLOW" else (("DENY_" if base in CAC_DENY_BASES else "BLOCK_") + base)
        if new not in out:
            out.append(new)
    return out


def _sources(ids: Sequence[str]) -> List[Dict[str, str]]:
    return [dict(SOURCES[s], id=s) for s in ids if s in SOURCES]


def overlay_controls(domains: Sequence[str], overlays: Sequence[str]) -> List[Dict[str, Any]]:
    """The controls each picked overlay maps to the rule's control domains,
    with the document they come from (compliance_mapping for HIPAA, NIST,
    PCI DSS and GDPR)."""
    import compliance_mapping as cm
    out = []
    for key in overlays:
        ov = OVERLAYS.get(key)
        if not ov:
            continue
        ctrls: List[str] = []
        for d in domains:
            src = (cm.CONTROL_DOMAINS.get(d, {}).get(ov["cm_key"]) if ov.get("cm_key") else ov.get("controls", {}).get(d)) or []
            for c in src:
                if c not in ctrls:
                    ctrls.append(c)
        if ctrls:
            out.append({"overlay": key, "label": ov["label"], "controls": ctrls, "source": dict(SOURCES[ov["source"]], id=ov["source"])})
    return out


# ---------------------------------------------------------------------------
# Scope (user rule 1)
# ---------------------------------------------------------------------------

def areas_in_scope(scope: Dict[str, Any]) -> Tuple[List[str], Dict[str, str]]:
    """(areas the Scope page puts in scope, {area: why not})."""
    pols = set(scope.get("policies") or [])
    platform = "zia_extras" in set(scope.get("scopes") or [])
    read, why = [], {}
    for a in AREA_ORDER:
        pol = AREAS[a]["policy"]
        ok = (pol in pols) if pol else platform
        if ok:
            read.append(a)
        else:
            why[a] = ((scope.get("not_in_scope") or {}).get(pol) if pol else None) or \
                f"Not in scope: {'ZIA platform' if not pol else 'its policy'} is not ticked on the Scope page, so the {AREAS[a]['label']} is not read or changed."
    return read, why


def _in_scope(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    """Why the baseline is out of scope, or None. Given the spec (the
    engine's check before sign-in), also every area it names explicitly
    (or its Undo touches) must be in scope: deny by default."""
    read, _ = areas_in_scope(scope)
    if not read:
        return ("Nothing the ZIA baseline builds is in scope on the Scope page: tick ZIA platform (Cloud Firewall, Sandbox, DNS Control, "
                "Advanced Threat Protection) or DLP (URL filtering, File Type Control; mark SSL inspection and Cloud App Control as Zscaler).")
    if not isinstance(spec, dict):
        return None
    if spec.get("action") == "revert":
        steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
        want = ["atp" if s.get("op") == "restore_atp" else s.get("area") for s in steps if isinstance(s, dict)]
    else:
        want = spec.get("areas") if isinstance(spec.get("areas"), list) else []
    out = [AREAS[a]["label"] for a in AREA_ORDER if a in want and a not in read]
    if out:
        return f"Not in scope on the Scope page: {', '.join(out)}. Leave them out of the baseline or tick their scope. Nothing was read."
    return None


def _cert_in_scope(scope: Dict[str, Any]) -> Optional[str]:
    if "ssl_inspection" in set(scope.get("policies") or []):
        return None
    why = (scope.get("not_in_scope") or {}).get("ssl_inspection") or (scope.get("read_blocked") or {}).get("ssl_inspection") or ""
    return ("Not in scope on the Scope page: the SSL certificate manager reads and changes only SSL inspection rules, and they are not "
            "in scope." + (f" {why}" if why else ""))


def capture_scope(scopes: Any, channels: Any) -> List[str]:
    """The rule areas a framework capture may read for a Scope page selection."""
    read, _ = areas_in_scope(ao.scope_for(scopes, channels))
    return [a for a in read if a in CAPTURE_AREAS]


# ---------------------------------------------------------------------------
# Review: the baseline as rules, before anything is read
# ---------------------------------------------------------------------------

def _norm_list(v: Any, what: str) -> List[str]:
    if v in (None, ""):
        return []
    if not isinstance(v, (list, tuple)):
        raise ao.OperationError(f"{what} must be a list.")
    return [str(x) for x in v]


_FIELD_PATH = re.compile(r"[a-z][a-z0-9_]{0,63}(\.[a-z][a-z0-9_]{0,63}){0,4}")
_STEP_ID = re.compile(r"[A-Za-z0-9_.:-]{1,64}")


def _check_step(st: Any) -> None:
    """An undo step is untrusted (it comes back from the page): its shape,
    and only fields a baseline sets (never a rule's id, name or rank)."""
    if not isinstance(st, dict) or st.get("op") not in ("delete", "restore", "restore_atp"):
        raise ao.OperationError("An undo step must be delete, restore or restore_atp.")
    if st["op"] != "restore_atp" and (isinstance(st.get("id"), bool) or not _STEP_ID.fullmatch(str(st.get("id") or ""))
                                      or not isinstance(st.get("name", ""), str) or len(st.get("name") or "") > 128
                                      or not isinstance(st.get("rule_type") or "", str) or len(st.get("rule_type") or "") > 64):
        raise ao.OperationError("An undo step names a rule by its id and name.")
    for k in ("fields", "expect"):
        if not isinstance(st.get(k) if st.get(k) is not None else {}, dict):
            raise ao.OperationError(f"An undo step's {k} must be an object.")
    for f in list((st.get("fields") or {})) + list((st.get("expect") or {})):
        if st["op"] == "restore_atp":
            if f not in ATP_KEYS:
                raise ao.OperationError(f"{str(f)[:60]!r} is not an Advanced Threat Protection setting.")
        elif not isinstance(f, str) or not _FIELD_PATH.fullmatch(f) or f in ("id", "name", "rank"):
            raise ao.OperationError(f"An undo may put back only the fields a baseline sets ({str(f)[:60]!r} is not one).")


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The baseline spec checked: tier, overlays, areas, prefix, choices.
    Raises OperationError for anything that cannot be built."""
    if not isinstance(spec, dict):
        raise ao.OperationError("The baseline must be an object.")
    out: Dict[str, Any] = {"type": TYPE}
    if spec.get("action") == "revert":
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps or len(steps) > 600:
            raise ao.OperationError("An undo names the steps to reverse.")
        for st in steps:
            _check_step(st)
        return {"type": TYPE, "action": "revert", "steps": steps}
    framework = spec.get("framework")
    out["tier"] = str(spec.get("tier") or ("captured" if framework else "balanced")).lower()
    if out["tier"] not in TIERS and not (framework and out["tier"] == "captured"):
        raise ao.OperationError(f"Unknown tier '{str(spec.get('tier'))[:40]}'. Use one of: {', '.join(TIERS)}.")
    out["overlays"] = [o for o in _norm_list(spec.get("overlays"), "overlays")]
    bad = [o for o in out["overlays"] if o not in OVERLAYS]
    if bad:
        raise ao.OperationError(f"Unknown compliance overlay(s): {', '.join(bad)}. Use: {', '.join(OVERLAYS)}.")
    areas = _norm_list(spec.get("areas"), "areas")
    bad = [a for a in areas if a not in AREAS]
    if bad:
        raise ao.OperationError(f"Unknown area(s): {', '.join(bad)}.")
    out["areas"] = [a for a in AREA_ORDER if a in areas] if areas else None
    prefix = str(spec.get("prefix") or "BL").strip()
    if not _PREFIX_RE.fullmatch(prefix):
        raise ao.OperationError("The name prefix is 1 to 10 letters, digits, '-' or '_' (it starts every rule name).")
    out["prefix"] = prefix
    mode = str(spec.get("mode") or "tier").lower()
    if mode not in ("tier", "allow_all", "block_all"):
        raise ao.OperationError("mode is tier, allow_all or block_all.")
    out["mode"] = mode
    rules = spec.get("rules") or {}
    if not isinstance(rules, dict):
        raise ao.OperationError("rules is an object of per-rule choices.")
    choices = {}
    for k, v in rules.items():
        if not isinstance(v, dict):
            raise ao.OperationError(f"The choice for {k} must be an object.")
        act = str(v.get("action") or "TIER").upper()
        if act not in ("TIER", "ALLOW", "BLOCK", "ISOLATE"):
            raise ao.OperationError(f"The action for {k} is TIER, ALLOW, BLOCK or ISOLATE.")
        choices[str(k)] = {"on": v.get("on") is not False, "action": act}
    out["rules"] = choices
    atp = spec.get("atp") or {}
    if not isinstance(atp, dict) or any(k not in ATP_KEYS or not isinstance(v, bool) for k, v in atp.items()):
        raise ao.OperationError("atp names Advanced Threat Protection settings with true or false.")
    out["atp"] = dict(atp)
    out["enable_rules"] = spec.get("enable_rules") is True
    for k in ("isolation_profile", "certificate"):
        out[k] = str(spec.get(k) or "")[:120]
    if framework:
        out["framework"] = load_framework(framework)
    return out


def _template_rules(n: Dict[str, Any]) -> List[Dict[str, Any]]:
    if n.get("framework"):
        return copy.deepcopy(n["framework"]["rules"])
    tier = n["tier"]
    out = []
    for r in CATALOG:
        if tier in r["tiers"]:
            x = copy.deepcopy(r)
            x["default"] = x["tiers"][tier]
            out.append(x)
    return out


def review(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Every rule of the baseline with its name, default and chosen action,
    on or off, locked, weakened, its sources and the overlay controls.
    Pure: reads nothing."""
    n = normalize(spec)
    if n.get("action") == "revert":
        raise ao.OperationError("An undo has no review.")
    rows = []
    for r in _template_rules(n):
        area = r["area"]
        meta = AREAS[area]
        ch = n["rules"].get(r["key"], {})
        default = r["default"]
        on = r.get("default_on", True) if "on" not in ch else ch["on"]
        lock = r.get("locked") or ""
        if lock:
            on = True
        choice = ch.get("action") or "TIER"
        if choice == "TIER" and n["mode"] != "tier" and meta["choose"]:
            choice = "ALLOW" if n["mode"] == "allow_all" else "BLOCK"
        if lock or r.get("action_locked") or choice not in meta["choose"]:
            choice = "TIER"
        action = copy.deepcopy(default)
        if choice != "TIER":
            if area == "cac":
                action = _cac_to(choice, list(default))
            elif choice == "ISOLATE":
                action = "ISOLATE"
            elif choice == "ALLOW":
                action = "ALLOW"
            elif choice == "BLOCK":
                action = default if _is_restrictive(default) and not str(default).startswith(("CAUTION", "ISOLATE")) else (
                    "BLOCK_DROP" if area == "firewall" else "BLOCK")
        weakened = ""
        if _is_restrictive(default) and not on and r.get("default_on", True):
            weakened = "switched off"
        elif _is_restrictive(default) and not _is_restrictive(action):
            weakened = f"{_act_label(default)} → {_act_label(action)}"
        elif str(default).startswith("BLOCK") and action in ("ISOLATE", "CAUTION"):
            weakened = f"{_act_label(default)} → {_act_label(action)}"   # isolation and a caution page both let the user in
        domains = list(meta["domain"])
        if area == "ftc" and r["fields"].get("operation") == "DOWNLOAD":
            domains = ["malware_threat"]
        rows.append({"key": r["key"], "area": area, "area_label": meta["label"], "suffix": r["suffix"], "title": r["title"],
                     "name": short_name(n["prefix"], r["suffix"]) if not r.get("name") else r["name"][:MAX_NAME],
                     "on": bool(on), "default_on": r.get("default_on", True), "default_action": default, "action": action,
                     "choice": choice, "choices": list(meta["choose"]) if not (lock or r.get("action_locked")) else [],
                     "locked": lock, "action_locked": r.get("action_locked") or "", "weakened": weakened, "catch_all": r.get("catch_all", False),
                     "risky": r.get("risky") if r.get("risky") and not _is_restrictive(action) else "",
                     "fields": r["fields"], "sources": _sources(r.get("sources") or []),
                     "controls": overlay_controls(domains, n["overlays"])})
    _unique_names(rows)
    tier = n["tier"]
    atp = []
    for k, label in ATP_SETTINGS:
        default = k not in ATP_TIER_OFF.get(tier, set())
        value = n["atp"].get(k, default)
        atp.append({"key": k, "label": label, "default": default, "value": value,
                    "weakened": "switched off" if default and not value else ""})
    return {"tier": tier, "tier_label": TIERS.get(tier, {}).get("label", "Captured framework"), "normalized": n, "rules": rows, "atp": atp,
            "atp_controls": overlay_controls(AREAS["atp"]["domain"], n["overlays"]), "atp_sources": _sources(["cis", "nistcsf"])}


def _act_label(a: Any) -> str:
    if isinstance(a, list):
        return "Block" if any(str(x).startswith(("BLOCK", "DENY")) for x in a) else (
            "Caution" if any(str(x).startswith("CAUTION") for x in a) else "Allow")
    return str(a or "").replace("_", " ").capitalize()


def catalog() -> Dict[str, Any]:
    """What the form offers: tiers, overlays, areas and every rule with its
    default per tier. Pure."""
    rules = []
    for r in CATALOG:
        meta = AREAS[r["area"]]
        rules.append({"key": r["key"], "area": r["area"], "suffix": r["suffix"], "title": r["title"], "tiers": r["tiers"],
                      "locked": r["locked"], "action_locked": r["action_locked"], "catch_all": r["catch_all"], "default_on": r["default_on"],
                      "choices": [] if (r["locked"] or r["action_locked"]) else list(meta["choose"]), "sources": _sources(r["sources"])})
    return {"tiers": [{"key": k, **v} for k, v in TIERS.items()],
            "overlays": [{"key": k, "label": v["label"], "source": dict(SOURCES[v["source"]], id=v["source"])} for k, v in OVERLAYS.items()],
            "areas": [{"key": a, "label": AREAS[a]["label"], "choices": list(AREAS[a]["choose"]), "default": a in DEFAULT_AREAS} for a in AREA_ORDER],
            "rules": rules, "atp": [{"key": k, "label": l, "off_in": [t for t, s in ATP_TIER_OFF.items() if k in s]} for k, l in ATP_SETTINGS],
            "area_controls": {a: overlay_controls(AREAS[a]["domain"], list(OVERLAYS)) for a in AREA_ORDER},
            "max_name": MAX_NAME}


# ---------------------------------------------------------------------------
# Payloads (snake_case, as the SDK takes them)
# ---------------------------------------------------------------------------

def _description(row: Dict[str, Any], tier_label: str) -> str:
    cites = "; ".join(s["title"].split(":")[0] for s in row["sources"][:2])
    return _fit_bytes(f"{row['title']}. ZIA baseline: {tier_label}. Source: {cites}.")


def payload(row: Dict[str, Any], facts: Dict[str, Any], tier_label: str, enabled: bool) -> Dict[str, Any]:
    """The rule as the SDK's add_rule takes it (order and rank set on create)."""
    area, f, act = row["area"], row["fields"], row["action"]
    body: Dict[str, Any] = {"name": row["name"], "description": _description(row, tier_label), "state": "ENABLED" if enabled else "DISABLED"}
    if area == "url":
        body.update(action=act, url_categories=list(f.get("url_categories") or []), protocols=list(f.get("protocols") or ["ANY_RULE"]),
                    request_methods=list(ALL_METHODS), block_override=False)
        if act == "CAUTION":
            body["request_methods"] = ["CONNECT", "GET", "HEAD"]
        if act == "ISOLATE":
            prof = facts.get("isolation_profile") or {}
            body.update(protocols=["HTTPS_RULE", "HTTP_RULE"], request_methods=["CONNECT", "GET"], user_agent_types=list(BROWSERS),
                        cbi_profile={k: prof[k] for k in ("id", "name", "url") if prof.get(k) is not None})
    elif area == "firewall":
        body.update(action=act, enable_full_logging=False)
        for k in ("nw_applications", "dest_countries", "source_countries"):
            if f.get(k):
                body[k] = list(f[k])
    elif area == "ssl":
        body.update(road_warrior_for_kerberos=False, platforms=list(pc.SSL_PLATFORMS))
        if f.get("url_categories"):
            body["url_categories"] = list(f["url_categories"])
        if act == "DECRYPT":
            tls = str(f.get("min_tls") or "TLS_1_2")
            action = {"type": "DECRYPT", "override_default_certificate": False,
                      "decrypt_sub_actions": {"server_certificates": "BLOCK", "ocsp_check": True, "block_ssl_traffic_with_no_sni_enabled": True,
                                              "min_client_tls_version": f"CLIENT_{tls}", "min_server_tls_version": f"SERVER_{tls}",
                                              "block_undecrypt": True, "http2_enabled": False}}
            cert = facts.get("certificate")
            if cert and not cert.get("default_certificate"):
                action["override_default_certificate"] = True
                action["ssl_interception_cert"] = {"id": cert["id"], "name": cert.get("name")}
        else:
            action = {"type": "DO_NOT_DECRYPT",
                      "do_not_decrypt_sub_actions": {"server_certificates": "ALLOW", "bypass_other_policies": False, "ocsp_check": False,
                                                     "block_ssl_traffic_with_no_sni_enabled": False}}
        body["action"] = action
    elif area == "sandbox":
        op = act
        prof = facts.get("isolation_profile")
        body.update(protocols=list(f.get("protocols") or SANDBOX_PROTOCOLS), file_types=list(f.get("file_types") or []),
                    ba_policy_categories=list(SANDBOX_CATEGORIES), ba_rule_action="BLOCK", first_time_enable=True,
                    first_time_operation=op, ml_action_enabled=bool(f.get("ml_action_enabled")))
        if op == "QUARANTINE_ISOLATE" and prof:
            body["cbi_profile"] = {k: prof[k] for k in ("id", "name", "url") if prof.get(k) is not None}
    elif area == "dns":
        body.update(action=act, protocols=list(f.get("protocols") or ["ANY_RULE"]))
        for k in ("applications", "dest_ip_categories", "dest_countries"):
            if f.get(k):
                body[k] = list(f[k])
        if f.get("trusted_resolver") and facts.get("trusted_resolver"):
            gw = facts["trusted_resolver"]
            body["dns_gateway"] = {"id": gw["id"], "name": gw.get("name")}
    elif area == "ftc":
        body.update(filtering_action=act, operation=f.get("operation") or "UPLOAD_DOWNLOAD", file_types=list(f.get("file_types") or []),
                    protocols=list(f.get("protocols") or ["ANY_RULE"]))
        if f.get("password_protected") is not None:
            body["password_protected"] = bool(f["password_protected"])
    elif area == "cac":
        body.update(type=f["type"], actions=list(act))
        if f.get("applications"):
            body["applications"] = list(f["applications"])
        if any(str(a).startswith("CAUTION_") for a in act):
            body["user_agent_types"] = list(BROWSERS)   # ZIA: a Caution action applies only to named user agents
    return body


_UNMANAGED = {"name", "order", "rank", "state", "id"}


def managed(body: Dict[str, Any], enable_rules: bool) -> Dict[str, Any]:
    """The flattened fields a re-run keeps as the baseline says (state only
    when the operator asked for enabled rules)."""
    flat = _flat({k: v for k, v in body.items() if k not in _UNMANAGED})
    if enable_rules:
        flat["state"] = "ENABLED"
    return flat


# ---------------------------------------------------------------------------
# Reading the tenant (GET only)
# ---------------------------------------------------------------------------

def _rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    import pack_export
    rows, err = pack_export._rows(ret)
    return [_deep_snake(r) for r in rows], err


def _svc(zia, area: str):
    svc = getattr(zia, AREAS[area]["service"], None)
    if svc is None:
        raise ao.OperationError(f"The installed zscaler-sdk-python has no {AREAS[area]['service']} service.")
    return svc


def read_area(zia, area: str, *, types: Sequence[str] = (), cancel=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every rule of one area (Cloud App Control: of the given types)."""
    ao._check_stop(cancel)
    pol = AREAS[area]["policy"]
    if area == "cac":
        out: List[Dict[str, Any]] = []
        for t in types or pc.CLOUD_APP_TYPES:
            rows, err = ao.read_rules(zia, pol, rule_type=t, cancel=cancel)
            if err:
                return out, err
            out.extend(_deep_snake(r) for r in rows)
        return out, None
    if pol:
        rows, err = ao.read_rules(zia, pol, cancel=cancel)
        return [_deep_snake(r) for r in rows], err
    try:
        return _rows(_svc(zia, area).list_rules())
    except ao.OperationError:
        raise
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def get_one(zia, area: str, rid: Any, rule_type: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One rule, read fresh, with every field the tenant sent: a field the
    SDK model leaves out (SDK 1.11.3's sandbox model has no cbiProfile) is
    taken from the raw answer, as the list reads do (pack_export._rows), so
    the update body written back from it keeps it and read-back sees it."""
    try:
        svc = _svc(zia, area)
        ret = svc.get_rule(rule_type, rid) if area == "cac" else svc.get_rule(rid)
        row, err = ao._one(ret)
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    if not row:
        return None, err
    import pack_export
    row = _deep_snake(row)
    for k, v in _deep_snake(pack_export._plain(_raw_body(ret) or {})).items():
        if row.get(k) in (None, "", [], {}) and v not in (None, "", [], {}):
            row[k] = v
    if area == "cac":
        row["rule_type"] = str(row.get("type") or rule_type)
    return row, err


def _raw_body(ret: Any) -> Optional[Dict[str, Any]]:
    """The JSON object the tenant sent (also the fields the SDK model leaves out), or None."""
    getter = getattr(ret[1], "get_body", None) if isinstance(ret, tuple) and len(ret) >= 3 else None
    try:
        body = getter() if callable(getter) else None
        body = json.loads(body) if isinstance(body, (bytes, str)) and body else body
    except Exception:  # noqa: BLE001 — the model's fields are used alone
        return None
    return body if isinstance(body, dict) else None


def read_atp(zia) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The ATP settings as the SDK model reads them, plus every other field
    the tenant sent, kept under its own (camelCase) name: _h_atp writes the
    whole object back, and a field left out of that PUT could be reset."""
    try:
        ret = _svc(zia, "atp").get_atp_settings()
        row, err = ao._one(ret)
        if row is None:
            return None, err
        row = _deep_snake(row)
        for k, v in (_raw_body(ret) or {}).items():
            if isinstance(k, str) and _snake(k) not in row and k not in row:
                row[k] = v
        return row, err
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def _call_rows(fn: Callable[[], Any]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        return _rows(fn())
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def read_certificates(zia) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Ready-to-use intermediate certificates: id, name, type, status, region,
    default and validity only (never a key or a certificate body)."""
    svc = getattr(zia, "intermediate_certificates", None)
    if svc is None:
        return [], "the installed zscaler-sdk-python has no intermediate_certificates service"
    rows, err = _call_rows(svc.list_ready_to_use)
    keep = ("id", "name", "type", "status", "region", "default_certificate", "cert_start_date", "cert_exp_date", "current_state")
    return [{k: r.get(k) for k in keep if r.get(k) is not None} for r in rows], err


def read_isolation_profiles(zia) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    svc = getattr(zia, "cloud_browser_isolation", None)
    if svc is None:
        return [], "the installed zscaler-sdk-python has no cloud_browser_isolation service"
    rows, err = _call_rows(svc.list_isolation_profiles)
    return [{k: r.get(k) for k in ("id", "name", "url", "default_profile") if r.get(k) is not None} for r in rows], err


def _read_facts(zia, rows: List[Dict[str, Any]], areas: Sequence[str], n: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """What the tenant has that the rules name: URL categories, network
    applications, cloud applications, isolation profiles, the Trusted
    Resolver gateway and certificates. A list that cannot be read leaves
    None (the rules that need it are then dropped: fail closed)."""
    facts: Dict[str, Any] = {"errors": {}}
    need = {r["area"] for r in rows if r["on"]}

    def get(key: str, label: str, fn: Callable[[], Tuple[List[Dict[str, Any]], Optional[str]]]) -> Optional[List[Dict[str, Any]]]:
        ao._check_stop(cancel)
        say(f"Reading the {label}…")
        got, err = fn()
        if err:
            facts["errors"][key] = err
            say(f"The {label} could not be read: {err[:160]}")
            return None
        return got

    if need & {"url", "ssl"}:
        svc = getattr(zia, "url_categories", None)
        cats = get("url_categories", "URL categories", lambda: _call_rows(svc.list_categories_lite) if svc else ([], "no url_categories service"))
        facts["url_categories"] = None if cats is None else {str(c.get("id")) for c in cats if c.get("id") is not None}
    if "firewall" in need:
        svc = getattr(zia, "cloud_firewall", None)
        apps = get("network_apps", "network applications", lambda: _call_rows(svc.list_network_apps) if svc else ([], "no cloud_firewall service"))
        facts["network_apps"] = None if apps is None else {str(a.get("id")) for a in apps if a.get("id") is not None}
    if "cac" in need and any(r["fields"].get("applications") for r in rows if r["area"] == "cac" and r["on"]):
        def apps():
            svc = getattr(zia, "cloud_applications", None)
            if svc is None:
                return [], "no cloud_applications service"
            out: List[Dict[str, Any]] = []
            for page in range(1, 21):
                ao._check_stop(cancel)
                got, err = _call_rows(lambda: svc.list_cloud_app_policy(query_params={"page": page, "page_size": 1000}))
                if err:
                    return out, err
                out.extend(got)
                if len(got) < 1000:
                    break
            return out, None
        got = get("cloud_apps", "cloud applications", apps)
        facts["cloud_apps"] = None if got is None else {str(a.get("app") or a.get("app_name") or "").upper() for a in got} - {""}
    if any(r["on"] and (r["action"] == "ISOLATE" or r["action"] == "QUARANTINE_ISOLATE") for r in rows):
        profs = get("isolation_profiles", "isolation profiles", lambda: read_isolation_profiles(zia))
        facts["isolation_profiles"] = profs
        pick = None
        if profs:
            if n.get("isolation_profile"):
                pick = next((p for p in profs if p.get("name") == n["isolation_profile"]), None)
                if pick is None:
                    facts.setdefault("warnings", []).append(
                        f"The isolation profile '{n['isolation_profile']}' is not in this tenant; the tenant's default profile is used instead.")
            pick = pick or next((p for p in profs if p.get("default_profile")), None) or (profs[0] if len(profs) == 1 else None)
        facts["isolation_profile"] = pick
    if any(r["on"] and r["fields"].get("trusted_resolver") for r in rows):
        svc = getattr(zia, "dns_gatways", None)   # the SDK's own spelling
        gws = get("dns_gateways", "DNS gateways", lambda: _call_rows(svc.list_dns_gateways) if svc else ([], "no dns_gatways service"))
        facts["trusted_resolver"] = next((g for g in gws or [] if g.get("nat_ztr_gateway")), None)
    if n.get("certificate") and any(r["on"] and r["area"] == "ssl" and r["action"] == "DECRYPT" for r in rows):
        certs = get("certificates", "ready-to-use intermediate certificates", lambda: read_certificates(zia))
        pick = next((c for c in certs or [] if c.get("name") == n["certificate"]), None)
        if pick is None:
            facts.setdefault("warnings", []).append(
                f"The certificate '{n['certificate']}' is not a ready-to-use intermediate certificate in this tenant; the Inspect rules use "
                "the tenant's default certificate.")
        facts["certificate"] = pick
    return facts


def fit(rows: List[Dict[str, Any]], facts: Dict[str, Any]) -> List[str]:
    """Drop what the tenant does not have, in place; returns the warnings.
    A rule left with nothing to match is dropped (rows get `dropped`): an
    empty match list would make it match everything."""
    warns = list(facts.get("warnings") or [])

    def trim(r: Dict[str, Any], field: str, have: Optional[Set[str]], what: str, err_key: str) -> None:
        want = list(r["fields"].get(field) or [])
        if not want:
            return
        if have is None:
            r["dropped"] = f"its {what} could not be checked against the tenant ({(facts['errors'].get(err_key) or 'not read')[:120]})"
            return
        keep = [x for x in want if str(x).upper() in have or str(x) in have]
        gone = [x for x in want if x not in keep]
        if gone:
            warns.append(f"{r['name']}: left out {what} this tenant does not have: {', '.join(gone)}.")
        if not keep:
            r["dropped"] = f"none of its {what} exist in this tenant ({', '.join(gone)}), and without them the rule would match everything"
        r["fields"] = dict(r["fields"], **{field: keep})

    for r in rows:
        if not r["on"]:
            continue
        a = r["area"]
        if a in ("url", "ssl"):
            trim(r, "url_categories", facts.get("url_categories"), "URL categories", "url_categories")
        elif a == "firewall":
            trim(r, "nw_applications", facts.get("network_apps"), "network applications", "network_apps")
        elif a == "cac":
            trim(r, "applications", facts.get("cloud_apps"), "cloud applications", "cloud_apps")
        if not r.get("dropped") and not r.get("catch_all") and not any(r["fields"].get(k) for k in MATCH_FIELDS.get(a, ())):
            # A framework rule (untrusted, or captured from a rule that matched
            # only users or locations) that names nothing would match all traffic.
            r["dropped"] = "it names nothing to match (no categories, applications, countries or file types), so it would match all traffic"
        if r["action"] == "ISOLATE" and not facts.get("isolation_profile"):
            warns.append(f"{r['name']}: this tenant has no usable Cloud Browser Isolation profile, so the rule shows a Caution page instead of isolating.")
            r["action"] = "CAUTION"
        if r["action"] == "QUARANTINE_ISOLATE" and not facts.get("isolation_profile"):
            warns.append(f"{r['name']}: no usable isolation profile, so first-time files are quarantined without isolation.")
            r["action"] = "QUARANTINE"
        if r["fields"].get("trusted_resolver") and not facts.get("trusted_resolver"):
            r["dropped"] = ("this tenant has no Zscaler Trusted Resolver DNS gateway" if "dns_gateways" not in facts["errors"]
                            else f"the DNS gateways could not be read ({facts['errors']['dns_gateways'][:120]})")
    return warns


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _ref(area: str, row: Dict[str, Any], *, rid: Any = None, name: str = "", rule_type: str = "", key: str = "") -> Dict[str, Any]:
    return {"type": "rule", "area": area, "policy_label": AREAS[area]["label"], "id": rid if rid is not None else (row or {}).get("id"),
            "name": name or str((row or {}).get("name") or ""), "rule_type": rule_type, "key": key}


def _is_default(row: Dict[str, Any]) -> bool:
    return ao._is_default(row)


def _last_order(rows: List[Dict[str, Any]]) -> int:
    return max([ao._int(r.get("order"), 0) for r in rows if not _is_default(r)] or [0])


def _match(rows: List[Dict[str, Any]], name: str, rule_type: str = "") -> Optional[Dict[str, Any]]:
    for r in rows:
        if str(r.get("name") or "") == name and (not rule_type or str(r.get("rule_type") or r.get("type") or "") == rule_type):
            return r
    return None


def _typed_every_time(items: List[Dict[str, Any]], groups: List[Dict[str, Any]], *, always: bool = False) -> str:
    """The phrase every apply must type, whatever the count of changes
    (admin_ops._finish `confirm_always`), or "" to keep the count rule.
    Asked when the plan creates a rule, turns one on (state ENABLED) or
    changes Advanced Threat Protection settings: ATP has no disabled state,
    so its change is live as soon as ZIA activates, which the app does right
    after the writes. `always` asks for it for any change (a certificate
    move: inspected sites break until devices trust the new root)."""
    changes = sum(1 for u in items if u.get("status") == "change")
    risky = always or any(g["handler"] in ("zb_create", "zb_atp")
                          or (g["handler"] == "zb_update" and str((g["target"].get("fields") or {}).get("state") or "").upper() == "ENABLED")
                          for g in groups)
    return f"APPLY {changes} CHANGE{'' if changes == 1 else 'S'}" if risky and changes else ""


def _plan(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    n = normalize(spec)
    if n.get("action") == "revert":
        return _plan_revert(client.zia, n, scope, say, cancel)
    in_scope, why = areas_in_scope(scope)
    asked = n["areas"] or [a for a in DEFAULT_AREAS if a in in_scope]
    out_of_scope = [a for a in (n["areas"] or []) if a not in in_scope]
    if out_of_scope:
        raise ao.OperationError("Not in scope on the Scope page: " + ", ".join(AREAS[a]["label"] for a in out_of_scope)
                                + ". Leave them out of the baseline or tick their scope. Nothing was read.")
    areas = [a for a in asked if a in in_scope]
    rev = review(spec)
    tier_label = rev["tier_label"]
    rows = [r for r in rev["rules"] if r["area"] in areas]
    on_rows = [r for r in rows if r["on"]]
    warnings: List[str] = []
    notes: List[str] = [why[a] for a in AREA_ORDER if a in why and a in (n["areas"] or DEFAULT_AREAS)]
    weak = [f"{r['name']} ({r['weakened']})" for r in rows if r["weakened"]] + [f"{s['label']} (switched off)" for s in rev["atp"] if s["weakened"] and "atp" in areas]
    if weak:
        warnings.append(f"Weaker than the {tier_label} tier: " + "; ".join(weak) + ".")
    warnings += [f"{r['name']}: {r['risky']}" for r in on_rows if r.get("risky")]
    zia = client.zia
    facts = _read_facts(zia, on_rows, areas, n, say, cancel)
    warnings += fit(on_rows, facts)
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    for area in [a for a in AREA_ORDER if a in areas and a != "atp"]:
        mine = [r for r in on_rows if r["area"] == area]
        if not mine:
            continue
        types = sorted({r["fields"]["type"] for r in mine}) if area == "cac" else ()
        say(f"Reading the {AREAS[area]['label']} rules…")
        existing, err = read_area(zia, area, types=types, cancel=cancel)
        if err:
            for r in mine:
                gk = f"zb:{area}:{r['key']}"
                items.append(ao._unit(gk + ":rule", gk, "rule_create", _ref(area, None, name=r["name"], key=r["key"]), "rule", None, None,
                                      status="excluded", reason=f"the {AREAS[area]['label']} rules could not be read: {err[:160]}"))
            warnings.append(f"{AREAS[area]['label']}: the rules could not be read ({err[:160]}); nothing is planned there.")
            continue
        creates = 0
        mine.sort(key=lambda r: 1 if r.get("catch_all") else 0)
        for r in mine:
            rtype = r["fields"].get("type", "") if area == "cac" else ""
            gk = f"zb:{area}:{r['key']}"
            if r.get("dropped"):
                items.append(ao._unit(gk + ":rule", gk, "rule_create", _ref(area, None, name=r["name"], rule_type=rtype, key=r["key"]),
                                      "rule", None, None, status="excluded", reason=f"Dropped: {r['dropped']}."))
                continue
            body = payload(r, facts, tier_label, n["enable_rules"])
            cur = _match(existing, r["name"], rtype)
            if cur is None:
                creates += 1
                summary = f"new rule, {_act_label(r['action']) if area not in ('ssl', 'sandbox') else str(r['action']).replace('_', ' ').lower()}, " \
                          f"{'enabled' if n['enable_rules'] else 'disabled'}{', last' if r.get('catch_all') else ''}"
                items.append(ao._unit(gk + ":rule", gk, "rule_create", _ref(area, None, name=r["name"], rule_type=rtype, key=r["key"]),
                                      "rule", "absent", summary))
                groups.append({"key": gk, "handler": "zb_create", "target": {"area": area, "name": r["name"], "rule_type": rtype,
                                                                             "payload": body, "catch_all": bool(r.get("catch_all")),
                                                                             "managed": managed(body, n["enable_rules"])}})
                continue
            ref = _ref(area, cur, rule_type=rtype, key=r["key"])
            lock = ao.lock_reason(AREAS[area]["policy"] or "url_filtering", cur)
            if lock:
                items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "exists", "exists", status="excluded",
                                      reason=f"a rule with this name exists but is {lock.split(':')[0]}"))
                continue
            want = managed(body, n["enable_rules"])
            have = _flat({k: v for k, v in cur.items()})
            units = []
            for field, value in sorted(want.items()):
                if not same(have.get(field), value):
                    units.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, _show(have.get(field)), _show(value)))
            fields = {u["field"]: want[u["field"]] for u in units}
            expect = {u["field"]: have.get(u["field"]) for u in units}
            if r.get("catch_all"):
                last = _last_order(existing)
                if ao._int(cur.get("order"), 0) < last or creates:
                    units.append(ao._unit(f"{gk}:order", gk, "rule_field", ref, "order", cur.get("order"), "last"))
                    fields["order"] = "last"
                    expect["order"] = cur.get("order")
            if not units:
                items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "as the baseline says", "as the baseline says",
                                      status="noop", reason="already as the baseline says"))
                continue
            items.extend(units)
            target = {"area": area, "id": cur.get("id"), "name": r["name"], "rule_type": rtype, "fields": fields, "expect": expect}
            if area == "ssl" and "action.type" in fields:
                target["action"] = body["action"]   # Inspect <-> Do not inspect: the whole action is replaced, not mixed
            groups.append({"key": gk, "handler": "zb_update", "target": target})
    if "atp" in areas:
        say("Reading the Advanced Threat Protection settings…")
        cur, err = read_atp(zia)
        gk = "zb:atp"
        ref = {"type": "settings", "area": "atp", "policy_label": AREAS["atp"]["label"], "id": None, "name": "Advanced Threat Protection"}
        if cur is None:
            warnings.append(f"Advanced Threat Protection: the settings could not be read ({(err or 'no answer')[:160]}); nothing is planned there.")
            items.append(ao._unit(gk + ":settings", gk, "atp_field", ref, "settings", None, None, status="excluded",
                                  reason=f"could not be read: {(err or 'no answer')[:160]}"))
        else:
            fields, expect = {}, {}
            for s in rev["atp"]:
                before = bool(cur.get(s["key"]))
                if before == s["value"]:
                    items.append(ao._unit(f"{gk}:{s['key']}", gk, "atp_field", ref, s["key"], before, s["value"], status="noop",
                                          reason="already as the baseline says"))
                else:
                    items.append(ao._unit(f"{gk}:{s['key']}", gk, "atp_field", ref, s["key"], before, s["value"]))
                    fields[s["key"]], expect[s["key"]] = s["value"], before
            if fields:
                groups.append({"key": gk, "handler": "zb_atp", "target": {"fields": fields, "expect": expect}})
            lowered = [s["label"] for s in rev["atp"] if s["key"] in fields and not fields[s["key"]]]
            if lowered:
                warnings.append("Advanced Threat Protection: the baseline turns off what this tenant blocks today: " + "; ".join(lowered)
                                + ". Pick the setting on in the review to keep it.")
    nspec = {k: v for k, v in n.items() if v not in (None, "", [], {})}
    nspec["type"] = TYPE
    if n.get("areas"):
        nspec["areas"] = n["areas"]
    created = sum(1 for g in groups if g["handler"] == "zb_create")
    notes.append("New rules are added below the tenant's own rules, in the baseline's order; the SSL catch-all and the firewall default "
                 "deny go last. Bulk changes can reorder them afterwards.")
    if not n["enable_rules"]:
        notes.append("Every new rule is created DISABLED: enable each one after review (Bulk changes, Enable or disable rules). "
                     "Re-running the baseline updates the rules it made in place and never changes their state.")
    return {"type": TYPE, "product": "zia", "spec": nspec, "items": items, "groups": groups,
            "title": f"ZIA baseline ({tier_label}{', ' + ', '.join(OVERLAYS[o]['label'] for o in n['overlays']) if n['overlays'] else ''}): "
                     f"{created} new, {len(groups) - created} updated",
            "warnings": warnings, "notes": notes, "review": rev["rules"], "atp_review": rev["atp"] if "atp" in areas else [],
            "atp_controls": rev["atp_controls"], "areas": areas, "confirm_always": _typed_every_time(items, groups)}


def _plan_revert(zia, n: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """The Undo of an applied baseline: delete what it created (only while it
    still carries the name it was given), put back each field it changed
    (only while the field still holds what the baseline set), and the ATP
    settings likewise."""
    in_scope, _ = areas_in_scope(scope)
    items, groups, warnings = [], [], []
    cache: Dict[str, Tuple[List[Dict[str, Any]], Optional[str]]] = {}
    for i, st in enumerate(n["steps"]):
        if not isinstance(st, dict) or st.get("op") not in ("delete", "restore", "restore_atp"):
            raise ao.OperationError("An undo step must be delete, restore or restore_atp.")
        area = "atp" if st["op"] == "restore_atp" else str(st.get("area") or "")
        if area not in AREAS:
            raise ao.OperationError(f"Unknown area in the undo: {area!r}.")
        if area not in in_scope:
            raise ao.OperationError(f"Not in scope on the Scope page: {AREAS[area]['label']}. The undo needs it in scope. Nothing was read.")
        gk = f"zbr:{i}"
        if area == "atp":
            cur, err = read_atp(zia)
            ref = {"type": "settings", "area": "atp", "policy_label": AREAS["atp"]["label"], "id": None, "name": "Advanced Threat Protection"}
            fields, expect = {}, {}
            for k, before in (st.get("fields") or {}).items():
                if k not in ATP_KEYS:
                    continue
                now = None if cur is None else bool(cur.get(k))
                if cur is None:
                    items.append(ao._unit(f"{gk}:{k}", gk, "atp_field", ref, k, None, before, status="excluded", reason=f"could not be read: {err}"))
                elif now == bool(before):
                    items.append(ao._unit(f"{gk}:{k}", gk, "atp_field", ref, k, now, before, status="noop", reason="already as before"))
                elif now != bool((st.get("expect") or {}).get(k)):
                    items.append(ao._unit(f"{gk}:{k}", gk, "atp_field", ref, k, now, before, status="excluded",
                                          reason="changed in the tenant since the baseline set it; left as it is"))
                else:
                    items.append(ao._unit(f"{gk}:{k}", gk, "atp_field", ref, k, now, bool(before)))
                    fields[k], expect[k] = bool(before), now
            if fields:
                groups.append({"key": gk, "handler": "zb_atp", "target": {"fields": fields, "expect": expect}})
            continue
        rtype = str(st.get("rule_type") or "")
        ck = f"{area}:{rtype}"
        if ck not in cache:
            say(f"Reading the {AREAS[area]['label']} rules…")
            cache[ck] = read_area(zia, area, types=[rtype] if rtype else (), cancel=cancel)
        rows, err = cache[ck]
        cur = next((r for r in rows if str(r.get("id")) == str(st.get("id"))), None)
        ref = _ref(area, cur, rid=st.get("id"), name=str(st.get("name") or ""), rule_type=rtype)
        if err:
            items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", None, None, status="excluded", reason=f"could not be read: {err[:160]}"))
            continue
        if st["op"] == "delete":
            if cur is None:
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", "absent", "absent", status="noop", reason="already gone"))
            elif str(cur.get("name") or "") != str(st.get("name") or ""):
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", "exists", "deleted", status="excluded",
                                      reason=f"it is now called '{cur.get('name')}', not the name the baseline gave it; left as it is"))
            else:
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", f"exists ({str(cur.get('state') or '').lower()})", "deleted"))
                groups.append({"key": gk, "handler": "zb_delete", "target": {"area": area, "id": cur.get("id"), "name": cur.get("name"), "rule_type": rtype}})
            continue
        if cur is None:
            items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "absent", "restored", status="excluded", reason="no longer in the tenant"))
            continue
        have = _flat(cur)
        fields, expect = {}, {}
        for field, before in (st.get("fields") or {}).items():
            want_now = (st.get("expect") or {}).get(field)
            now = have.get(field)
            if field == "order":
                if same(now, before):
                    items.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, now, before, status="noop", reason="already as before"))
                else:
                    items.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, now, before))
                    fields[field], expect[field] = before, now
                continue
            if same(now, before):
                items.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, _show(now), _show(before), status="noop", reason="already as before"))
            elif not same(now, want_now):
                items.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, _show(now), _show(before), status="excluded",
                                      reason="changed in the tenant since the baseline set it; left as it is"))
            else:
                items.append(ao._unit(f"{gk}:{field}", gk, "rule_field", ref, field, _show(now), _show(before)))
                fields[field], expect[field] = before, now
        if fields:
            groups.append({"key": gk, "handler": "zb_update", "target": {"area": area, "id": cur.get("id"), "name": cur.get("name"),
                                                                         "rule_type": rtype, "fields": fields, "expect": expect}})
    if not items:
        warnings.append("Nothing to undo.")
    return {"type": TYPE, "product": "zia", "spec": n, "items": items, "groups": groups, "title": "Undo a ZIA baseline", "warnings": warnings,
            "notes": ["Only what the baseline did and nobody changed since is reversed; everything else is left as it is."],
            "confirm_always": _typed_every_time(items, groups)}


# ---------------------------------------------------------------------------
# Handlers (each write through pack_ops; a re-read right before it)
# ---------------------------------------------------------------------------

def _halt_or_fail(run, units, err: Optional[str], what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _area_cache(run, area: str, rule_type: str = "") -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    cache = run.__dict__.setdefault("_zb_lists", {})
    key = f"{area}:{rule_type}"
    if key not in cache:
        cache[key] = read_area(run.zia, area, types=[rule_type] if rule_type else ())
    return cache[key]


def _h_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    rows, err = _area_cache(run, area, t["rule_type"])
    if err:
        _halt_or_fail(run, units, err, f"the {AREAS[area]['label']} rules")
        return
    if _match(rows, t["name"], t["rule_type"]) is not None:
        run.mark(units, "conflict", "a rule with this name appeared in the tenant since the preview; left as it is")
        return
    body = copy.deepcopy(t["payload"])
    body["order"] = _last_order(rows) + 1
    body["rank"] = 7
    out = ops.create(run.zia, "policy", body, channel=AREAS[area]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"]["id"] = out.id
        rows.append(dict(body, id=out.id, rule_type=t["rule_type"], type=t["rule_type"] or None))
        run.created.append({"type": "rule", "area": area, "id": out.id, "name": t["name"], "rule_type": t["rule_type"]})
        run.log(f"[{AREAS[area]['label']}] {t['name']}: created at order {body['order']} ({body.get('state', '').lower()})")


def _h_update(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    fresh, err = get_one(run.zia, area, t["id"], t["rule_type"])
    if fresh is None:
        _halt_or_fail(run, units, err or "not found", "the rule")
        return
    have = _flat(fresh)
    ok = []
    for u in units:
        f = u["field"]
        if f != "order" and not same(have.get(f), t["expect"].get(f)):
            run.mark([u], "conflict", f"changed in the tenant since the preview: {f} is {_show(have.get(f))} now; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    body = _deep_snake(ao._body(fresh))
    if t.get("action"):
        body["action"] = copy.deepcopy(t["action"])
    for u in ok:
        f = u["field"]
        if f == "order":
            if t["fields"]["order"] == "last":
                rows, rerr = read_area(run.zia, area, types=[t["rule_type"]] if t["rule_type"] else ())
                if rerr:
                    _halt_or_fail(run, [u], rerr, f"the {AREAS[area]['label']} rules")
                    ok = [x for x in ok if x is not u]
                    continue
                body["order"] = _last_order(rows)
            else:
                body["order"] = t["fields"]["order"]
        else:
            _set_path(body, f, t["fields"][f])
    if not ok:
        return
    if area == "cac":
        body["type"] = t["rule_type"] or fresh.get("rule_type") or fresh.get("type")
    out = ops.update(run.zia, "policy", t["id"], body, channel=AREAS[area]["channel"], name=t["name"], log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        if any(u["field"] == "order" for u in ok):
            for u in ok:
                if u["field"] == "order":
                    u["sent_order"] = body.get("order")
        run.log(f"[{AREAS[area]['label']}] {t['name']}: updated {', '.join(u['field'] for u in ok)}")


def _h_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    fresh, err = get_one(run.zia, area, t["id"], t["rule_type"])
    if fresh is None:
        if err and ao._read_halt(err):
            _halt_or_fail(run, units, err, "the rule")
        else:
            run.mark(units, "noop", "already gone")
        return
    if str(fresh.get("name") or "") != str(t["name"]):
        run.mark(units, "conflict", f"renamed since the preview (now '{fresh.get('name')}'); left as it is")
        return
    item = {"kind": "policy", "id": t["id"], "name": t["name"], "channel": AREAS[area]["channel"], "type": t["rule_type"] or None}
    out = ops.delete(run.zia, item, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{AREAS[area]['label']}] {t['name']}: deleted")


def _h_atp(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    cur, err = read_atp(run.zia)
    if cur is None:
        _halt_or_fail(run, units, err or "no answer", "the Advanced Threat Protection settings")
        return
    ok = []
    for u in units:
        if bool(cur.get(u["field"])) != bool(t["expect"].get(u["field"])):
            run.mark([u], "conflict", f"changed in the tenant since the preview: {u['field']} is {bool(cur.get(u['field']))} now; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    body = {k: v for k, v in cur.items() if v is not None}
    for u in ok:
        body[u["field"]] = bool(t["fields"][u["field"]])
    out = ops.update(run.zia, "atp_settings", None, body, name="Advanced Threat Protection", log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        run.log(f"[Advanced Threat Protection] set {', '.join(u['field'] + '=' + str(u['after']).lower() for u in ok)}")


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def _verify(run) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    groups = {g["key"]: g for g in run.p["groups"]}
    cache: Dict[str, Tuple[Optional[Dict[str, Any]], Optional[str]]] = {}
    atp: List[Any] = []
    for u in applied:
        out["checked"] += 1
        o, g = u["object"], groups.get(u["group"]) or {}
        t = g.get("target") or {}
        if u["kind"] == "atp_field":
            if not atp:
                atp.append(read_atp(run.zia))
            row, err = atp[0]
            ok = row is not None and bool(row.get(u["field"])) == bool(t["fields"].get(u["field"]))
        elif u["kind"] == "cert":
            k = f"ssl:{o['id']}"
            if k not in cache:
                cache[k] = get_one(run.zia, "ssl", o["id"])
            row, err = cache[k]
            ok = row is not None and _cert_of(row)[0] == t.get("to_id")
        else:
            area = o["area"]
            k = f"{area}:{o.get('id')}"
            if k not in cache:
                cache[k] = get_one(run.zia, area, o.get("id"), o.get("rule_type") or "") if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            if u["kind"] == "rule_delete":
                ok, err = row is None, None
            elif u["kind"] == "rule_create":
                have = _flat(row or {})
                ok = row is not None and all(same(have.get(f), v) for f, v in (t.get("managed") or {}).items() if f != "state")
            elif u["field"] == "order":
                ok = row is not None and (t["fields"]["order"] != "last" or same(row.get("order"), u.get("sent_order", row.get("order"))))
            else:
                ok = row is not None and same(_flat(row).get(u["field"]), t["fields"].get(u["field"]))
        if not ok and err and u["kind"] != "rule_delete":
            out["unread"].append(f"{o.get('name')}: {err}")
            u["verified"] = None
            continue
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o.get('name')}: {u['field']} is not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    groups = {g["key"]: g for g in result.get("groups") or []}
    steps: List[Dict[str, Any]] = []
    restore: Dict[str, Dict[str, Any]] = {}
    for u in applied:
        o, t = u["object"], (groups.get(u["group"]) or {}).get("target") or {}
        if u["kind"] == "rule_create" and o.get("id") is not None:
            steps.append({"op": "delete", "area": o["area"], "id": o["id"], "name": o["name"], "rule_type": o.get("rule_type") or ""})
        elif u["kind"] == "rule_delete":
            continue   # an undo of an undo would re-create a rule: not offered
        elif u["kind"] in ("rule_field", "atp_field"):
            key = u["group"]
            if key not in restore:
                restore[key] = ({"op": "restore_atp", "fields": {}, "expect": {}} if u["kind"] == "atp_field" else
                                {"op": "restore", "area": o["area"], "id": o["id"], "name": o["name"], "rule_type": o.get("rule_type") or "",
                                 "fields": {}, "expect": {}})
            f = u["field"]
            restore[key]["fields"][f] = (t.get("expect") or {}).get(f)
            restore[key]["expect"][f] = u.get("sent_order") if f == "order" else (t.get("fields") or {}).get(f)
    steps = list(reversed(steps)) + list(restore.values())
    return {"type": TYPE, "action": "revert", "steps": steps} if steps else None


# ---------------------------------------------------------------------------
# SSL certificate manager
# ---------------------------------------------------------------------------

def _cert_of(rule: Dict[str, Any]) -> Tuple[Any, str]:
    """(certificate id or 'default', its name) an SSL rule uses."""
    a = rule.get("action") or {}
    cert = a.get("ssl_interception_cert") or {}
    if a.get("override_default_certificate") and cert.get("id") is not None:
        return cert["id"], str(cert.get("name") or cert["id"])
    return "default", "the tenant's default certificate"


def ssl_rule_rows(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in sorted(rules, key=ao._sort_key):
        cid, cname = _cert_of(r)
        typ = str((r.get("action") or {}).get("type") or "")
        out.append({"id": r.get("id"), "name": r.get("name"), "order": r.get("order"), "state": ao._state(r), "action": typ,
                    "inspect": typ == "DECRYPT", "certificate_id": cid, "certificate": cname,
                    "locked": ao.lock_reason("ssl_inspection", r) or ""})
    return out


def _plan_cert(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    if not isinstance(spec, dict):
        raise ao.OperationError("The certificate move must be an object.")
    moves = spec.get("moves")
    if moves is None:
        ids = spec.get("rules") or []
        if not isinstance(ids, list) or not ids:
            raise ao.OperationError("Pick at least one SSL inspection rule.")
        target = spec.get("certificate")
        if target in (None, ""):
            raise ao.OperationError("Pick the certificate to move the rules to.")
        moves = [{"id": i, "certificate": target} for i in ids]
    if not isinstance(moves, list) or not moves or len(moves) > ao.MAX_TARGETS:
        raise ao.OperationError(f"Move 1 to {ao.MAX_TARGETS} rules at a time.")
    norm: List[Dict[str, Any]] = []
    seen: Dict[str, Any] = {}
    for m in moves:
        if not isinstance(m, dict) or not all(isinstance(m.get(k), (int, str)) and not isinstance(m.get(k), bool)
                                              and _STEP_ID.fullmatch(str(m.get(k))) for k in ("id", "certificate")):
            raise ao.OperationError("Each move names a rule id and a certificate (an id, or 'default').")
        rid = str(m["id"])
        if rid in seen:
            if str(seen[rid]) != str(m["certificate"]):
                raise ao.OperationError(f"Rule {rid} is moved to two different certificates: pick one.")
            continue   # the same move twice is one move
        seen[rid] = m["certificate"]
        norm.append({"id": m["id"], "certificate": m["certificate"]})
    zia = client.zia
    say("Reading the ready-to-use intermediate certificates…")
    certs, cerr = read_certificates(zia)
    ao._check_stop(cancel)
    say("Reading the SSL inspection rules…")
    rules, rerr = read_area(zia, "ssl", cancel=cancel)
    by_id = {str(r.get("id")): r for r in rules}
    cert_by_id = {str(c.get("id")): c for c in certs}
    default = next((c for c in certs if c.get("default_certificate")), None)
    items, groups, warnings = [], [], []
    if cerr:
        warnings.append(f"The certificates could not be read ({cerr[:160]}); nothing is planned.")
    if rerr:
        warnings.append(f"The SSL inspection rules could not be read ({rerr[:160]}); nothing is planned.")
    for m in norm:
        r = by_id.get(str(m["id"]))
        gk = f"cert:{m['id']}"
        ref = _ref("ssl", r, rid=m["id"])
        tid = m["certificate"]
        target = cert_by_id.get(str(tid))
        if str(tid) == "default" or (target is not None and target.get("default_certificate")):
            to_id, to_name = "default", "the tenant's default certificate"
        elif target is not None:
            to_id, to_name = target["id"], str(target.get("name") or target["id"])
        else:
            to_id, to_name = None, f"certificate {tid}"
        if cerr or rerr:
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", None, to_name, status="excluded", reason="could not be read"))
            continue
        if r is None:
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", None, to_name, status="excluded", reason="no such rule in the tenant now"))
            continue
        if to_id is None:
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", None, to_name, status="excluded",
                                  reason="not a ready-to-use intermediate certificate in this tenant"))
            continue
        cid, cname = _cert_of(r)
        lock = ao.lock_reason("ssl_inspection", r)
        typ = str((r.get("action") or {}).get("type") or "")
        if lock:
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", cname, to_name, status="excluded", reason=lock))
        elif typ != "DECRYPT":
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", cname, to_name, status="excluded",
                                  reason=f"not an Inspect rule (action {typ.replace('_', ' ').lower() or 'unknown'}): it uses no certificate"))
        elif str(cid) == str(to_id):
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", cname, to_name, status="noop", reason="already uses it"))
        else:
            items.append(ao._unit(gk, gk, "cert", ref, "certificate", cname, to_name, value=to_id))
            groups.append({"key": gk, "handler": "zb_cert", "target": {"id": r.get("id"), "name": r.get("name"), "from_id": cid,
                                                                       "to_id": to_id, "to_name": to_name}})
    if default is None and any(g["target"]["to_id"] == "default" for g in groups):
        warnings.append("No certificate is marked as the tenant's default; the rules will use ZIA's own default certificate.")
    n = len(groups)
    return {"type": CERT_TYPE, "product": "zia", "spec": {"type": CERT_TYPE, "moves": norm}, "items": items, "groups": groups,
            "title": f"Move {n} SSL inspection rule{'s' if n != 1 else ''} to another certificate", "warnings": warnings,
            "notes": ["Before activating, make sure devices trust the new certificate's root, or inspected sites show certificate errors."],
            "confirm_always": _typed_every_time(items, groups, always=True)}


def _h_cert(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_one(run.zia, "ssl", t["id"])
    if fresh is None:
        _halt_or_fail(run, units, err or "not found", "the rule")
        return
    cid, cname = _cert_of(fresh)
    if str(cid) != str(t["from_id"]) or str((fresh.get("action") or {}).get("type")) != "DECRYPT":
        run.mark(units, "conflict", f"changed in the tenant since the preview (now {cname}); left as it is")
        return
    body = _deep_snake(ao._body(fresh))
    action = dict(body.get("action") or {})
    if t["to_id"] == "default":
        action["override_default_certificate"] = False
        action.pop("ssl_interception_cert", None)
    else:
        action["override_default_certificate"] = True
        action["ssl_interception_cert"] = {"id": t["to_id"], "name": t["to_name"]}
    body["action"] = action
    out = ops.update(run.zia, "policy", t["id"], body, channel=pc.SSL, name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[SSL inspection] {t['name']}: certificate → {t['to_name']}")


def _cert_inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    groups = {g["key"]: g for g in result.get("groups") or []}
    moves = [{"id": groups[u["group"]]["target"]["id"], "certificate": groups[u["group"]]["target"]["from_id"]}
             for u in result.get("items") or [] if u.get("status") == "applied" and u["group"] in groups]
    return {"type": CERT_TYPE, "moves": moves} if moves else None


# ---------------------------------------------------------------------------
# What the page lists before planning
# ---------------------------------------------------------------------------

def _read_catalog(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    out = catalog()
    read, why = areas_in_scope(scope)
    out["in_scope"], out["not_in_scope_areas"] = read, why
    zia = client.zia
    if "url" in read or "sandbox" in read:
        say("Reading the isolation profiles…")
        out["isolation_profiles"], err = read_isolation_profiles(zia)
        if err:
            out.setdefault("errors", {})["isolation_profiles"] = err
    ao._check_stop(cancel)
    if "ssl" in read:
        say("Reading the ready-to-use intermediate certificates…")
        out["certificates"], err = read_certificates(zia)
        if err:
            out.setdefault("errors", {})["certificates"] = err
    return out


def _read_certs(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    zia = client.zia
    say("Reading the ready-to-use intermediate certificates…")
    certs, cerr = read_certificates(zia)
    ao._check_stop(cancel)
    say("Reading the SSL inspection rules…")
    rules, rerr = read_area(zia, "ssl", cancel=cancel)
    errs = {k: v for k, v in (("certificates", cerr), ("ssl_inspection", rerr)) if v}
    rows = ssl_rule_rows(rules)
    say(f"{len(rows)} SSL inspection rules, {len(certs)} ready-to-use certificates.")
    return {"certificates": certs, "ssl_rules": rows, "errors": errs}


# ---------------------------------------------------------------------------
# Framework capture (Export from tenant, "ZIA policy framework") and load
# ---------------------------------------------------------------------------
CAPTURE_AREAS = ("url", "firewall", "ssl", "sandbox", "dns", "ftc")
# A framework field's shape: a list of Zscaler names, one name, or true/false.
_LIST_FIELDS = {"url_categories", "protocols", "nw_applications", "dest_countries", "source_countries", "file_types", "applications",
                "dest_ip_categories"}
_BOOL_FIELDS = {"ml_action_enabled", "password_protected", "trusted_resolver"}
_CAPTURE_FIELDS = {
    "url": ("url_categories", "protocols"),
    "firewall": ("nw_applications", "dest_countries", "source_countries"),
    "ssl": ("url_categories",),
    "sandbox": ("file_types", "protocols", "ml_action_enabled"),
    "dns": ("applications", "protocols", "dest_ip_categories", "dest_countries"),
    "ftc": ("file_types", "operation", "protocols", "password_protected"),
}
_ACTIONS = {
    "url": {"ALLOW", "BLOCK", "CAUTION", "ISOLATE"},
    "firewall": {"ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP"},
    "ssl": {"DECRYPT", "DO_NOT_DECRYPT"},
    "sandbox": {"ALLOW_SCAN", "QUARANTINE", "ALLOW_NOSCAN", "QUARANTINE_ISOLATE"},
    "dns": {"ALLOW", "BLOCK", "REDIR_REQ_KEEP_SENDER"},
    "ftc": {"ALLOW", "BLOCK", "CAUTION"},
}


def _capture_rule(area: str, r: Dict[str, Any], n: int, skipped: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    import pack_export
    name = str(r.get("name") or "")
    if not _name_ok(" ".join(name.split())[:MAX_NAME]):
        skipped.append({"name": name[:MAX_NAME], "area": AREAS[area]["label"],
                        "reason": "its name is empty or has characters a framework file does not carry (<, > or control characters)"})
        return None
    if area == "ssl":
        a = r.get("action") or {}
        action = str(a.get("type") or "")
        d = a.get("decrypt_sub_actions") or {}
        tls = str(d.get("min_client_tls_version") or "").replace("CLIENT_", "") or "TLS_1_2"
    elif area == "sandbox":
        action = str(r.get("first_time_operation") or "")
    elif area == "ftc":
        action = str(r.get("filtering_action") or "")
    else:
        action = str(r.get("action") or "")
    if action not in _ACTIONS[area]:
        skipped.append({"name": name, "area": AREAS[area]["label"], "reason": f"its action ({action or 'none'}) is not one the baseline can apply"})
        return None
    if area == "dns" and action.startswith("REDIR") and r.get("dns_gateway"):
        pass   # applied with the target tenant's Trusted Resolver gateway
    elif area == "dns" and action.startswith("REDIR"):
        skipped.append({"name": name, "area": AREAS[area]["label"], "reason": "a redirect without a DNS gateway cannot be rebuilt"})
        return None
    fields: Dict[str, Any] = {}
    for k in _CAPTURE_FIELDS[area]:
        v = r.get(k)
        if v not in (None, "", []):
            fields[k] = v
    bad = [k for k, v in fields.items() if not _field_ok(k, [c for c in v if not str(c).upper().startswith("CUSTOM_")]
                                                        if k == "url_categories" and isinstance(v, list) else v)]
    if bad:   # leaving one match field out would widen the rule: the rule is left out
        skipped.append({"name": name, "area": AREAS[area]["label"], "field": ", ".join(bad),
                        "reason": f"its {', '.join(bad)} cannot be carried in a framework file (not a list of Zscaler names); the rule is not captured"})
        return None
    if "url_categories" in fields:
        custom = [c for c in fields["url_categories"] if str(c).upper().startswith("CUSTOM_")]
        if custom:
            skipped.append({"name": name, "area": AREAS[area]["label"], "field": "url_categories", "values": [str(c) for c in custom],
                            "reason": "custom URL categories are objects of the source tenant; left out of the rule"})
            fields["url_categories"] = [c for c in fields["url_categories"] if c not in custom]
            if not fields["url_categories"]:
                skipped.append({"name": name, "area": AREAS[area]["label"], "reason": "every URL category it named was custom; the rule is not captured"})
                return None
    if area == "ssl":
        fields["min_tls"] = tls if re.fullmatch(r"TLS_1_[0-3]", tls) else "TLS_1_2"
        fields.setdefault("url_categories", [])
    if area == "dns" and action.startswith("REDIR"):
        fields["trusted_resolver"] = True
    used = [w for k, w in pack_export._TENANT_SCOPE.items() if r.get(k) not in (None, "", [], {})]
    for k, w in (("nw_services", "network services"), ("nw_service_groups", "network service groups"), ("src_ip_groups", "source IP groups"),
                 ("dest_ip_groups", "destination IP groups"), ("labels", "labels"), ("devices", "devices"), ("device_groups", "device groups"),
                 ("cloud_applications", "cloud applications")):
        if r.get(k) not in (None, "", [], {}):
            used.append(w)
    if used:
        skipped.append({"name": name, "area": AREAS[area]["label"], "field": "scope",
                        "reason": f"names {', '.join(sorted(set(used)))} of the source tenant; left out, so the rule applies to everyone where it goes"})
    return {"key": f"{area}.c{n}", "area": area, "name": name[:MAX_NAME], "suffix": name[:MAX_NAME], "title": _fit_bytes(str(r.get("description") or name), 200),
            "default": action, "fields": fields, "sources": [], "locked": "", "action_locked": "",
            "catch_all": area == "ssl" and not fields.get("url_categories"), "default_on": True, "risky": "", "state": ao._state(r)}


def capture(client, areas: Sequence[str], *, name: str = "", tenant_label: str = "", log: LogFn = None, cancel: Any = None) -> Dict[str, Any]:
    """The tenant's URL filtering, Cloud Firewall, SSL inspection, Sandbox,
    DNS Control and File Type Control rules (the areas given: those in
    scope) as a portable framework. Read-only, paced like Export from tenant
    (pack_export._read: a rate refusal is waited out and retried). Default,
    predefined and read-only rules are left out; tenant objects a rule names
    (users, groups, locations, custom URL categories, network services,
    gateways ...) are left out and listed in `not_exported`.
    Returns {status: ready | error | stopped, framework?, error?}."""
    import pack_export
    from datetime import datetime, timezone
    _log = log or (lambda m: None)
    fw: Dict[str, Any] = {"format": FRAMEWORK_FORMAT, "format_version": FRAMEWORK_VERSION, "name": (name or f"Captured from {tenant_label or 'tenant'}")[:120],
                          "captured_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source_tenant": tenant_label,
                          "areas": {}, "not_exported": [],
                          "notes": ["Cloud App Control, DLP and the Advanced Threat Protection settings are not captured: they point at objects "
                                    "of this tenant (applications, engines, dictionaries) or at settings outside the rule lists.",
                                    "Applying the framework (Bulk changes, ZIA security baseline, Load a framework) creates every rule DISABLED "
                                    "unless chosen otherwise, and drops what the target tenant does not have."]}
    zia = client.zia
    for area in [a for a in CAPTURE_AREAS if a in areas]:
        if pack_export._stopped(cancel):
            return {"status": "stopped", "stopped": "You clicked Stop."}
        _log(f"Reading the tenant: {AREAS[area]['label']} rules…")
        rows, err, rate = pack_export._read(f"{AREAS[area]['label']} rules", lambda a=area: read_area(zia, a), _log, cancel)
        if pack_export._stopped(cancel):
            return {"status": "stopped", "stopped": "You clicked Stop."}
        if err and rate:
            return {"status": "error", "error": pack_export._rate_error(f"{AREAS[area]['label']} rules", err)}
        if err:
            fw["not_exported"].append({"name": AREAS[area]["label"], "area": AREAS[area]["label"], "reason": f"could not be read: {str(err)[:160]}"})
            continue
        out = []
        for r in sorted(rows or [], key=ao._sort_key):
            if ao.lock_reason(AREAS[area]["policy"] or "url_filtering", r):
                continue
            c = _capture_rule(area, r, len(out) + 1, fw["not_exported"])
            if c:
                out.append(c)
        if len(out) > MAX_FRAMEWORK_RULES:
            # A framework holds MAX_FRAMEWORK_RULES rules per area (load_framework
            # refuses more): each rule cut is named, so it can be recreated by hand.
            for c in out[MAX_FRAMEWORK_RULES:]:
                fw["not_exported"].append({"name": c["name"], "area": AREAS[area]["label"],
                                           "reason": f"only the first {MAX_FRAMEWORK_RULES} of {len(out)} rules fit in a framework; "
                                                     "recreate this one in the target tenant"})
            out = out[:MAX_FRAMEWORK_RULES]
        if out:
            fw["areas"][area] = out
        _log(f"Reading the tenant: {AREAS[area]['label']}: {len(fw['areas'].get(area) or [])} rule(s) captured.")
    fw["counts"] = {a: len(v) for a, v in fw["areas"].items()}
    return {"status": "ready", "framework": fw}


_UNSAFE_TEXT = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_UNSAFE_NAME = re.compile("[<>\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


def _name_ok(name: str) -> bool:
    return bool(name) and not _UNSAFE_NAME.search(name)


def _field_ok(k: str, v: Any) -> bool:
    """A framework field's value as load_framework accepts it: a list of
    Zscaler names, one name, a TLS version or true/false."""
    if k in _BOOL_FIELDS:
        return isinstance(v, bool)
    if k == "min_tls":
        return isinstance(v, str) and re.fullmatch(r"TLS_1_[0-3]", v) is not None
    if k in _LIST_FIELDS:
        return isinstance(v, list) and len(v) <= 500 and all(isinstance(x, str) and _ENUM_RE.fullmatch(x) for x in v)
    return isinstance(v, str) and _ENUM_RE.fullmatch(v) is not None


def load_framework(fw: Any) -> Dict[str, Any]:
    """Check an uploaded framework (untrusted): its format, areas, sizes and
    every value; returns {name, rules}. Raises OperationError."""
    if not isinstance(fw, dict) or fw.get("format") != FRAMEWORK_FORMAT:
        raise ao.OperationError(f"Not a ZIA policy framework (expected format '{FRAMEWORK_FORMAT}').")
    ver = fw.get("format_version")
    if type(ver) is not int or ver != FRAMEWORK_VERSION:
        raise ao.OperationError("This framework file is from a newer version of the app." if type(ver) is int and ver > FRAMEWORK_VERSION
                                else f"This framework file has no usable format_version (expected {FRAMEWORK_VERSION}).")
    areas = fw.get("areas")
    if not isinstance(areas, dict) or not areas:
        raise ao.OperationError("The framework has no rules.")
    rules, total = [], 0
    for area, rows in areas.items():
        if area not in CAPTURE_AREAS or not isinstance(rows, list):
            raise ao.OperationError(f"Unknown area in the framework: {str(area)[:40]!r}.")
        total += len(rows)
        if total > MAX_FRAMEWORK_RULES * len(CAPTURE_AREAS) or len(rows) > MAX_FRAMEWORK_RULES:
            raise ao.OperationError("The framework has too many rules.")
        for i, r in enumerate(rows):
            if not isinstance(r, dict):
                raise ao.OperationError("Each framework rule must be an object.")
            # Deny by default: a name and a title are text, the fields an
            # object; a name carries no markup, control, bidirectional or
            # invisible character (it becomes a rule name in the tenant).
            if not isinstance(r.get("name"), str) or not isinstance(r.get("title", ""), (str, type(None))) \
                    or not isinstance(r.get("fields", {}), (dict, type(None))):
                raise ao.OperationError(f"Framework rule {i + 1} in {area}: name and title are text and fields an object.")
            name = " ".join(r["name"].split())[:MAX_NAME]
            if not name or _UNSAFE_NAME.search(name):
                raise ao.OperationError(f"Framework rule {i + 1} in {area} has no usable name.")
            action = str(r.get("default") or "")
            if action not in _ACTIONS[area]:
                raise ao.OperationError(f"{name}: action {action[:40]!r} is not allowed for {AREAS[area]['label']}.")
            raw = r.get("fields")
            if raw is None:
                raw = {}
            if not isinstance(raw, dict):
                raise ao.OperationError(f"{name}: fields must be an object.")
            allowed = _CAPTURE_FIELDS[area] + (("min_tls",) if area == "ssl" else ()) + (("trusted_resolver",) if area == "dns" else ())
            fields: Dict[str, Any] = {}
            for k, v in raw.items():
                if k not in allowed:
                    continue
                if not _field_ok(k, v):
                    raise ao.OperationError(f"{name}: the value of {k} is not "
                                            + ("true or false." if k in _BOOL_FIELDS else "a list of Zscaler names." if k in _LIST_FIELDS
                                               else "a Zscaler name."))
                fields[k] = list(v) if isinstance(v, list) else v
            rules.append({"key": f"{area}.c{i + 1}", "area": area, "name": name, "suffix": name, "default": action, "fields": fields,
                          "title": _fit_bytes(_UNSAFE_TEXT.sub(" ", r.get("title") or name), 200), "sources": [], "locked": "", "action_locked": "",
                          "catch_all": area == "ssl" and not fields.get("url_categories"), "default_on": True, "risky": ""})
    return {"name": str(fw.get("name") or "Framework")[:120], "rules": rules}


# ---------------------------------------------------------------------------
# Registration on the Bulk changes engine
# ---------------------------------------------------------------------------
ao.register(TYPE, family=FAMILY, product="zia", label="ZIA security baseline",
            hint="Build URL filtering, Cloud Firewall, SSL inspection, Sandbox, DNS Control, File Type Control and Cloud App Control "
                 "rules (and the Advanced Threat Protection settings) from a Strict, Balanced, Permissive or Healthcare zero trust tier, "
                 "with compliance overlays, or from a framework captured from another tenant. Rules arrive disabled.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_catalog,
            handlers={"zb_create": _h_create, "zb_update": _h_update, "zb_delete": _h_delete, "zb_atp": _h_atp},
            verify=_verify, inverse=_inverse, script="ops_zia_baseline.js")
ao.register(CERT_TYPE, family=CERT_FAMILY, product="zia", label="SSL certificate manager",
            hint="See which intermediate certificate each SSL inspection rule uses and move picked Inspect rules to another "
                 "ready-to-use certificate.",
            in_scope=_cert_in_scope, plan=_plan_cert, read_objects=_read_certs, handlers={"zb_cert": _h_cert},
            verify=_verify, inverse=_cert_inverse, script="ops_zia_baseline.js")
