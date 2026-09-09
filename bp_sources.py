#!/usr/bin/env python3
"""
Zscaler Best-Practices Source Registry
=======================================
Authoritative list of WHERE we look for Zscaler best-practice guidance,
each rated on a credibility scale so the UI and report generator can
badge entries appropriately.

Credibility tiers
-----------------
  Tier 1  (100)  Official Zscaler property. The canonical source of truth.
                 Examples: help.zscaler.com, trust.zscaler.com,
                 www.zscaler.com/blogs (authored by Zscaler), Zscaler's
                 own GitHub org.
  Tier 2  ( 80)  Authoritative third-party documenting a supported
                 integration. Hyperscaler docs (Microsoft Learn, AWS
                 docs, Google Cloud docs), Terraform registry's
                 Zscaler-published providers.
  Tier 3  ( 60)  Community / crowd-sourced. Good signal but unvetted.
                 Reddit r/zscaler, Stack Overflow, unofficial blogs.

A source may declare `sitemaps` (XML sitemap or sitemap index URLs on
its own host): those are read first and list every article in one or
two requests; `seeds` are only page-walked when no sitemap could be
read. `sitemap_child_filter` keeps a sitemap index to the children whose
URL contains one of the given words (e.g. "blog").

Each source declares whether it is `crawlable` — if False, it's listed
for user reference but the crawler won't try to scrape it (SPAs, forums
with aggressive anti-bot, login-walled content, etc.). Non-crawlable
sources still contribute curated entries in zscaler_best_practices.py.

Adding a source
---------------
1. Append a dict here (see the shape below).
2. Add its host to the allowlist in zscaler_update_check.py:ALLOWED_HOSTS
   so the crawler/_safe_get path will let it through.
3. Optional: add curated entries in zscaler_best_practices.py tagged
   with `source=<source_id>` so they render with the right credibility
   badge even before a crawl discovers them.

Security posture
----------------
Every fetch still flows through zscaler_update_check._safe_get which
enforces the host allowlist, timeouts, and TLS-MITM bypass env var.
Adding a source here does NOT automatically permit fetches — the host
allowlist is the gate.
"""
from __future__ import annotations
from typing import Any, Dict, List


# Credibility scale constants — keep in sync with the UI badge colors.
TIER_OFFICIAL      = 100   # Zscaler itself
TIER_AUTHORITATIVE = 80    # Partner / hyperscaler / registry
TIER_COMMUNITY     = 60    # Forums, blogs, Q&A


SOURCES: List[Dict[str, Any]] = [
    # ─── Tier 1: Official Zscaler properties ────────────────────────
    {
        "id": "help_zscaler",
        "name": "Zscaler Help Portal",
        "host": "help.zscaler.com",
        "tier": "official",
        "credibility": TIER_OFFICIAL,
        "crawlable": True,
        "seeds": [
            "https://help.zscaler.com/",
            "https://help.zscaler.com/zia",
            "https://help.zscaler.com/zpa",
            "https://help.zscaler.com/zscaler-client-connector",
            "https://help.zscaler.com/zdx",
            "https://help.zscaler.com/zidentity",
            "https://help.zscaler.com/deception",
            "https://help.zscaler.com/zscaler-deployments-operations",
        ],
        # The portal publishes a sitemap; it lists every article in one
        # request and does not depend on how the navigation is rendered.
        "sitemaps": ["https://help.zscaler.com/sitemap.xml"],
        "article_patterns": ["best-practice", "leading-practice"],
        "why": "Canonical product documentation — all official Best-Practice / Leading-Practice guides live here.",
    },
    {
        "id": "zscaler_blogs",
        "name": "Zscaler Blogs",
        "host": "www.zscaler.com",
        "tier": "official",
        "credibility": TIER_OFFICIAL,
        "crawlable": True,
        # The blog index is paginated; these cover the main content hubs.
        "seeds": [
            "https://www.zscaler.com/blogs",
            "https://www.zscaler.com/blogs/product-insights",
            "https://www.zscaler.com/blogs/security-research",
            "https://www.zscaler.com/blogs/zero-trust",
        ],
        "sitemaps": ["https://www.zscaler.com/sitemap.xml"],
        "sitemap_child_filter": ["blog"],   # a sitemap index: only walk the blog children
        "article_patterns": ["best-practice", "leading-practice", "how-to", "guide"],
        "why": "Zscaler-authored posts. Often the first place new feature-level guidance appears before it lands in help.zscaler.com.",
    },
    {
        "id": "zscaler_trust",
        "name": "Zscaler Trust Portal",
        "host": "trust.zscaler.com",
        "tier": "official",
        "credibility": TIER_OFFICIAL,
        "crawlable": False,  # Heavily dynamic / status-page driven
        "seeds": ["https://trust.zscaler.com/"],
        "article_patterns": [],
        "why": "Operational trust portal — advisories, incident write-ups, and post-mortems that inform operational best practices.",
    },
    {
        "id": "zscaler_developer",
        "name": "Zscaler Developer Portal",
        "host": "developer.zscaler.com",
        "tier": "official",
        "credibility": TIER_OFFICIAL,
        "crawlable": True,
        "seeds": [
            "https://developer.zscaler.com/",
            "https://developer.zscaler.com/docs",
        ],
        "sitemaps": ["https://developer.zscaler.com/sitemap.xml"],
        "article_patterns": ["best-practice", "guide", "how-to"],
        "why": "Official API/SDK reference. Integration best practices for OneAPI consumers.",
    },
    {
        "id": "zscaler_github",
        "name": "Zscaler GitHub Organization",
        "host": "github.com",
        "tier": "official",
        "credibility": TIER_OFFICIAL,
        "crawlable": False,  # GitHub renders with JS; use curated READMEs instead.
        "seeds": ["https://github.com/zscaler"],
        "article_patterns": [],
        "why": "Official Zscaler open-source: SDKs, Terraform provider, Ansible collection. READMEs contain reference deployments.",
    },

    # ─── Tier 2: Authoritative integration docs ─────────────────────
    {
        "id": "terraform_registry",
        "name": "Terraform Registry — Zscaler Providers",
        "host": "registry.terraform.io",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": False,  # Registry pages are heavily JS-rendered
        "seeds": [
            "https://registry.terraform.io/providers/zscaler/zia/latest/docs",
            "https://registry.terraform.io/providers/zscaler/zpa/latest/docs",
            "https://registry.terraform.io/providers/zscaler/zcc/latest/docs",
        ],
        "article_patterns": [],
        "why": "Zscaler-published Terraform providers. Docs include resource-level best practices for IaC deployments.",
    },
    {
        "id": "ms_learn",
        "name": "Microsoft Learn — Zscaler Integrations",
        "host": "learn.microsoft.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://learn.microsoft.com/en-us/entra/identity/saas-apps/zscalerprivateaccess-tutorial",
            "https://learn.microsoft.com/en-us/entra/identity/saas-apps/zscaler-tutorial",
        ],
        "article_patterns": ["zscaler"],
        "why": "Microsoft-authored integration guides for Entra/Azure AD SSO + SCIM with ZIA/ZPA — the de-facto pattern most customers follow.",
    },
    {
        "id": "aws_docs",
        "name": "AWS Documentation — Zscaler Patterns",
        "host": "docs.aws.amazon.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/zscaler-private-access-zpa-integration-with-aws.html",
        ],
        "article_patterns": ["zscaler"],
        "why": "AWS prescriptive-guidance write-ups for ZPA-on-AWS connector placement.",
    },

    # ─── Tier 2 Authoritative — Ecosystem partners (SIEM / EDR / IdP)
    {
        "id": "splunk_lantern",
        "name": "Splunk Lantern — Zscaler Recipes",
        "host": "lantern.splunk.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://lantern.splunk.com/Search?q=zscaler",
        ],
        "article_patterns": ["zscaler"],
        "why": "Splunk-authored use-case recipes for ingesting/searching ZIA + ZPA logs in Splunk ES.",
    },
    {
        "id": "splunkbase",
        "name": "Splunkbase — Zscaler Apps & TAs",
        "host": "splunkbase.splunk.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": False,  # Splunkbase is heavily JS-rendered; use curated entries.
        "seeds": ["https://splunkbase.splunk.com/apps?keyword=zscaler"],
        "article_patterns": [],
        "why": "Official Splunk/Zscaler apps: CIM-compliant add-ons that define the canonical data model for Zscaler logs.",
    },
    {
        "id": "crowdstrike_integrations",
        "name": "CrowdStrike Marketplace — Zscaler Integrations",
        "host": "www.crowdstrike.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://www.crowdstrike.com/partners/zscaler/",
        ],
        "article_patterns": ["zscaler"],
        "why": "CrowdStrike-authored write-ups on Falcon + ZPA posture integration and ZIA + Falcon telemetry sharing.",
    },
    {
        "id": "okta_help",
        "name": "Okta Help — Zscaler Integrations",
        "host": "help.okta.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://help.okta.com/oie/en-us/content/topics/apps/apps-overview-get-started.htm",
        ],
        "article_patterns": ["zscaler"],
        "why": "Okta-authored SSO + SCIM provisioning guides for ZIA and ZPA (the second most common IdP pairing after Entra).",
    },
    {
        "id": "ping_docs",
        "name": "Ping Identity Docs — Zscaler SSO",
        "host": "docs.pingidentity.com",
        "tier": "authoritative",
        "credibility": TIER_AUTHORITATIVE,
        "crawlable": True,
        "seeds": [
            "https://docs.pingidentity.com/",
        ],
        "article_patterns": ["zscaler"],
        "why": "PingFederate / PingOne SSO integration guides for ZIA and ZPA.",
    },

    # ─── Tier 3: Community knowledge ────────────────────────────────
    {
        "id": "zscaler_community",
        "name": "Zscaler Community",
        "host": "community.zscaler.com",
        "tier": "community",
        "credibility": TIER_COMMUNITY,
        "crawlable": True,
        "seeds": [
            "https://community.zscaler.com/",
            "https://community.zscaler.com/s/topic/best-practices",
        ],
        "article_patterns": ["best-practice", "leading-practice", "how-to"],
        "why": "Zscaler-hosted customer community. Mixed: official posts from Zscaler staff + customer-contributed patterns. Treat as community-tier unless post author is a Zscaler employee.",
    },
    {
        "id": "reddit_zscaler",
        "name": "Reddit /r/zscaler",
        "host": "www.reddit.com",
        "tier": "community",
        "credibility": TIER_COMMUNITY,
        "crawlable": False,  # Reddit aggressively rate-limits unauth scraping; use curated.
        "seeds": ["https://www.reddit.com/r/zscaler/"],
        "article_patterns": [],
        "why": "Unofficial practitioner discussions. Useful for real-world gotchas but entirely unvetted.",
    },
]


def get_source(source_id: str) -> Dict[str, Any]:
    """Return the full source record for an id, or {} if unknown."""
    for s in SOURCES:
        if s["id"] == source_id:
            return s
    return {}


def credibility_for(source_id: str) -> int:
    """Return the numeric credibility (0-100) for a source id. Unknown
    sources default to 0 so the UI can show a warning badge."""
    s = get_source(source_id)
    return int(s.get("credibility", 0))


def tier_label(credibility: int) -> str:
    """Map a credibility score to a human-readable tier label."""
    if credibility >= TIER_OFFICIAL:
        return "Official"
    if credibility >= TIER_AUTHORITATIVE:
        return "Authoritative"
    if credibility >= TIER_COMMUNITY:
        return "Community"
    return "Unverified"


def crawlable_sources() -> List[Dict[str, Any]]:
    """Sources the crawler is allowed to hit (has a fetchable, non-SPA
    seed). Non-crawlable sources are still listed in SOURCES so the UI
    can render their curated entries with the right badge."""
    return [s for s in SOURCES if s.get("crawlable") and s.get("seeds")]


def allowed_hosts() -> List[str]:
    """Every host the source registry expects the HTTP layer to permit."""
    return sorted({s["host"] for s in SOURCES if s.get("host")})
