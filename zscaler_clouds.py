"""The Zscaler clouds a tenant can live on, and how each one is reached.

One table for the whole app (the web GUI, the API server, the assessment
engine, the SDK wrapper, the MCP server and the discovery tool), so a
cloud is never spelled or mapped differently in two places.

A tenant's cloud is the one in its ZIA admin URL: admin.zscaler.net,
admin.zscalerone.net, admin.zscalertwo.net, admin.zscalerthree.net,
admin.zscloud.net, admin.zscalerten.net, admin.zscalerbeta.net,
admin.zscalergov.net or admin.zscalergov.us.

OneAPI does not care which commercial cloud the tenant is on: every
commercial tenant signs in at <vanity>.zslogin.net and calls
api.zsapi.net. Only three environments are different, and they are what
the SDK's `cloud` setting selects:

    beta   <vanity>.zsloginbeta.net     api.beta.zsapi.net
    gov    <vanity>.zidentitygov.net    api.zscalergov.net   (FedRAMP, zscalergov.net)
    govus  <vanity>.zidentitygov.us     api.zscalergov.us    (FedRAMP, zscalergov.us)
"""
from __future__ import annotations

from typing import Dict, List, Optional

# value the app stores → (label for people, ZIA admin host, OneAPI environment or None for commercial)
CLOUDS: Dict[str, Dict[str, Optional[str]]] = {
    "production":   {"label": "Commercial (zscaler.net and every other commercial cloud)", "admin": "admin.zscaler.net", "environment": None},
    "zscaler":      {"label": "zscaler.net", "admin": "admin.zscaler.net", "environment": None},
    "zscalerone":   {"label": "zscalerone.net", "admin": "admin.zscalerone.net", "environment": None},
    "zscalertwo":   {"label": "zscalertwo.net", "admin": "admin.zscalertwo.net", "environment": None},
    "zscalerthree": {"label": "zscalerthree.net", "admin": "admin.zscalerthree.net", "environment": None},
    "zscloud":      {"label": "zscloud.net", "admin": "admin.zscloud.net", "environment": None},
    "zscalerten":   {"label": "zscalerten.net", "admin": "admin.zscalerten.net", "environment": None},
    "zscalerbeta":  {"label": "zscalerbeta.net (beta / preview)", "admin": "admin.zscalerbeta.net", "environment": "beta"},
    "zscalergov":   {"label": "zscalergov.net (US Government, FedRAMP)", "admin": "admin.zscalergov.net", "environment": "gov"},
    "zscalergovus": {"label": "zscalergov.us (US Government, FedRAMP)", "admin": "admin.zscalergov.us", "environment": "govus"},
}

# Other spellings people and older saved profiles use.
ALIASES: Dict[str, str] = {
    "": "production", "prod": "production", "commercial": "production",
    "beta": "zscalerbeta", "zspreview": "zscalerbeta", "preview": "zscalerbeta",
    "gov": "zscalergov", "zscalergov.net": "zscalergov", "fedramp": "zscalergov",
    "govus": "zscalergovus", "zscalergov.us": "zscalergovus",
    "ten": "zscalerten",
}
for _name in list(CLOUDS):
    ALIASES.setdefault(f"{_name}.net", _name)

ALLOWED = frozenset(CLOUDS) | frozenset(k for k in ALIASES if k)

_ENV_HOSTS: Dict[Optional[str], Dict[str, str]] = {
    None:    {"login": "{vanity}.zslogin.net", "api": "https://api.zsapi.net"},
    "beta":  {"login": "{vanity}.zsloginbeta.net", "api": "https://api.beta.zsapi.net"},
    "gov":   {"login": "{vanity}.zidentitygov.net", "api": "https://api.zscalergov.net"},
    "govus": {"login": "{vanity}.zidentitygov.us", "api": "https://api.zscalergov.us"},
}


def normalize(cloud: Optional[str]) -> str:
    """The stored cloud value for any accepted spelling (case-insensitive,
    with or without `.net`, `gov`/`govus`/`beta` accepted). Raises
    ValueError, naming the accepted values, for anything else."""
    c = (cloud or "").strip().lower()
    c = c.removeprefix("admin.")
    if c in CLOUDS:
        return c
    if c in ALIASES:
        return ALIASES[c]
    raise ValueError(f"Unknown Zscaler cloud '{cloud}'. Use the name in the tenant's admin URL: {', '.join(sorted(CLOUDS))}.")


def environment(cloud: Optional[str]) -> Optional[str]:
    """The OneAPI environment the SDK needs for `cloud`: None for every
    commercial cloud (the SDK must then be given no cloud at all), or
    'beta', 'gov', 'govus'."""
    return CLOUDS[normalize(cloud)]["environment"]


def token_url(vanity_domain: str, cloud: Optional[str]) -> str:
    """The OAuth2 token endpoint for a tenant on `cloud`."""
    return "https://" + _ENV_HOSTS[environment(cloud)]["login"].format(vanity=vanity_domain) + "/oauth2/v1/token"


def api_base(cloud: Optional[str]) -> str:
    """The OneAPI gateway for a tenant on `cloud`."""
    return _ENV_HOSTS[environment(cloud)]["api"]


def is_government(cloud: Optional[str]) -> bool:
    return environment(cloud) in ("gov", "govus")


def choices() -> List[Dict[str, Optional[str]]]:
    """What a cloud picker shows, in a sensible order."""
    return [{"value": name, **spec} for name, spec in CLOUDS.items()]
