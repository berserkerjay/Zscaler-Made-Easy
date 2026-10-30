"""ZIA admin ranking: whether it is on, and the order rules are evaluated in.

When the tenant's Admin Ranking is on, ZIA evaluates the rules of a ranked
policy by admin rank first (0 is the highest rank, 7 the lowest) and by
rule order within one rank; when it is off, by rule order alone. Every
analysis that decides "which rule applies" (the Path analyzer and its
what-if, Test a list, workload traffic into ZIA, the shadowed-rule
analysis) orders rules through this module so they agree.

Sources (what is relied on, and what is assumed):

  * The setting: GET /zia/advancedSettings, field enableAdminRankAccess
    (zscaler-sdk-python 1.11.3, zia/models/advanced_settings.py; read by
    zia.advanced_settings.get_advanced_settings, the call sdk_client maps
    to /zia/advancedSettings). The SDK docstring calls it "admin
    rank-based access control in policies".
  * The evaluation order: Zscaler Help, "Understanding Admin Rank"
    (help.zscaler.com/zia/understanding-admin-rank, already cited in
    zscaler_automation_checks.py): rank 0 is the highest, 7 the lowest,
    and with admin ranking enabled the rule order is evaluated with the
    admin rank first. Not re-fetched in this session (the help site was
    not reachable), so the wording is as recorded there.
  * Which rules carry a rank: the SDK models with a `rank` field (URL
    filtering, Cloud App Control, SSL inspection, File Type Control, Web
    DLP, Cloud Firewall filtering, DNS and IPS, Sandbox, bandwidth, SaaS
    and Endpoint DLP). RANKED lists the policies the analyses here order.

Assumed (not confirmed in a source, said where it matters):

  * A rule without a rank, or with one outside 0..7, sits at rank 7 (the
    rank the API gives new rules; remediation.py and pack_deploy.py use it).
  * Rank ties fall back to rule order, then rule id; the default rule stays
    last whatever its rank.
  * Through the SDK client a missing enableAdminRankAccess reads as false
    (the SDK model's default); the raw client sees the API's own answer.
  * ZPA policies and Cloud & Branch Connector forwarding rules are not
    ranked here (workload_path, zpa_path keep rule order).

The setting is read only when ZIA platform is ticked on the Scope page (it
is a ZIA platform setting, like the other advanced settings url_tools
reads). Not read, unreadable or absent from an older kept read, it is
never guessed: the analyses keep plain rule order and say so wherever rank
order would decide differently.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

ENDPOINT = "/zia/advancedSettings"
FIELD = "enableAdminRankAccess"
SCOPES = ("zia_extras",)
SOURCE = ("ZIA advanced settings (GET /zia/advancedSettings, enableAdminRankAccess); evaluation order per Zscaler Help, "
          "Understanding Admin Rank (help.zscaler.com/zia/understanding-admin-rank)")
HIGHEST, LOWEST = 0, 7
DEFAULT_RANK = LOWEST   # assumed: a rule without a rank is at the lowest rank
ON, OFF, UNKNOWN, OUT_OF_SCOPE = "on", "off", "unknown", "out_of_scope"

# Policy keys (data_flow / zia_path_modules sections, shadow_rules policies)
# whose rules ZIA orders by rank when admin ranking is on.
RANKED = frozenset({"url", "cac", "ssl", "ftc", "dlp", "firewall", "dns", "sandbox",
                    "url_filtering", "cloud_app_control", "ssl_inspection", "web_dlp"})

NOT_IN_SCOPE_WHY = "ZIA platform is not ticked on the Scope page, so the admin ranking setting was not read"
NOT_RECORDED_WHY = "the kept tenant read was made before the admin ranking setting was read"


def in_scope(scopes: Any) -> bool:
    """Whether the Scope page's ticked scopes allow reading the setting."""
    sc = {str(s).strip() for s in scopes} if isinstance(scopes, (list, tuple, set, frozenset)) else set()
    return any(s in sc for s in SCOPES)


def _setting(state: str, why: str = "") -> Dict[str, Any]:
    return {"state": state, "why": why, "source": SOURCE}


def parse(data: Any) -> Dict[str, Any]:
    """The setting from an /advancedSettings answer (camelCase or the SDK's
    snake_case). Absent or not a yes/no: unknown, never off."""
    if not isinstance(data, dict):
        return _setting(UNKNOWN, "the advanced settings answer was not a settings object")
    for k in (FIELD, "enable_admin_rank_access"):
        if k in data:
            v = data[k]
            if isinstance(v, bool):
                return _setting(ON if v else OFF)
            if isinstance(v, str) and v.strip().lower() in ("true", "false"):
                return _setting(ON if v.strip().lower() == "true" else OFF)
            return _setting(UNKNOWN, f"{FIELD} was not true or false")
    return _setting(UNKNOWN, f"the advanced settings do not say whether admin ranking is on ({FIELD} is missing)")


def read(client: Any, scopes: Any) -> Dict[str, Any]:
    """{state: on | off | unknown | out_of_scope, why, source}. One GET,
    only when ZIA platform is in scope; a failed read is unknown with the
    reason, never off."""
    if not in_scope(scopes):
        return _setting(OUT_OF_SCOPE, NOT_IN_SCOPE_WHY)
    try:
        data, code = client.get(ENDPOINT)
    except Exception as e:  # noqa: BLE001 — Stop is re-raised by the caller's stop_on; anything else is "could not read"
        import zia_rate
        from data_flow import ReadStopped
        if isinstance(e, (ReadStopped, zia_rate.Cancelled)):
            raise
        return _setting(UNKNOWN, f"the advanced settings could not be read ({type(e).__name__})")
    if code != 200:
        return _setting(UNKNOWN, f"the advanced settings could not be read (HTTP {code})")
    return parse(data)


def state_of(setting: Any) -> str:
    """The state of a recorded setting; anything missing (an older kept
    read or snapshot) is unknown."""
    st = setting.get("state") if isinstance(setting, dict) else None
    return st if st in (ON, OFF, UNKNOWN, OUT_OF_SCOPE) else UNKNOWN


def recorded(setting: Any) -> Dict[str, Any]:
    """A recorded setting as stored, or unknown for a read made before it was recorded."""
    if isinstance(setting, dict) and state_of(setting) == setting.get("state"):
        return dict(setting)
    return _setting(UNKNOWN, NOT_RECORDED_WHY)


def rank_of(rule: Any) -> int:
    """The rule's admin rank, 0..7; DEFAULT_RANK when it has none (assumed)."""
    v = rule.get("rank") if isinstance(rule, dict) else None
    if isinstance(v, bool):
        return DEFAULT_RANK
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return DEFAULT_RANK
    return n if HIGHEST <= n <= LOWEST else DEFAULT_RANK


def shown_rank(rule: Any) -> Optional[int]:
    """The rank to show next to the order: the rule's own, or None when it has none."""
    v = rule.get("rank") if isinstance(rule, dict) else None
    if v is None or isinstance(v, bool):
        return None
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if HIGHEST <= n <= LOWEST else None


def key(base: Callable[[Any], Sequence[Any]], ranked: bool, is_default: Callable[[Any], bool] = lambda r: False) -> Callable[[Any], Tuple[Any, ...]]:
    """A sort key: the default rule last, then (when `ranked`) the admin
    rank, then the caller's own key (order, id)."""
    def k(r: Any) -> Tuple[Any, ...]:
        return (1 if is_default(r) else 0, rank_of(r) if ranked else 0) + tuple(base(r))
    return k


def ordered(rules: Iterable[Any], base: Callable[[Any], Sequence[Any]], ranked: bool,
            is_default: Callable[[Any], bool] = lambda r: False) -> List[Any]:
    return sorted(rules, key=key(base, ranked, is_default))


def alternative(state: str) -> Optional[bool]:
    """The other ordering to compare with: rank order when the setting is
    on is compared with plain order (to say rank decided), and when it is
    not known (unknown, not in scope) plain order is compared with rank
    order (to say it could decide differently). None when it is off."""
    if state == ON:
        return False
    if state in (UNKNOWN, OUT_OF_SCOPE):
        return True
    return None


def same_rule(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is b
    if a is b:
        return True
    ia, ib = (a.get("id") if isinstance(a, dict) else None), (b.get("id") if isinstance(b, dict) else None)
    return ia is not None and str(ia) == str(ib)


def _where(rule: Dict[str, Any]) -> str:
    rk = shown_rank(rule)
    o = rule.get("order")
    return ", ".join(x for x in ((f"rank {rk}" if rk is not None else f"no rank, taken as {DEFAULT_RANK}"),
                                 (f"order {o}" if o not in (None, "") else "")) if x)


def name_of(rule: Dict[str, Any]) -> str:
    return str(rule.get("name") or f"rule {rule.get('id')}")


def rank_decided(chosen: Dict[str, Any], by_order: Dict[str, Any]) -> str:
    """The sentence for a decision admin rank made: `chosen` (rank first)
    beat `by_order`, which plain rule order would have picked."""
    return (f"Admin ranking is on, so rules are evaluated by admin rank first: '{name_of(chosen)}' ({_where(chosen)}) "
            f"decides before '{name_of(by_order)}' ({_where(by_order)}), which also matches and comes first by rule order.")


def caution(setting: Any, by_order: Dict[str, Any], by_rank: Dict[str, Any]) -> str:
    """The plain-language caution when the setting is not known and rank
    order would pick another rule with another outcome."""
    st = state_of(setting)
    why = (setting or {}).get("why") if isinstance(setting, dict) else ""
    head = ("Admin ranking was not read" if st == OUT_OF_SCOPE else "Admin ranking could not be read") + (f" ({why})" if why else "")
    return (f"{head}; rules '{name_of(by_order)}' ({_where(by_order)}) and '{name_of(by_rank)}' ({_where(by_rank)}) "
            f"would decide differently with it on: '{name_of(by_order)}' decides by rule order, '{name_of(by_rank)}' by admin rank.")


def describe(setting: Any) -> str:
    """One sentence for the result's assumptions."""
    st = state_of(setting)
    why = (setting or {}).get("why") if isinstance(setting, dict) else ""
    if st == ON:
        return "Admin ranking is on (ZIA advanced settings): ranked policies are evaluated by admin rank first (0 highest, 7 lowest), then by rule order."
    if st == OFF:
        return "Admin ranking is off (ZIA advanced settings): rules are evaluated by rule order."
    return ("Admin ranking " + ("was not read" if st == OUT_OF_SCOPE else "could not be read") + (f" ({why})" if why else "")
            + ": rules are taken in rule order, and a module where admin rank would decide differently says so.")
