"""Manual bypass and PAC what-if on the Path analyzer (path_manual).

A pasted PAC (a PAC ZIA does not host), manual VPN gateways and Z-Tunnel
2.0 inclusion and exclusion lists are evaluated by the same checks as the
tenant's own lists (zcc_bypass, pac_eval: interpreted, never run): on
their own next to the tenant's answer, or added to the app profiles read
("merge") with the whole trace labelled hypothetical. Every input is
untrusted: capped, checked for its kind, refused in words before sign-in.
A fake tenant answers every read; nothing touches the network."""
from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

import data_flow as df
import dlp_api_server as srv
import pac_eval
import path_analyzer as pa
import path_manual as pm
from test_qa_func_path import FULL, PAC_FWD, Tenant, hop, run
from test_zcc_bypass_path import corp, profiles

DIRECT_PAC = """function FindProxyForURL(url, host) {
  if (dnsDomainIs(host, ".partner.example")) return "DIRECT";
  return "PROXY gateway.zscaler.net:80; DIRECT";
}"""


def manual(**kw):
    return pm.parse(kw)


def alone(dest, m, routes=None, **kw):
    return run(dest, routes if routes is not None else profiles(corp()), manual=m, **kw)


# ── Parsing: untrusted input ────────────────────────────────────────────
def test_nothing_given_is_no_manual_input():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: empty manual inputs are none, so the analysis is unchanged."""
    assert pm.parse(None) is None and pm.parse({}) is None
    assert pm.parse({"vpn_gateways": [], "pac_text": "  ", "mode": "alone"}) is None


@pytest.mark.parametrize("raw,why", [
    ({"ipv4_exclude": ["not-an-ip"]}, "is not an address"),
    ({"dest_exclude": ["bad host!"]}, "is not a host name"),
    ({"vpn_gateways": ["vpn\x07.example"]}, "control characters"),
    ({"vpn_gateways": ["x" * 300]}, "longer than"),
    ({"vpn_gateways": [f"g{i}.example" for i in range(pm.MAX_LIST + 1)]}, f"at most {pm.MAX_LIST}"),
    ({"vpn_gateways": 7}, "give a list"),
    ({"vpn_gateways": [7]}, "every entry is text"),
    ({"pac_text": "return 'DIRECT';"}, "no FindProxyForURL"),
    ({"pac_text": "function FindProxyForURL(u,h){}" + " " * pac_eval.MAX_SOURCE}, "longer than"),
    ({"pac_text": 5}, "is text"),
    ({"mode": "apply"}, "on their own"),
    ({"shell": "rm -rf /"}, "Unknown manual input"),
    ("vpn.example", "a set of lists"),
])
def test_bad_manual_inputs_are_refused_in_words(raw, why):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-400 · WSTG-INPV-01: a wrong kind, a control character, an oversized entry, list or PAC is refused with a sentence."""
    with pytest.raises(pm.ManualError) as e:
        pm.parse(raw)
    assert why in str(e.value)


def test_entries_are_split_deduplicated_and_kept_as_typed():
    """ASVS V5.1.3 · CWE-20: one per line, commas or spaces; brackets on IPv6 dropped; duplicates once; a port on a gateway is allowed."""
    m = pm.parse({"vpn_gateways": "vpn.acme.example:443\nvpn.acme.example:443, 198.51.100.9", "ipv4_exclude": ["[2001:db8::/32]", "52.0.0.0/8"],
                  "dest_exclude": "*.zoom.us .partner.example"})
    assert m["vpn_gateways"] == ["vpn.acme.example:443", "198.51.100.9"]
    assert m["ipv4_exclude"] == ["2001:db8::/32", "52.0.0.0/8"] and m["dest_exclude"] == ["*.zoom.us", ".partner.example"]
    assert m["mode"] == "alone" and pm.counts(m)["vpn_gateways"] == 2


# ── On their own: oracle ────────────────────────────────────────────────
@pytest.mark.parametrize("inputs,dest,outcome,decider", [
    ({"vpn_gateways": ["vpn.acme.example"]}, "vpn.acme.example", "bypassed", "VPN gateway bypass"),
    ({"vpn_gateways": ["198.51.100.0/24:443"]}, "198.51.100.20", "bypassed", "VPN gateway bypass"),
    ({"vpn_gateways": ["vpn.acme.example"]}, "files.example", "forwarded", None),
    ({"ipv4_exclude": ["52.0.0.0/8"]}, "52.1.2.3", "bypassed", "Z-Tunnel 2.0 destination exclusions"),
    ({"ipv4_include": ["198.51.100.0/24"]}, "203.0.113.5", "bypassed", "Z-Tunnel 2.0 destination inclusions"),
    ({"ipv4_include": ["198.51.100.0/24"]}, "198.51.100.7", "forwarded", None),
    ({"ipv4_include": ["198.51.100.0/24"]}, "example.org", "unknown", None),     # a host name is never resolved
    ({"dest_exclude": ["files.example"]}, "files.example", "forwarded", None),   # a domain list decides DNS, not tunnelling
    ({"pac_text": DIRECT_PAC}, "www.partner.example", "bypassed", "Pasted PAC"),
    ({"pac_text": DIRECT_PAC}, "example.org", "forwarded", None),
    ({"vpn_gateways": ["vpn.acme.example"], "pac_text": DIRECT_PAC}, "vpn.acme.example", "bypassed", "VPN gateway bypass"),   # VPN first
])
def test_manual_inputs_on_their_own_oracle(inputs, dest, outcome, decider):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: manual VPN gateways, Z-Tunnel 2.0 lists and a pasted PAC decide as the tenant's own lists would, in order, naming the list."""
    res = alone(dest, manual(**inputs))
    mi = res["manual_inputs"]
    assert mi["hypothetical"] is True and mi["mode"] == "alone"
    assert mi["outcome"] == outcome, mi
    assert (mi["decided_by"] or {}).get("list") == decider
    if outcome == "bypassed":
        assert mi["headline"].startswith("What-if:") and "never reach Zscaler" in mi["headline"]
    # Alone never changes the tenant's own answer: the profile has no bypass.
    assert hop(res, "zcc")["status"] == "pass" and res["verdict"]["reaches_zscaler"]


def test_the_pasted_pac_is_interpreted_never_run_and_shown_as_a_step():
    """ASVS V5.2.4 · V12.3.3 · CWE-94 · CWE-95: a pasted PAC that would run code is never executed; the steps are shown in the shared hop shape."""
    evil = "function FindProxyForURL(url, host) { eval('x'); return 'DIRECT'; }"
    res = alone("example.org", manual(pac_text=evil))
    mi = res["manual_inputs"]
    assert mi["outcome"] in ("unknown", "bypassed")
    pac = next(h for h in mi["modules"] if h["key"] == "pac")
    assert pac["module"] == "PAC file (pasted)"
    good = alone("www.partner.example", manual(pac_text=DIRECT_PAC))["manual_inputs"]
    assert [h["key"] for h in good["modules"]] == ["zcc", "pac"] and good["pac"]["status"] == "bypass"


def test_a_pac_decides_web_traffic_only():
    """ASVS V1.4.4 · CWE-697: for SSH the pasted PAC does not apply and the block says why."""
    res = alone("www.partner.example", manual(pac_text=DIRECT_PAC), protocol="tcp", port=22)
    mi = res["manual_inputs"]
    assert mi["outcome"] == "forwarded" and mi["pac"]["status"] == "na" and "web traffic only" in mi["pac"]["detail"]


# ── Merge: added to the tenant's profiles ───────────────────────────────
def test_merged_inputs_change_the_trace_and_are_labelled_hypothetical():
    """ASVS V1.4.4 · CWE-697 · CWE-451: in merge mode a manual VPN gateway bypasses on the traced path itself, and the verdict says it is a what-if."""
    m = manual(vpn_gateways=["vpn.acme.example"], mode="merge")
    res = run("vpn.acme.example", profiles(corp()), manual=m)
    assert hop(res, "zcc")["status"] == "bypass" and hop(res, "zcc")["bypass"]["list"] == "VPN gateway bypass"
    assert res["verdict"]["hypothetical"] is True and res["verdict"]["headline"].startswith("What-if (your manual inputs added)")
    assert res["manual_inputs"]["merged"]["profiles"] == 1
    assert any(a.startswith("What-if: the manual inputs") for a in res["assumptions"])
    # The read kept for the next destination is the tenant's, without the inputs.
    kept = res["snapshot_for_cache"]["client_connector"]["app_profiles"][0]
    assert "vpn.acme.example" not in (kept["bypass"].get("vpn_gateways") or []) + (kept["lists"].get("vpn_gateways") or [])


def test_a_pac_hosted_outside_zia_is_said_and_a_pasted_one_replaces_it():
    """ASVS V1.4.4 · CWE-754 · CWE-697: a forwarding profile's PAC on another server is 'not evaluated: hosted outside ZIA'; pasted in merge mode it is evaluated."""
    routes = profiles(corp(), fwd=PAC_FWD)
    res = run("www.partner.example", routes)
    p = hop(res, "pac")
    assert p["status"] == "unknown" and p["why"] == "PAC hosted outside ZIA" and "pac.example/p.pac" in p["detail"]
    res = run("www.partner.example", routes, manual=manual(pac_text=DIRECT_PAC, mode="merge"))
    p = hop(res, "pac")
    assert p["status"] == "bypass" and p["decided_by"]["name"] == pm.PAC_NAME
    assert res["verdict"]["outcome"] == "bypassed" and res["verdict"]["hypothetical"]


def test_apply_never_changes_the_read_it_is_given():
    """ASVS V1.4.4 · CWE-664: the merge works on a copy; the tenant read is not changed."""
    zcc = df.read_client_connector(Tenant(profiles(corp())))
    before = copy.deepcopy(zcc)
    z, info = pm.apply(zcc, manual(vpn_gateways=["a.example"], ipv4_exclude=["52.0.0.0/8"], pac_text=DIRECT_PAC, mode="merge"))
    assert zcc == before and info["profiles"] == 1
    assert z["app_profiles"][0]["tunnel"]["exclude"][-1] == "52.0.0.0/8" and z["pac_files"][0]["url"] == pm.PAC_URL


# ── The route: checked before sign-in ───────────────────────────────────
@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(srv, "_build_client", lambda req: (_ for _ in ()).throw(AssertionError("must not sign in")))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("must not sign in")))
    return TestClient(srv.app)


BODY = {"destination": "vpn.acme.example", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "vanity_domain": "acme",
        "scopes": ["zcc", "dlp"], "channels": {"web_dlp": "zscaler"}}


@pytest.mark.parametrize("bad,why", [
    ({"ipv4_exclude": ["nope"]}, "is not an address"),
    ({"pac_text": "<script>alert(1)</script>"}, "no FindProxyForURL"),
])
def test_the_route_refuses_bad_inputs_before_sign_in(api, bad, why):
    """ASVS V5.1.3 · V13.1.3 · CWE-20 · WSTG-INPV-01: a bad what-if input is a 400 in words before any sign-in; nothing is read."""
    r = api.post("/api/path-analyzer/start", json=dict(BODY, whatif_bypass=bad))
    assert r.status_code == 400, r.text
    assert why in r.json()["detail"] and "Nothing was read" in r.json()["detail"]
    assert "<script>" not in r.text


def test_merge_needs_client_connector_in_scope(api):
    """ASVS V4.1.3 · CWE-863: merging into the tenant's app profiles while Client Connector is not ticked is refused before sign-in."""
    r = api.post("/api/path-analyzer/start", json=dict(BODY, scopes=["dlp"], whatif_bypass={"vpn_gateways": ["vpn.acme.example"], "mode": "merge"}))
    assert r.status_code == 400 and r.json()["detail"] == srv.PATH_MANUAL_MERGE_NOT_IN_SCOPE
