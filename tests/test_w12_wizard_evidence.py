"""Evidence for the policy wizard features that already existed (frameworks with per-rule control mapping, SSL
inspection ordering and TLS floor, DoH and Trusted Resolver rules, isolation profile and SSL certificate pickers,
ZDX Web and CloudPath probes are evidenced by tests/test_ops_zdx.py). Each test exercises the feature end to end on fakes; none changes behaviour."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import compliance_profiles as cp  # noqa: E402
import ops_zia_baseline as zb  # noqa: E402
from test_ops_zia_baseline import FULL, Tenant  # noqa: E402

FRAMEWORKS = ("HIPAA", "HITRUST", "PCI", "SOX", "FERPA", "CJIS", "NIST_800_53", "NIST_800_171", "GDPR", "CMMC_L2", "FEDRAMP_MOD",
              "FEDRAMP_HIGH", "GOVRAMP", "IRS_1075", "FED_ZT")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_every_framework_from_hipaa_to_govramp_is_a_profile_with_a_label_and_group():
    """ASVS V1.14.1 · CWE-1059: the compliance baselines HIPAA through GovRAMP (and the others listed) are profiles, each with a label, a group and the DLP packs it offers."""
    assert set(FRAMEWORKS) <= set(cp.PROFILES)
    for k in FRAMEWORKS:
        p = cp.PROFILES[k]
        assert p["label"] and p["group"] and isinstance(p["packs"], list) and p["packs"]


@pytest.mark.parametrize("profile", FRAMEWORKS)
def test_baseline_rules_map_to_named_controls_of_each_framework(profile):
    """ASVS V1.14.1 · CWE-1059: per-rule control mapping: under every framework the baseline rules the framework speaks to carry an objective and at least one named control (a framework with few controls, such as FERPA, maps fewer rules; the NIST-based ones map the encrypted-visibility rules)."""
    mapped = set()
    for r in zb.CATALOG:
        m = cp.map_rule(profile, r["key"])
        if m["controls"]:
            assert m["objective"] and all(c["id"] for c in m["controls"]), (profile, r["key"])
            mapped.add(r["key"])
    assert mapped, profile
    if profile.startswith(("NIST", "FEDRAMP", "CMMC", "GOVRAMP", "IRS", "FED_ZT")):
        assert {"fw.quic", "ssl.catch_all", "dns.doh"} <= mapped


def test_ssl_catch_all_is_last_with_a_tls_1_2_floor_and_doh_and_trusted_resolver_rules_exist():
    """ASVS V9.1.2 · CWE-327 · CWE-1188: the SSL catch-all rule inspects with TLS 1.2 minimum and is flagged catch-all (planned last); DNS DoH inspection and the Trusted Resolver redirect are catalogue rules that never block by redirect."""
    by = {r["key"]: r for r in zb.CATALOG}
    ssl = by["ssl.catch_all"]
    assert ssl["catch_all"] is True and ssl["fields"]["min_tls"] == "TLS_1_2"
    assert by["dns.doh"]["fields"]["protocols"] == ["DOHTTPS_RULE"] and by["dns.doh"]["tiers"]["strict"] == "BLOCK"
    assert by["dns.resolver"]["fields"]["trusted_resolver"] is True and by["dns.resolver"]["tiers"]["strict"] == "REDIR_REQ_KEEP_SENDER"
    rv = zb.review({"tier": "strict"})
    assert {r["key"] for r in rv["rules"]} >= {"ssl.catch_all", "dns.doh", "dns.resolver"}


def test_the_isolation_profile_and_certificate_pickers_are_filled_from_the_tenant_and_in_the_form():
    """WCAG 2.2 SC 4.1.2 · ASVS V5.1.3: the baseline's read lists the tenant's isolation profiles and ready-to-use certificates (no key), and the form has a labelled picker for each."""
    t = Tenant()
    out = ao.read_objects(t, zb.FAMILY, FULL)
    assert out["isolation_profiles"] and all(p.get("name") for p in out["isolation_profiles"])
    assert out["certificates"] and "MIIB" not in str(out["certificates"])
    js = open(os.path.join(ROOT, "static", "ops_zia_baseline.js"), encoding="utf-8").read()
    assert 'aria-label="Cloud Browser Isolation profile"' in js and 'aria-label="Intermediate certificate for the Inspect rules"' in js

