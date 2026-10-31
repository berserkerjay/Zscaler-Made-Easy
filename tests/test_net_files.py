"""Network files: DNS records for Client Connector hostnames
(dns_forward_zones.py, the fleet page) and Zscaler's published IP ranges
built into firewall allowlists (zscaler_ip_ranges.py, Policy exports).

DNS: hostnames cleaned into RFC 1123 labels (an oracle table), nothing a
tenant can type reaches a configuration file, duplicates and collisions
reported and written once, the Unbound, BIND named.conf and zone file
output checked by small grammar checkers written here, the CSV
spreadsheet-safe, the options checked, and the API building from a
finished fleet read with counts only in the audit log.

IP ranges: aggregation checked against a brute-force oracle (every
address of small IPv4 and IPv6 windows, seeded random sets, exclusions,
both ends of each address space), feeds checked as untrusted
(malformed, oversized, deep, too many entries, private or over-broad
ranges, host names outside Zscaler's domains), the fetch off by default
and only ever to https://config.zscaler.com with no redirect and a size
cap, staleness and missing feeds said out loud, every output format, and
the API.

No test reaches a DNS server, Zscaler or a tenant: the feeds are small
made-up fixtures in the config portal's format (tests/fixtures/
zscaler_ranges), the network is refused (or a recorder that answers from a
table), and the fleet read is built by zcc_fleet.analyze from fake devices.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import ipaddress
import json
import os
import random
import re
from pathlib import Path

import pytest
import requests
import requests.adapters

import dns_forward_zones as dfz
import zscaler_ip_ranges as zr

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "zscaler_ranges"
NOW = dt.datetime(2026, 10, 31, 12, 0, tzinfo=dt.timezone.utc)
LDH = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


@pytest.fixture(autouse=True)
def _own_folder(tmp_path, monkeypatch):
    """Each test keeps its feeds in its own folder; the network is refused."""
    monkeypatch.setenv("DLP_CHECK_ZSCALER_RANGES_DIR", str(tmp_path / "ranges"))
    monkeypatch.delenv("DLP_CHECK_ZSCALER_RANGES_MAX_AGE_DAYS", raising=False)

    def refuse(self, request, **kw):
        raise AssertionError(f"no network in tests: {request.url}")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", refuse)


def fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


def dev(host, platform="Windows", reg="registered", user="", seen=3600):
    return {"hostname": host, "platform": platform, "registration": reg, "user": user, "seconds_since_seen": seen}


def build(devs, **kw):
    kw.setdefault("domain", "corp.example.com")
    kw.setdefault("resolvers", "10.0.0.12")
    return dfz.build(devs, now=NOW, **kw)


# ══ DNS: labels ══════════════════════════════════════════════════════
LABELS = [
    ("LKF-LT-0001", "lkf-lt-0001", False),
    ("lkf-lt-0001", "lkf-lt-0001", False),
    ("John's MacBook Pro", "johns-macbook-pro", True),
    ("Rowans-MacBook-Pro.local", "rowans-macbook-pro", True),
    ("pc1.corp.example.com", "pc1", True),
    ("PC_1", "pc-1", True),
    ("pc--1", "pc-1", True),
    ("-edge-", "edge", True),
    ("Ünïcødé-PC", "unicde-pc", True),
    ("ＰＣ１", "pc1", True),                      # full-width letters fold (NFKD)
    ("xn--abc", "xn-abc", True),                 # never a reserved '--' label
    ("a" * 80, "a" * 63, True),
    ("a" * 62 + "-b", "a" * 62, True),           # cut at 63, no trailing '-'
    ("1234", "1234", False),
    ("", "", True), ("---", "", True), (".hidden", "", True), ("日本", "", True), (None, "", True),
]


@pytest.mark.parametrize("raw,label,changed", LABELS)
def test_hostnames_become_rfc1123_labels(raw, label, changed):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: each hostname becomes one RFC 1123 label (letters, digits, inner '-', at most 63) or nothing, and a change is said."""
    got, note = dfz.clean_label(raw)
    assert got == label
    if got:
        assert LDH.match(got) and got[2:4] != "--"
    assert (note != "") == changed, note


INJECT = ['pc"; forward-addr: 6.6.6.6 #', "pc\nforward-zone:", "pc}; zone \"x\" {", "pc;rm -rf /", "pc $ORIGIN evil.", "pc‮1", "pc\x00x",
          "=HYPERLINK(\"http://x\")", "pc\\x", "pc'x", "pc`x", "pc{x}", "pc x"]


def test_nothing_a_tenant_types_reaches_a_configuration_file():
    """ASVS V5.3.6 · CWE-74 · CWE-93 · WSTG-INPV-12: quotes, newlines, ';', braces, '$', spaces and control characters in hostnames never reach the Unbound, BIND or zone text; every name there is LDH."""
    out = build([dev(h) for h in INJECT], resolvers="10.0.0.12, 2001:db8::53")
    zones, _, _ = check_unbound(out["files"]["unbound"])
    assert zones and all(z["addrs"] == ["10.0.0.12", "2001:db8::53"] for z in zones), "no injected forward-addr"
    assert len(check_named(out["files"]["bind_forward"])) == len(zones)
    assert set(check_zone(out["files"]["bind_zone"])) == {"corp.example.com."}, "no injected $ORIGIN"
    for key in ("unbound", "bind_forward", "bind_zone"):
        text = out["files"][key]
        assert "\x00" not in text and "‮" not in text and "6.6.6.6" not in text and "rm -rf" not in text and '\\"' not in text


def test_the_comment_lines_carry_no_tenant_text():
    """CWE-117 · ASVS V5.3.6: the header comments hold only the date, the checked domain and the resolver addresses, never a hostname."""
    out = build([dev("pc\n#evil")], read_at="2026-10-31T10:00:00+00:00")
    for key in ("unbound", "bind_forward", "bind_zone"):
        comments = [ln for ln in out["files"][key].splitlines() if ln.startswith(("#", "//", ";"))]
        assert comments and not any("evil" in c for c in comments)


def test_duplicates_and_collisions_are_reported_and_written_once():
    """CWE-694 (duplicate identifiers) · ASVS V1.4.4: the same hostname twice is a duplicate; two hostnames that give one label are a collision; each name is written once and both are listed."""
    out = build([dev("LKF-LT-0001"), dev("lkf-lt-0001"), dev("PC_1", "macOS"), dev("PC-1", "Linux"), dev("pc.1")])
    c = out["counts"]
    assert c["records"] == 3 and c["duplicates"] == 1 and c["collisions"] == 1
    assert out["duplicates"] == [{"fqdn": "lkf-lt-0001.corp.example.com", "hostname": "LKF-LT-0001", "extra_enrolments": 1}]
    assert out["collisions"] == [{"fqdn": "pc-1.corp.example.com", "hostnames": ["PC_1", "PC-1"]}]
    assert out["files"]["unbound"].count('name: "pc-1.corp.example.com."') == 1
    assert out["files"]["bind_forward"].count('zone "lkf-lt-0001.corp.example.com"') == 1
    rows = list(csv.DictReader(io.StringIO(out["files"]["csv"])))
    assert [r["status"] for r in rows] == ["ok", "duplicate", "renamed", "collision", "renamed"]
    assert rows[-1]["fqdn"] == "pc.corp.example.com" and "domain part dropped" in rows[-1]["note"]
    assert any("collision" in w for w in out["warnings"])


def test_unusable_reserved_and_too_long_names_are_refused_with_a_reason():
    """CWE-20 · ASVS V5.1.4: a hostname with no letters or digits, one equal to the zone file's resolver name, or one too long for the domain is not written and says why."""
    long_dom = ".".join(["d" * 60] * 3) + ".example"
    out = build([dev("---"), dev("zcc-resolver-1"), dev("ok-1")])
    assert out["counts"]["invalid"] == 1 and out["counts"]["reserved"] == 1 and out["counts"]["records"] == 1
    assert {r["status"] for r in out["refused"]} == {"invalid", "reserved"}
    too = build([dev("a" * 63)], domain=long_dom[:240])
    assert too["counts"]["too_long"] == 1 and too["counts"]["records"] == 0 and too["warnings"]


def test_the_device_filters_platform_registration_and_last_seen():
    """ASVS V1.4.4 · CWE-697: only the ticked platforms, registered devices (unless unticked) and devices seen within the window get names; each filter is counted."""
    devs = [dev("win"), dev("mac", "macOS"), dev("phone", "iOS"), dev("gone", reg="removed"), dev("old", seen=40 * 86400), dev("never", seen=None), dev("odd", "?")]
    out = build(devs, seen_within_days=30)
    names = sorted(r["label"] for r in out["preview"] if r["fqdn"])
    assert names == ["mac", "win"]
    c = out["counts"]
    assert (c["filtered_platform"], c["filtered_registration"], c["filtered_seen"]) == (2, 1, 2)
    every = build(devs, platforms=list(dfz.PLATFORMS), registered_only=False)
    assert every["counts"]["records"] == 7


def test_email_domain_mappings_add_a_second_name():
    """ASVS V5.1.3 · CWE-20: a device whose user's e-mail domain is mapped also gets a name under the mapped DNS domain; bad mapping lines are refused in words."""
    out = build([dev("lt-1", user="a@Subsidiary.com"), dev("lt-2", user="b@corp.example.com")], mappings="# comment\nsubsidiary.com: sub.corp.example\n@other.com = other.example")
    fq = sorted(r["fqdn"] for r in out["preview"])
    assert fq == ["lt-1.corp.example.com", "lt-1.sub.corp.example", "lt-2.corp.example.com"]
    assert "$ORIGIN sub.corp.example." in out["files"]["bind_zone"]
    for bad in ("subsidiary.com", "a: b: c", "bad domain: x.example", "x.com: -bad-.example"):
        with pytest.raises(dfz.DnsInputError):
            build([dev("x")], mappings=bad)


@pytest.mark.parametrize("domain", ["", "corp example.com", "a..b", "-a.example", "a_b.example", "x" * 64 + ".example", "a.example\n", "a.example;", "exаmple.com"])
def test_a_domain_that_is_not_a_dns_name_is_refused(domain):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the domain must be LDH labels; anything else is a plain refusal before any text is built."""
    if domain == "a.example\n":
        assert dfz.check_domain(domain) == "a.example"       # surrounding white space is trimmed, as typed
        return
    with pytest.raises(dfz.DnsInputError):
        build([dev("x")], domain=domain)


@pytest.mark.parametrize("resolvers", ["", "10.0.0.256", "0.0.0.0", "224.0.0.1", "255.255.255.255", "ff02::1", "::", "dns.example", "1.2.3.4; 5.6.7.8\nx",
                                       ",".join(f"10.0.0.{i}" for i in range(1, 10))])
def test_a_resolver_that_is_not_a_unicast_address_is_refused(resolvers):
    """ASVS V5.1.3 · CWE-20: one to eight IPv4 or IPv6 unicast addresses; a name, a broadcast, multicast or unspecified address is refused."""
    with pytest.raises(dfz.DnsInputError):
        build([dev("x")], resolvers=resolvers)


def test_resolvers_are_deduplicated_and_ipv4_mapped_addresses_unwrapped():
    """CWE-20: the same address twice is used once; ::ffff:10.0.0.12 is 10.0.0.12."""
    assert dfz.check_resolvers("10.0.0.12, ::ffff:10.0.0.12 2001:DB8::53") == ["10.0.0.12", "2001:db8::53"]


# ── grammar checkers (oracles written here) ──────────────────────────
def check_unbound(text: str):
    """unbound.conf(5): clauses `server:` and `forward-zone:`; inside them only
    the attributes used here, quoted absolute names, IP addresses."""
    clause, zones, names, insecure, local = None, [], set(), set(), set()
    for ln in text.splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        if ln in ("server:", "forward-zone:"):
            clause = ln[:-1]
            if clause == "forward-zone":
                zones.append({"name": None, "addrs": []})
            continue
        m = re.fullmatch(r"    ([a-z-]+): (.+)", ln)
        assert m and clause, ln
        key, val = m.groups()
        if clause == "server":
            if key == "local-zone":
                mm = re.fullmatch(r'"([a-z0-9.-]+\.)" transparent', val)
                assert mm, ln
                local.add(mm.group(1))
            else:
                assert key == "domain-insecure" and re.fullmatch(r'"[a-z0-9.-]+\."', val), ln
                insecure.add(val.strip('"'))
        else:
            if key == "name":
                assert zones[-1]["name"] is None and re.fullmatch(r'"[a-z0-9.-]+\."', val), ln
                zones[-1]["name"] = val.strip('"')
                assert zones[-1]["name"] not in names
                names.add(zones[-1]["name"])
            else:
                assert key == "forward-addr", ln
                ipaddress.ip_address(val)
                zones[-1]["addrs"].append(val)
    assert all(z["name"] and z["addrs"] for z in zones)
    return zones, local, insecure


def check_named(text: str):
    """BIND 9 named.conf forward zones: `zone "<name>" { type forward; forward only; forwarders { ip; ... }; };`."""
    body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("//"))
    assert body.count("{") == body.count("}")
    zones = re.findall(r'zone "([a-z0-9.-]+)" \{\n    type forward;\n    forward only;\n    forwarders \{ ((?:[0-9a-f:.]+; )+)\};\n\};', body)
    assert len(zones) == body.count("zone ")
    for name, fwd in zones:
        assert not name.endswith(".") and all(LDH.match(x) for x in name.split("."))
        for ip in fwd.split(";"):
            if ip.strip():
                ipaddress.ip_address(ip.strip())
    return [z[0] for z in zones]


def check_zone(text: str):
    """Zone file (RFC 1035 section 5.1): $ORIGIN absolute, $TTL a number,
    records `<label> IN A|AAAA|NS <rdata>`; every NS target has its glue
    record in the same $ORIGIN section."""
    origin, sections = None, {}
    for ln in text.splitlines():
        if not ln.strip() or ln.startswith(";"):
            continue
        if ln.startswith("$ORIGIN "):
            origin = ln.split()[1]
            assert origin.endswith(".") and all(LDH.match(x) for x in origin[:-1].split("."))
            sections[origin] = {"glue": {}, "ns": []}
            continue
        if ln.startswith("$TTL "):
            assert 30 <= int(ln.split()[1]) <= 86400
            continue
        parts = ln.split()
        assert origin and len(parts) == 4 and parts[1] == "IN" and LDH.match(parts[0]), ln
        owner, _, rr, data = parts
        if rr in ("A", "AAAA"):
            ip = ipaddress.ip_address(data)
            assert ip.version == (4 if rr == "A" else 6)
            sections[origin]["glue"][owner] = data
        else:
            assert rr == "NS" and LDH.match(data), ln
            sections[origin]["ns"].append((owner, data))
    for sec in sections.values():
        assert all(t in sec["glue"] for _, t in sec["ns"])
    return sections


def test_the_unbound_file_is_well_formed_and_matches_the_names():
    """ASVS V5.3.6 · CWE-20 · CWE-116: every forward zone has a quoted absolute name and the resolver addresses; local-zone and domain-insecure follow the switches."""
    devs = [dev(f"LT-{i:04d}") for i in range(30)]
    out = build(devs, resolvers="10.0.0.12 2001:db8::53")
    zones, local, insecure = check_unbound(out["files"]["unbound"])
    assert len(zones) == 30 and all(z["addrs"] == ["10.0.0.12", "2001:db8::53"] for z in zones)
    assert local == insecure == {z["name"] for z in zones}
    off = build(devs, unbound_local_zone=False, unbound_insecure=False)["files"]["unbound"]
    zones2, local2, insecure2 = check_unbound(off)
    assert len(zones2) == 30 and not local2 and not insecure2 and "server:" not in off


def test_the_bind_files_are_well_formed():
    """ASVS V5.3.6 · CWE-116: named.conf forward zones parse, and the zone file has $ORIGIN, $TTL, one NS per resolver per name and glue for every NS target."""
    out = build([dev("a"), dev("b"), dev("c", user="x@sub.com")], resolvers="10.0.0.12, 2001:db8::53", ttl=600, mappings="sub.com: sub.example")
    assert sorted(check_named(out["files"]["bind_forward"])) == ["a.corp.example.com", "b.corp.example.com", "c.corp.example.com", "c.sub.example"]
    secs = check_zone(out["files"]["bind_zone"])
    assert set(secs) == {"corp.example.com.", "sub.example."}
    main = secs["corp.example.com."]
    assert main["glue"] == {"zcc-resolver-1": "10.0.0.12", "zcc-resolver-2": "2001:db8::53"}
    assert sorted(main["ns"]) == [("a", "zcc-resolver-1"), ("a", "zcc-resolver-2"), ("b", "zcc-resolver-1"), ("b", "zcc-resolver-2"),
                                  ("c", "zcc-resolver-1"), ("c", "zcc-resolver-2")]
    assert "$TTL 600" in out["files"]["bind_zone"]


@pytest.mark.parametrize("ttl", [0, 29, 86401, "x"])
def test_a_ttl_outside_30_to_86400_is_refused(ttl):
    """CWE-20 · ASVS V5.1.4: the zone file TTL is 30 to 86400 seconds."""
    with pytest.raises(dfz.DnsInputError):
        build([dev("a")], ttl=ttl)


def test_the_csv_is_spreadsheet_safe():
    """ASVS V5.3.9 (CSV injection) · CWE-1236 · WSTG-INPV-05: a hostname starting with = + - @ is written as text."""
    out = build([dev('=HYPERLINK("http://x")'), dev("+cmd"), dev("@sum")])
    rows = list(csv.reader(io.StringIO(out["files"]["csv"])))
    assert rows[0] == list(dfz.CSV_COLUMNS)
    for r in rows[1:]:
        assert r[0][0] == "'", r


def test_a_huge_device_list_is_refused():
    """ASVS V12.1.1 · CWE-400 · CWE-770: more devices than the cap is a plain refusal, not a huge file."""
    with pytest.raises(dfz.DnsInputError):
        build(({"hostname": "x", "platform": "Windows", "registration": "registered"} for _ in range(dfz.MAX_DEVICES + 1)))


def test_an_incomplete_fleet_read_says_the_files_are_incomplete():
    """CWE-754 · ASVS V1.4.4: a fleet read that kept only part of the device list is not presented as complete."""
    out = build([dev("a")], truncated=True)
    assert out["truncated"] and any("incomplete" in w for w in out["warnings"])


# ── DNS: the API and the page ────────────────────────────────────────
def _api():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _fleet_job(devices_raw, status="read"):
    """A finished fleet read built by the app's own analysis from fake devices."""
    import pack_jobs
    import zcc_fleet
    tel = {"status": status, "reason": "", "devices": devices_raw, "service": {"status": "read" if status == "read" else "unavailable", "rows": []}}
    res = zcc_fleet.analyze({"read_status": {}}, tel, now=NOW)
    res["status"] = "done"
    job = pack_jobs.start("fleet", lambda log, cancel: res)
    job.thread.join(10)
    return job.id


RAW = [{"udid": "U1", "machineHostname": "LKF-LT-0001", "user": "avery@larkspur.example", "type": 3, "registrationState": "Registered",
        "last_seen_time": "2026-10-31 10:00:00"},
       {"udid": "U2", "machineHostname": "Rowan's MacBook Pro", "user": "rowan@larkspur.example", "type": 4, "registrationState": "Registered",
        "last_seen_time": "2026-10-31 10:00:00"},
       {"udid": "U3", "machineHostname": "LKF-LT-0001", "user": "avery@larkspur.example", "type": 3, "registrationState": "Registered",
        "last_seen_time": "2026-10-30 10:00:00"}]


def test_the_api_builds_from_a_finished_fleet_read_and_audits_counts_only():
    """ASVS V7.1.1 · V8.3.4 · CWE-532 · CWE-359: the records come from a finished fleet read; the audit entry holds counts, never a hostname or a user."""
    c = _api()
    jid = _fleet_job(RAW)
    r = c.post(f"/api/zcc/fleet/{jid}/dns-records", json={"domain": "corp.example.com", "resolvers": "10.0.0.12"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["counts"]["records"] == 2 and d["counts"]["duplicates"] == 1
    assert 'name: "rowans-macbook-pro.corp.example.com."' in d["files"]["unbound"]
    assert set(d["file_names"]) == {"unbound", "bind_forward", "bind_zone", "csv"}
    log = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    assert "zcc_dns_records" in log
    tail = [ln for ln in log.splitlines() if "zcc_dns_records" in ln][-1]
    assert "lkf" not in tail.lower() and "avery" not in tail.lower() and "rowan" not in tail.lower()
    assert re.search(r"records\W+2", tail), tail


def test_the_api_refuses_bad_options_unknown_runs_and_reads_without_devices():
    """ASVS V5.1.3 · CWE-20 · CWE-754: a bad domain is a 400 in words; an unknown run is a 404; a read without devices is a 409, not empty files."""
    c = _api()
    jid = _fleet_job(RAW)
    bad = c.post(f"/api/zcc/fleet/{jid}/dns-records", json={"domain": "not a domain", "resolvers": "10.0.0.12"})
    assert bad.status_code == 400 and "not a DNS name" in bad.json()["detail"]
    assert c.post("/api/zcc/fleet/nosuchjob00/dns-records", json={"domain": "a.example", "resolvers": "10.0.0.12"}).status_code == 404
    none = _fleet_job([], status="unavailable")
    assert c.post(f"/api/zcc/fleet/{none}/dns-records", json={"domain": "a.example", "resolvers": "10.0.0.12"}).status_code == 409
    big = c.post(f"/api/zcc/fleet/{jid}/dns-records", json={"domain": "a.example", "resolvers": "1" * 9000})
    assert big.status_code == 422


def test_the_fleet_page_has_the_dns_section_with_help_and_no_raw_html():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · ASVS V5.3.3 · CWE-79: the section labels each field, every control has help, and the script escapes every value it writes as HTML."""
    html = (ROOT / "static" / "report_fleet.html").read_text(encoding="utf-8")
    for needle in ('<section class="zf-sec" id="zfDns" aria-labelledby="zfDnsH">', '<label for="zfDnsDomain">', '<label for="zfDnsResolvers">',
                   '<legend>Platforms</legend>', '/static/fleet_dns.js', 'role="status" aria-live="polite"'):
        assert needle in html, needle
    from test_c6_tooltips import CAT
    page = CAT["pages"]["/report/fleet"]
    for sel in ("#zfDnsDomain", "#zfDnsResolvers", 'input[name="zfDnsPlat"]', "#zfDnsRegistered", "#zfDnsSeen", "#zfDnsMap", "#zfDnsLocalZone",
                "#zfDnsInsecure", "#zfDnsTtl", "#zfDnsBuild", "#zfDnsUnbound", "#zfDnsNamed", "#zfDnsZone", "#zfDnsCsv"):
        assert sel in page, sel
    js = (ROOT / "static" / "fleet_dns.js").read_text(encoding="utf-8")
    assert "<td>${E(c)}</td>" in js and "${E(h)}</th>" in js and "${E(w)}" in js and "<caption>${E(caption)}</caption>" in js
    assert js.count("innerHTML =") == 3 and "innerHTML = parts.join('')" in js
    assert "s.textContent = t" in js


# ══ IP ranges: aggregation ═══════════════════════════════════════════
def _bits(nets, base, size):
    """The addresses of `nets` inside [base, base + size) as a set of offsets (the oracle)."""
    out = set()
    for n in nets:
        n = ipaddress.ip_network(n)
        lo, hi = max(int(n.network_address), base), min(int(n.broadcast_address), base + size - 1)
        out |= set(range(lo - base, hi - base + 1)) if lo <= hi else set()
    return out


def _minimal_count(bits, base):
    """The fewest CIDR blocks covering exactly `bits`: split into maximal runs
    of consecutive addresses, then cut each run from its low end into the
    largest aligned power-of-two block that fits (the standard minimal
    decomposition of one interval; two maximal runs never share a block)."""
    n, s, i = 0, sorted(bits), 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and s[j + 1] == s[j] + 1:
            j += 1
        a, b = base + s[i], base + s[j]
        while a <= b:
            size = 1
            while a % (size * 2) == 0 and a + size * 2 - 1 <= b:
                size *= 2
            n += 1
            a += size
        i = j + 1
    return n


@pytest.mark.parametrize("seed", range(40))
@pytest.mark.parametrize("family", [4, 6])
def test_aggregation_covers_exactly_the_union_minus_the_exclusions_with_the_fewest_cidrs(seed, family):
    """CWE-682 (incorrect calculation) · ASVS V1.4.4: against a brute-force oracle over a 4,096-address window, the result covers exactly (ranges minus exclusions), never overlaps, and uses the fewest CIDRs."""
    rnd = random.Random(seed * 7 + family)
    base_net = ipaddress.ip_network("198.51.0.0/20" if family == 4 else "2001:db8:abcd::/116")
    base, size, top = int(base_net.network_address), base_net.num_addresses, base_net.max_prefixlen

    def rand_net():
        plen = rnd.randint(top - 9, top)
        off = rnd.randrange(0, size) & ~((1 << (top - plen)) - 1)
        return ipaddress.ip_network((base + off, plen))
    nets = [rand_net() for _ in range(rnd.randint(1, 25))]
    holes = [rand_net() for _ in range(rnd.randint(0, 6))]
    agg = zr.aggregate([str(n) for n in nets], [str(h) for h in holes])
    other = 6 if family == 4 else 4
    assert agg[other] == []
    got = [ipaddress.ip_network(c) for c in agg[family]]
    want = _bits(nets, base, size) - _bits(holes, base, size)
    assert _bits(got, base, size) == want
    assert sum(n.num_addresses for n in got) == len(want), "no overlaps"
    assert got == sorted(got)
    assert len(got) == _minimal_count(want, base)


EDGES = [
    (["0.0.0.0/0"], [], ["0.0.0.0/0"]),
    (["0.0.0.0/1", "128.0.0.0/1"], [], ["0.0.0.0/0"]),
    (["255.255.255.255/32", "255.255.255.254/32"], [], ["255.255.255.254/31"]),
    (["0.0.0.0/32", "0.0.0.1/32"], [], ["0.0.0.0/31"]),
    (["10.0.0.1/32", "10.0.0.2/32"], [], ["10.0.0.1/32", "10.0.0.2/32"]),       # adjacent but not one aligned block
    (["10.0.0.0/24", "10.0.0.128/25", "10.0.0.0/24"], [], ["10.0.0.0/24"]),    # nested and repeated
    (["10.0.0.5/24"], [], ["10.0.0.0/24"]),                                     # host bits cleared
    (["10.0.0.0/24"], ["10.0.0.0/24"], []),
    (["10.0.0.0/24"], ["9.0.0.0/8"], ["10.0.0.0/24"]),
    (["10.0.0.0/24"], ["10.0.0.0/8"], []),
    (["10.0.0.0/24"], ["10.0.0.128/32"], ["10.0.0.0/25", "10.0.0.129/32", "10.0.0.130/31", "10.0.0.132/30", "10.0.0.136/29", "10.0.0.144/28",
                                           "10.0.0.160/27", "10.0.0.192/26"]),
    (["0.0.0.0/0"], ["255.255.255.255/32"], None),
    (["::/0"], [], ["::/0"]),
    (["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/128"], [], ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"]),
    (["2001:db8::/33", "2001:db8:8000::/33"], [], ["2001:db8::/32"]),
    (["2001:db8::/32"], ["2001:db8::/48"], None),
    (["10.0.0.0/8", "2001:db8::/32"], ["10.0.0.0/8"], ["2001:db8::/32"]),       # families never mix
]


@pytest.mark.parametrize("nets,holes,want", EDGES)
def test_aggregation_edge_cases(nets, holes, want):
    """CWE-682 · CWE-193 (off-by-one) · ASVS V1.4.4: both ends of each address space, adjacent blocks that cannot merge, nesting, host bits, exclusions inside, around and outside, and mixed families."""
    agg = zr.aggregate(nets, holes)
    got = agg[4] + agg[6]
    if want is not None:
        assert got == want
    # in every case: exactly the union minus the holes
    for fam in (4, 6):
        inside = [ipaddress.ip_network(n, strict=False) for n in nets if ipaddress.ip_network(n, strict=False).version == fam]
        out_n = [ipaddress.ip_network(n) for n in agg[fam]]
        total = sum(n.num_addresses for n in out_n)
        want_total = 0
        iv = zr.merge_intervals([(int(n.network_address), int(n.broadcast_address)) for n in (ipaddress.ip_network(x, strict=False) for x in nets) if n.version == fam])
        hv = zr.merge_intervals([(int(n.network_address), int(n.broadcast_address)) for n in (ipaddress.ip_network(x, strict=False) for x in holes) if n.version == fam])
        for a, b in zr.subtract_intervals(iv, hv):
            want_total += b - a + 1
        assert total == want_total
        assert inside or not out_n


def test_the_interval_helpers_against_brute_force():
    """CWE-682: merge and subtract agree with sets of integers for random intervals."""
    rnd = random.Random(5)
    for _ in range(300):
        keep = [(a, a + rnd.randint(0, 20)) for a in (rnd.randint(0, 200) for _ in range(rnd.randint(0, 8)))]
        holes = [(a, a + rnd.randint(0, 20)) for a in (rnd.randint(0, 200) for _ in range(rnd.randint(0, 8)))]
        s_keep = {x for a, b in keep for x in range(a, b + 1)}
        s_hole = {x for a, b in holes for x in range(a, b + 1)}
        res = zr.subtract_intervals(zr.merge_intervals(keep), zr.merge_intervals(holes))
        got = {x for a, b in res for x in range(a, b + 1)}
        assert got == s_keep - s_hole
        assert all(b + 1 < c for (_, b), (c, _) in zip(res, res[1:])), "joined and sorted"


# ══ IP ranges: feeds as untrusted input ══════════════════════════════
@pytest.mark.parametrize("value,ok", [
    ("165.225.0.0/17", "165.225.0.0/17"), ("165.225.0.5/17", "165.225.0.0/17"), ("165.225.240.14", "165.225.240.14/32"),
    ("2605:4300::/32", "2605:4300::/32"), (" 136.226.0.0/16 ", "136.226.0.0/16"),
    ("10.0.0.0/8", None), ("192.168.1.0/24", None), ("100.64.0.0/10", None), ("127.0.0.1", None), ("169.254.0.0/16", None),
    ("224.0.0.0/4", None), ("240.0.0.0/4", None), ("0.0.0.0/0", None), ("8.0.0.0/7", None), ("192.0.2.0/24", None),
    ("fe80::/10", None), ("fc00::/7", None), ("::1", None), ("ff02::/16", None), ("2001:db8::/32", None), ("2600::/15", None),
    ("::ffff:165.225.0.0/112", None), ("not-an-ip", None), ("1.2.3.4/33", None), ("", None), (None, None), (12345, None), ("1" * 70, None),
])
def test_a_feed_range_must_be_a_public_unicast_cidr_no_wider_than_slash_8_or_16(value, ok):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-183 (permissive list): a tampered feed cannot add a private, reserved, documentation, multicast, IPv4-mapped or over-broad range to an allowlist."""
    got, why = zr.check_cidr(value)
    assert got == ok, (value, why)
    assert (why == "") == (ok is not None)


@pytest.mark.parametrize("value,ok", [
    ("ams2-2.sme.zscaler.net", "ams2-2.sme.zscaler.net"), ("AMS2-2-VPN.ZSCALER.NET.", "ams2-2-vpn.zscaler.net"), ("*.private.zscaler.com", "*.private.zscaler.com"),
    ("gateway.zscloud.net", "gateway.zscloud.net"), ("zpath.net", "zpath.net"),
    ("evil.example.com", None), ("zscaler.net.evil.com", None), ("xzscaler.net", None), ("a.zscaler.net\nb", None), ('a"b.zscaler.net', None),
    ("*.zscaler.net.evil.com", None), ("a..zscaler.net", None), ("-a.zscaler.net", None), ("a.*.zscaler.net", None), ("", None), (None, None),
])
def test_a_feed_host_name_must_be_under_a_zscaler_domain(value, ok):
    """ASVS V5.1.3 · CWE-20 · CWE-183: a host name in a feed must be an LDH name under one of Zscaler's domains, or it is dropped."""
    assert zr.check_host(value)[0] == ok


@pytest.mark.parametrize("feed,cloud,name", [
    ("cenr", "zscaler.net", "cenr_zscaler_net.json"), ("hubs_recommended", "zscaler.net", "hubs_recommended_zscaler_net.json"),
    ("hubs_required", "zscaler.net", "hubs_required_zscaler_net.json"), ("future", "zscaler.net", "future_zscaler_net.json"),
    ("svpn", "zscaler.net", "svpn_zscaler_net.json"), ("zpa", "private.zscaler.com", "zpa_private_zscaler_com.json"),
])
def test_each_feed_fixture_parses(feed, cloud, name):
    """ASVS V5.1.3 · CWE-20: each feed in the config portal's format is read into ranges (and host names), with nothing refused."""
    p = zr.parse(feed, cloud, fx(name))
    assert p["ranges"] and p["rejected_total"] == 0
    if feed == "cenr":
        assert {r["region"] for r in p["ranges"]} == {"EMEA", "Americas", "APAC"}
        assert {"Amsterdam II", "Chicago"} <= {r["city"] for r in p["ranges"]}
        assert {h["host"] for h in p["hosts"]} >= {"ams2-2.sme.zscaler.net", "ams2-2-vpn.zscaler.net"}
    if feed == "zpa":
        assert {r["region"] for r in p["ranges"]} == {"ZPA Public Service Edges", "ZPA Log Streaming"}
        assert {h["host"] for h in p["hosts"]} == {"*.private.zscaler.com", "*.zpath.net"}


def test_bad_entries_are_dropped_and_counted_and_the_rest_kept():
    """ASVS V5.1.3 · CWE-20 · CWE-345: in a feed of the right shape, a private, over-broad or malformed range and a foreign host name are dropped with a reason; the good ones stay."""
    doc = json.loads(fx("cenr_zscaler_net.json"))
    doc["zscaler.net"]["continent : EMEA"]["city : Bad"] = [{"range": "10.0.0.0/8"}, {"range": "0.0.0.0/0"}, {"range": "nope"},
                                                             {"range": "185.46.212.0/22", "hostname": "evil.example.com", "vpn": "x‮.zscaler.net"}]
    p = zr.parse("cenr", "zscaler.net", json.dumps(doc))
    assert p["rejected_total"] == 5 and {r["why"] for r in p["rejected"]} >= {"not a public unicast range", "wider than /8", "not an IP address or CIDR", "not under a Zscaler domain"}
    assert "185.46.212.0/22" in {r["cidr"] for r in p["ranges"]}
    assert all("‮" not in r["value"] for r in p["rejected"])


MALFORMED = [
    ("cenr", b"", "not valid JSON"), ("cenr", b"{", "not valid JSON"), ("cenr", b'{"zscaler.net": NaN}', "not valid JSON"),
    ("cenr", b"[]", "object keyed by the cloud"), ("cenr", b'{"zscloud.net": {}}', "not zscaler.net"),
    ("cenr", b'{"zscaler.net": []}', "not the cloud enforcement node feed"), ("cenr", b'{"zscaler.net": {"continent : X": []}}', "not an object of cities"),
    ("cenr", b'{"zscaler.net": {"continent : X": {"city : Y": {}}}}', "not a list of nodes"),
    ("cenr", b'{"zscaler.net": {"continent : X": {"city : Y": ["1.2.3.4"]}}}', "not an object"),
    ("cenr", b'{"zscaler.net": {"continent : X": {"city : Y": [{"range": "10.0.0.0/8"}]}}}', "no usable range"),
    ("hubs_recommended", b'{"prefixes": ["165.225.0.0/17"]}', "no 'hubPrefixes' list"), ("hubs_recommended", b'{"hubPrefixes": "165.225.0.0/17"}', "is not a list"),
    ("hubs_recommended", b'{"hubPrefixes": []}', "no usable range"), ("future", b'["170.85.0.0/16"]', "no 'prefixes' list"),
    ("svpn", b'{"svpnIPs": {"a": 1}}', "is not a list"), ("zpa", b'{"content": [1]}', "not an object"), ("zpa", b'{"content": [{"IPs": "x"}]}', "not a list"),
    ("cenr", b"\xff\xfe\x00", "not valid JSON"), ("cenr", ("[" * 5000 + "]" * 5000).encode(), "nested too deeply"),
]


@pytest.mark.parametrize("feed,data,words", MALFORMED)
def test_a_malformed_feed_is_refused_whole_in_words(feed, data, words):
    """ASVS V5.1.3 · V5.5.3 · CWE-20 · CWE-502 · CWE-674: a feed that is not JSON, has the wrong shape, NaN, or is nested too deeply is refused with a plain reason."""
    cloud = "private.zscaler.com" if feed == "zpa" else "zscaler.net"
    with pytest.raises(zr.FeedError) as e:
        zr.parse(feed, cloud, data)
    assert words in str(e.value), str(e.value)


def test_an_oversized_or_overfull_feed_is_refused_before_it_is_read():
    """ASVS V12.1.1 · CWE-400 · CWE-770 · WSTG-BUSL-07: a feed over 4 MB is refused before parsing; one with more entries than the cap is refused."""
    with pytest.raises(zr.FeedError, match="larger than 4 MB"):
        zr.parse("hubs_recommended", "zscaler.net", b" " * (zr.MAX_BYTES + 1))
    many = json.dumps({"hubPrefixes": [f"165.{i // 256}.{i % 256}.0/24" for i in range(zr.MAX_ENTRIES + 1)]})
    with pytest.raises(zr.FeedError, match="more than"):
        zr.parse("hubs_recommended", "zscaler.net", many)


def test_a_refused_import_keeps_the_feed_kept_before_and_a_damaged_file_is_not_used():
    """ASVS V5.1.3 · CWE-345 · CWE-354: a refused import changes nothing; a kept file edited by hand to hold a private range is not used."""
    zr.import_file("hubs_recommended", "zscaler.net", fx("hubs_recommended_zscaler_net.json"), now=NOW)
    with pytest.raises(zr.FeedError):
        zr.import_file("hubs_recommended", "zscaler.net", b'{"hubPrefixes": ["10.0.0.0/8"]}', now=NOW)
    kept = zr.load("hubs_recommended", "zscaler.net")
    assert kept and "165.225.0.0/17" in {r["cidr"] for r in kept["ranges"]}
    p = zr.feed_path("hubs_recommended", "zscaler.net")
    doc = json.loads(open(p, encoding="utf-8").read())
    doc["ranges"].append({"cidr": "10.0.0.0/8", "region": "Global", "city": ""})
    open(p, "w", encoding="utf-8").write(json.dumps(doc))
    assert zr.load("hubs_recommended", "zscaler.net") is None
    assert zr.feed_status("hubs_recommended", "zscaler.net")["present"] is False


def test_feeds_and_clouds_come_from_fixed_tables_only():
    """ASVS V5.1.3 · CWE-22 · CWE-918: a feed or cloud name outside the tables never reaches a URL or a file name."""
    for feed, cloud in [("cenr", "../../etc"), ("cenr", "evil.com"), ("zpa", "zscaler.net"), ("cenr", "private.zscaler.com"), ("x", "zscaler.net")]:
        with pytest.raises(zr.FeedError):
            zr.feed_url(feed, cloud)
        with pytest.raises(zr.FeedError):
            zr.feed_path(feed, cloud)
    assert zr.zia_cloud("production") == "zscaler.net" and zr.zia_cloud("zscalertwo") == "zscalertwo.net" and zr.zia_cloud("zscalergov.us") == "zscalergov.us"
    with pytest.raises(zr.FeedError):
        zr.zia_cloud("evil.example")


def test_the_feed_addresses_follow_the_config_portal():
    """ASVS V1.14.1 · CWE-1059: every feed is a path under https://config.zscaler.com/api/ (documented as assumed in the module)."""
    assert zr.feed_url("cenr", "zscaler.net") == "https://config.zscaler.com/api/zscaler.net/cenr/json"
    assert zr.feed_url("hubs_recommended", "zscloud.net") == "https://config.zscaler.com/api/zscloud.net/hubs/cidr/json/recommended"
    assert zr.feed_url("hubs_required", "zscaler.net").endswith("/hubs/cidr/json/required")
    assert zr.feed_url("future", "zscaler.net").endswith("/zscaler.net/future/json")
    assert zr.feed_url("svpn", "zscaler.net").endswith("/zscaler.net/svpn/json")
    assert zr.feed_url("zpa", "private.zscaler.com") == "https://config.zscaler.com/api/private.zscaler.com/zpa/json"
    assert "ASSUMED" in zr.__doc__


# ══ IP ranges: the fetch ═════════════════════════════════════════════
def test_fetching_is_off_by_default_and_sends_nothing():
    """ASVS V1.14.1 · V12.6.1 · CWE-1188 (insecure default) · CWE-918: the switch starts off; a fetch then is refused before any request (the network refuses all calls in this test)."""
    assert zr.settings()["enabled"] is False and zr.status()["enabled"] is False
    calls = []
    with pytest.raises(zr.FetchDisabled):
        zr.fetch("zscaler", ["cenr"], get=lambda url, cap: calls.append(url) or b"{}")
    assert calls == []


def test_a_fetch_goes_only_to_the_config_portal_and_keeps_each_feed_on_its_own():
    """ASVS V12.6.1 · CWE-918 · CWE-754: with the switch on, each chosen feed is one GET to config.zscaler.com with a size cap; one failing feed does not stop the others and is recorded."""
    zr.set_enabled(True)
    seen = []
    table = {"cenr": fx("cenr_zscaler_net.json"), "recommended": fx("hubs_recommended_zscaler_net.json"), "zpa/json": fx("zpa_private_zscaler_com.json")}

    def get(url, cap):
        seen.append((url, cap))
        for k, v in table.items():
            if k in url:
                return v
        raise zr.FeedError("config.zscaler.com answered HTTP 404.")
    out = zr.fetch("zscaler", ["cenr", "hubs_recommended", "svpn", "zpa"], zpa_cloud="private.zscaler.com", get=get, now=NOW)
    assert all(u.startswith("https://config.zscaler.com/api/") and cap == zr.MAX_BYTES for u, cap in seen)
    assert [r["ok"] for r in out["results"]] == [True, True, False, True]
    assert "404" in zr.settings()["last_error"]
    kept = {(k["feed"], k["cloud"]) for k in out["status"]["kept"]}
    assert kept == {("cenr", "zscaler.net"), ("hubs_recommended", "zscaler.net"), ("zpa", "private.zscaler.com")}
    assert all(k["source"] == "fetched" and k["fetched_at"] == "2026-10-31T12:00:00Z" for k in out["status"]["kept"])


class _Resp:
    def __init__(self, status=200, body=b"{}", headers=None, chunks=None):
        self.status_code, self.content, self.headers = status, body, headers or {}
        self.raw = object() if chunks is not None else None
        self._chunks = chunks or []

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        pass


@pytest.mark.parametrize("url", ["http://config.zscaler.com/api/zscaler.net/cenr/json", "https://evil.example/api/x", "https://config.zscaler.com.evil.example/x",
                                 "https://user:pw@config.zscaler.com/x", "https://config.zscaler.com:8443/x", "https://config.zscaler.com/x?y=1",
                                 "https://169.254.169.254/latest/"])
def test_the_fetcher_refuses_any_other_address_before_a_request(monkeypatch, url):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: only https://config.zscaler.com (port 443, no credentials, no query) is ever requested."""
    sent = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: sent.append(a) or _Resp())
    with pytest.raises(zr.FeedError, match="Only https://config.zscaler.com"):
        zr._get(url, 1000)
    assert sent == []


def test_the_fetcher_never_follows_a_redirect_and_keeps_tls_and_a_timeout(monkeypatch):
    """ASVS V9.2.1 · V12.6.1 · CWE-601 · CWE-295: a redirect is refused, not followed; the request has a timeout and TLS verification stays on."""
    calls = []

    def fake(url, **kw):
        calls.append(kw)
        return _Resp(302, headers={"Location": "https://evil.example/"})
    monkeypatch.setattr(requests, "get", fake)
    with pytest.raises(zr.FeedError, match="redirect"):
        zr._get("https://config.zscaler.com/api/zscaler.net/cenr/json", 1000)
    assert len(calls) == 1 and calls[0]["allow_redirects"] is False and calls[0]["timeout"] and calls[0].get("verify", True) is not False


@pytest.mark.parametrize("resp", [_Resp(headers={"Content-Length": "5000"}), _Resp(body=b"x" * 5000), _Resp(chunks=[b"x" * 600, b"x" * 600])])
def test_the_fetcher_stops_reading_at_the_cap(monkeypatch, resp):
    """ASVS V12.1.1 · CWE-400 · CWE-770: an answer declared or streamed past the cap is refused, not read into memory."""
    monkeypatch.setattr(requests, "get", lambda url, **kw: resp)
    with pytest.raises(zr.FeedError, match="larger than"):
        zr._get("https://config.zscaler.com/api/zscaler.net/cenr/json", 1000)


def test_the_fetcher_reads_a_good_answer(monkeypatch):
    """ASVS V12.6.1 · CWE-20: a 200 answer under the cap is read whole."""
    monkeypatch.setattr(requests, "get", lambda url, **kw: _Resp(chunks=[b'{"hubPrefixes":', b' ["165.225.0.0/17"]}']))
    assert zr._get("https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/recommended", 1000) == b'{"hubPrefixes": ["165.225.0.0/17"]}'


# ══ IP ranges: building and rendering ════════════════════════════════
def _keep_all(now=NOW):
    for feed, name in [("cenr", "cenr_zscaler_net.json"), ("hubs_recommended", "hubs_recommended_zscaler_net.json"),
                       ("hubs_required", "hubs_required_zscaler_net.json"), ("future", "future_zscaler_net.json"), ("svpn", "svpn_zscaler_net.json")]:
        zr.import_file(feed, "zscaler.net", fx(name), now=now)
    zr.import_file("zpa", "private.zscaler.com", fx("zpa_private_zscaler_com.json"), now=now)


ALL = ["cenr", "hubs_recommended", "hubs_required", "future", "svpn", "zpa"]


def test_the_allowlist_per_region_and_overall():
    """ASVS V1.4.4 · CWE-682: ranges are grouped per region (cloud enforcement nodes) and Global, aggregated in each and overall, with the host names and every source's date."""
    _keep_all()
    r = zr.build("zscaler", ALL, zpa_cloud="private.zscaler.com", now=NOW)
    assert r["complete"] and not r["warnings"]
    regions = {x["region"]: x for x in r["regions"]}
    assert set(regions) == {"APAC", "Americas", "EMEA", "Global", "ZPA Log Streaming", "ZPA Public Service Edges"}
    assert regions["Americas"]["ipv4"] == ["136.226.0.0/22"] and regions["Americas"]["ipv6"] == ["2605:4300:1211::/48"]
    assert "136.226.0.0/16" in r["all"]["ipv4"] and "136.226.0.0/22" not in r["all"]["ipv4"], "covered by the hub range"
    assert "2605:4300::/32" in r["all"]["ipv6"] and "2605:4300:1211::/48" not in r["all"]["ipv6"]
    assert {h["host"] for h in r["hosts"]} >= {"fra4.sme.zscaler.net", "*.zpath.net"}
    assert all(s["status"] == "ok" and s["fetched_at"] == "2026-10-31T12:00:00Z" for s in r["sources"])


def test_regions_exclusions_extra_ranges_and_families():
    """ASVS V1.4.4 · CWE-682 · CWE-20: only the chosen regions; an excluded range is cut out of a larger one; added ranges are kept (a private one with a warning); IPv6 can be left out; a typed line that is not a range is refused."""
    _keep_all()
    r = zr.build("zscaler", ["cenr"], regions=["EMEA"], exclude="165.225.240.0/24\n# a comment", extra="192.168.10.0/24, 23.4.43.0/24", ipv6=False, now=NOW)
    assert [x["region"] for x in r["regions"]] == ["EMEA", "Added by you"]
    assert r["all"]["ipv4"] == ["23.4.43.0/24", "165.225.72.0/22", "165.225.241.0/24", "165.225.242.0/23", "192.168.10.0/24"]
    assert r["all"]["ipv6"] == [] and r["counts"]["excluded"] == 1 and r["counts"]["added"] == 2
    assert any("192.168.10.0/24 is not a public range" in w for w in r["warnings"])
    with pytest.raises(zr.FeedError, match="line 2"):
        zr.build("zscaler", ["cenr"], exclude="165.225.240.0/24\nnot-a-range", now=NOW)
    with pytest.raises(zr.FeedError):
        zr.build("zscaler", ["cenr"], ipv4=False, ipv6=False, now=NOW)


def test_a_missing_feed_is_unknown_and_a_stale_one_is_marked():
    """CWE-754 · CWE-672 (use after expiry) · ASVS V1.4.4: a feed never fetched or imported is unknown, never an empty list; one older than 30 days is stale and the allowlist says so."""
    zr.import_file("cenr", "zscaler.net", fx("cenr_zscaler_net.json"), now=NOW - dt.timedelta(days=31))
    r = zr.build("zscaler", ["cenr", "svpn"], now=NOW)
    assert not r["complete"]
    st = {s["feed"]: s["status"] for s in r["sources"]}
    assert st == {"cenr": "stale", "svpn": "missing"}
    assert any("unknown" in w for w in r["warnings"]) and any("more than 30 days" in w for w in r["warnings"])
    nothing = zr.build("zscaler", ["svpn"], now=NOW)
    assert nothing["all"] == {"ipv4": [], "ipv6": []} and any("No range is left" in w for w in nothing["warnings"])


def test_a_new_copy_says_what_was_added_and_removed():
    """ASVS V7.1.3 · CWE-778: after a second fetch or import, each source lists the ranges added and removed since the copy before."""
    zr.import_file("hubs_recommended", "zscaler.net", fx("hubs_recommended_zscaler_net.json"), now=NOW - dt.timedelta(days=2))
    zr.import_file("hubs_recommended", "zscaler.net", json.dumps({"hubPrefixes": ["165.225.0.0/17", "137.31.0.0/22"]}), now=NOW)
    s = zr.build("zscaler", ["hubs_recommended"], now=NOW)["sources"][0]
    assert s["added"] == ["137.31.0.0/22"] and s["removed_total"] == 4 and s["previous_at"] == "2026-10-29T12:00:00Z"


def test_every_output_format():
    """ASVS V5.3.9 · CWE-1236 · CWE-116: the plain list and the Palo Alto IP list hold one CIDR per line and nothing else; the URL list host names only; the CSV is spreadsheet-safe; the JSON and the Microsoft 365-style list parse with their keys."""
    _keep_all()
    r = zr.build("zscaler", ALL, zpa_cloud="private.zscaler.com", now=NOW)
    for fmt in ("txt", "edl_ip"):
        name, media, text = zr.render(r, fmt)
        lines = text.splitlines()
        assert lines == r["all"]["ipv4"] + r["all"]["ipv6"] and media.startswith("text/plain") and name.endswith(".txt")
        assert all(ipaddress.ip_network(x) for x in lines)
    _, _, urls = zr.render(r, "edl_url")
    assert urls.splitlines() == [h["host"] for h in r["hosts"]] and all(zr.check_host(h)[0] for h in urls.splitlines())
    _, media, text = zr.render(r, "csv")
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ["region", "family", "cidr"] and media.startswith("text/csv")
    assert all(not c[:1] in "=+-@" for row in rows for c in row)
    j = json.loads(zr.render(r, "json")[2])
    assert j["ipv4"] == r["all"]["ipv4"] and j["sources"][0]["url"].startswith("https://config.zscaler.com/") and j["complete"] is True
    m = json.loads(zr.render(r, "m365")[2])
    assert m and all(set(s) >= {"id", "serviceArea", "ips", "urls", "required"} and isinstance(s["id"], int) for s in m)
    assert all(ipaddress.ip_network(ip) for s in m for ip in s["ips"])
    with pytest.raises(zr.FeedError):
        zr.render(r, "xlsx")


def test_a_region_name_from_a_feed_cannot_break_out_of_the_csv_or_json():
    """ASVS V5.3.9 · CWE-1236 · CWE-74: a region name with a formula start, quotes, a newline or bidi controls stays one cell, shown as text."""
    doc = {"zscaler.net": {"continent : =cmd|' /C calc'!A0\n‮": {"city : x\"y": [{"range": "165.225.240.0/23"}]}}}
    zr.import_file("cenr", "zscaler.net", json.dumps(doc), now=NOW)
    r = zr.build("zscaler", ["cenr"], now=NOW)
    text = zr.render(r, "csv")[2]
    rows = list(csv.reader(io.StringIO(text)))
    assert len(rows) == 2 and rows[1][0].startswith("'=") and "\n" not in rows[1][0] and "‮" not in rows[1][0]
    json.loads(zr.render(r, "json")[2])


# ══ IP ranges: the API, the page, the declaration ════════════════════
def test_the_api_switch_import_build_download_and_forget_each_audited():
    """ASVS V4.1.3 · V7.2.1 · CWE-778: the switch starts off; Fetch now while off is a 409; a refused import is a 400 in words; build and download use the kept feeds; switching, importing and forgetting are audited."""
    c = _api()
    st = c.get("/api/zscaler-ranges").json()
    assert st["enabled"] is False and st["host"] == "config.zscaler.com" and st["kept"] == []
    assert c.post("/api/zscaler-ranges/fetch", json={"cloud": "zscaler.net", "feeds": ["cenr"]}).status_code == 409
    bad = c.post("/api/zscaler-ranges/import", json={"cloud": "zscaler.net", "feed": "cenr", "content": "{}"})
    assert bad.status_code == 400 and "not imported" in bad.json()["detail"]
    ok = c.post("/api/zscaler-ranges/import", json={"cloud": "zscaler.net", "feed": "cenr", "content": fx("cenr_zscaler_net.json").decode()})
    assert ok.status_code == 200 and ok.json()["source"] == "imported"
    b = c.post("/api/zscaler-ranges/build", json={"cloud": "zscaler.net", "feeds": ["cenr"]})
    assert b.status_code == 200 and b.json()["counts"]["ipv4"] > 0
    d = c.post("/api/zscaler-ranges/download", json={"cloud": "zscaler.net", "feeds": ["cenr"], "format": "edl_ip"})
    assert d.status_code == 200 and "attachment" in d.headers["content-disposition"] and d.text.splitlines()[0] == "136.226.0.0/22"
    assert c.post("/api/zscaler-ranges/download", json={"cloud": "zscaler.net", "feeds": ["cenr"], "format": "exe"}).status_code == 400
    assert c.post("/api/zscaler-ranges/build", json={"cloud": "evil.example", "feeds": ["cenr"]}).status_code == 400
    assert c.put("/api/zscaler-ranges/settings", json={"enabled": True}).json()["enabled"] is True
    assert c.delete("/api/zscaler-ranges?cloud=../x").status_code == 400
    assert c.delete("/api/zscaler-ranges").json()["kept"] == []
    log = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    for event in ("zscaler_ranges_import", "zscaler_ranges_settings", "zscaler_ranges_remove"):
        assert event in log


def test_an_oversized_import_is_refused_by_the_api():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: an import body past the feed's cap is refused (422 or 413) and nothing is kept."""
    c = _api()
    r = c.post("/api/zscaler-ranges/import", json={"cloud": "zscaler.net", "feed": "cenr", "content": "{" + " " * (zr.MAX_BYTES + 2048) + "}"})
    assert r.status_code in (413, 422) and zr.status()["kept"] == []


def test_the_destination_is_declared_with_the_other_outbound_destinations():
    """ASVS V14.1.1 · V12.6.1 · CWE-1059: config.zscaler.com is the fetcher's only host, is on the app's outbound allowlist and is listed in SECURITY.md as off by default."""
    import zscaler_update_check
    assert zr.ALLOWED_HOSTS == frozenset({"config.zscaler.com"}) and "config.zscaler.com" in zscaler_update_check.ALLOWED_HOSTS
    line = next(ln for ln in (ROOT / "SECURITY.md").read_text(encoding="utf-8").splitlines() if ln.startswith("| Outbound calls"))
    assert "config.zscaler.com" in line and "off by default" in line


def test_the_exports_page_has_the_section_off_by_default_with_help():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · SC 4.1.2 · ASVS V14.1.1: the section names the destination, the switch starts unticked, each field is labelled and every control has help."""
    html = (ROOT / "static" / "report_exports.html").read_text(encoding="utf-8")
    for needle in ('<section aria-labelledby="exRgH" id="exRanges"', '<input type="checkbox" id="exRgFetchOn" role="switch" aria-describedby="exRgBox">',
                   '<label class="ex-rg-text" for="exRgExclude">', '<label class="ex-rg-text" for="exRgExtra">', "config.zscaler.com", "/static/net_ranges.js"):
        assert needle in html, needle
    assert 'id="exRgFetchOn" role="switch" checked' not in html
    from test_c6_tooltips import CAT
    page = CAT["pages"]["/report/exports"]
    for sel in ("#exRgCloud", "#exRgZpa", 'input[name="exRgFeed"]', "#exRgFetchOn", "#exRgFetch", "#exRgRemove", "#exRgImpFeed", "#exRgFile", "#exRgImport",
                'input[name="exRgRegion"]', "#exRgV4", "#exRgV6", "#exRgExclude", "#exRgExtra", "#exRgBuild", "#exRgTxt", "#exRgCsv", "#exRgEdlIp",
                "#exRgEdlUrl", "#exRgJson", "#exRgM365"):
        assert sel in page, sel
    js = (ROOT / "static" / "net_ranges.js").read_text(encoding="utf-8")
    assert "E(st.last_error)" in js and "E(w)" in js and "E(s.url)" in js and "E(r.region)" in js
