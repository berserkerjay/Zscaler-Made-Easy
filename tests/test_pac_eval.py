"""ASVS V5.2.4 · ASVS V5.2.5 · CWE-94 · CWE-95 · OWASP A03:2021: the PAC evaluator interprets a PAC file without ever running it.

pac_eval parses and interprets the subset of JavaScript PAC files use; it
has no JavaScript engine and calls no eval. Everything else is refused in
words ("could not evaluate safely: ..."), and the source size, nesting,
steps, branches and time are capped (ASVS V12.1 / CWE-400 / CWE-674),
checked here with hostile inputs the way tests/test_dos_limits.py checks
the other parsers: by CPU time against a generous budget, and by counts.
No network, no clock: DNS is never looked up and the clock is injected.
"""
from __future__ import annotations

import copy
import socket
import time

import pytest

import data_flow as df
import log_analyzer as la
import pac_eval as pe
import ssl_flow as sf


def _cpu(fn, *a, **kw):
    start = time.process_time()
    out = fn(*a, **kw)
    return time.process_time() - start, out


def pac(body: str, pre: str = "") -> str:
    return pre + "function FindProxyForURL(url, host) {\n" + body + "\n}"


CORP = pac('''
  host = host.toLowerCase();
  if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example")) return "DIRECT";
  else if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";
  if (shExpMatch(host, "*.dropbox.com")) return "DIRECT";
  if (shExpMatch(url, "http://legacy.*")) return "PROXY proxy.corp.example:8080";
  if (url.substring(0, 6) == "https:" && host.indexOf("partner") == 0) return "PROXY partner-proxy.example:3128";
  return zs;''', pre='var zs = "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT";\n')


# ── What it answers ────────────────────────────────────────────────────
@pytest.mark.parametrize("url,host,kind,result", [
    ("https://www.dropbox.com/s/x", "www.dropbox.com", "direct", "DIRECT"),
    ("https://intranet/", "intranet", "direct", "DIRECT"),
    ("https://wiki.corp.example/", "wiki.corp.example", "direct", "DIRECT"),
    ("https://10.1.2.3/", "10.1.2.3", "direct", "DIRECT"),
    ("http://legacy.example/", "legacy.example", "other_proxy", "PROXY proxy.corp.example:8080"),
    ("https://partner.example/", "partner.example", "other_proxy", "PROXY partner-proxy.example:3128"),
    ("https://www.example.com/", "www.example.com", "zscaler", "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80; DIRECT"),
])
def test_a_pac_is_answered_and_classified(url, host, kind, result):
    """ASVS V5.2.4 · CWE-95: each destination gets the PAC's answer, classified DIRECT, Zscaler or another proxy."""
    # Act
    r = pe.evaluate(CORP, url, host, dns="assume_public")
    # Assert
    assert r["status"] == "ok" and r["error"] is None, r
    assert r["kind"] == kind and r["result"] == result


def test_the_host_is_taken_from_the_url_when_not_given():
    """ASVS V5.1.3 · CWE-20: evaluate(url) alone derives the host the browser would pass (lower case, no port)."""
    r = pe.evaluate(CORP, "https://WWW.Dropbox.com:443/x")
    assert r["kind"] == "direct"


@pytest.mark.parametrize("answer,kind,fallback", [
    ("DIRECT", "direct", False),
    ("PROXY ${GATEWAY}:80; DIRECT", "zscaler", True),
    ("PROXY gateway.zscalertwo.net:80", "zscaler", False),
    ("HTTPS gw.zscloud.net:443", "zscaler", False),
    ("PROXY 127.0.0.1:9000", "zscaler", False),
    ("PROXY 127.0.0.1:3128", "other_proxy", False),
    ("PROXY gateway.zscaler.net.evil.example:80", "other_proxy", False),
    ("PROXY proxy.corp:8080; PROXY ${GATEWAY}:80", "other_proxy", False),
    ("", "invalid", False),
    ("BOGUS host", "invalid", False),
])
def test_answers_are_classified_by_their_first_entry(answer, kind, fallback):
    """ASVS V5.1.3 · CWE-20: the first entry decides; a lookalike domain is not Zscaler; a trailing DIRECT is fail-open."""
    c = pe.classify(answer)
    assert c["kind"] == kind and c["fallback_direct"] is fallback


def test_an_unknown_condition_lists_every_answer_and_what_it_depends_on():
    """ASVS V5.2.4 · CWE-95: time, DNS and the device's address are never guessed: both branches are followed and named."""
    src = pac('''
      if (timeRange(9, 17)) return "PROXY gateway.zscaler.net:80";
      if (isInNet(myIpAddress(), "192.168.0.0", "255.255.0.0")) return "DIRECT";
      return "PROXY gateway.zscaler.net:80";''')
    r = pe.evaluate(src, "https://example.com/", "example.com")
    assert r["status"] == "depends" and r["kind"] == "mixed" and r["result"] is None
    assert {o["kind"] for o in r["outcomes"]} == {"zscaler", "direct"}
    assert set(r["depends_on"]) == {pe.R_TIME, pe.R_MYIP}
    assert [c["state"] for c in r["trail"]] == ["unknown", "unknown"]


def test_an_undecided_branch_with_the_same_answer_is_decided():
    """ASVS V5.2.4 · CWE-95: when every branch gives the same answer, the answer does not depend on the unknown."""
    r = pe.evaluate(pac('return weekdayRange("MON", "FRI") ? "DIRECT" : "DIRECT";'), "https://a.example/")
    assert r["status"] == "ok" and r["kind"] == "direct" and r["depends_on"] == []


def test_dns_is_never_looked_up(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: evaluating a PAC makes no DNS query; dnsResolve is stubbed or injected."""
    def boom(*a, **k):
        raise AssertionError("DNS was looked up")
    monkeypatch.setattr(socket, "gethostbyname", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    src = pac('if (isResolvable(host) && isInNet(dnsResolve(host), "203.0.113.0", "255.255.255.0")) return "DIRECT"; return "PROXY ${GATEWAY}:80";')
    unknown = pe.evaluate(src, "https://example.com/", "example.com")
    assert unknown["status"] == "depends" and pe.R_DNS in unknown["depends_on"]
    injected = pe.evaluate(src, "https://example.com/", "example.com", resolve=lambda h: "203.0.113.7")
    assert injected["kind"] == "direct"
    public = pe.evaluate(pac('if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT"; return "PROXY ${GATEWAY}:80";'),
                         "https://example.com/", "example.com", dns="assume_public")
    assert public["kind"] == "zscaler" and public["assumptions"] == [pe.A_PUBLIC]


@pytest.mark.parametrize("helper,args,expected", [
    ("shExpMatch", '"www.box.com", "*.box.com"', True),
    ("shExpMatch", '"box.com", "*.box.com"', False),
    ("shExpMatch", '"a.b", "?.?"', True),
    ("dnsDomainIs", '"www.corp.example", ".corp.example"', True),
    ("dnsDomainIs", '"corp.example", ".corp.example"', False),
    ("localHostOrDomainIs", '"www", "www.corp.example"', True),
    ("localHostOrDomainIs", '"www.corp.example", "www.corp.example"', True),
    ("localHostOrDomainIs", '"www.other.example", "www.corp.example"', False),
    ("isPlainHostName", '"intranet"', True),
    ("isPlainHostName", '"intranet.corp"', False),
    ("isInNet", '"10.2.3.4", "10.0.0.0", "255.0.0.0"', True),
    ("isInNet", '"11.2.3.4", "10.0.0.0", "255.0.0.0"', False),
    ("isInNet", '"10.2.3.4", "bad", "255.0.0.0"', False),
])
def test_the_pac_helpers_follow_the_pac_definitions(helper, args, expected):
    """ASVS V5.1.3 · CWE-20: shExpMatch, dnsDomainIs, localHostOrDomainIs, isPlainHostName and isInNet answer as browsers do."""
    r = pe.evaluate(pac(f'return {helper}({args}) ? "DIRECT" : "PROXY ${{GATEWAY}}:80";'), "https://x.example/")
    assert r["kind"] == ("direct" if expected else "zscaler"), r


def test_strings_numbers_and_operators_follow_javascript():
    """ASVS V5.1.3 · CWE-20: concatenation, comparison, !, ternary and the string methods behave as in a browser."""
    src = pac('''
      var a = "Ab" + 1 + 2, b = 1 + 2 + "x", n = dnsDomainLevels("a.b.c");
      var s = "www.Example.com".toLowerCase();
      if (a !== "Ab12" || b != "3x" || n !== 2 || !(n >= 2) || s.length != 15) return "DIRECT";
      if (s.substring(4, 11) != "example" || s.substr(-3) != "com" || s.charAt(0) != "w" || s.lastIndexOf(".") != 11) return "DIRECT";
      if ("10" == 10 && null == undefined && !(null === undefined) && "b" > "a") return "PROXY ${GATEWAY}:80";
      return "DIRECT";''')
    r = pe.evaluate(src, "https://x.example/")
    assert r["kind"] == "zscaler", r


def test_helper_functions_and_top_level_variables_are_evaluated():
    """ASVS V5.2.4 · CWE-95: a PAC's own helper functions are interpreted too, with their own variables."""
    src = 'var gw = "PROXY ${GATEWAY}:80";\nfunction isCorp(h) { var x = h; return dnsDomainIs(x, ".corp.example"); }\n' + pac(
        'if (isCorp(host)) return "DIRECT"; return gw;')
    assert pe.evaluate(src, "https://a.corp.example/")["kind"] == "direct"
    assert pe.evaluate(src, "https://a.example/")["kind"] == "zscaler"


# ── Never runs code: everything outside the subset is refused in words ──
@pytest.mark.parametrize("body,construct", [
    ('while (true) {} return "DIRECT";', "'while'"),
    ('for (;;) {}', "'for'"),
    ('return eval("1");', "'eval'"),
    ('return new Function("return 1")();', "'new'"),
    ('return /dropbox/.test(host) ? "DIRECT" : "PROXY x:1";', "a regular expression"),
    ('return `DIRECT`;', "a template literal"),
    ('return host.constructor;', "the property 'constructor'"),
    ('return host.__proto__;', "the property '__proto__'"),
    ('return host.split(".")[0];', "the property 'split'"),
    ('var o = {a: 1}; return "DIRECT";', "an object literal"),
    ('return [1][0];', "an array literal"),
    ('return this.x;', "'this'"),
    ('return typeof host;', "'typeof'"),
    ('return alert.call(null);', "the property 'call'"),
    ('return require("fs");', "the function 'require'"),
    ('return process;', "the unknown name 'process'"),
    ('return constructor;', "the unknown name 'constructor'"),
    ('return Object.prototype;', "the property 'prototype'"),
    ('try { return "DIRECT"; } catch (e) {}', "'try'"),
    ('switch (host) { case "a": return "DIRECT"; }', "'switch'"),
    ('var f = function () { return 1; }; return "DIRECT";', "a function expression"),
    ('return (x = 1);', "an assignment inside an expression"),
])
def test_anything_outside_the_subset_could_not_be_evaluated_safely(body, construct):
    """ASVS V5.2.4 · ASVS V5.2.5 · CWE-94 · CWE-95 · WSTG-INPV-11: no construct outside the subset is run; it is named."""
    r = pe.evaluate(pac(body), "https://a.example/")
    assert r["status"] == "error" and r["kind"] == "error" and r["outcomes"] == []
    assert r["error"].startswith("could not evaluate safely: ") and construct in r["error"], r["error"]


def test_a_file_without_findproxyforurl_is_refused():
    """ASVS V5.1.3 · CWE-20: a script that is not a PAC file is not evaluated."""
    assert "no function FindProxyForURL" in pe.evaluate("var x = 1;", "https://a/")["error"]


def test_the_evaluator_has_no_engine_or_eval():
    """ASVS V5.2.4 · CWE-95: the module imports no JavaScript engine and calls neither eval nor exec."""
    import ast
    import inspect as ins
    tree = ast.parse(ins.getsource(pe))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names} \
        | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not ({"eval", "exec", "compile", "__import__", "getattr", "setattr"} & names)
    assert not ({"js2py", "quickjs", "py_mini_racer", "dukpy", "subprocess", "ctypes", "socket"} & imported)


# ── Caps: size, depth, steps, branches, time ──────────────────────────
@pytest.mark.parametrize("name,src", [
    ("deep parentheses", pac("return " + "(" * 5000 + '"DIRECT"' + ")" * 5000 + ";")),
    ("deep blocks", pac("{" * 5000 + "}" * 5000 + ' return "DIRECT";')),
    ("deep negation", pac("return " + "!" * 20000 + "true;")),
    ("deep calls", pac("return " + "isPlainHostName(" * 3000 + "host" + ")" * 3000 + ";")),
    ("deep ternary", pac("return " + "host ? " * 3000 + '"DIRECT"' + ' : "DIRECT"' * 3000 + ";")),
    ("nested ifs", pac("if (host) " * 5000 + 'return "DIRECT";')),
    ("open parentheses", pac("return " + "(" * 100000)),
])
def test_deep_nesting_is_refused_in_words_not_a_crash(name, src):
    """ASVS V12.1.1 · CWE-674 · CWE-400 · WSTG-BUSL-09: hostile nesting is a named refusal, never a RecursionError."""
    spent, r = _cpu(pe.evaluate, src, "https://a.example/")
    assert r["status"] == "error" and "nesting deeper than" in r["error"], (name, r["error"])
    assert spent < 2.0, f"{name}: {spent:.2f} s"


def test_nesting_boundary():
    """ASVS V12.1.1 · CWE-674: nesting up to the limit is evaluated; one level more is refused."""
    ok = pe.evaluate(pac("return " + "(" * (pe.MAX_DEPTH - 2) + '"DIRECT"' + ")" * (pe.MAX_DEPTH - 2) + ";"), "https://a/")
    over = pe.evaluate(pac("return " + "(" * (pe.MAX_DEPTH + 1) + '"DIRECT"' + ")" * (pe.MAX_DEPTH + 1) + ";"), "https://a/")
    assert ok["kind"] == "direct" and over["status"] == "error"


@pytest.mark.parametrize("name,src", [
    ("long else-if chain", pac("".join(f'if (host == "h{i}.example") return "DIRECT"; else ' for i in range(5000)) + 'return "PROXY ${GATEWAY}:80";')),
    ("long || chain", pac("if (" + " || ".join(f'shExpMatch(host, "*.d{i}.example")' for i in range(4000)) + ') return "DIRECT"; return "PROXY ${GATEWAY}:80";')),
    ("long concatenation", pac("return " + " + ".join('"x"' for _ in range(20000)) + ";")),
])
def test_long_flat_pac_files_are_linear(name, src):
    """ASVS V12.1.1 · CWE-400 · CWE-1333 · WSTG-BUSL-09: long flat PAC files (common in real tenants) evaluate in bounded time."""
    spent, r = _cpu(pe.evaluate, src, "https://www.example.com/")
    assert spent < 2.0, f"{name}: {spent:.2f} s"
    assert r["status"] in ("ok", "error")


def test_a_pac_over_the_size_cap_is_refused_before_it_is_parsed():
    """ASVS V12.1.1 · CWE-400 · CWE-770: a PAC over MAX_SOURCE is refused without tokenising it."""
    big = pac("// " + "a" * pe.MAX_SOURCE + '\nreturn "DIRECT";')
    spent, r = _cpu(pe.evaluate, big, "https://a/")
    assert r["status"] == "error" and "larger than" in r["error"] and spent < 0.5


def test_the_step_budget_ends_a_runaway_pattern_match():
    """ASVS V12.1.1 · CWE-400 · CWE-1333: shExpMatch's work counts against the step budget (no catastrophic backtracking)."""
    src = pac('if (shExpMatch("' + "a" * 4000 + '", "' + "*a" * 2000 + 'b")) return "DIRECT"; return "PROXY ${GATEWAY}:80";')
    spent, r = _cpu(pe.evaluate, src, "https://a/")
    assert spent < 2.0 and r["kind"] == "zscaler"
    capped = pe.evaluate(src, "https://a/", max_steps=2000)
    assert capped["status"] == "error" and "more than 2000 evaluation steps" in capped["error"]


def test_the_time_budget_uses_the_injected_clock():
    """ASVS V12.1.1 · CWE-400: evaluation stops once its time budget is spent (clock injected: deterministic)."""
    ticks = iter(range(0, 10 ** 9, 1))
    src = pac("".join(f'if (host == "h{i}") return "DIRECT";\n' for i in range(3000)) + 'return "PROXY ${GATEWAY}:80";')
    r = pe.evaluate(src, "https://a/", clock=lambda: float(next(ticks)), max_seconds=0.5)
    assert r["status"] == "error" and "s of evaluation" in r["error"]


def test_too_many_undecided_branches_is_refused():
    """ASVS V12.1.1 · CWE-400 · CWE-407: branches followed on unknown conditions are capped (no exponential blow-up)."""
    src = pac("var r = 'PROXY ${GATEWAY}:80';\n" + "if (timeRange(1)) r = r + 'a'; else r = r + 'b';\n" * 40 + "return r;")
    spent, r = _cpu(pe.evaluate, src, "https://a/")
    assert r["status"] == "error" and "undecided branches" in r["error"] and spent < 2.0


def test_a_huge_string_is_refused():
    """ASVS V12.1.1 · CWE-400 · CWE-770: concatenation cannot build a string over MAX_STRING."""
    src = pac('var s = "' + "x" * 40000 + '"; s = s + s; return s + s;')
    r = pe.evaluate(src, "https://a/")
    assert r["status"] == "error" and "string longer than" in r["error"]


@pytest.mark.parametrize("name", ["__proto__", "constructor", "prototype", "hasOwnProperty", "toString", "valueOf", "__class__", "__dict__"])
def test_prototype_like_names_are_plain_variables(name):
    """ASVS V5.1.4 · CWE-1321 · CWE-915: prototype-like names are ordinary variables; nothing reaches Python or JS internals."""
    src = pac(f'var {name} = "PROXY ${{GATEWAY}}:80"; {name} = {name} + "; DIRECT"; return {name};')
    r = pe.evaluate(src, "https://a/")
    assert r["kind"] == "zscaler" and r["result"] == "PROXY ${GATEWAY}:80; DIRECT"


def test_fuzzed_inputs_never_raise():
    """ASVS V5.1.3 · CWE-20 · CWE-248: mutated PAC files are answered or refused, never an exception (deterministic fuzz)."""
    import random
    rnd = random.Random(1234)
    alphabet = list('(){}[];,.?:!<>+-*/%="\' \n') + ["if", "else", "return", "var", "host", "url", "shExpMatch", "isInNet", "DIRECT", "PROXY",
                                                       "function", "FindProxyForURL", "__proto__", "/*", "*/", "//", "\\", "`", "$", "0x1F", "1e3"]
    for i in range(400):
        s = list(CORP)
        for _ in range(rnd.randint(1, 8)):
            pos = rnd.randrange(len(s))
            if rnd.random() < 0.5:
                s.insert(pos, rnd.choice(alphabet))
            else:
                del s[pos]
        r = pe.evaluate("".join(s), "https://www.example.com/", dns="assume_public")
        assert r["status"] in ("ok", "depends", "error"), i
        if r["status"] == "error":
            assert r["error"].startswith(pe.PREFIX)


# ── Static facts, from the same parse ──────────────────────────────────
def test_inspect_lists_the_conditions_that_lead_to_direct():
    """ASVS V5.1.3 · CWE-20: the bypass inventory comes from the parse: positive conditions guarding a literal DIRECT."""
    info = pe.inspect(pac('''
      if (!shExpMatch(host, "*.never.example") && shExpMatch(host, "*.box.com")) return "DIRECT";
      if (isInNet(host, "8.0.0.0", "255.0.0.0")) { return "DIRECT"; }
      return dnsDomainIs(host, ".bank.example") ? "DIRECT" : "PROXY ${GATEWAY}:80";'''))
    rules = {(r["fn"], r["value"]) for r in info["direct_rules"]}
    assert rules == {("shExpMatch", "*.box.com"), ("isInNet", "8.0.0.0"), ("dnsDomainIs", ".bank.example")}
    assert info["isinnet_on_host"] and info["returns"][-1] == "PROXY ${GATEWAY}:80"


def test_the_tenant_read_keeps_the_direct_hosts_from_the_parse():
    """ASVS V5.1.3 · CWE-20: data_flow's PAC reader is pac_eval (one PAC implementation)."""
    assert df._pac_direct_hosts('function FindProxyForURL(url, host) { if (shExpMatch(host, "*.box.com")) { return "DIRECT"; } return "PROXY x:1"; }') == ["*.box.com"]
    assert df._pac_direct_hosts("function FindProxyForURL(url, host) { while (1) {} }") == []


# ── The Path analyzer's PAC hop ────────────────────────────────────────
DEST = {"label": "www.box.com", "host": "www.box.com", "url": "https://www.box.com/upload", "kind": "host", "categories": ["FILE_HOST"],
        "applications": [], "app_classes": []}


def _trace(source, host="www.box.com"):
    zcc = {"app_profiles": [{"id": 1, "name": "App", "platform": "windows", "active": True, "priority": 1, "pac_url": "https://pac.example/p.pac",
                             "bypass": {"domains": [], "apps": [], "ips": []}, "forwarding_profile": 2,
                             "strict_enforcement": True, "ssl_cert": True, "endpoint_dlp": True}],
           "forwarding_profiles": [{"id": 2, "name": "Fwd", "actions": {"off": {"mode_kind": "pac", "mode_label": "Enforce proxy (PAC)",
                                                                                "pac_url": "https://pac.example/p.pac"}}}],
           "pac_files": [{"id": 3, "name": "Corp PAC", "url": "https://pac.example/p.pac", "has_content": True,
                          "direct_hosts": pe.direct_hosts(source), "source": source}], "errors": []}
    zia = {k: [] for k in ("ssl", "url", "cac", "ftc", "dlp", "endpoint", "saas", "email")}
    zia["ssl"] = [sf.normalize_ssl_rule({"id": 10, "name": "Decrypt", "action": "DECRYPT"})]
    dest = dict(copy.deepcopy(DEST), host=host, label=host, url=f"https://{host}/")
    return df.trace(dest, "off", "windows", zcc, zia)


def _pac_hop(t):
    return next(h for h in t["hops"] if h["key"] == "pac")


def test_the_path_hop_evaluates_the_pac_and_names_the_answer():
    """ASVS V5.2.4 · CWE-95: the PAC hop is the evaluated answer, in the shared hop shape, never a regex guess."""
    t = _trace(CORP, "www.dropbox.com")
    h = _pac_hop(t)
    assert h["status"] == "bypass" and t["outcome"] == "bypassed" and h["decided_by"]["name"] == "Corp PAC"
    v = h["module_view"]
    assert set(v) == {"module", "verdict", "rule", "overlaps", "criteria", "notes"}
    assert v["module"] == "pac" and v["verdict"] == "direct" and v["rule"] == {"name": "Corp PAC", "order": None}
    assert {"name": 'shExpMatch(host, "*.dropbox.com")', "state": "match"} in v["criteria"]
    z = _trace(CORP, "www.example.com")
    assert _pac_hop(z)["status"] == "pass" and "fail-open" in _pac_hop(z)["detail"] and z["reaches_zscaler"]


def test_a_computed_bypass_the_old_pattern_reader_missed_is_found():
    """ASVS V5.2.4 · CWE-95: a DIRECT reached through a variable or helper is found by evaluation."""
    src = 'var d = "DIR" + "ECT";\nfunction bad(h) { return h.indexOf("box") >= 0; }\n' + pac('if (bad(host)) return d; return "PROXY ${GATEWAY}:80";')
    assert _pac_hop(_trace(src))["status"] == "bypass"


def test_another_proxy_is_a_bypass_and_an_unknown_branch_is_a_warning():
    """ASVS V5.2.4 · CWE-95: another proxy bypasses Zscaler; an answer that depends on the device is a named warning."""
    other = _trace(pac('return "PROXY squid.corp:3128";'))
    assert _pac_hop(other)["status"] == "bypass" and "another proxy" in _pac_hop(other)["detail"]
    dep = _trace(pac('if (isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0")) return "DIRECT"; return "PROXY ${GATEWAY}:80";'))
    h = _pac_hop(dep)
    assert h["status"] == "warn" and h["weak_point"]["severity"] == "medium" and dep["reaches_zscaler"]
    assert pe.R_MYIP in h["depends_on"]


def test_a_pac_that_cannot_be_evaluated_is_unverified_not_a_pass():
    """ASVS V5.2.5 · CWE-94 · secure by default: an unevaluable PAC is 'unknown', never silently 'no DIRECT'."""
    t = _trace(pac('return /box/.test(host) ? "DIRECT" : "PROXY ${GATEWAY}:80";'))
    h = _pac_hop(t)
    assert h["status"] == "unknown" and "could not evaluate safely: a regular expression" in h["detail"] and t["outcome"] == "unknown"


def test_the_pac_source_is_not_copied_into_each_trace():
    """ASVS V8.3.4 · CWE-200: the PAC text stays in the tenant read; the per-trace inventory leaves it out."""
    t = _trace(CORP)
    assert all("source" not in f for f in t["connector_inventory"]["pac_files"])


# ── The log analyzer uses the same evaluator ───────────────────────────
def test_the_log_analyzer_evaluates_the_uploaded_pac():
    """ASVS V5.2.4 · CWE-95: the uploaded PAC is evaluated (never run) for common destinations, and the result is shown."""
    p = la.analyze_pac("corp.pac", CORP)
    ev = p["summary"]["evaluation"]
    assert ev["ok"] and ev["error"] is None
    kinds = {s["url"]: s["kind"] for s in ev["samples"]}
    assert kinds["https://www.dropbox.com/"] == "direct" and kinds["https://www.example.com/"] == "zscaler"
    assert kinds["http://intranet/"] == "direct"


def test_the_log_analyzer_finds_a_computed_data_channel_bypass():
    """ASVS V5.2.4 · CWE-95: a data channel answered DIRECT through computed logic is a high finding."""
    src = 'function f(h) { return h.indexOf("dropbox") >= 0; }\n' + pac('if (f(host)) return "DIRECT"; return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";')
    p = la.analyze_pac("p.pac", src)
    assert any(f["title"] == "Data channels are answered without Zscaler" and f["severity"] == "high" for f in p["findings"])


def test_the_log_analyzer_says_when_a_pac_could_not_be_evaluated():
    """ASVS V5.2.5 · CWE-94: a PAC outside the subset is reported in words, not run and not guessed."""
    p = la.analyze_pac("p.pac", pac('for (var i = 0; i < 3; i++) {} return "DIRECT";'))
    f = next(f for f in p["findings"] if f["title"] == "The PAC could not be evaluated safely")
    assert "could not evaluate safely: 'for'" in f["what"] and p["summary"]["evaluation"]["ok"] is False
