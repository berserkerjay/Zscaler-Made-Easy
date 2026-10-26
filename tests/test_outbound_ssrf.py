"""Outbound requests and server-side request forgery (QA check T15).

Every place the app fetches a URL is tested here without a network: the
HTTP transport (requests' HTTPAdapter.send) is replaced by a recorder that
answers from a table and remembers what would have been sent. Nothing
connects to anything, loopback included.

Covered: the allowlisted fetcher every upstream read goes through
(zscaler_update_check._safe_get: update check, best-practice crawler, SaaS
matrix, upstream check, Beacon), the crawler's link filter, the OneAPI
sign-in host built from the vanity domain (app, assessment engine, SDK
wrapper used by the MCP server), the SDK's sign-in timeout, the digest
webhook, and a source scan that every requests call carries a timeout and
none turns TLS verification off.
"""
from __future__ import annotations

import ast
import os
import types
from typing import Any, Callable, Dict, List, Tuple

import pytest
import requests
import requests.adapters
from requests.models import Response
from urllib3.util import parse_url

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Internal and non-http targets an attacker would aim a request at.
INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "https://127.0.0.1:8000/api/ping",
    "https://[::1]/",
    "http://169.254.169.254/latest/meta-data/iam/",
    "https://10.0.0.5/admin",
    "https://192.168.1.1/",
    "https://localhost/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://help.zscaler.com/x",
    "https://evil.example/",
]


class Recorder:
    """Stands in for the network: answers each request from `routes`
    (host -> callable(request) -> (status, headers, body)) and records
    (method, url, host, timeout, verify, body, authorization) for every request."""

    def __init__(self) -> None:
        self.routes: Dict[str, Callable[[Any], Tuple[int, Dict[str, str], bytes]]] = {}
        self.sent: List[Dict[str, Any]] = []

    def send(self, adapter, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        host = (parse_url(request.url).host or "").lower()
        body = request.body if isinstance(request.body, (bytes, type(None))) else str(request.body).encode()
        self.sent.append({"method": request.method, "url": request.url, "host": host, "timeout": timeout,
                          "verify": verify, "body": body or b"", "authorization": request.headers.get("Authorization")})
        route = self.routes.get(host)
        if route is None:
            raise requests.exceptions.ConnectionError(f"recorder: no route for {host}")
        status, headers, content = route(request)
        r = Response()
        r.status_code, r._content, r.url, r.request = status, content, request.url, request
        r.headers.update(headers)
        return r

    @property
    def hosts(self) -> List[str]:
        return [s["host"] for s in self.sent]


@pytest.fixture
def net(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", lambda self, request, **kw: rec.send(self, request, **kw))
    for key in ("ZSCALER_UPDATE_VERIFY_TLS", "ZSCALER_UPDATE_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy",
                "ALL_PROXY", "all_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(key, raising=False)
    return rec


def ok(body: bytes = b"<title>Doc</title>"):
    return lambda request: (200, {}, body)


def redirect(location: str, status: int = 302):
    return lambda request: (status, {"Location": location}, b"")


# ── The allowlisted fetcher (zscaler_update_check._safe_get) ───────────────

@pytest.mark.parametrize("url", INTERNAL_TARGETS + [
    "http://help.zscaler.com/zia",                        # cleartext on an allowlisted host
    "https://127.0.0.1\\@help.zscaler.com/",              # urllib.parse reads help.zscaler.com, urllib3 connects to 127.0.0.1
    "https://help.zscaler.com\\@127.0.0.1/",
    "https://user:pass@help.zscaler.com/",                # credentials in the URL
    "https://help.zscaler.com:443@127.0.0.1/",
    "https://help.zscaler.com\t.evil/",
    " https://help.zscaler.com@127.0.0.1",
    "https://help.zscaler.com./zia",                      # trailing-dot spelling is not on the list
    "",
])
def test_safe_get_refuses_urls_off_the_allowlist(net, url):
    """ASVS V5.2.6 · V12.6.1 · CWE-918 · WSTG-INPV-19: the fetcher sends nothing for a URL off its https allowlist."""
    import zscaler_update_check as zu
    net.routes = {"127.0.0.1": ok(b"INTERNAL"), "help.zscaler.com": ok()}

    body, status, err = zu._safe_get(url)

    assert (body, status) == (None, 0) and err
    assert net.sent == []


def test_safe_get_reads_an_allowlisted_https_page_with_timeout_and_tls_verified(net):
    """ASVS V9.2.1 · CWE-295 · CWE-1088: an allowlisted page is read once, with the fetch timeout and certificate checks on."""
    import zscaler_update_check as zu
    net.routes = {"help.zscaler.com": ok(b"page")}

    body, status, err = zu._safe_get("https://help.zscaler.com/zia/about-dlp-engines")

    assert (body, status, err) == (b"page", 200, "")
    assert len(net.sent) == 1 and net.sent[0]["timeout"] == zu.FETCH_TIMEOUT and net.sent[0]["verify"] is True


@pytest.mark.parametrize("location", INTERNAL_TARGETS + [
    "//127.0.0.1/steal",                                  # scheme-relative
    "http://help.zscaler.com/zia",                        # downgrade to cleartext on the same host
    "https://127.0.0.1\\@help.zscaler.com/",
    "https://admin@help.zscaler.com/",
])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_safe_get_refuses_a_redirect_off_the_allowlist(net, location, status):
    """ASVS V5.2.6 · V12.6.1 · CWE-918 · WSTG-INPV-19: a redirect from an allowlisted host to an internal or foreign target is not followed."""
    import zscaler_update_check as zu
    net.routes = {"help.zscaler.com": redirect(location, status), "127.0.0.1": ok(b"INTERNAL"),
                  "169.254.169.254": ok(b"INTERNAL"), "evil.example": ok(b"EVIL")}

    body, code, err = zu._safe_get("https://help.zscaler.com/zia/x")

    assert body is None and code == 0 and err.startswith("redirect refused")
    assert net.hosts == ["help.zscaler.com"]


def test_safe_get_follows_redirects_that_stay_on_the_allowlist(net):
    """ASVS V5.2.6 · CWE-918: a relative or cross-allowlist redirect is followed, each hop checked, TLS still verified."""
    import zscaler_update_check as zu
    net.routes = {"help.zscaler.com": lambda r: (302, {"Location": "/zia/new"}, b"") if r.url.endswith("/old") else
                  (301, {"Location": "https://pypi.org/final"}, b""),
                  "pypi.org": ok(b"final")}

    body, status, err = zu._safe_get("https://help.zscaler.com/zia/old")

    assert (body, status, err) == (b"final", 200, "")
    assert net.hosts == ["help.zscaler.com", "help.zscaler.com", "pypi.org"]
    assert all(s["verify"] is True and s["timeout"] == zu.FETCH_TIMEOUT for s in net.sent)


@pytest.mark.parametrize("hops,ok_expected", [(0, True), (1, True), ("max", True), ("max+1", False)])
def test_safe_get_bounds_the_redirect_chain(net, hops, ok_expected):
    """ASVS V12.6.1 · CWE-674 · CWE-400: at most MAX_REDIRECTS hops are followed, then the fetch stops."""
    import zscaler_update_check as zu
    n = {"max": zu.MAX_REDIRECTS, "max+1": zu.MAX_REDIRECTS + 1}.get(hops, hops)

    def chain(request):
        i = int(request.url.rsplit("/", 1)[-1])
        return (302, {"Location": f"/hop/{i + 1}"}, b"") if i < n else (200, {}, b"end")
    net.routes = {"help.zscaler.com": chain}

    body, status, err = zu._safe_get("https://help.zscaler.com/hop/0")

    assert (body == b"end") is ok_expected
    assert len(net.sent) == min(n, zu.MAX_REDIRECTS) + 1


@pytest.mark.parametrize("env,arg,expected", [
    (None, None, True),        # secure default
    ("1", None, True),
    ("0", None, False),        # the operator's explicit, documented opt-out
    (None, False, False),      # the page's explicit "skip TLS verification" tick
    ("0", True, True),         # an explicit argument wins over the setting
])
def test_safe_get_verifies_tls_unless_explicitly_told_not_to(net, monkeypatch, env, arg, expected):
    """ASVS V9.2.1 · CWE-295: certificate checks are on unless the operator or the page explicitly opts out, on every hop."""
    import zscaler_update_check as zu
    if env is not None:
        monkeypatch.setenv("ZSCALER_UPDATE_VERIFY_TLS", env)
    net.routes = {"help.zscaler.com": lambda r: (302, {"Location": "/b"}, b"") if r.url.endswith("/a") else (200, {}, b"ok")}

    zu._safe_get("https://help.zscaler.com/a", verify_tls=arg)

    assert [s["verify"] for s in net.sent] == [expected, expected]


# ── The best-practice crawler ─────────────────────────────────────────────

@pytest.mark.parametrize("url,allowed", [
    ("https://www.zscaler.com/blogs/best-practice-guide", True),
    ("https://WWW.ZSCALER.COM/blogs/x", True),
    ("http://www.zscaler.com/blogs/x", False),
    ("https://127.0.0.1\\@www.zscaler.com/blogs/x", False),
    ("https://user@www.zscaler.com/blogs/x", False),
    ("https://help.zscaler.com/blogs/x", False),           # another source's host
    ("https://www.zscaler.com.evil.example/blogs/x", False),
    ("javascript:alert(1)", False),
    ("", False),
])
def test_crawler_link_filter_matches_the_fetcher(url, allowed):
    """ASVS V5.2.6 · CWE-918 · CWE-436: a link is crawlable only when the fetcher would fetch it and it stays on its source's host."""
    import bp_crawler

    result = bp_crawler._is_allowed_for_source(url, "www.zscaler.com")

    assert result is allowed


def test_crawler_never_fetches_or_lists_a_sitemap_url_that_points_inside(net, monkeypatch, tmp_path):
    """ASVS V5.2.6 · V12.6.1 · CWE-918 · WSTG-INPV-19: a hostile sitemap entry neither reaches 127.0.0.1 nor enters the library."""
    import bp_crawler
    monkeypatch.setattr(bp_crawler, "CRAWL_POLITE_DELAY", 0)
    monkeypatch.setattr(bp_crawler, "_cache_path", lambda: str(tmp_path / "bp_cache.json"))
    hostile = ["https://127.0.0.1\\@www.zscaler.com/blogs/best-practice-a", "http://www.zscaler.com/blogs/best-practice-b",
               "https://x@www.zscaler.com/blogs/best-practice-c"]
    good = "https://www.zscaler.com/blogs/best-practice-good"
    locs = "".join(f"<url><loc>{u}</loc></url>" for u in hostile + [good])
    net.routes = {"www.zscaler.com": lambda r: (200, {}, f"<urlset>{locs}</urlset>".encode()) if r.url.endswith("sitemap.xml")
                  else (200, {}, b"<title>Good</title>"),
                  "127.0.0.1": ok(b"<title>INTERNAL</title>")}

    res = bp_crawler.crawl(force=True, source_ids=["zscaler_blogs"])

    assert "127.0.0.1" not in net.hosts
    assert [e["url"] for e in res["new_entries"]] == [good]


# ── The OneAPI sign-in host (vanity domain) ───────────────────────────────

HOSTILE_VANITY = ["evil.example/?", "127.0.0.1:9/x?", "169.254.169.254/latest#", "acme@evil.example", "acme\\@evil.example",
                  "acme evil", "acme/../x", "-acme", "acme-", "a" * 64, ".acme", "acme..x", ""]


@pytest.mark.parametrize("vanity", HOSTILE_VANITY)
@pytest.mark.parametrize("cloud", ["production", "zscalerbeta", "zscalergov", "zscalergovus"])
def test_token_url_refuses_a_vanity_domain_that_is_not_a_dns_name(vanity, cloud):
    """ASVS V5.1.3 · V5.2.6 · CWE-918 · CWE-522: a vanity domain that could move the sign-in off Zscaler's domain is refused."""
    import zscaler_clouds

    with pytest.raises(ValueError):
        zscaler_clouds.token_url(vanity, cloud)


@pytest.mark.parametrize("vanity", ["acme", "acme-corp", "a1", "a", "a" * 63, "acme.eu"])
@pytest.mark.parametrize("cloud,suffix", [("production", ".zslogin.net"), ("zscalerbeta", ".zsloginbeta.net"),
                                          ("zscalergov", ".zidentitygov.net"), ("zscalergovus", ".zidentitygov.us")])
def test_token_url_stays_under_the_zscaler_sign_in_domain(vanity, cloud, suffix):
    """ASVS V5.2.6 · CWE-918: every accepted vanity domain gives an https host under the cloud's Zscaler sign-in domain."""
    import zscaler_clouds

    url = zscaler_clouds.token_url(vanity, cloud)

    p = parse_url(url)
    assert p.scheme == "https" and p.host == f"{vanity.lower()}{suffix}" and p.path == "/oauth2/v1/token" and p.auth is None


@pytest.fixture
def env_creds(monkeypatch):
    for k, v in {"ZSCALER_CLIENT_ID": "cid-example", "ZSCALER_CLIENT_SECRET": "secret-example-123",
                 "ZSCALER_VANITY_DOMAIN": "acme", "ZSCALER_CLOUD": "production"}.items():
        monkeypatch.setenv(k, v)
    for k in ("ZSCALER_AUTH_METHOD", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY"):
        monkeypatch.delenv(k, raising=False)


@pytest.mark.parametrize("vanity", ["127.0.0.1:9/steal?x=", "evil.example/#", "evil.example?", "user@evil.example"])
@pytest.mark.parametrize("tool", ["run_assessment", "run_section"])
def test_mcp_tool_vanity_argument_cannot_send_the_client_secret_elsewhere(net, env_creds, vanity, tool):
    """ASVS V5.2.6 · V2.10.4 · CWE-918 · CWE-522: an MCP tool's vanity_domain cannot steer the environment's client secret off Zscaler."""
    import dlp_mcp_server
    fn = getattr(getattr(dlp_mcp_server, tool), "fn", getattr(dlp_mcp_server, tool))
    kwargs = {"section": "DLP"} if tool == "run_section" else {}

    out = fn(vanity_domain=vanity, **kwargs)

    assert "Invalid vanity domain" in str(out.get("error"))
    assert net.sent == []


def _sign_in_builders():
    import sdk_client

    def mcp_wrapper():
        sdk_client.SdkClient("cid-example", "secret-example-123", "acme", "zscalerten").auth()

    def web_app():
        import dlp_api_server as srv
        with pytest.raises(Exception):
            srv._build_sdk_client({"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-example",
                                   "client_secret": "secret-example-123"})
    return {"sdk_client.SdkClient (MCP server)": mcp_wrapper, "dlp_api_server._build_sdk_client": web_app}


@pytest.mark.parametrize("name", ["sdk_client.SdkClient (MCP server)", "dlp_api_server._build_sdk_client"])
def test_oneapi_sign_in_has_a_timeout_and_goes_only_to_zscaler(net, name):
    """ASVS V2.10.4 · CWE-1088 · CWE-400: the OneAPI token request carries a timeout and goes only to <vanity>.zslogin.net over verified TLS."""
    build = _sign_in_builders()[name]

    build()

    token_posts = [s for s in net.sent if s["url"].endswith("/oauth2/v1/token")]
    assert token_posts, net.sent
    for s in token_posts:
        assert s["host"] == "acme.zslogin.net" and s["url"].startswith("https://")
        assert s["timeout"] is not None and s["verify"] is not False


def test_mcp_wrapper_gives_the_sdk_a_request_timeout():
    """ASVS V2.10.4 · CWE-1088: the MCP server's SDK client has a bounded request timeout like the web app's."""
    import sdk_client

    cfg = sdk_client.SdkClient("cid", "sec", "acme", "zscalerten")._config

    assert 0 < cfg["requestTimeout"] <= 120 and cfg["rateLimit"]["maxRetrySeconds"] <= 60


def test_bounded_requests_keeps_an_explicit_timeout():
    """CWE-1088: the sign-in timeout shim fills a missing timeout and never overrides one the caller set."""
    import tenant_auth
    seen = []
    fake = types.SimpleNamespace(post=lambda *a, **k: seen.append(k["timeout"]), get=lambda *a, **k: seen.append(k["timeout"]),
                                 request=lambda *a, **k: seen.append(k["timeout"]), Response=object)
    bounded = tenant_auth._BoundedRequests(fake)

    bounded.post("u"); bounded.post("u", timeout=None); bounded.get("u", timeout=5); bounded.request("GET", "u")

    assert seen == [tenant_auth.SDK_SIGN_IN_TIMEOUT, tenant_auth.SDK_SIGN_IN_TIMEOUT, 5, tenant_auth.SDK_SIGN_IN_TIMEOUT]
    assert bounded.Response is object


# ── The digest webhook ────────────────────────────────────────────────────

@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("location", ["http://169.254.169.254/latest/api/token", "https://127.0.0.1/hook", "https://evil.example/"])
def test_webhook_redirect_is_not_followed(net, status, location):
    """ASVS V12.6.1 · CWE-918 · CWE-601: a webhook that redirects does not get the digest re-posted to the Location."""
    import continuous_eval as ce
    net.routes = {"hooks.slack.com": redirect(location, status), "169.254.169.254": ok(), "127.0.0.1": ok(), "evil.example": ok()}

    out = ce._send_webhook("subject", "digest", "https://hooks.slack.com/services/T/B/X")

    assert out["sent"] is False and "redirect" in out["why"]
    assert net.hosts == ["hooks.slack.com"]


@pytest.mark.parametrize("url", ["http://hooks.slack.com/services/T/B/X", "file:///etc/passwd", "gopher://127.0.0.1/", ""])
def test_webhook_must_be_https(net, url):
    """ASVS V9.2.2 · CWE-319: a webhook that is not https:// is not posted to."""
    import continuous_eval as ce

    out = ce._send_webhook("subject", "digest", url)

    assert out["sent"] is False and net.sent == []


def test_webhook_posts_once_with_a_timeout(net):
    """ASVS V12.6.1 · CWE-1088: a working https webhook gets one post, with a timeout and certificate checks."""
    import continuous_eval as ce
    net.routes = {"hooks.slack.com": ok(b"ok")}

    out = ce._send_webhook("subject", "digest", "https://hooks.slack.com/services/T/B/X")

    assert out["sent"] is True and len(net.sent) == 1
    assert net.sent[0]["timeout"] and net.sent[0]["verify"] is True


# ── Every outbound call in the app's source ───────────────────────────────

def _app_modules() -> List[str]:
    out = [f for f in os.listdir(ROOT) if f.endswith(".py")]
    out += [os.path.join("tools", f) for f in os.listdir(os.path.join(ROOT, "tools")) if f.endswith(".py")]
    return sorted(out)


_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


def _requests_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _HTTP_VERBS:
            base = node.func.value
            # requests.get(...), and the assessment engine's session (s.sess.get(...))
            if (isinstance(base, ast.Name) and base.id == "requests") or (isinstance(base, ast.Attribute) and base.attr == "sess"):
                yield node


@pytest.mark.parametrize("module", _app_modules())
def test_every_outbound_request_has_a_timeout_and_keeps_tls_verification(module):
    """ASVS V9.2.1 · V12.6.1 · CWE-1088 · CWE-295: every requests call in the app passes timeout= and none passes verify=False."""
    with open(os.path.join(ROOT, module), encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=module)

    calls = list(_requests_calls(tree))

    for call in calls:
        kw = {k.arg: k.value for k in call.keywords}
        assert "timeout" in kw or any(k.arg is None for k in call.keywords), f"{module}:{call.lineno} sends without a timeout"
        v = kw.get("verify")
        assert not (isinstance(v, ast.Constant) and v.value is False), f"{module}:{call.lineno} turns TLS verification off"


# ── The app update check (GitHub REST API) ────────────────────────────────

@pytest.mark.parametrize("location", ["https://evil.example/x", "http://127.0.0.1/x", "http://169.254.169.254/latest/"])
def test_github_token_never_follows_a_redirect_off_api_github_com(net, monkeypatch, location):
    """ASVS V2.10.4 · V12.6.1 · CWE-522 · CWE-918: the read-only GitHub token is sent to api.github.com only, with a timeout."""
    import app_update
    monkeypatch.setenv("DLP_CHECK_GITHUB_TOKEN", "ghp_example_not_a_token")
    monkeypatch.delenv("DLP_CHECK_GITHUB_REPO", raising=False)
    net.routes = {"api.github.com": redirect(location), "evil.example": ok(b"{}"), "127.0.0.1": ok(b"{}"), "169.254.169.254": ok(b"{}")}

    app_update.github_branch_head("main")

    first, rest = net.sent[0], net.sent[1:]
    assert first["host"] == "api.github.com" and first["url"].startswith("https://") and first["timeout"]
    assert first["authorization"] == "Bearer ghp_example_not_a_token"
    assert all(s["authorization"] is None for s in rest)


def test_github_check_refuses_a_branch_outside_the_allowlist(net):
    """ASVS V5.1.3 · CWE-918 · CWE-88: a branch name that is not main, qa or dev never reaches a URL."""
    import app_update

    with pytest.raises(ValueError):
        app_update.valid_branch("main/../../users/x")

    assert net.sent == []
