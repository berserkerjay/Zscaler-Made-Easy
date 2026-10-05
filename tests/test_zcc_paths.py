"""
Client Connector (ZCC) OneAPI paths: the app-profile listing lives at
/web/policy/listByCompany (per the Zscaler SDK); older API generations
used other names. The client tries each candidate and, when a call
fails, the finding names the path and HTTP status instead of a generic
"not accessible".
"""
from __future__ import annotations

import dlp_assessment_full_auto as fa


class _Resp:
    def __init__(self, code, body=None, text=""):
        self.status_code, self._body, self.text, self.headers = code, body, text, {}

    def json(self):
        return self._body


class FakeSession:
    """requests.Session stand-in: a route table keyed by path."""
    def __init__(self, routes):
        self.routes, self.calls, self.headers = routes, [], {}

    def get(self, url, params=None, timeout=None):
        path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] if "://" in url else url
        self.calls.append(path)
        code, body = self.routes.get(path, (404, None))
        return _Resp(code, body, "" if body is not None else "Not Found")


def _client(routes):
    c = fa.Client("cid", "sec", "acme", "production")
    c.sess = FakeSession(routes)
    c.token, c.exp = "t", 9e12
    return c


def test_app_profiles_resolve_to_the_sdk_path_with_fallbacks():
    assert fa._resolve_ep("/zcc/appProfiles") == "/zcc/papi/public/v1/application-profiles"
    assert fa._resolve_candidates("/zcc/webPolicies") == ["/zcc/papi/public/v1/application-profiles", "/zcc/papi/public/v1/web/policy/listByCompany",
                                                          "/zcc/papi/public/v1/webPolicy/listByCompany",
                                                          "/zcc/papi/public/v1/webPolicies/listByCompany"]
    assert fa._resolve_candidates("/zcc/forwardingProfiles") == ["/zcc/papi/public/v1/webForwardingProfile/listByCompany"]
    assert fa._resolve_ep("/zcc/privacyInfo") == "/zcc/papi/public/v1/getWebPrivacyInfo"


def test_client_takes_the_first_path_that_exists_and_caches_it():
    profiles = [{"id": 1, "name": "Windows-Corp", "os": "windows"}]
    c = _client({"/zcc/papi/public/v1/web/policy/listByCompany": (200, profiles)})
    d, code = c.get("/zcc/appProfiles")
    assert code == 200 and d == profiles
    # A tenant on the older naming: the first path 404s, the second answers.
    c2 = _client({"/zcc/papi/public/v1/webPolicy/listByCompany": (200, profiles)})
    d, code = c2.get("/zcc/appProfiles")
    assert code == 200 and d == profiles and c2.sess.calls[-2:] == ["/zcc/papi/public/v1/web/policy/listByCompany", "/zcc/papi/public/v1/webPolicy/listByCompany"]
    c2.get("/zcc/appProfiles")
    assert len(c2.sess.calls) == 3                     # cached under the short endpoint
    items, err = fa._g(c2, "/zcc/appProfiles", "AppProfiles")
    assert err is None and items == profiles


def test_a_real_failure_names_the_path_and_status():
    c = _client({})                                     # nothing answers
    d, code = c.get("/zcc/appProfiles")
    assert code == 404 and d["path"] == "/zcc/papi/public/v1/application-profiles" and len(d["tried"]) == 4
    items, err = fa._g(c, "/zcc/appProfiles", "AppProfiles")
    assert items is None and err.status == fa.R.INFO
    assert "not readable" in err.detail and "web/policy/listByCompany -> HTTP 404" in err.detail
    # A 403 stops at the first path (the route exists; the client lacks the scope) and says so.
    c3 = _client({"/zcc/papi/public/v1/web/policy/listByCompany": (403, None)})
    d, code = c3.get("/zcc/appProfiles")
    assert code == 403 and len(c3.sess.calls) == 2
    _, err = fa._g(c3, "/zcc/appProfiles", "AppProfiles")
    assert "/zcc/papi/public/v1/web/policy/listByCompany -> HTTP 403" in err.detail and "role" in err.detail
