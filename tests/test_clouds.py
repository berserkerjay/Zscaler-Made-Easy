"""Every Zscaler cloud a tenant can live on is reachable the right way from
every entry point: the commercial clouds (zscaler.net through
zscalerten.net) through zslogin.net and api.zsapi.net, beta through the
beta hosts, and the FedRAMP clouds (zscalergov.net, zscalergov.us) through
their own identity provider and gateway. One table (zscaler_clouds) feeds
the GUI, the API server, the assessment engine, the SDK wrapper and the
discovery tool."""
from __future__ import annotations

import os
import re

import pytest

import zscaler_clouds as zc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

COMMERCIAL = ("production", "zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscloud", "zscalerten")


@pytest.mark.parametrize("cloud", COMMERCIAL)
def test_every_commercial_cloud_uses_the_shared_login_and_gateway(cloud):
    assert zc.environment(cloud) is None
    assert zc.token_url("acme", cloud) == "https://acme.zslogin.net/oauth2/v1/token"
    assert zc.api_base(cloud) == "https://api.zsapi.net"
    assert not zc.is_government(cloud)


def test_government_and_beta_clouds_use_their_own_hosts():
    assert zc.environment("zscalergov") == "gov" and zc.token_url("acme", "zscalergov") == "https://acme.zidentitygov.net/oauth2/v1/token"
    assert zc.api_base("zscalergov") == "https://api.zscalergov.net" and zc.is_government("zscalergov")
    assert zc.environment("zscalergovus") == "govus" and zc.api_base("zscalergovus") == "https://api.zscalergov.us"
    assert zc.token_url("acme", "govus") == "https://acme.zidentitygov.us/oauth2/v1/token"
    assert zc.environment("zscalerbeta") == "beta" and zc.token_url("acme", "beta") == "https://acme.zsloginbeta.net/oauth2/v1/token"
    assert zc.api_base("zspreview") == "https://api.beta.zsapi.net"


def test_spellings_people_use_are_accepted_and_nonsense_is_named():
    for spelling, stored in (("ZSCALERTEN", "zscalerten"), ("zscalerten.net", "zscalerten"), ("admin.zscalergov.net", "zscalergov"),
                             ("gov", "zscalergov"), ("govus", "zscalergovus"), ("zscalergov.us", "zscalergovus"), ("", "production"),
                             ("Beta", "zscalerbeta"), ("zscloud.net", "zscloud")):
        assert zc.normalize(spelling) == stored, spelling
    with pytest.raises(ValueError, match="Unknown Zscaler cloud 'zscalerfour'"):
        zc.normalize("zscalerfour")


def test_the_server_validator_and_the_sdk_mapping_follow_the_table():
    import security
    from fastapi import HTTPException
    assert security.validate_cloud("zscalerten") == "zscalerten" and security.validate_cloud("gov") == "zscalergov"
    assert security.validate_cloud("") == "production"
    with pytest.raises(HTTPException) as ex:
        security.validate_cloud("zscalerfour")
    assert ex.value.status_code == 400 and "zscalerten" in ex.value.detail
    import dlp_api_server as srv
    assert srv._oneapi_cloud("zscalerten") is None and srv._oneapi_cloud("zscalergov") == "gov" and srv._oneapi_cloud("zscalergov.us") == "govus"
    assert srv._oneapi_cloud("zscalerbeta") == "beta" and srv._oneapi_cloud("nonsense") is None
    sdk_client = pytest.importorskip("sdk_client", reason="the Zscaler SDK and its dependencies are not installed in this interpreter")
    assert sdk_client.SdkClient("id", "secret", "acme", "zscalerten")._config["cloud"] == "production"
    assert sdk_client.SdkClient("id", "secret", "acme", "zscalergov")._config["cloud"] == "gov"
    assert sdk_client.SdkClient("id", "secret", "acme", "zscalergov.us")._config["cloud"] == "govus"


def test_the_assessment_engine_and_discovery_tool_reach_every_cloud():
    import dlp_assessment_full_auto as fa
    import discover_endpoints as de
    assert fa._base_url("zscalerten") == "https://api.zsapi.net" and fa._token_url("acme", "zscalerten") == "https://acme.zslogin.net/oauth2/v1/token"
    assert fa._base_url("zscalergov") == "https://api.zscalergov.net" and fa._token_url("acme", "zscalergov") == "https://acme.zidentitygov.net/oauth2/v1/token"
    assert fa._base_url("zscloud") == "https://api.zsapi.net", "a commercial cloud name must never become api.<cloud>.zsapi.net"
    assert set(fa.CLOUDS) == set(zc.CLOUDS)
    assert de._base_url("zscalergovus") == "https://api.zscalergov.us/v1" and de._token_url("acme", "production").endswith("zslogin.net/oauth2/v1/token")
    c = fa.Client("id", "secret", "acme", "zscalergov")
    assert c.base == "https://api.zscalergov.net"


def test_the_gui_offers_every_cloud_by_its_admin_url():
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    picker = html[html.find('<select id="cloud"'):]
    picker = picker[:picker.find("</select>")]
    values = set(re.findall(r'<option value="([^"]+)"', picker))
    assert values == set(zc.CLOUDS), {"missing from the picker": sorted(set(zc.CLOUDS) - values), "not a cloud": sorted(values - set(zc.CLOUDS))}
    assert "zscalerten.net" in picker and "zscalergov.net" in picker and "zscalergov.us" in picker
