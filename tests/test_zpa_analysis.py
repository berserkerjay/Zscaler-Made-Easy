"""ZPA analysis templates and ZPA diagnostics: the reader (paced, Stop-able,
read-only, only when ZPA is in scope), every template in the catalog, the
strict no-false-positive rule for unreachable access rules, the
diagnostics (segment match, rule order, explanations), the API (jobs,
reuse of a read, exports) and the page conventions.

The fake tenant answers with the SDK's own models (zscaler.zpa.models)
built from API-shaped JSON, and with a response whose get_results() is that
JSON, exactly as the SDK's list methods return (items, response, error)."""
from __future__ import annotations

import copy
import csv
import io
import os
import re
import threading
import time

import pytest
from fastapi.testclient import TestClient

import zpa_analysis as za
import zpa_reader as zr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = 1_760_000_000.0
DAY = 86400
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "216196257331281920"}
ZPA_SCOPE = {"scopes": ["zpa"], "channels": {}, "from_page": True}


def _us(t):   # connectors report broker times in microseconds
    return str(int(t * 1_000_000))


def _ports(*pairs):
    out = []
    for a, b in pairs:
        out += [str(a), str(b)]
    return out


def _seg(i, name, domains, tcp, group, servers, **kw):
    d = {"id": i, "name": name, "enabled": True, "domainNames": domains, "tcpPortRanges": _ports(*tcp), "segmentGroupId": group,
         "segmentGroupName": group, "serverGroups": [{"id": s, "name": s} for s in servers], "bypassType": "NEVER",
         "healthReporting": "ON_ACCESS", "doubleEncrypt": False}
    d.update(kw)
    return d


def _op(t, lhs, rhs, name=""):
    o = {"objectType": t, "lhs": lhs, "rhs": rhs}
    if name:
        o["name"] = name
    return o


def _cond(*ops, operator="OR", negated=False):
    return {"operator": operator, "negated": negated, "operands": list(ops)}


def _rule(i, order, name, action, *conds, **kw):
    d = {"id": i, "ruleOrder": str(order), "name": name, "action": action, "operator": "AND", "conditions": list(conds)}
    d.update(kw)
    return d


APP = lambda sid: _op("APP", "id", sid)                      # noqa: E731
GRP = lambda gid: _op("APP_GROUP", "id", gid)                # noqa: E731
SCIM = lambda gid, name="": _op("SCIM_GROUP", "idp1", gid, name)   # noqa: E731
ZAPP = _op("CLIENT_TYPE", "id", "zpn_client_type_zapp")


def messy():
    """A tenant built to trip every template at least once."""
    old, recent = NOW - 30 * DAY, NOW - 60
    return {
        "segments": [
            _seg("s-git", "Git servers", ["git.corp.example"], [(22, 22), (443, 443)], "sg-eng", ["srv-dc1"]),
            _seg("s-jira", "Jira", ["jira.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]),
            _seg("s-mirror", "Git mirror", ["git.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]),
            _seg("s-wild", "Corp wildcard", ["*.corp.example"], [(80, 80), (443, 443)], "sg-gen", ["srv-dc1"]),
            _seg("s-pay", "Payroll", ["payroll.corp.example"], [(443, 443)], "sg-fin", ["srv-dc1"]),
            _seg("s-unused", "Unused app", ["unused.corp.example"], [(8443, 8443)], "sg-misc", ["srv-dc1"]),
            _seg("s-legacy", "Legacy app", ["legacy.corp.example"], [(443, 443)], "sg-old", ["srv-dc1"]),
            _seg("s-broad", "Everything dot com", ["*.com", "10.0.0.0/8"], [(1, 65535)], "sg-gen", ["srv-dc1"], bypassType="ALWAYS"),
            _seg("s-rdp", "RDP jump hosts", ["rdp.corp.example", "10.20.30.0/24"], [(3389, 3389)], "sg-gen", ["srv-dc1"], healthReporting="NONE"),
            _seg("s-orphan", "Orphan app", ["orphan.corp.example"], [(443, 443)], "sg-gen", []),
            _seg("s-intra", "Intranet", ["intranet.corp.example"], [(443, 443)], "sg-gen", ["srv-branch"], bypassType="ON_NET"),
            _seg("s-wide", "Wide ports", ["wide.corp.example"], [(5000, 9000)], "sg-gen", ["srv-dc1"]),
            # A Privileged Remote Access segment and a Browser Access (unmanaged device) segment.
            _seg("s-pra", "Plant jump hosts", ["pra.corp.example"], [(3389, 3389)], "sg-gen", ["srv-dc1"],
                 commonAppsDto={"appsConfig": [{"appTypes": ["SECURE_REMOTE_ACCESS"]}]}),
            _seg("s-ba", "HR portal", ["hr.corp.example"], [(443, 443)], "sg-gen", ["srv-dc1"],
                 clientlessApps=[{"id": "ca1", "name": "hr", "enabled": True}]),
        ],
        "segment_groups": [
            {"id": "sg-eng", "name": "Engineering apps", "enabled": True, "applications": [{"id": "s-git"}, {"id": "s-jira"}, {"id": "s-mirror"}]},
            {"id": "sg-gen", "name": "General", "enabled": True},
            {"id": "sg-fin", "name": "Finance apps", "enabled": True},
            {"id": "sg-misc", "name": "Misc", "enabled": True},
            {"id": "sg-old", "name": "Old apps", "enabled": False},
            {"id": "sg-empty", "name": "Empty group", "enabled": True, "applications": []},
        ],
        "server_groups": [
            {"id": "srv-dc1", "name": "DC1 servers", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": [{"id": "cg-dc1", "name": "DC1 connectors"}]},
            {"id": "srv-static", "name": "Static servers", "enabled": True, "dynamicDiscovery": False, "servers": [], "appConnectorGroups": [{"id": "cg-dc2", "name": "DC2 connectors"}]},
            {"id": "srv-none", "name": "No connectors", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": []},
            {"id": "srv-branch", "name": "Branch servers", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": [{"id": "cg-branch", "name": "Branch connectors"}]},
            {"id": "srv-lab", "name": "Lab servers", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": [{"id": "cg-empty", "name": "Empty connectors"}]},
        ],
        "connector_groups": [
            {"id": "cg-dc1", "name": "DC1 connectors", "enabled": True},
            {"id": "cg-dc2", "name": "DC2 connectors", "enabled": True},
            {"id": "cg-branch", "name": "Branch connectors", "enabled": True},
            {"id": "cg-empty", "name": "Empty connectors", "enabled": True},
            {"id": "cg-spare", "name": "Spare connectors", "enabled": True},
        ],
        "connectors": [
            {"id": "c1", "name": "dc1-a", "enabled": True, "appConnectorGroupId": "cg-dc1", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
             "currentVersion": "24.1.1", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(recent)},
            {"id": "c2", "name": "dc1-b", "enabled": True, "appConnectorGroupId": "cg-dc1", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
             "currentVersion": "24.1.1", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(recent)},
            {"id": "c3", "name": "dc2-a", "enabled": True, "appConnectorGroupId": "cg-dc2", "controlChannelStatus": "ZPN_STATUS_DISCONNECTED",
             "currentVersion": "24.1.1", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(old), "lastBrokerDisconnectTime": _us(old + 60)},
            {"id": "c4", "name": "branch-a", "enabled": True, "appConnectorGroupId": "cg-branch", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
             "currentVersion": "24.1.1", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(recent)},
            {"id": "c5", "name": "branch-b", "enabled": True, "appConnectorGroupId": "cg-branch", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",
             "currentVersion": "23.9.4", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(recent)},
        ],
        "service_edge_groups": [{"id": "pse-1", "name": "Branch PSE", "enabled": True, "isPublic": False, "serviceEdges": []}],
        "service_edges": [],
        "idps": [{"id": "idp1", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True},
                 {"id": "idp2", "name": "Old ADFS", "enabled": False}],
        "saml_attributes": [{"id": "attr-dept", "name": "Department", "idpId": "idp2", "samlName": "department"}],
        "posture_profiles": [{"id": "p1", "name": "Corp device", "postureUdid": "udid-1"}],
        "trusted_networks": [{"id": "tn1", "name": "HQ", "networkId": "net-1"}],
        "machine_groups": [{"id": "mg1", "name": "Kiosks", "enabled": True}],
        "scim_groups": {"idp1": [{"id": "g-eng", "name": "Engineering", "idpId": "idp1"}, {"id": "g-con", "name": "Contractors", "idpId": "idp1"}]},
        "policies": {
            "access": [
                _rule("r1", 1, "Engineering to Git", "ALLOW", _cond(GRP("sg-eng")), _cond(SCIM("g-eng", "Engineering")), _cond(ZAPP)),
                _rule("r2", 2, "Engineering to Git with posture", "ALLOW", _cond(APP("s-git")), _cond(SCIM("g-eng")), _cond(ZAPP),
                      _cond(_op("POSTURE", "udid-1", "true"))),
                _rule("r3", 3, "Block engineering from Jira", "DENY", _cond(APP("s-jira")), _cond(SCIM("g-eng")), _cond(ZAPP)),
                _rule("r4", 4, "Payroll deny", "DENY", _cond(APP("s-pay")), _cond(SCIM("g-con", "Contractors"))),
                _rule("r5", 5, "Wildcard for all", "ALLOW", _cond(APP("s-wild"), APP("s-intra"), APP("s-rdp"), APP("s-broad"), APP("s-orphan"), APP("s-wide"),
                                                                 APP("s-pra"), APP("s-ba"))),
                _rule("r6", 6, "Sales via SAML", "ALLOW", _cond(APP("s-jira")), _cond(_op("SAML", "attr-dept", "Sales"))),
                _rule("r7", 7, "Dangling", "ALLOW", _cond(APP("s-gone"), GRP("sg-old")), _cond(_op("POSTURE", "udid-gone", "true"))),
                _rule("r8", 8, "Old allow all", "ALLOW", disabled="1"),
                _rule("r9", 9, "Contractors deny", "DENY", _cond(GRP("sg-eng")), _cond(SCIM("g-con"))),
            ],
            "timeout": [_rule("t1", 1, "Reauth everyone", "RE_AUTH"), _rule("t2", 2, "Reauth engineering", "RE_AUTH", _cond(SCIM("g-eng"))),
                        _rule("t3", 3, "Default", "RE_AUTH", defaultRule=True)],
            "client_forwarding": [_rule("f1", 1, "Bypass all", "BYPASS")],
            "inspection": [_rule("i1", 1, "Inspect engineering", "INSPECT", _cond(GRP("sg-eng")), zpnInspectionProfileId="ip1")],
            "isolation": [],
            "capabilities": [_rule("cap1", 1, "Jump host full transfer", "CHECK_CAPABILITIES", _cond(APP("s-pra")),
                                   privilegedCapabilities={"capabilities": ["CLIPBOARD_COPY", "FILE_DOWNLOAD", "MONITOR_SESSION"]})],
            # The credential rule's action name is assumed (the SDK does not list one).
            "credential": [_rule("cr1", 1, "Shared admin login", "INJECT_CREDENTIALS", _cond(_op("CONSOLE", "id", "con-1")),
                                 credential={"id": "cred-1", "name": "plant-admin"})],
            "redirection": [_rule("rd1", 1, "Branch always via PSE", "REDIRECT_ALWAYS", serviceEdgeGroups=[{"id": "pse-1", "name": "Branch PSE"}]),
                            _rule("rd2", 2, "Prefer a PSE", "REDIRECT_PREFERRED")],
            "clientless": [],
        },
        "servers": [{"id": "sv1", "name": "old-db", "address": "10.0.0.5", "enabled": True, "appServerGroupIds": []}],
        "inspection_profiles": [{"id": "ip1", "name": "OWASP monitor", "paranoiaLevel": "1", "globalControlActions": ["PREDEFINED:PASS", "CUSTOM:NONE"],
                                 "predefinedControls": [{"id": "pc1", "action": "PASS"}]}],
        "custom_controls": [{"id": "cc1", "name": "Block admin path", "action": "BLOCK", "associatedInspectionProfileNames": []}],
        "business_continuity": [{"id": "bc1", "backupEnabled": True, "maxAllowedDownTime": "30", "maxAllowedDownTimeUnit": "MINUTES",
                                 "sitespPrivateKey": "-----BEGIN PRIVATE KEY-----canary-bc-key", "idpCert": "canary-bc-cert"}],
        "private_clouds": [{"id": "pc1", "name": "Plant site", "enabled": True, "siteControllerGroupIds": [{"id": "pcg1", "name": "Plant floor"}]}],
        "private_cloud_groups": [{"id": "pcg1", "name": "Plant floor", "enabled": True}],
        "private_cloud_controllers": [{"id": "pcc1", "name": "plant-pcc-1", "enabled": True, "privateCloudControllerGroupId": "pcg1",
                                       "controlChannelStatus": "ZPN_STATUS_DISCONNECTED"}],
        "branch_connector_groups": [{"id": "bcg1", "name": "Store 12", "enabled": True}],
        "branch_connectors": [],
        "cloud_connector_groups": [{"id": "ccg1", "name": "AWS us-east-1", "enabled": True}],
        "cloud_connectors": [{"id": "ccn1", "name": "aws-cc-1", "enabled": True, "edgeConnectorGroupId": "ccg1", "fingerprint": "canary-fp"}],
    }


def clean():
    """A well-run tenant: nothing for any template to find."""
    recent = NOW - 60
    con = lambda i, g: {"id": i, "name": i, "enabled": True, "appConnectorGroupId": g, "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED",  # noqa: E731
                        "currentVersion": "24.1.1", "expectedVersion": "24.1.1", "lastBrokerConnectTime": _us(recent)}
    return {
        "segments": [
            _seg("s-git", "Git servers", ["git.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"], doubleEncrypt=True),
            _seg("s-jira", "Jira", ["jira.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]),
            _seg("s-ssh", "Build hosts", ["build.corp.example"], [(22, 22)], "sg-ops", ["srv-dc1"], healthReporting="ON_ACCESS"),
        ],
        "segment_groups": [{"id": "sg-eng", "name": "Engineering apps", "enabled": True}, {"id": "sg-ops", "name": "Ops", "enabled": True}],
        "server_groups": [{"id": "srv-dc1", "name": "DC1 servers", "enabled": True, "dynamicDiscovery": True,
                           "appConnectorGroups": [{"id": "cg-dc1", "name": "DC1 connectors"}]}],
        "connector_groups": [{"id": "cg-dc1", "name": "DC1 connectors", "enabled": True}],
        "connectors": [con("c1", "cg-dc1"), con("c2", "cg-dc1")],
        "service_edge_groups": [], "service_edges": [],
        "idps": [{"id": "idp1", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True}],
        "saml_attributes": [], "posture_profiles": [{"id": "p1", "name": "Corp device", "postureUdid": "udid-1"}],
        "trusted_networks": [], "machine_groups": [],
        "scim_groups": {"idp1": [{"id": "g-eng", "name": "Engineering"}, {"id": "g-ops", "name": "Ops"}]},
        "policies": {
            "access": [
                # Not shadowing each other: r2 needs Ops (r1 needs Engineering); r3's app set is wider than r1's.
                _rule("r1", 1, "Engineering apps", "ALLOW", _cond(GRP("sg-eng")), _cond(SCIM("g-eng")), _cond(_op("POSTURE", "udid-1", "true"))),
                _rule("r2", 2, "Ops apps", "ALLOW", _cond(GRP("sg-ops"), GRP("sg-eng")), _cond(SCIM("g-ops")), _cond(_op("POSTURE", "udid-1", "true"))),
                _rule("r3", 3, "Default deny", "DENY"),
            ],
            "timeout": [_rule("t1", 1, "Engineering", "RE_AUTH", _cond(SCIM("g-eng"))), _rule("t2", 2, "Default", "RE_AUTH", defaultRule=True)],
            "client_forwarding": [], "isolation": [],
            "inspection": [_rule("i1", 1, "Inspect all web", "INSPECT", _cond(GRP("sg-eng"), GRP("sg-ops")), zpnInspectionProfileId="ip1")],
            "redirection": [], "credential": [], "capabilities": [], "clientless": [],
        },
        "servers": [], "business_continuity": [], "private_clouds": [], "private_cloud_groups": [], "private_cloud_controllers": [],
        "branch_connector_groups": [], "branch_connectors": [], "cloud_connector_groups": [], "cloud_connectors": [],
        "inspection_profiles": [{"id": "ip1", "name": "OWASP block", "globalControlActions": ["PREDEFINED:BLOCK"], "customControls": [{"id": "cc1", "action": "BLOCK"}]}],
        "custom_controls": [{"id": "cc1", "name": "Admin path", "action": "BLOCK", "associatedInspectionProfileNames": [{"id": "ip1", "name": "OWASP block"}]}],
    }


# ── the fake SDK client ───────────────────────────────────────────────
from zscaler.zpa.models.app_connector_groups import AppConnectorGroup  # noqa: E402
from zscaler.zpa.models.app_connectors import AppConnectorController  # noqa: E402
from zscaler.zpa.models.application_segment import ApplicationSegments  # noqa: E402
from zscaler.zpa.models.idp import IDPController  # noqa: E402
from zscaler.zpa.models.machine_groups import MachineGroup  # noqa: E402
from zscaler.zpa.models.policyset_controller_v1 import PolicySetControllerV1  # noqa: E402
from zscaler.zpa.models.posture_profiles import PostureProfile  # noqa: E402
from zscaler.zpa.models.saml_attributes import SAMLAttribute  # noqa: E402
from zscaler.zpa.models.scim_groups import SCIMGroup  # noqa: E402
from zscaler.zpa.models.segment_group import SegmentGroup  # noqa: E402
from zscaler.zpa.models.server_group import ServerGroup  # noqa: E402
from zscaler.zpa.models.service_edge_groups import ServiceEdgeGroup  # noqa: E402
from zscaler.zpa.models.service_edges import ServiceEdge  # noqa: E402
from zscaler.zpa.models.trusted_network import TrustedNetwork  # noqa: E402
from zscaler.zpa.models.app_protection_profile import AppProtectionProfile, CustomControls  # noqa: E402
from zscaler.zpa.models.application_servers import AppServers  # noqa: E402
from zscaler.zpa.models.branch_connectors import BranchConnectorController  # noqa: E402
from zscaler.zpa.models.business_continuity import BusinessContinuity  # noqa: E402
from zscaler.zpa.models.cloud_connector_controller import CloudConnectorController  # noqa: E402
from zscaler.zpa.models.cloud_connector_groups import CloudConnectorGroup  # noqa: E402
from zscaler.zpa.models.common import CommonIDName  # noqa: E402
from zscaler.zpa.models.private_cloud import PrivateCloud  # noqa: E402
from zscaler.zpa.models.private_cloud_controller import PrivateCloudController  # noqa: E402
from zscaler.zpa.models.private_cloud_group import PrivateCloudGroup  # noqa: E402

SERVICES = {   # service attribute: (list method, data key, SDK model)
    "application_segment": ("list_segments", "segments", ApplicationSegments),
    "segment_groups": ("list_groups", "segment_groups", SegmentGroup),
    "server_groups": ("list_groups", "server_groups", ServerGroup),
    "app_connector_groups": ("list_connector_groups", "connector_groups", AppConnectorGroup),
    "app_connectors": ("list_connectors", "connectors", AppConnectorController),
    "service_edge_group": ("list_service_edge_groups", "service_edge_groups", ServiceEdgeGroup),
    "service_edges": ("list_service_edges", "service_edges", ServiceEdge),
    "idp": ("list_idps", "idps", IDPController),
    "saml_attributes": ("list_saml_attributes", "saml_attributes", SAMLAttribute),
    "posture_profiles": ("list_posture_profiles", "posture_profiles", PostureProfile),
    "trusted_networks": ("list_trusted_networks", "trusted_networks", TrustedNetwork),
    "machine_groups": ("list_machine_groups", "machine_groups", MachineGroup),
    "servers": ("list_servers", "servers", AppServers),
    "business_continuity": ("list_business_continuity_settings", "business_continuity", BusinessContinuity),
    "private_cloud": ("list_private_clouds", "private_clouds", PrivateCloud),
    "private_cloud_group": ("list_cloud_groups", "private_cloud_groups", PrivateCloudGroup),
    "private_cloud_controller": ("list_cloud_controllers", "private_cloud_controllers", PrivateCloudController),
    "branch_connector_group": ("list_branch_connector_groups", "branch_connector_groups", CommonIDName),
    "branch_connectors": ("list_branch_connectors", "branch_connectors", BranchConnectorController),
    "cloud_connector_groups": ("list_cloud_connector_groups", "cloud_connector_groups", CloudConnectorGroup),
    "cloud_connector_controller": ("list_cloud_connectors", "cloud_connectors", CloudConnectorController),
}
# A service with more than one list: (service, method) -> (data key, SDK model).
METHODS = {("app_protection", "list_profiles"): ("inspection_profiles", AppProtectionProfile),
           ("app_protection", "list_custom_controls"): ("custom_controls", CustomControls)}
# Lists added after the first fixtures: a fixture without them answers an empty list.
NEW_KEYS = {"servers", "business_continuity", "private_clouds", "private_cloud_groups", "private_cloud_controllers",
            "branch_connector_groups", "branch_connectors", "cloud_connector_groups", "cloud_connectors",
            "inspection_profiles", "custom_controls"}


class FakeResp:
    """The SDK response: get_results() is the page's raw JSON."""

    def __init__(self, raw):
        self._raw = raw

    def get_results(self):
        return list(self._raw)


class FakeService:
    def __init__(self, tenant, name):
        self._tenant, self._name = tenant, name

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        t = self._tenant
        if not attr.startswith("list_"):
            def write(*a, **k):
                t.writes.append(f"{self._name}.{attr}")
                raise AssertionError(f"write attempted: {self._name}.{attr}")
            return write

        def lister(*args, query_params=None, **kw):
            qp = dict(query_params or {})
            t.calls.append((self._name, attr, args, qp))
            if t.hook:
                t.hook(self._name, attr, args)
            if self._name in t.fail:
                return None, None, t.fail[self._name]
            page, size = int(qp.get("page", 1)), int(qp.get("page_size", 20))
            if self._name == "policies":
                ptype = args[0]
                items, model = t.data["policies"].get(ptype, []), PolicySetControllerV1
            elif self._name == "scim_groups":
                items, model = t.data["scim_groups"].get(args[0], []), SCIMGroup
            else:
                key, model = METHODS.get((self._name, attr)) or SERVICES[self._name][1:]
                items = t.data.get(key, []) if key in NEW_KEYS else t.data[key]
            chunk = copy.deepcopy(items[(page - 1) * size: page * size])
            return [model(copy.deepcopy(x)) for x in chunk], FakeResp(chunk), None
        return lister


class FakeZpa:
    def __init__(self, tenant):
        self._tenant = tenant

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return FakeService(self._tenant, name)


class FakeTenant:
    """client.zpa.<service>.list_*(): what zscaler.ZscalerClient exposes."""

    def __init__(self, data=None, hook=None, fail=None):
        self.data = data if data is not None else messy()
        self.calls, self.writes = [], []
        self.hook, self.fail = hook, dict(fail or {})
        self.zpa = FakeZpa(self)


def read(data=None, **kw):
    return zr.read(FakeTenant(data, **kw), pace=0)


# ── the reader ────────────────────────────────────────────────────────
def test_the_reader_reads_every_list_read_only_and_keeps_raw_values():
    t = FakeTenant()
    snap = zr.read(t, pace=0)
    names = {(c[0], c[1]) for c in t.calls}
    for svc, (method, _k, _m) in SERVICES.items():
        assert (svc, method) in names, svc
    for svc, method in METHODS:
        assert (svc, method) in names, (svc, method)
    assert {c[2][0] for c in t.calls if c[0] == "policies"} == {"access", "timeout", "client_forwarding", "inspection", "isolation",
                                                               "redirection", "credential", "capabilities", "clientless"}
    assert [c[2] for c in t.calls if c[0] == "scim_groups"] == [("idp1",)], "SCIM groups only for the IdPs the rules name"
    assert not t.writes and all(c[1].startswith("list_") for c in t.calls)
    assert all(c[3].get("page_size") == "500" for c in t.calls if c[0] != "business_continuity"), "pages of the SDK's documented maximum"
    assert [c[3] for c in t.calls if c[0] == "business_continuity"] == [{}], "the business continuity list takes no parameters"
    git = next(s for s in snap["segments"] if s["id"] == "s-git")
    assert git["tcp"] == [[22, 22], [443, 443]] and git["tcp_raw"]["legacy"] == ["22", "22", "443", "443"]
    static = next(g for g in snap["server_groups"] if g["id"] == "srv-static")
    assert static["dynamic_discovery"] is False and static["dynamic_discovery_raw"] is False and static["servers_listed"]
    c3 = next(c for c in snap["connectors"] if c["id"] == "c3")
    assert c3["status_raw"] == "ZPN_STATUS_DISCONNECTED" and c3["connected"] is False and abs(c3["last_connect"] - (NOW - 30 * DAY)) < 1
    access = snap["policies"]["access"]
    assert [r["name"] for r in access][:3] == ["Engineering to Git", "Engineering to Git with posture", "Block engineering from Jira"]
    assert access[7]["disabled"] is True and access[7]["disabled_raw"] == "1"
    assert snap["policies"]["timeout"][-1]["default_rule"] is True


def test_the_reader_pages_until_a_short_page_and_falls_back_to_models():
    data = messy()
    data["segments"] = [_seg(f"s{i}", f"App {i}", [f"a{i}.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]) for i in range(1203)]
    t = FakeTenant(data)
    snap = zr.read(t, pace=0)
    pages = [c[3]["page"] for c in t.calls if c[0] == "application_segment"]
    assert pages == ["1", "2", "3"] and len(snap["segments"]) == 1203
    assert snap["collections"]["segments"]["complete"] is True
    # Without raw JSON the SDK models' as_dict() (snake_case) is read the same way.
    seg = za_seg = zr.normalize_segment(ApplicationSegments(messy()["segments"][0]).as_dict())
    assert seg["domains"] == ["git.corp.example"] and za_seg["segment_group_id"] == "sg-eng" and seg["tcp"] == [[22, 22], [443, 443]]


def test_a_failed_list_is_not_assessed_never_reported_as_empty():
    snap = read(fail={"app_connectors": "403 Forbidden: the API client has no ZPA role"})
    assert snap["connectors"] is None and snap["collections"]["connectors"]["read"] is False
    assert "403" in snap["collections"]["connectors"]["error"]
    out = za.analyze(snap, now=NOW)
    ids = {c["id"] for c in out["not_assessed"]}
    assert {"ZPA-CG-01", "ZPA-CG-02", "ZPA-CG-03", "ZPA-CG-04", "ZPA-AC-01"} <= ids
    assert not [f for f in out["findings"] if f["template"].startswith("ZPA-CG") or f["template"] == "ZPA-AC-01"]
    assert all(c["not_read"] for c in out["not_assessed"])


def test_the_reader_paces_and_stop_ends_it_with_nothing_more_read():
    cancel = threading.Event()
    seen = []

    def hook(svc, method, args):
        seen.append(svc)
        if svc == "server_groups":
            cancel.set()
    t = FakeTenant(hook=hook)
    with pytest.raises(zr.Stopped):
        zr.read(t, cancel=cancel, pace=0)
    assert seen[-1] == "server_groups", "nothing is read after Stop"
    # Pacing: the wait between calls is honoured, and Stop interrupts it.
    cancel2 = threading.Event()
    t2 = FakeTenant()
    threading.Timer(0.3, cancel2.set).start()
    t0 = time.monotonic()
    with pytest.raises(zr.Stopped):
        zr.read(t2, cancel=cancel2, pace=0.2)
    assert len(t2.calls) <= 3 and time.monotonic() - t0 < 2


def test_the_reader_needs_the_sdk_zpa_services():
    with pytest.raises(zr.ReadError):
        zr.read(object(), pace=0)


def test_the_reader_drives_the_real_sdk_services_and_paths():
    """The real zscaler.zpa services with a recording request executor:
    the method names and signatures the reader calls exist, and they hit
    the documented customer-scoped paths."""
    from zscaler.zpa.zpa_service import ZPAService
    seen = []

    class Resp:
        def __init__(self, items):
            self._items = items

        def get_results(self):
            return list(self._items)

    class Executor:
        def create_request(self, method, url, *a, **k):
            seen.append((method, url, dict(k.get("params") or (a[2] if len(a) > 2 else {}) or {})))
            return {"method": method, "url": url}, None

        def execute(self, request, *a, **k):
            return Resp([{"id": "1", "name": "x"}] if "policyType/ACCESS" not in request["url"] else []), None

    class Client:
        zpa = ZPAService(Executor(), {"client": {"customerId": "216196257331281920"}})

    snap = zr.read(Client(), pace=0)
    assert all(m == "GET" for m, _u, _p in seen), "read-only"
    urls = [u.replace(" ", "").replace("\n", "") for _m, u, _p in seen]
    base = "/zpa/mgmtconfig/v1/admin/customers/216196257331281920"
    for path in ("/application", "/segmentGroup", "/serverGroup", "/appConnectorGroup", "/connector", "/serviceEdgeGroup", "/serviceEdge",
                 "/policySet/rules/policyType/ACCESS_POLICY", "/policySet/rules/policyType/TIMEOUT_POLICY",
                 "/policySet/rules/policyType/CLIENT_FORWARDING_POLICY", "/policySet/rules/policyType/INSPECTION_POLICY",
                 "/policySet/rules/policyType/ISOLATION_POLICY"):
        assert any(u.startswith(base) and u.endswith(path) for u in urls), path
    assert any("/zpa/mgmtconfig/v2/admin/customers/216196257331281920/idp" in u for u in urls)
    assert all(v["read"] for v in snap["collections"].values()), snap["collections"]


# ── the templates ─────────────────────────────────────────────────────
def _by(out, tid):
    return [f for f in out["findings"] if f["template"] == tid]


@pytest.fixture(scope="module")
def messy_out():
    return za.analyze(read(), now=NOW)


def test_the_catalog_has_at_least_fifteen_documented_templates():
    assert len(za.CATALOG) >= 15 and len({c["id"] for c in za.CATALOG}) == len(za.CATALOG)
    for c in za.CATALOG:
        assert c["severity"] in za.SEVERITIES and c["title"] and c["scope"] and len(c["checks"]) >= 60, c["id"]
        assert c["title"][0].isupper() and c["title"][1:] == c["title"][1:] and not c["title"].endswith(".")
    implemented = set(za._TEMPLATES) | set(za._PRODUCED_BY)
    assert implemented == {c["id"] for c in za.CATALOG}


def test_every_template_fires_on_the_messy_tenant(messy_out):
    fired = {f["template"] for f in messy_out["findings"]}
    # AP-07 needs no access rules and IN-01 no INSPECT rule at all: each has its own test.
    missing = {c["id"] for c in za.CATALOG} - fired - {"ZPA-AP-07", "ZPA-IN-01"}
    assert not missing, f"templates never exercised: {missing}"
    for f in messy_out["findings"]:
        assert set(f) >= {"template", "severity", "object", "reason", "fix"}
        assert f["reason"].endswith(".") and f["fix"].endswith(".") and f["reason"][0].isupper()
        assert f["reason"].count(". ") <= 1, f"one plain sentence: {f['reason']}"
    counts = messy_out["counts"]
    assert counts["total"] == len(messy_out["findings"]) == sum(counts["by_severity"].values())
    assert counts["templates"] == len(za.CATALOG) and counts["assessed"] == len(za.CATALOG)


def test_no_access_rules_is_said_once_not_per_segment():
    data = messy()
    data["policies"]["access"] = []
    out = za.analyze(read(data), now=NOW)
    assert len(_by(out, "ZPA-AP-07")) == 1 and not _by(out, "ZPA-AS-01") and not _by(out, "ZPA-AP-05")


def test_the_clean_tenant_has_no_finding_at_all():
    out = za.analyze(read(clean()), now=NOW)
    assert out["findings"] == [], [(f["template"], f["reason"]) for f in out["findings"]]
    assert all(c["status"] == "clean" for c in out["catalog"])


def test_unreachable_rules_name_the_rule_that_matches_first(messy_out):
    sh = {f["object"]: f for f in _by(messy_out, "ZPA-AP-01")}
    assert set(sh) == {"Engineering to Git with posture", "Block engineering from Jira"}
    assert sh["Engineering to Git with posture"]["severity"] == "medium", "same action: redundant"
    assert sh["Block engineering from Jira"]["severity"] == "high", "opposite action: the deny never happens"
    assert sh["Block engineering from Jira"]["shadowed_by"] == "Engineering to Git"


def _ix(rules, data=None):
    d = copy.deepcopy(data or messy())
    d["policies"]["access"] = rules
    snap = read(d)
    return snap, za._Index(snap)


@pytest.mark.parametrize("a,b", [
    # A needs posture, B does not force it.
    (_rule("a", 1, "A", "ALLOW", _cond(GRP("sg-eng")), _cond(_op("POSTURE", "udid-1", "true"))), _rule("b", 2, "B", "DENY", _cond(APP("s-git")))),
    # B reaches an app A does not.
    (_rule("a", 1, "A", "ALLOW", _cond(APP("s-git"))), _rule("b", 2, "B", "DENY", _cond(APP("s-git"), APP("s-jira")))),
    # Rule-level OR: not compared.
    (_rule("a", 1, "A", "ALLOW", _cond(APP("s-git")), _cond(SCIM("g-eng")), operator="OR"), _rule("b", 2, "B", "DENY", _cond(APP("s-git")), _cond(SCIM("g-eng")))),
    # A negated condition B does not carry identically.
    (_rule("a", 1, "A", "ALLOW", _cond(SCIM("g-con"), negated=True)), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")))),
    # A disabled.
    (_rule("a", 1, "A", "ALLOW", disabled=True), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")))),
    # Different microtenants.
    (_rule("a", 1, "A", "ALLOW", microtenantId="m1"), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")), microtenantId="m2")),
    # B's OR condition is wider than A's.
    (_rule("a", 1, "A", "ALLOW", _cond(SCIM("g-eng"))), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng"), SCIM("g-con")))),
    # An app condition mixed with a user operand: not a comparable shape.
    (_rule("a", 1, "A", "ALLOW", _cond(APP("s-git"), SCIM("g-eng"))), _rule("b", 2, "B", "DENY", _cond(APP("s-git")), _cond(SCIM("g-eng")))),
    # Unknown action: not terminal.
    (_rule("a", 1, "A", "SOMETHING_NEW"), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")))),
    # A names the segment group B's app is NOT in.
    (_rule("a", 1, "A", "ALLOW", _cond(GRP("sg-fin"))), _rule("b", 2, "B", "DENY", _cond(APP("s-git")))),
])
def test_anything_that_cannot_be_compared_is_not_shadowed(a, b):
    snap, ix = _ix([a, b])
    rules = snap["policies"]["access"]
    assert not za.shadows(rules[0], rules[1], ix)
    assert not _by(za.analyze(snap, now=NOW), "ZPA-AP-01")


@pytest.mark.parametrize("a,b", [
    (_rule("a", 1, "A", "ALLOW"), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")))),
    (_rule("a", 1, "A", "ALLOW", _cond(SCIM("g-eng"), SCIM("g-con"))), _rule("b", 2, "B", "DENY", _cond(SCIM("g-eng")), _cond(ZAPP))),
    (_rule("a", 1, "A", "ALLOW", _cond(GRP("sg-eng"))), _rule("b", 2, "B", "DENY", _cond(APP("s-git"), APP("s-jira")))),
    (_rule("a", 1, "A", "DENY", _cond(SCIM("g-eng"), SCIM("g-con"), operator="AND")), _rule("b", 2, "B", "DENY", _cond(SCIM("g-con"), SCIM("g-eng"), operator="AND"))),
    (_rule("a", 1, "A", "ALLOW", _cond(SCIM("g-con"), negated=True)), _rule("b", 2, "B", "ALLOW", _cond(SCIM("g-con"), negated=True), _cond(ZAPP))),
])
def test_a_provable_superset_shadows(a, b):
    snap, ix = _ix([a, b])
    rules = snap["policies"]["access"]
    assert za.shadows(rules[0], rules[1], ix)


def test_dangling_disabled_and_idp_findings_name_the_objects(messy_out):
    d = _by(messy_out, "ZPA-AP-02")
    assert [f["object"] for f in d] == ["Dangling"]
    assert "s-gone" in d[0]["reason"] and "udid-gone" in d[0]["reason"] and "Old apps" in d[0]["reason"] and "disabled" in d[0]["reason"]
    i = _by(messy_out, "ZPA-AP-03")
    assert [f["object"] for f in i] == ["Sales via SAML"] and "Old ADFS is disabled" in i[0]["reason"]


def test_access_policy_shape_findings(messy_out):
    assert [f["object"] for f in _by(messy_out, "ZPA-AP-04")] == ["Wildcard for all"] and _by(messy_out, "ZPA-AP-04")[0]["severity"] == "medium"
    assert "Contractors deny" in _by(messy_out, "ZPA-AP-05")[0]["reason"]
    nc = {f["object"]: f for f in _by(messy_out, "ZPA-AP-06")}
    assert set(nc) == {"Reauth everyone", "Bypass all"}, "the default rule is never reported"
    assert nc["Bypass all"]["severity"] == "medium" and nc["Reauth everyone"]["severity"] == "low"
    assert "2 rules below it" in nc["Reauth everyone"]["reason"]
    data = messy()
    data["policies"]["access"].insert(0, _rule("r0", 0, "Everyone everything", "ALLOW"))
    out = za.analyze(read(data), now=NOW)
    assert [(f["object"], f["severity"]) for f in _by(out, "ZPA-AP-04") if f["object"] == "Everyone everything"] == [("Everyone everything", "high")]


def test_segment_findings(messy_out):
    names = lambda tid: sorted(f["object"] for f in _by(messy_out, tid))  # noqa: E731
    assert names("ZPA-AS-01") == ["Unused app"]
    assert names("ZPA-AS-02") == ["Payroll"]
    assert names("ZPA-AS-03") == ["Git servers / Git mirror"] or names("ZPA-AS-03") == ["Git mirror / Git servers"]
    broad = _by(messy_out, "ZPA-AS-04")
    assert [f["object"] for f in broad] == ["Everything dot com"] and broad[0]["severity"] == "high" and "10.0.0.0/8" in broad[0]["reason"]
    ports = {f["object"]: f["severity"] for f in _by(messy_out, "ZPA-AS-05")}
    assert ports == {"Everything dot com": "medium", "Wide ports": "low"}
    byp = {f["object"]: f["severity"] for f in _by(messy_out, "ZPA-AS-06")}
    assert byp == {"Everything dot com": "high", "Intranet": "low"}
    assert names("ZPA-AS-07") == ["RDP jump hosts"]
    assert names("ZPA-AS-08") == ["Orphan app"]
    insp = names("ZPA-AS-09")
    assert "Payroll" in insp and "Git servers" not in insp and "RDP jump hosts" not in insp
    assert names("ZPA-AS-10") == ["Corp wildcard", "Everything dot com"]


def test_group_server_connector_and_edge_findings(messy_out):
    sg = {f["object"]: f["severity"] for f in _by(messy_out, "ZPA-SG-01")}
    assert sg == {"Old apps": "medium", "Empty group": "low"}
    assert [f["object"] for f in _by(messy_out, "ZPA-SV-01")] == ["Static servers"]
    assert [f["object"] for f in _by(messy_out, "ZPA-SV-02")] == ["No connectors"]
    cg1 = {f["object"]: f["severity"] for f in _by(messy_out, "ZPA-CG-01")}
    assert cg1 == {"Empty connectors": "high", "Spare connectors": "low"}
    assert [f["object"] for f in _by(messy_out, "ZPA-CG-02")] == ["DC2 connectors"]
    assert [f["object"] for f in _by(messy_out, "ZPA-CG-03")] == ["DC2 connectors"]
    v = _by(messy_out, "ZPA-CG-04")
    assert [f["object"] for f in v] == ["Branch connectors"] and "23.9.4" in v[0]["reason"] and "branch-b" in v[0]["reason"]
    st = _by(messy_out, "ZPA-AC-01")
    assert [f["object"] for f in st] == ["dc2-a"] and "30 days ago" in st[0]["reason"]
    assert [f["object"] for f in _by(messy_out, "ZPA-SE-01")] == ["Branch PSE"]


def test_findings_are_sorted_most_severe_first(messy_out):
    ranks = [za.SEV_RANK[f["severity"]] for f in messy_out["findings"]]
    assert ranks == sorted(ranks)


# ── diagnostics ───────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def snap():
    return read()


ENG = {"scim_groups": ["Engineering"], "client_type": "zpn_client_type_zapp", "posture_pass": ["Corp device"]}


def test_the_most_specific_segment_wins(snap):
    d = za.diagnose(snap, ENG, "git.corp.example", 22)
    assert d["segment"]["match"]["name"] == "Git servers", "exact FQDN beats *.corp.example; port 22 only in Git servers"
    assert [c["name"] for c in d["segment"]["candidates"]] == ["Git servers", "Corp wildcard"] or d["segment"]["candidates"][0]["name"] == "Git servers"
    w = za.diagnose(snap, ENG, "https://wiki.corp.example/page")
    assert w["destination"]["port"] == 443 and not w["destination"]["port_assumed"]
    assert w["segment"]["match"]["name"] == "Corp wildcard"
    ip = za.diagnose(snap, ENG, "10.20.30.7", 3389)
    assert ip["segment"]["match"]["name"] == "RDP jump hosts", "a /24 beats the /8"


def test_equal_matches_are_reported_as_ambiguous(snap):
    d = za.diagnose(snap, ENG, "git.corp.example", 443)
    assert d["segment"]["ambiguous"] and "ambiguous" in d["hops"][1]["detail"]


def test_a_port_outside_every_segment_is_not_carried_by_zpa(snap):
    d = za.diagnose(snap, ENG, "jira.corp.example", 8080)
    assert d["verdict"]["outcome"] == "not_zpa"
    assert "Jira" in d["verdict"]["summary"] and "not this port" in d["verdict"]["summary"]
    assert za.diagnose(snap, {}, "example.org", 443)["verdict"]["outcome"] == "not_zpa"


def test_the_first_matching_rule_decides_with_every_earlier_rule_explained(snap):
    d = za.diagnose(snap, ENG, "jira.corp.example", 443)
    v = d["verdict"]
    assert v["outcome"] == "allowed" and v["rule"] == "Engineering to Git"
    assert d["access"]["evaluated"][-1]["name"] == "Engineering to Git" and len(d["access"]["evaluated"]) == 1
    sales = {"scim_groups": [], "saml": "Department=Sales", "client_type": "zpn_client_type_zapp", "posture_pass": []}
    s = za.diagnose(snap, sales, "jira.corp.example", 443)
    ev = {w["name"]: w for w in s["access"]["evaluated"]}
    assert s["verdict"]["rule"] == "Sales via SAML" and s["verdict"]["outcome"] == "allowed"
    assert ev["Engineering to Git"]["status"] == "not_matched" and "SCIM group Engineering" in ev["Engineering to Git"]["why"]
    assert ev["Engineering to Git with posture"]["status"] == "not_matched" and "app segment Git servers" in ev["Engineering to Git with posture"]["why"]
    assert ev["Block engineering from Jira"]["status"] == "not_matched"
    assert ev["Payroll deny"]["why"].startswith("It applies to app segment Payroll")
    assert "Allowed by access rule \"Sales via SAML\"" in s["verdict"]["headline"] and "Jira" in s["verdict"]["headline"]


def test_unknown_facts_make_a_rule_conditional_not_a_match(snap):
    d = za.diagnose(snap, {}, "jira.corp.example", 443)
    first = d["access"]["evaluated"][0]
    assert first["status"] == "conditional" and "SCIM groups" in first["depends_on"] and "client type" in first["depends_on"]
    assert d["verdict"]["outcome"] == "conditional" and d["verdict"]["headline"].startswith("Depends on the user")
    assert any("Left as any" in a for a in d["assumptions"])


def test_a_deny_rule_and_the_default_deny(snap):
    con = {"scim_groups": ["Contractors"], "client_type": "zpn_client_type_zapp", "posture_pass": [], "saml": "Department=Engineering"}
    d = za.diagnose(snap, con, "payroll.corp.example", 443)
    assert d["verdict"]["outcome"] == "denied" and d["verdict"]["rule"] == "Payroll deny"
    nobody = {"scim_groups": [], "client_type": "zpn_client_type_zapp", "posture_pass": [], "saml": "Department=Ops"}
    d = za.diagnose(snap, nobody, "jira.corp.example", 443)
    assert d["verdict"]["outcome"] == "denied" and d["access"]["decision"] == "default_deny" and "by default" in d["verdict"]["headline"]
    assert [w["status"] for w in d["access"]["evaluated"] if w["name"] == "Old allow all"] == ["disabled"]


def test_server_and_connector_hops_and_an_unreachable_allow(snap):
    d = za.diagnose(snap, ENG, "jira.corp.example", 443)
    keys = [h["key"] for h in d["hops"]]
    assert keys == ["user", "segment", "segment_group", "access", "server_groups", "connectors", "business_continuity"]
    assert "DC1 connectors" in d["hops"][-1]["detail"] and "2 of 2 connected" in d["hops"][-1]["detail"]
    data = messy()
    for c in data["connectors"]:
        c["controlChannelStatus"] = "ZPN_STATUS_DISCONNECTED"
    d = za.diagnose(read(data), ENG, "jira.corp.example", 443)
    assert d["verdict"]["outcome"] == "unreachable" and "no App Connector" in d["verdict"]["headline"]
    orphan = za.diagnose(snap, {}, "orphan.corp.example", 443)
    assert orphan["verdict"]["outcome"] == "unreachable" and orphan["serving"]["sg_status"] == "blocked"


def test_bypass_always_is_said_first(snap):
    d = za.diagnose(snap, {}, "shop.example.com", 443)
    assert d["verdict"]["outcome"] == "bypassed" and "ALWAYS" in d["verdict"]["headline"]


def test_other_policies_report_their_first_match(snap):
    d = za.diagnose(snap, ENG, "jira.corp.example", 443)
    o = d["other_policies"]
    assert o["timeout"]["rule"]["name"] == "Reauth everyone" and o["client_forwarding"]["rule"]["name"] == "Bypass all"
    assert o["inspection"]["rule"]["name"] == "Inspect engineering" and o["isolation"]["rule"] is None


@pytest.mark.parametrize("dest,port,proto", [("", None, "tcp"), ("not a host!", None, "tcp"), ("git.corp.example", 70000, "tcp"),
                                             ("git.corp.example", "x", "tcp"), ("git.corp.example", 443, "icmp")])
def test_bad_destinations_are_refused_in_words(snap, dest, port, proto):
    with pytest.raises(ValueError):
        za.diagnose(snap, {}, dest, port, proto)


# ── the API ───────────────────────────────────────────────────────────
@pytest.fixture
def api(monkeypatch):
    import dlp_api_server as srv
    built = []
    tenant = FakeTenant()

    def build(creds):
        built.append(dict(creds))
        return tenant
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(zr, "PACE_SECONDS", 0)
    return srv, TestClient(srv.app), tenant, built


def _wait(t, job, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("body,needle", [
    ({"scopes": ["dlp"], "channels": {}, "from_page": True}, "tick ZPA"),
    ({"scopes": [], "channels": {}, "from_page": True}, "tick ZPA"),
])
def test_refused_before_any_read_unless_zpa_is_in_scope(api, body, needle):
    srv, t, tenant, built = api
    for path, extra in (("/api/zpa/analysis/start", {}), ("/api/zpa/diagnose", {"destination": "git.corp.example"})):
        r = t.post(path, json=dict(CREDS, **body, **extra))
        assert r.status_code == 400 and needle in r.json()["detail"] and "Nothing was read" in r.json()["detail"], r.text
    assert built == [] and tenant.calls == []


def test_refused_before_sign_in_without_oneapi_or_customer_id(api, monkeypatch):
    srv, t, tenant, built = api
    monkeypatch.delenv("ZSCALER_CUSTOMER_ID", raising=False)
    r = t.post("/api/zpa/analysis/start", json=dict(CREDS, customer_id="", **ZPA_SCOPE))
    assert r.status_code == 400 and "customer ID" in r.json()["detail"]
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "k" * 12, "customer_id": "123"}
    r = t.post("/api/zpa/analysis/start", json=dict(legacy, **ZPA_SCOPE))
    assert r.status_code == 400 and "OneAPI" in r.json()["detail"]
    assert built == [] and tenant.calls == []


def test_the_analysis_job_returns_findings_catalog_and_counts_and_a_second_question_reads_nothing(api):
    srv, t, tenant, built = api
    r = t.post("/api/zpa/analysis/start", json=dict(CREDS, **ZPA_SCOPE), headers={"X-Start-Token": "a" * 32})
    assert r.status_code == 200 and r.json()["kind"] == "zpa"
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done", snap
    res = snap["result"]
    assert built and built[0]["customer_id"] == CREDS["customer_id"]
    assert res["report_id"].startswith("zpa-") and "snapshot" not in res and res["counts"]["total"] == len(res["findings"]) > 15
    assert len(res["catalog"]) == len(za.CATALOG) and res["choices"]["scim_groups"] == ["Contractors", "Engineering"]
    assert any("Reading ZPA application segments" in l for l in res["logs"]) and "secret-secret-secret" not in str(res)
    assert not tenant.writes
    n = len(tenant.calls)
    d = t.post("/api/zpa/diagnose", json=dict(ZPA_SCOPE, report_id=res["report_id"], destination="jira.corp.example", port="443", user=ENG))
    assert d.status_code == 200 and d.json()["status"] == "done", d.text
    assert d.json()["result"]["verdict"]["rule"] == "Engineering to Git" and len(tenant.calls) == n, "no new read"
    # Reports and exports
    g = t.get(f"/api/zpa/report/{res['report_id']}")
    assert g.status_code == 200 and "snapshot" not in g.json()
    c = t.get(f"/api/zpa/report/{res['report_id']}/export?format=csv&severity=high")
    rows = list(csv.DictReader(io.StringIO(c.text)))
    assert c.status_code == 200 and rows and {x["severity"] for x in rows} == {"high"} and "attachment" in c.headers["content-disposition"]
    j = t.get(f"/api/zpa/report/{res['report_id']}/export?format=json").json()
    assert j["counts"] == res["counts"] and len(j["catalog"]) == len(za.CATALOG)
    assert t.get("/api/zpa/report/zpa-nope").status_code == 404


def test_a_diagnosis_without_a_read_reads_first_as_a_job(api):
    srv, t, tenant, built = api
    r = t.post("/api/zpa/diagnose", json=dict(CREDS, **ZPA_SCOPE, destination="payroll.corp.example:443",
                                              user={"scim_groups": ["Contractors"], "client_type": "zpn_client_type_zapp"}))
    assert r.status_code == 200 and "job_id" in r.json()
    snap = _wait(t, r.json()["job_id"])
    res = snap["result"]
    assert res["diagnosis"]["verdict"]["outcome"] == "denied" and res["diagnosis"]["report_id"] == res["report_id"]
    bad = t.post("/api/zpa/diagnose", json=dict(CREDS, **ZPA_SCOPE, destination="bad host!"))
    assert bad.status_code == 400


def test_stop_ends_the_job_as_stopped_with_nothing_more_read_and_nothing_kept(api, monkeypatch):
    srv, t, tenant, built = api
    gate, entered = threading.Event(), threading.Event()

    def hook(svc, method, args):
        if svc == "server_groups":
            entered.set()
            gate.wait(10)
    tenant.hook = hook
    before = {k for k in srv._REPORTS if k.startswith("zpa-")}
    r = t.post("/api/zpa/analysis/start", json=dict(CREDS, **ZPA_SCOPE))
    job = r.json()["job_id"]
    assert entered.wait(10)
    assert t.post(f"/api/dlp-packs/jobs/{job}/cancel").status_code == 200
    n = len(tenant.calls)
    gate.set()
    snap = _wait(t, job)
    assert snap["status"] == "cancelled", snap
    res = snap["result"] or {}
    assert res.get("stopped") and "findings" not in res and "report_id" not in res
    assert len(tenant.calls) == n, f"reads after Stop: {tenant.calls[n:]}"
    assert any("nothing more is read" in l for l in snap["logs"])
    assert {k for k in srv._REPORTS if k.startswith("zpa-")} == before


def test_csv_cells_are_formula_safe(api):
    srv, t, tenant, built = api
    tenant.data["segments"][0]["name"] = "=HYPERLINK(\"http://x\")"
    tenant.data["segments"][0]["bypassType"] = "ALWAYS"
    r = t.post("/api/zpa/analysis/start", json=dict(CREDS, **ZPA_SCOPE))
    res = _wait(t, r.json()["job_id"])["result"]
    text = t.get(f"/api/zpa/report/{res['report_id']}/export?format=csv").text
    for row in csv.reader(io.StringIO(text)):
        for cell in row:
            assert not re.match(r"^[=+\-@]", cell), cell


# ── the page ──────────────────────────────────────────────────────────
def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def test_the_page_follows_the_report_page_conventions():
    import dlp_api_server as srv
    html = _read("static", "report_zpa.html")
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html
    assert '<a class="rp-btn" href="/">← Back to the assessment</a>' in html and '<main class="rp-card"' in html
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    assert 'role="tablist"' in html and html.count('<button type="button" role="tab"') == 3 and html.count('<section role="tabpanel"') == 3
    assert 'role="status"' in html and 'aria-live="polite"' in html
    style = html[html.index("<style>"):html.index("</style>")] if "<style>" in html else ""
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style), "colours come from the tokens"
    assert "linear-gradient" not in style and "box-shadow" not in style
    assert "/api/dlp-packs/jobs/stop-before-start" in html and "'X-Start-Token': startToken" in html
    assert "/api/zpa/analysis/start" in html and "/api/zpa/diagnose" in html and "/export?format=csv" in html
    c = TestClient(srv.app)
    r = c.get("/report/zpa")
    assert r.status_code == 200 and "ZPA analysis" in r.text and "no-cache" in r.headers["cache-control"]


def test_the_page_is_explained_and_on_the_toolbar():
    js = _read("static", "explain.js")
    assert "  X.zpa = {" in js and js.index("  X.zpa = {") < js.index("  X.path = {")
    assert "'/report/zpa': 'zpa'" in js and "'zpa'" in js[js.index("DLP_EXPLAIN_ORDER"):]
    block = js[js.index("  X.zpa = {"):]
    assert "group: 'Find the gaps', name: 'ZPA analysis'" in block[:200]
    html = _read("static", "index.html")
    assert html.index('onclick="openZpaTab()"') < html.index('onclick="openPathAnalyzerTab()"')
    assert "function openZpaTab()" in html
    assert "ZPA analysis" in _read("docs", "OVERVIEW.md")
