"""Export from tenant as Terraform (the whole tenant): every object type the
catalogue names is read through the installed SDK's own call from an
offline fixture tenant (no network), written as the provider's resource
with an import block, references by Terraform address or lookup by name,
`terraform fmt`-clean, and with no secret in any file. Out-of-scope reads
are refused before sign-in."""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import time
import zipfile

import pytest

import offline_tenant as ot
import tenant_terraform as tt

ALL_SCOPES = ["dlp", "zia_extras", "zpa", "ztw"]
ALL_CHANNELS = {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}
CANARIES = ("CANARY-PSK-7f3a9", "CANARY-PASSWORD-b81c", "CANARY-PASSPHRASE-55e2", "CANARY-PRIVKEY-0d4e", "CANARY-TOKEN-a9c1",
            "CANARY-PROVKEY-3b6f", "CANARY-APIKEY-c7d0", "CANARY-FILEPW-91aa")


# ---------------------------------------------------------------------------
# The fixture tenant: one object per type, made from the provider schema
# ---------------------------------------------------------------------------

def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


# Arguments the API answers as one object, not a list of objects.
SINGLE = {"action", "template", "account_details", "prov_url_data", "common_apps_dto", "system_proxy_data", "partner_info",
          "config", "user_experience", "security_controls", "debug_mode", "forward_to_zia", "deep_link", "watermark",
          "auto_scale_details", "decrypt_sub_actions", "do_not_decrypt_sub_actions", "ssl_interception_cert"}


def _value(attr: str, kind: str, sub, n: int):
    """A made-up API value for one argument, in the API's own (camelCase) form."""
    if kind == "s":
        return f"v-{attr}-{n}"
    if kind == "n":
        return 7
    if kind == "f":
        return 1.5
    if kind == "b":
        return True
    if kind == "ls":
        return [f"a-{attr}-{n}"]
    if kind == "ln":
        return [5]
    if kind == "ids":
        return [{"id": 101, "name": f"Ref {attr} {n}"}]
    if kind == "sids":
        return [{"id": "201", "name": f"Ref {attr} {n}"}]
    if kind == "idb":
        return {"id": 301} if attr in SINGLE else [{"id": 301}]
    if kind == "sidb":
        return [{"id": "401"}]
    if kind == "extid":
        return [{"externalId": "e-501", "name": "Segment 501"}]
    if kind == "secret":
        return "CANARY-PASSWORD-b81c"
    if kind == "blk":
        obj = {_camel(a): _value(a, k, s, n) for a, k, _r, s in sub}
        return obj if attr in SINGLE else [obj]
    raise AssertionError(kind)


class _Probe(ot.OfflineStore):
    """A tenant with nothing in it (every list empty) that records every path asked for."""

    def __init__(self):
        super().__init__("snap-" + "0" * 16, "snapshot", {}, {"tenant_label": "probe"})
        self.asked = []

    def answer_get(self, url, params=None):
        self.asked.append(ot.normalize_path(url))
        return 200, []


def paths_of(t):
    """The GET paths the SDK's call for this type sends (recorded, not assumed)."""
    st = _Probe()
    tt.read_type(ot.OfflineSdkClient(st, ot.creds_for(st)), t)
    assert st.asked, f"{t['key']}: the SDK call sent no request"
    return st.asked


def fixture_row(t, n: int = 1):
    row = {"id": 9000 + n if t["product"] != "zpa" else str(9000 + n)}
    for attr, kind, _req, sub in tt.schema_of(t["resource"]):
        row[_camel(attr)] = _value(attr, kind, sub, n)
    row[_camel(t["name"])] = f"Fixture {t['label']} {n}"
    if t["resource"] in ("zpa_application_segment_pra",):
        row["commonAppsDto"]["appsConfig"][0]["appTypes"] = ["SECURE_REMOTE_ACCESS"]
    if t["resource"] in ("zpa_application_segment_inspection",):
        row["commonAppsDto"]["appsConfig"][0]["appTypes"] = ["INSPECT"]
    if t["key"] == "ztc.forwarding_gateways":
        row["type"] = "ZIA"
    if t["hook"] == "policy_v2":
        row["conditions"] = [{"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": "777"},
                                                             {"objectType": "SAML", "lhs": "12", "rhs": "Finance"}]}]
    if t["key"] == "zia.dlp_engines":
        row["engineExpression"] = "((D61.S > 1))"
    # secrets the tenant would hold: never to be written
    row.update({"preSharedKey": CANARIES[0], "password": CANARIES[1], "passphrase": CANARIES[2], "privateKey": CANARIES[3],
                "authenticationToken": CANARIES[4], "provisioningKey": CANARIES[5], "apiKey": CANARIES[6]})
    return row


def store_for(types, rows_per_type=1, extra=None):
    """An offline snapshot holding `rows_per_type` fixture objects of each type,
    under the path the installed SDK asks for."""
    responses = {}
    for t in types:
        paths = paths_of(t)
        rows = [fixture_row(t, n) for n in range(1, rows_per_type + 1)]
        if t["key"] == "zia.cloud_app_control_rules":
            for r in rows:
                r["type"] = "AI_ML"
        def wrap(items):
            if t["product"] == "zpa":
                return {"totalPages": "1", "list": items}
            if t["key"] == "zcc.trusted_networks":
                return {"trustedNetworkContracts": items}
            return items
        body = rows[0] if t["singleton"] and not t["method"].startswith("list") else wrap(rows)
        responses[paths[0]] = {"status": 200, "body": body}
        for extra_path in paths[1:]:   # the other lists of the same type (other rule types, the other key type) are empty
            responses.setdefault(extra_path, {"status": 200, "body": body if t["singleton"] and not t["method"].startswith("list") else wrap([])})
    responses.update(extra or {})
    st = ot.OfflineStore("snap-" + "1" * 16, "snapshot", responses, {"tenant_label": "Fixture tenant"})
    return ot.OfflineSdkClient(st, ot.creds_for(st))


def run(client, keys, opts=None, plan_info=None):
    opts = opts or tt.normalize_options(None)
    snap = tt.read_tenant(client, keys)
    files, rep = tt.generate(snap, opts, tenant_label="Fixture tenant", plan_info=plan_info, generated_at="2026-10-31T00:00:00Z")
    return files, rep, snap


def resource_block(files, resource, label=None):
    text = "\n".join(c for p, c in files.items() if p.endswith(".tf"))
    m = re.search(r'resource "%s" "%s" \{\n(.*?)\n\}\n' % (re.escape(resource), label or r"[a-z0-9_]+"), text, re.S)
    assert m, f"no {resource} resource in the workspace"
    return m.group(1)


# ---------------------------------------------------------------------------
# Per-resource-type oracle
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [t["key"] for t in tt.TYPES])
def test_every_type_is_read_through_the_sdk_and_written_as_its_resource(key):
    """ASVS V5.3.1 · CWE-116 · WSTG-INPV-11: each object type is read with the SDK's call and written with every argument it holds."""
    t = tt.BY_KEY[key]
    client = store_for([t])
    files, rep, snap = run(client, [key])
    assert not snap["unread"], snap["unread"]
    assert rep["products"][t["product"]]["resources"] == {t["resource"]: 1}, rep["products"][t["product"]]
    block = resource_block(files, t["resource"])
    for attr, kind, _req, _sub in tt.schema_of(t["resource"]):
        if kind == "secret":
            assert re.search(rf"\n?\s*{attr}\s+= lookup\(var\.{t['secrets'][attr]}, ", block), f"{key}.{attr} is a variable"
        elif attr == "microtenant_id" and kind == "s":
            assert f"{attr} " in block
        else:
            assert re.search(rf"(^|\n)\s*{attr}\s+(=|\{{)", block), f"{key}: {attr} not written"
    imports = files[f"{tt.ROOT_DIR}/{t['product']}/imports.tf"]
    expected_id = t["import_id"] or t["import_fmt"].format(id=snap["types"][key][0]["id"], type=snap["types"][key][0].get("type", ""))
    assert re.search(r"import \{\n  to = %s\.[a-z0-9_]+\n  id = \"%s\"\n\}" % (t["resource"], re.escape(expected_id)), imports), imports
    every = "\n".join(files.values())
    assert not any(c in every for c in CANARIES), "a secret reached the workspace"


def test_the_catalogue_covers_the_three_providers_as_promised():
    """ASVS V1.14.1 · CWE-1059 · WSTG-INFO-02: ZIA, ZPA and Cloud & Branch Connector resource types are all covered."""
    cat = tt.catalogue()["products"]
    assert len(cat["zia"]) >= 49 and len(cat["zpa"]) >= 30 and len(cat["ztc"]) >= 10
    assert len({t["resource"] for t in tt.TYPES}) == len(tt.TYPES), "one resource type per catalogue entry"
    assert set(tt.SCHEMAS) == {t["resource"] for t in tt.TYPES}
    for t in tt.TYPES:
        assert t["resource"].startswith(t["product"] + "_")


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

def _tenant_with_references():
    zia = "/zia/api/v1"
    body = {
        f"{zia}/ruleLabels": [{"id": 11, "name": "Finance"}],
        f"{zia}/ipDestinationGroups": [{"id": 21, "name": "Payment hosts", "type": "DSTN_FQDN", "addresses": ["pay.example.com"]}],
        f"{zia}/firewallFilteringRules": [
            {"id": 31, "name": "Allow payments", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW",
             "labels": [{"id": 11, "name": "Finance"}], "destIpGroups": [{"id": 21, "name": "Payment hosts"}],
             "groups": [{"id": 41, "name": "Finance Team"}], "users": [{"id": 51, "name": "Avery Quinn"}],
             "nwServices": [{"id": 61, "name": "HTTPS"}]},
            {"id": 32, "name": "Default Firewall Filtering Rule", "order": -1, "defaultRule": True, "action": "ALLOW"}],
        f"{zia}/networkServices": [{"id": 61, "name": "HTTPS", "type": "PREDEFINED"}],
        f"{zia}/dlpDictionaries": [{"id": 61, "name": "Account numbers", "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES",
                                    "patterns": [{"action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": "AC-[0-9]{6}"}]},
                                   {"id": 62, "name": "Credit Cards", "custom": False}],
        f"{zia}/dlpEngines": [{"id": 71, "name": "Accounts", "customDlpEngine": True, "engineExpression": "((D61.S > 1) AND (D62.S > 0))"}],
        "/zpa/mgmtconfig/v1/admin/customers/{customerId}/segmentGroup": {"list": [{"id": "81", "name": "Billing apps", "enabled": True}]},
        "/zpa/mgmtconfig/v1/admin/customers/{customerId}/application": {"list": [
            {"id": "91", "name": "Billing", "segmentGroupId": "81", "domainNames": ["billing.example"], "tcpPortRanges": ["443", "443"],
             "serverGroups": [{"id": "95", "name": "Billing servers"}]}]},
        "/zpa/mgmtconfig/v1/admin/customers/{customerId}/policySet/rules/policyType/ACCESS_POLICY": {"list": [
            {"id": "101", "name": "Finance to billing", "action": "ALLOW",
             "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": "91"},
                                                             {"objectType": "APP_GROUP", "lhs": "id", "rhs": "81"}]},
                            {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "lhs": "7", "rhs": "123"}]}]}]},
    }
    responses = {p: {"status": 200, "body": b} for p, b in body.items()}
    st = ot.OfflineStore("snap-" + "2" * 16, "snapshot", responses, {"tenant_label": "Refs"})
    return ot.OfflineSdkClient(st, ot.creds_for(st))


REF_KEYS = ["zia.rule_labels", "zia.ip_destination_groups", "zia.firewall_rules", "zia.network_services", "zia.dlp_dictionaries",
            "zia.dlp_engines", "zpa.segment_groups", "zpa.application_segments", "zpa.access_rules"]


def test_references_between_exported_objects_are_terraform_addresses():
    """ASVS V5.3.1 · CWE-1188 · WSTG-BUSL-01: a rule names exported objects by address, others by lookup, users by id only."""
    files, rep, _ = run(_tenant_with_references(), REF_KEYS)
    rule = resource_block(files, "zia_firewall_filtering_rule", "allow_payments")
    assert "labels {\n    id = [zia_rule_labels.finance.id]" in rule
    assert "dest_ip_groups {\n    id = [zia_firewall_filtering_destination_groups.payment_hosts.id]" in rule
    assert "groups {\n    id = [data.zia_group_management.finance_team.id]" in rule, "an unexported group is looked up by name"
    assert "nw_services {\n    id = [data.zia_firewall_filtering_network_service.https.id]" in rule, "a predefined service by name"
    assert "users {\n    id = [51]" in rule and "Avery Quinn" not in "\n".join(files.values()), "a user keeps its id; never its name"
    ds = files[f"{tt.ROOT_DIR}/zia/datasource.tf"]
    assert 'data "zia_group_management" "finance_team" {\n  name = "Finance Team"\n}' in ds
    eng = resource_block(files, "zia_dlp_engines", "accounts")
    assert ('engine_expression = "((D${zia_dlp_dictionaries.account_numbers.id}.S > 1) AND '
            '(D${data.zia_dlp_dictionaries.credit_cards.id}.S > 0))"') in eng
    seg = resource_block(files, "zpa_application_segment", "billing")
    assert "segment_group_id = zpa_segment_group.billing_apps.id" in seg
    assert "server_groups {\n    id = [data.zpa_server_group.billing_servers.id]" in seg, "an unexported server group is looked up by name"
    pol = resource_block(files, "zpa_policy_access_rule_v2", "finance_to_billing")
    assert "values      = [zpa_application_segment.billing.id]" in pol and "values      = [zpa_segment_group.billing_apps.id]" in pol
    assert 'entry_values {\n        rhs = "123"\n        lhs = "7"' in pol, "a SCIM group operand keeps lhs / rhs"
    zia = rep["products"]["zia"]
    assert zia["references"]["resource"] >= 3 and zia["references"]["data"] >= 3
    assert "Default Firewall Filtering Rule" not in resource_block(files, "zia_firewall_filtering_rule"), "the default rule is not exported"
    assert any("Default Firewall Filtering Rule" in s["what"] for s in zia["skipped"])
    # every address used is a resource or data source the workspace declares
    for product in ("zia", "zpa"):
        text = "\n".join(c for p, c in files.items() if p.startswith(f"{tt.ROOT_DIR}/{product}/") and p.endswith(".tf"))
        declared = set(re.findall(r'^resource "([a-z0-9_]+)" "([a-z0-9_]+)"', text, re.M))
        data = set(re.findall(r'^data "([a-z0-9_]+)" "([a-z0-9_]+)"', text, re.M))
        for res, lab in re.findall(r"(?<![\w.])((?:zia|zpa|ztc)_[a-z0-9_]+)\.([a-z0-9_]+)\.(?:id|vpn_id)\b", text):
            assert (res, lab) in declared, f"{res}.{lab} is not declared"
        for res, lab in re.findall(r"\bdata\.([a-z0-9_]+)\.([a-z0-9_]+)\.id\b", text):
            assert (res, lab) in data, f"data.{res}.{lab} is not declared"


def test_import_blocks_adopt_every_exported_object():
    """ASVS V1.14.2 · CWE-665 · WSTG-CONF-02: every resource has exactly one import block with its tenant id."""
    files, rep, _ = run(_tenant_with_references(), REF_KEYS)
    for product in ("zia", "zpa"):
        text = "\n".join(c for p, c in files.items() if p.startswith(f"{tt.ROOT_DIR}/{product}/") and p.endswith(".tf") and "imports.tf" not in p)
        res = set(re.findall(r'^resource "([a-z0-9_]+)" "([a-z0-9_]+)"', text, re.M))
        imp = re.findall(r"import \{\n  to = ([a-z0-9_]+)\.([a-z0-9_]+)\n  id = \"([^\"]+)\"\n\}", files[f"{tt.ROOT_DIR}/{product}/imports.tf"])
        assert {(a, b) for a, b, _ in imp} == res and len(imp) == len(res)
    assert ("zia_firewall_filtering_rule", "allow_payments", "31") in imp_all(files)
    assert ("zpa_policy_access_rule_v2", "finance_to_billing", "101") in imp_all(files)
    assert 'required_version = ">= 1.5.0"' in files[f"{tt.ROOT_DIR}/zia/terraform.tf"]


def imp_all(files):
    return {tuple(m) for p, c in files.items() if p.endswith("imports.tf")
            for m in re.findall(r"to = ([a-z0-9_]+)\.([a-z0-9_]+)\n  id = \"([^\"]+)\"", c)}


# ---------------------------------------------------------------------------
# Secrets, untrusted strings, layout
# ---------------------------------------------------------------------------

def test_no_secret_reaches_any_file_and_secrets_become_sensitive_variables():
    """ASVS V8.3.4 · CWE-312 · WSTG-ATHN-07: pre-shared keys, passwords, keys and tokens never reach the zip; they are sensitive variables."""
    keys = ["zia.vpn_credentials", "zpa.pra_credentials", "zpa.provisioning_keys", "zpa.cbi_profiles", "zia.locations"]
    client = store_for([tt.BY_KEY[k] for k in keys], rows_per_type=2)
    files, rep, _ = run(client, keys)
    data = tt.zip_files(files)
    blob = data + b"".join(zipfile.ZipFile(io.BytesIO(data)).read(n) for n in zipfile.ZipFile(io.BytesIO(data)).namelist())
    for c in CANARIES:
        assert c.encode() not in blob, c
    assert "(set)" not in "\n".join(files.values()), "a masked value is never written as a value"
    zv = files[f"{tt.ROOT_DIR}/zia/variables.tf"]
    assert re.search(r'variable "vpn_pre_shared_keys" \{.*?sensitive\s+= true', zv, re.S)
    pv = files[f"{tt.ROOT_DIR}/zpa/variables.tf"]
    for var in ("pra_credential_passwords", "pra_credential_passphrases", "pra_credential_private_keys", "cbi_debug_file_passwords"):
        assert re.search(r'variable "%s" \{\n  description = "[^"]+"\n  type\s+= map\(string\)\n  default\s+= \{\}\n  nullable\s+= false\n  sensitive\s+= true' % var, pv), var
    for path in (f"{tt.ROOT_DIR}/zia/variables.tf", f"{tt.ROOT_DIR}/zpa/variables.tf"):
        for block in re.findall(r'variable "[^"]+" \{.*?\n\}', files[path], re.S):
            assert "description" in block and "type" in block, block
        assert re.search(r'variable "zscaler_client_secret" \{[^}]*sensitive\s+= true', files[path])
    assert "provisioning_key " not in resource_block(files, "zpa_provisioning_key"), "the key ZPA generates is never written"


def test_tenant_strings_cannot_inject_hcl():
    """ASVS V5.3.1 · CWE-94 · WSTG-INPV-11: a name or description with quotes, ${, %{ or line breaks stays a plain string."""
    evil = 'x" \n}\nresource "null_resource" "p" { provisioner "local-exec" { command = "id" } }\n${file("/etc/passwd")} %{ if true }'
    responses = {"/zia/api/v1/ruleLabels": {"status": 200, "body": [{"id": 1, "name": evil, "description": evil}]}}
    st = ot.OfflineStore("snap-" + "3" * 16, "snapshot", responses, {"tenant_label": "Evil"})
    files, _rep, _ = run(ot.OfflineSdkClient(st, ot.creds_for(st)), ["zia.rule_labels"])
    text = files[f"{tt.ROOT_DIR}/zia/objects.tf"]
    assert re.findall(r'^resource "([a-z_]+)"', text, re.M) == ["zia_rule_labels"], "only the label is a resource"
    assert not re.search(r"^\s*provisioner", text, re.M) and "$${file(" in text and "%%{ if" in text
    for line in text.split("\n"):
        assert line.startswith(("#", "resource ", "  name ", "  description ", "}")) or line == "", line
    assert all(re.fullmatch(r"tenant-terraform/(README\.md|export_report\.json|(zia|zpa|ztc)/[A-Za-z0-9_.]+)", p) for p in files)


def test_options_prefix_namespace_exclude_and_personal_data():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: export options are validated; prefix, mirror and exclusion apply; personal data is opt-in."""
    for bad in ({"prefix": "Bad-Prefix"}, {"namespace": "https://evil/x"}, {"microtenant_id": "12a"}, {"products": ["zdx"]},
                {"types": ["zia.nope"]}, {"exclude": "zia.locations"}):
        with pytest.raises(tt.ExportRefused):
            tt.normalize_options(**bad)
    opts = tt.normalize_options(["zia"], prefix="acme", namespace="registry.example.com/zscaler", exclude=["zia.locations"])
    p = tt.plan(ALL_SCOPES, ALL_CHANNELS, opts)
    assert "zia.locations" not in p["read"] and "excluded" in p["left_out"]["zia.locations"]
    assert "zia.subscription_alerts" in p["left_out"] and "personal data" in p["left_out"]["zia.subscription_alerts"]
    assert "zia.subscription_alerts" in tt.plan(ALL_SCOPES, ALL_CHANNELS, opts, include_personal=True)["read"]
    assert all(tt.BY_KEY[k]["product"] == "zia" for k in p["read"])
    files, _rep, _ = run(store_for([tt.BY_KEY["zia.rule_labels"]]), ["zia.rule_labels"], opts=opts)
    assert 'resource "zia_rule_labels" "acme_fixture_rule_labels_1"' in files[f"{tt.ROOT_DIR}/zia/objects.tf"]
    assert 'source  = "registry.example.com/zscaler/zia"' in files[f"{tt.ROOT_DIR}/zia/terraform.tf"]


# ---------------------------------------------------------------------------
# Scope rule
# ---------------------------------------------------------------------------

def test_scope_rule_reads_only_what_is_ticked():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: only types the Scope page puts in scope are planned; the rest say why."""
    opts = tt.normalize_options(None)
    p = tt.plan(["zpa"], {}, opts)
    assert p["read"] and all(k.startswith("zpa.") for k in p["read"])
    assert "tick ZIA platform" in p["not_in_scope"]["zia.firewall_dns_rules"]
    assert "Cloud & Branch Connector" in p["not_in_scope"]["ztc.forwarding_rules"]
    p2 = tt.plan(["dlp"], {"web_dlp": "zscaler"}, tt.normalize_options(["zia"]))
    assert "zia.web_dlp_rules" in p2["read"] and "zia.endpoint_dlp_rules" in p2["not_in_scope"]
    assert "zia.dlp_dictionaries" in p2["read"] and "zia.locations" in p2["not_in_scope"]
    with pytest.raises(tt.ExportRefused) as e:
        tt.plan([], {}, opts)
    assert "Nothing was read" in str(e.value)
    with pytest.raises(tt.ExportRefused) as e:
        tt.plan(["zpa"], {}, tt.normalize_options(None, types=["zia.locations", "zpa.segment_groups"]))
    assert "Locations" in str(e.value) and "Nothing was read" in str(e.value)


def _wait(c, job_id, timeout=60):
    since, logs = 0, []
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = c.get(f"/api/dlp-packs/jobs/{job_id}?since={since}").json()
        logs += snap["logs"]
        since = snap["next"]
        if snap["status"] != "running":
            snap["logs"] = logs
            return snap
        time.sleep(0.05)
    raise AssertionError("the job did not finish in time")


def test_route_refuses_out_of_scope_before_sign_in(monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: an export with nothing in scope, or a type not ticked, is a 400 and no client is built."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1))
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "72000000000000001"}
    r = c.post("/api/tenant-terraform/start", json=dict(creds, scopes=[], channels={}, from_page=True))
    assert r.status_code == 400 and "Nothing was read" in r.json()["detail"]
    r = c.post("/api/tenant-terraform/start", json=dict(creds, scopes=["zpa"], from_page=True, types=["zia.firewall_rules"]))
    assert r.status_code == 400 and "Cloud Firewall rules" in r.json()["detail"]
    r = c.post("/api/tenant-terraform/start", json=dict(creds, scopes=["zpa"], from_page=True, prefix="NOT OK"))
    assert r.status_code == 400
    r = c.post("/api/tenant-terraform/start", json=dict(creds, scopes=["zpa"], from_page=True, customer_id="", auth_method="legacy",
                                                        username="admin@acme.example", password="pw-pw-pw-pw", api_key="a" * 12))
    assert r.status_code == 400
    assert not built, "nothing was signed in to"


def test_route_exports_the_sample_tenant_as_a_zip(monkeypatch):
    """ASVS V12.5.1 · CWE-22 · WSTG-BUSL-01: the sample tenant exports as a zip of fmt-clean workspaces with generated paths only."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    st = ot.sample_store(reset=True)
    client = ot.OfflineSdkClient(st, ot.creds_for(st))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "72000000000000001",
            "scopes": ALL_SCOPES, "channels": ALL_CHANNELS, "from_page": True}
    r = c.post("/api/tenant-terraform/start", json=body)
    assert r.status_code == 200 and r.json()["kind"] == "tenant_terraform", r.text
    snap = _wait(c, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    assert "artifact" not in snap["result"]
    assert snap["result"]["products"]["zia"]["resources"] > 20 and snap["result"]["products"]["zpa"]["resources"] > 5
    assert any("Nothing is written to the tenant" in l for l in snap["logs"])
    z = c.get(snap["download"])
    assert z.status_code == 200 and z.headers["content-type"].startswith("application/zip")
    zf = zipfile.ZipFile(io.BytesIO(z.content))
    names = zf.namelist()
    assert "tenant-terraform/zia/imports.tf" in names and "tenant-terraform/zpa/imports.tf" in names
    assert all(not n.startswith("/") and ".." not in n for n in names)
    rep = json.loads(zf.read("tenant-terraform/export_report.json"))
    assert rep["not_exported"], "what was not exported is said, never silent"
    cat = c.get("/api/tenant-terraform/catalogue").json()
    assert set(cat["products"]) == {"zia", "zpa", "ztc", "zcc"}


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform not installed")
def test_the_workspaces_are_terraform_fmt_clean(tmp_path):
    """ASVS V14.1.1 · CWE-1078 · WSTG-CONF-01: every generated .tf file passes `terraform fmt -check`."""
    client = store_for(tt.TYPES)
    files, _rep, _ = run(client, [t["key"] for t in tt.TYPES])
    for path, content in files.items():
        p = tmp_path / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    r = subprocess.run(["terraform", "fmt", "-check", "-recursive", "-diff", str(tmp_path)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"terraform fmt would change: {r.stdout}{r.stderr}"


def test_the_layout_is_fmt_clean_without_terraform():
    """ASVS V14.1.1 · CWE-1078 · WSTG-CONF-01: the generator's own fmt pass changes nothing it wrote (aligned, no trailing space)."""
    from pack_terraform import hcl_fmt
    client = store_for(tt.TYPES)
    files, _rep, _ = run(client, [t["key"] for t in tt.TYPES])
    for path, content in files.items():
        if path.endswith(".tf"):
            assert hcl_fmt(content) == content, path
            assert not re.search(r"[ \t]+\n", content), path


# ---------------------------------------------------------------------------
# Clone mode, Client Connector
# ---------------------------------------------------------------------------

def test_clone_mode_writes_rules_disabled_without_imports_and_leaves_settings_out():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-01: a clone for another tenant has no import blocks, every rule DISABLED and segments off unless asked."""
    keys = ["zia.firewall_rules", "zia.url_filtering_rules", "zpa.application_segments", "zpa.segment_groups", "ztc.forwarding_rules",
            "zia.advanced_settings", "zia.locations"]
    client = store_for([tt.BY_KEY[k] for k in keys])
    opts = tt.normalize_options(None, mode="clone")
    p = tt.plan(ALL_SCOPES, ALL_CHANNELS, opts)
    assert "zia.advanced_settings" in p["left_out"] and "zia.locations" in p["left_out"], "settings and tenant-bound objects stay out"
    read = [k for k in keys if k in p["read"]]
    files, rep, _ = run(client, read, opts=opts, plan_info=p)
    assert not any(path.endswith("imports.tf") for path in files) and rep["mode"] == "clone" and rep["rules_disabled"]
    for res in ("zia_firewall_filtering_rule", "zia_url_filtering_rules", "ztc_traffic_forwarding_rule"):
        assert 'state = "DISABLED"' in re.sub(r" +=", " =", resource_block(files, res)), res
    assert "enabled = false" in re.sub(r" +=", " =", resource_block(files, "zpa_application_segment"))
    assert "Clone mode" in files[f"{tt.ROOT_DIR}/zia/README.md"]
    kept, _r, _ = run(client, read, opts=tt.normalize_options(None, mode="clone", keep_rule_state=True), plan_info=p)
    assert 'state = "v-state-1"' in re.sub(r" +=", " =", resource_block(kept, "zia_firewall_filtering_rule")), "asked: the state is kept"
    adopt, _r, _ = run(client, read)
    assert 'state = "v-state-1"' in re.sub(r" +=", " =", resource_block(adopt, "zia_firewall_filtering_rule")), "adopting changes nothing"
    with pytest.raises(tt.ExportRefused):
        tt.normalize_options(None, mode="apply")


def test_client_connector_trusted_networks_take_the_provider_form():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a v1 trusted network (comma lists, 0/1) is written in the zcc provider's form; profiles name it by address."""
    body = {"trustedNetworkContracts": [{"id": 5, "networkName": "Head office", "active": False, "conditionType": 1,
                                         "dnsServers": "10.0.0.53, 10.0.1.53", "trustedSubnets": "10.0.0.0/16", "hostnames": "dc1.corp.example"}]}
    fwd = [{"id": 7, "name": "Road warrior", "active": True, "trustedNetworkIds": [5], "conditionType": 0,
            "forwardingProfileActions": [{"networkType": 0, "actionType": 1, "systemProxyData": {"enablePac": True, "pacUrl": "https://pac.example/p.pac"}}]}]
    responses = {"/zcc/papi/public/v1/webTrustedNetwork/listByCompany": {"status": 200, "body": body},
                 "/zcc/papi/public/v1/webForwardingProfile/listByCompany": {"status": 200, "body": fwd}}
    st = ot.OfflineStore("snap-" + "5" * 16, "snapshot", responses, {"tenant_label": "ZCC"})
    files, rep, snap = run(ot.OfflineSdkClient(st, ot.creds_for(st)), ["zcc.trusted_networks", "zcc.forwarding_profiles"])
    assert not snap["unread"], snap["unread"]
    tn = re.sub(r" +=", " =", resource_block(files, "zcc_trusted_network", "head_office"))
    assert 'name = "Head office"' in tn and "active = false" in tn and 'condition_type = "ANY"' in tn
    assert 'dns_server_ips = ["10.0.0.53", "10.0.1.53"]' in tn and 'trusted_subnet_ips = ["10.0.0.0/16"]' in tn and 'hostname = "dc1.corp.example"' in tn
    fp = re.sub(r" +=", " =", resource_block(files, "zcc_forwarding_profile", "road_warrior"))
    assert "trusted_network_ids = [zcc_trusted_network.head_office.id]" in fp
    assert "network_type = 0" in fp and "action_type = 1" in fp and 'pac_url = "https://pac.example/p.pac"' in fp
    assert 'source  = "zscaler/zcc"' in files[f"{tt.ROOT_DIR}/zcc/terraform.tf"]
    assert ("zcc_trusted_network", "head_office", "5") in imp_all(files)


def test_zpa_microtenant_is_read_as_asked_and_calls_without_a_query_still_work():
    """ASVS V4.1.3 · CWE-639 · WSTG-ATHZ-02: a ZPA microtenant id goes on every ZPA list that takes one; lists without a query still read."""
    seen = []

    class _Store(ot.OfflineStore):
        def answer_get(self, url, params=None):
            seen.append((ot.normalize_path(url), dict(params or {})))
            return 200, {"totalPages": "1", "list": []}

    st = _Store("snap-" + "6" * 16, "snapshot", {}, {"tenant_label": "MT"})
    snap = tt.read_tenant(ot.OfflineSdkClient(st, ot.creds_for(st)), ["zpa.segment_groups", "zpa.cbi_banners"], microtenant_id="216196257331285825")
    assert not snap["unread"], snap["unread"]
    seg = [p for u, p in seen if u.endswith("/segmentGroup")]
    assert seg and seg[0].get("microtenantId") == "216196257331285825"
