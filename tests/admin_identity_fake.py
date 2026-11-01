"""Stateful fakes of the SDK services the day-to-day admin types use
(ops_zia_directory, ops_zia_pac, ops_zid): the same method names, arguments
and (result, response, error) answers as zscaler-sdk-python 1.11.3, the
real SDK models as results, and the body each write would put on the wire
(the SDK's own snake_case -> camelCase conversion), recorded for the payload
oracles. No network, no clock."""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from zscaler.helpers import convert_keys_to_camel_case
from zscaler.zia.models.pac_files import PacFiles, PacFileValidationResponse
from zscaler.zia.models.user_management import Department, Groups, UserManagement
from zscaler.zid.models.api_client import APIClientRecords, APIClients, APIClientSecrets
from zscaler.zid.models.groups import GroupRecord, Groups as ZidGroups
from zscaler.zid.models.resource_servers import ResourceServers
from zscaler.zid.models.users import UserRecord, Users

CANARY_SECRET = "CANARY-ZID-SECRET-7f3a9c"
NOT_FOUND = '{"status": 404, "code": "RESOURCE_NOT_FOUND", "message": "Resource not found"}'


class Resp:
    def __init__(self, body: Any):
        self._body = copy.deepcopy(body)   # an SDK model built from the same dict may change it in place

    def get_body(self) -> Any:
        return copy.deepcopy(self._body)

    def get_results(self) -> Any:
        return copy.deepcopy(self._body)


def wire(kw: Dict[str, Any]) -> Dict[str, Any]:
    """What the SDK sends for these keyword arguments (request_executor._prepare_body)."""
    return convert_keys_to_camel_case(copy.deepcopy(kw))


class _Base:
    def __init__(self, t: "Tenant"):
        self.t = t


# ── ZIA user management ────────────────────────────────────────────────

class UserManagementAPI(_Base):
    def _list(self, kind: str, model, query_params: Optional[dict] = None, key: str = "search"):
        q = dict(query_params or {})
        self.t.reads.append(("GET", kind, q))
        rows = list(self.t.zia[kind].values())
        needle = str(q.get(key) or "").lower()
        if needle:
            rows = [r for r in rows if str(r.get("name") or "").lower().startswith(needle)]
        size, page = int(q.get("page_size") or 100), int(q.get("page") or 1)
        rows = rows[(page - 1) * size: page * size]
        return [model(copy.deepcopy(r)) for r in rows], Resp(rows), None

    def _get(self, kind: str, model, oid):
        self.t.reads.append(("GET", kind, str(oid)))
        row = self.t.zia[kind].get(str(oid))
        if row is None:
            return None, Resp(None), NOT_FOUND
        return model(copy.deepcopy(row)), Resp(row), None

    def _add(self, kind: str, model, kw):
        body = wire(kw)
        self.t.sent.append(("POST", kind, body))
        if self.t.refuse.get(("add", kind)):
            return None, Resp(None), self.t.refuse[("add", kind)]
        oid = str(self.t.new_id())
        row = dict(body, id=int(oid))
        self.t.zia[kind][oid] = row
        return model(copy.deepcopy(row)), Resp(row), None

    def _update(self, kind: str, model, oid, kw):
        body = wire(kw)
        self.t.sent.append(("PUT", kind, str(oid), body))
        if str(oid) not in self.t.zia[kind]:
            return None, Resp(None), NOT_FOUND
        row = dict(body, id=int(oid))
        self.t.zia[kind][str(oid)] = row
        return model(copy.deepcopy(row)), Resp(row), None

    def _delete(self, kind: str, oid):
        self.t.sent.append(("DELETE", kind, str(oid)))
        if self.t.zia[kind].pop(str(oid), None) is None:
            return None, Resp(None), NOT_FOUND
        return None, Resp(None), None

    def list_users(self, query_params=None):
        return self._list("users", UserManagement, query_params, key="name")

    def get_user(self, user_id):
        return self._get("users", UserManagement, user_id)

    def add_user(self, **kwargs):
        return self._add("users", UserManagement, kwargs)

    def update_user(self, user_id, **kwargs):
        return self._update("users", UserManagement, user_id, kwargs)

    def delete_user(self, user_id):
        return self._delete("users", user_id)

    def list_groups(self, query_params=None):
        return self._list("groups", Groups, query_params)

    def get_group(self, group_id):
        return self._get("groups", Groups, group_id)

    def add_group(self, **kwargs):
        return self._add("groups", Groups, kwargs)

    def update_group(self, group_id, **kwargs):
        return self._update("groups", Groups, group_id, kwargs)

    def delete_group(self, group_id):
        return self._delete("groups", group_id)

    def list_departments(self, query_params=None):
        return self._list("departments", Department, query_params)

    def get_department(self, department_id):
        return self._get("departments", Department, department_id)

    def add_department(self, **kwargs):
        return self._add("departments", Department, kwargs)

    def update_department(self, department_id, **kwargs):
        return self._update("departments", Department, department_id, kwargs)

    def delete_department(self, deparment_id):
        return self._delete("departments", deparment_id)


# ── ZIA hosted PAC files (every version is one row: id + pacVersion) ──────

class PacFilesAPI(_Base):
    def list_pac_files(self, query_params=None):
        self.t.reads.append(("GET", "pacFiles", dict(query_params or {})))
        rows = [r for r in self.t.pac if str(r.get("pacVersionStatus")) == "DEPLOYED"]
        return [PacFiles(copy.deepcopy(r)) for r in rows], Resp(rows), None

    def get_pac_file(self, pac_id, query_params=None):
        self.t.reads.append(("GET", "pacFiles/version", str(pac_id)))
        rows = [r for r in self.t.pac if str(r["id"]) == str(pac_id)]
        if not rows:
            return None, Resp(None), NOT_FOUND
        return [PacFiles(copy.deepcopy(r)) for r in rows], Resp(rows), None

    def validate_pac_file(self, pac_file_content):
        self.t.sent.append(("POST", "pacFiles/validate", len(pac_file_content)))
        ok = "FindProxyForURL" in pac_file_content and "SYNTAX ERROR" not in pac_file_content
        body = {"success": ok, "errorCount": 0 if ok else 1, "warningCount": 0,
                "messages": [] if ok else [{"line": 3, "column": 1, "severity": "ERROR", "message": "Unexpected token", "fatal": True}]}
        return PacFileValidationResponse(copy.deepcopy(body)), Resp(body), None

    def add_pac_file(self, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("POST", "pacFiles", body))
        pid = self.t.new_id()
        row = dict(body, id=pid, pacVersion=1, pacUrl=f"https://pac.example.net/{pid}.pac", editable=True)
        self.t.pac.append(row)
        return PacFiles(copy.deepcopy(row)), Resp(row), None

    def clone_pac_file(self, pac_id, pac_version, pac_content, pac_version_status, pac_verification_status="VERIFY_NOERR",
                       pac_commit_message="", delete_version=None):
        body = wire({"pac_content": pac_content, "pac_verification_status": pac_verification_status,
                     "pac_commit_message": pac_commit_message, "pac_version_status": pac_version_status})
        self.t.sent.append(("POST", f"pacFiles/{pac_id}/version/{pac_version}", body))
        rows = [r for r in self.t.pac if str(r["id"]) == str(pac_id)]
        parent = next(r for r in rows if r["pacVersionStatus"] == "DEPLOYED")
        new = dict(parent, **body, pacVersion=max(r["pacVersion"] for r in rows) + 1)
        self.t.pac.append(new)
        return PacFiles(copy.deepcopy(new)), Resp(new), None

    def update_pac_file(self, pac_id, pac_version, pac_version_action, new_lkg_ver=None, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("PUT", f"pacFiles/{pac_id}/version/{pac_version}/action/{pac_version_action}", body))
        for r in self.t.pac:
            if str(r["id"]) == str(pac_id):
                if r["pacVersion"] == int(pac_version):
                    r["pacVersionStatus"] = "DEPLOYED"
                elif r["pacVersionStatus"] == "DEPLOYED":
                    r["pacVersionStatus"] = "LKG"
        return PacFiles(copy.deepcopy(body)), Resp(body), None

    def delete_pac_file(self, pac_id):
        self.t.sent.append(("DELETE", "pacFiles", str(pac_id)))
        before = len(self.t.pac)
        self.t.pac = [r for r in self.t.pac if str(r["id"]) != str(pac_id)]
        return (None, Resp(None), None) if len(self.t.pac) < before else (None, Resp(None), NOT_FOUND)


class Zia:
    def __init__(self, t: "Tenant"):
        self.user_management = UserManagementAPI(t)
        self.pac_files = PacFilesAPI(t)


# ── ZIdentity ──────────────────────────────────────────────────────────

class ZidUsersAPI(_Base):
    def list_users(self, query_params=None):
        q = dict(query_params or {})
        self.t.reads.append(("GET", "zid/users", q))
        rows = list(self.t.zid_users.values())
        if q.get("login_name"):
            rows = [r for r in rows if r["loginName"] == q["login_name"]]
        if q.get("login_name[like]"):
            rows = [r for r in rows if q["login_name[like]"].lower() in r["loginName"].lower()]
        body = {"records": rows[int(q.get("offset") or 0):][: int(q.get("limit") or 100)], "results_total": len(rows)}
        return Users(copy.deepcopy(body)), Resp(body), None

    def get_user(self, user_id):
        self.t.reads.append(("GET", "zid/user", str(user_id)))
        row = self.t.zid_users.get(str(user_id))
        return (UserRecord(copy.deepcopy(row)), Resp(row), None) if row else (None, Resp(None), NOT_FOUND)

    def add_user(self, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("POST", "zid/users", body))
        uid = f"u-{self.t.new_id()}"
        self.t.zid_users[uid] = dict(body, id=uid, source="API")
        return UserRecord(copy.deepcopy(self.t.zid_users[uid])), Resp(self.t.zid_users[uid]), None

    def update_user(self, user_id, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("PUT", f"zid/users/{user_id}", body))
        # A PUT replaces the editable fields (a field left out is cleared); id, source and entitlements stay.
        editable = ("loginName", "displayName", "firstName", "lastName", "primaryEmail", "secondaryEmail", "status", "department", "idp",
                    "customAttrsInfo")
        row = dict({k: v for k, v in self.t.zid_users[str(user_id)].items() if k not in editable}, **body)
        self.t.zid_users[str(user_id)] = row
        return UserRecord(copy.deepcopy(row)), Resp(row), None

    def delete_user(self, user_id):
        self.t.sent.append(("DELETE", "zid/users", str(user_id)))
        return (None, Resp(None), None) if self.t.zid_users.pop(str(user_id), None) else (None, Resp(None), NOT_FOUND)

    def list_user_group_details(self, user_id, query_params=None):
        self.t.reads.append(("GET", f"zid/users/{user_id}/groups", dict(query_params or {})))
        rows = [copy.deepcopy(self.t.zid_groups[g]) for g, members in self.t.zid_members.items() if str(user_id) in members]
        body = {"records": rows, "results_total": len(rows)}
        return ZidGroups(copy.deepcopy(body)), Resp(body), None


class Executor:
    """The SDK's request executor for the ZIdentity raw calls: records each
    request (method, path, body) and answers like ZIdentity (assumed shapes)."""

    def __init__(self, t: "Tenant"):
        self.t = t

    def create_request(self, method, endpoint, body=None, headers=None, params=None, use_raw_data_for_body=False):
        return {"method": method, "endpoint": endpoint, "body": copy.deepcopy(body)}, None

    def execute(self, req, model=None):
        self.t.sent.append((req["method"], req["endpoint"], req["body"]))
        if self.t.refuse.get(("raw", req["endpoint"].rsplit(":", 1)[-1])):
            return None, self.t.refuse[("raw", req["endpoint"].rsplit(":", 1)[-1])]
        if req["endpoint"].endswith(":resetpassword"):
            return Resp(self.t.reset_answer), None
        return Resp("OK"), None


class ZidGroupsAPI(_Base):
    def list_groups(self, query_params=None):
        self.t.reads.append(("GET", "zid/groups", dict(query_params or {})))
        body = {"records": list(self.t.zid_groups.values()), "results_total": len(self.t.zid_groups)}
        return ZidGroups(copy.deepcopy(body)), Resp(body), None

    def get_group(self, group_id):
        self.t.reads.append(("GET", "zid/group", str(group_id)))
        row = self.t.zid_groups.get(str(group_id))
        return (GroupRecord(copy.deepcopy(row)), Resp(row), None) if row else (None, Resp(None), NOT_FOUND)

    def add_user_to_group(self, group_id, user_id, **kwargs):
        self.t.sent.append(("POST", f"zid/groups/{group_id}/users/{user_id}", wire(kwargs)))
        self.t.zid_members.setdefault(str(group_id), set()).add(str(user_id))
        return None, Resp(None), None

    def remove_user_from_group(self, group_id, user_id):
        self.t.sent.append(("DELETE", f"zid/groups/{group_id}/users/{user_id}", {}))
        self.t.zid_members.setdefault(str(group_id), set()).discard(str(user_id))
        return None, Resp(None), None


class ApiClientAPI(_Base):
    def list_api_clients(self, query_params=None):
        self.t.reads.append(("GET", "zid/api-clients", dict(query_params or {})))
        body = {"records": list(self.t.clients.values()), "results_total": len(self.t.clients)}
        return APIClients(copy.deepcopy(body)), Resp(body), None

    def get_api_client(self, client_id):
        self.t.reads.append(("GET", "zid/api-client", str(client_id)))
        row = self.t.clients.get(str(client_id))
        return (APIClientRecords(copy.deepcopy(row)), Resp(row), None) if row else (None, Resp(None), NOT_FOUND)

    def add_api_client(self, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("POST", "zid/api-clients", body))
        cid = f"c-{self.t.new_id()}"
        row = dict(body, id=cid)
        self.t.clients[cid] = row
        self.t.secrets[cid] = []
        # An answer that carries a secret anyway (assumed shape): it must be dropped unread.
        answer = dict(row, clientSecret=CANARY_SECRET + "-create")
        return APIClientRecords(copy.deepcopy(answer)), Resp(answer), None

    def update_api_client(self, client_id, **kwargs):
        body = wire(kwargs)
        self.t.sent.append(("PUT", f"zid/api-clients/{client_id}", body))
        self.t.clients[str(client_id)] = dict(body, id=str(client_id))
        return APIClientRecords(copy.deepcopy(self.t.clients[str(client_id)])), Resp(self.t.clients[str(client_id)]), None

    def delete_api_client(self, client_id):
        self.t.sent.append(("DELETE", "zid/api-clients", str(client_id)))
        self.t.secrets.pop(str(client_id), None)
        return (None, Resp(None), None) if self.t.clients.pop(str(client_id), None) else (None, Resp(None), NOT_FOUND)

    def get_api_client_secret(self, client_id):
        self.t.reads.append(("GET", "zid/secrets", str(client_id)))
        rows = [dict(s, value=CANARY_SECRET + "-old") for s in self.t.secrets.get(str(client_id), [])]
        return APIClientSecrets(copy.deepcopy({})), Resp(rows), None

    def add_api_client_secret(self, client_id, **kwargs):
        self.t.sent.append(("POST", f"zid/api-clients/{client_id}/secrets", wire(kwargs)))
        if self.t.refuse.get(("add", "secret")):
            return None, Resp(None), self.t.refuse[("add", "secret")]
        sid = f"s-{self.t.new_id()}"
        self.t.secrets.setdefault(str(client_id), []).append({"id": sid, "createdAt": 1, "expiresAt": 2})
        body = {"id": sid, "createdAt": 1, "expiresAt": 2, "value": CANARY_SECRET}
        return APIClientSecrets(copy.deepcopy(body)), Resp(body), None

    def delete_api_client_secret(self, client_id, secret_id):
        self.t.sent.append(("DELETE", f"zid/api-clients/{client_id}/secrets", str(secret_id)))
        self.t.secrets[str(client_id)] = [s for s in self.t.secrets.get(str(client_id), []) if s["id"] != secret_id]
        return None, Resp(None), None


class ResourceServersAPI(_Base):
    def list_resource_servers(self, query_params=None):
        self.t.reads.append(("GET", "zid/resource-servers", dict(query_params or {})))
        body = {"records": copy.deepcopy(self.t.servers), "results_total": len(self.t.servers)}
        return ResourceServers(copy.deepcopy(body)), Resp(body), None


class Zid:
    def __init__(self, t: "Tenant"):
        self.users = ZidUsersAPI(t)
        self.users._request_executor = Executor(t)
        self.groups = ZidGroupsAPI(t)
        self.api_client = ApiClientAPI(t)
        self.resource_servers = ResourceServersAPI(t)


PAC_V1 = 'function FindProxyForURL(url, host) {\n  return "PROXY ${GATEWAY_FX}:80";\n}\n'
PAC_V2 = ('function FindProxyForURL(url, host) {\n  if (dnsDomainIs(host, ".corp.example")) { return "DIRECT"; }\n'
          '  return "PROXY ${GATEWAY_FX}:80";\n}\n')


class Tenant:
    def __init__(self) -> None:
        self.reads: List[Any] = []
        self.sent: List[Any] = []
        self.refuse: Dict[Any, str] = {}
        self._n = 5000
        g = lambda i, n, **kw: dict({"id": i, "name": n}, **kw)  # noqa: E731
        self.zia = {
            "groups": {"31": g(31, "All Staff"), "32": g(32, "Drivers"), "33": g(33, "Finance Team"), "34": g(34, "Developers"),
                       "35": g(35, "Okta Engineering", idpId=7), "36": g(36, "Service Admin", isSystemDefined=True)},
            "departments": {"21": g(21, "Operations"), "22": g(22, "Finance"), "23": g(23, "Engineering"), "24": g(24, "Customer Service")},
            "users": {"41": {"id": 41, "name": "Avery Quinn", "email": "avery@acme.example", "department": g(22, "Finance"),
                             "groups": [g(33, "Finance Team")], "comments": "", "authMethods": ["BASIC"]},
                      "42": {"id": 42, "name": "Rowan Ellis", "email": "rowan@acme.example", "department": g(23, "Engineering"),
                             "groups": [g(34, "Developers")]},
                      "43": {"id": 43, "name": "Root Admin", "email": "admin@acme.example", "department": g(21, "Operations"),
                             "groups": [], "adminUser": True}},
        }
        self.pac = [{"id": 61, "name": "corp.pac", "domain": "acme.example", "pacVersion": 1, "pacVersionStatus": "LKG", "pacContent": PAC_V1,
                     "pacCommitMessage": "first", "editable": True, "pacVerificationStatus": "VERIFY_NOERR"},
                    {"id": 61, "name": "corp.pac", "domain": "acme.example", "pacVersion": 2, "pacVersionStatus": "DEPLOYED", "pacContent": PAC_V2,
                     "pacCommitMessage": "corp direct", "editable": True, "pacUrl": "https://pac.example.net/corp.pac",
                     "pacVerificationStatus": "VERIFY_NOERR"}]
        self.zid_users = {"u-1": {"id": "u-1", "loginName": "avery@acme.example", "displayName": "Avery Quinn", "status": True, "source": "UI"},
                          "u-2": {"id": "u-2", "loginName": "rowan@acme.example", "displayName": "Rowan Ellis", "status": True, "source": "UI"},
                          "u-3": {"id": "u-3", "loginName": "boss@acme.example", "displayName": "Boss", "status": True, "adminEntitlementEnabled": True},
                          "u-4": {"id": "u-4", "loginName": "sync@acme.example", "displayName": "Synced", "status": True, "source": "SCIM"}}
        self.zid_groups = {"g-1": {"id": "g-1", "name": "Finance", "source": "UI"}, "g-2": {"id": "g-2", "name": "Engineering", "source": "UI"},
                           "g-dyn": {"id": "g-dyn", "name": "Everyone (dynamic)", "isDynamicGroup": True}}
        self.zid_members: Dict[str, set] = {"g-1": {"u-1"}, "g-2": set(), "g-dyn": {"u-1", "u-2"}}
        self.reset_answer: Any = "OK"
        self.servers = [{"id": "rs-1", "name": "Zscaler APIs", "defaultApi": True, "serviceScopes": [
            {"service": {"id": "s-zia", "name": "ZIA", "displayName": "ZIA"},
             "scopes": [{"id": "sc-ro", "name": "zs:config:zia:acme:Read Only"}, {"id": "sc-sa", "name": "zs:config:zia:acme:Super Admin"}]}]}]
        self.clients = {"c-1": {"id": "c-1", "name": "Reporting", "description": "monthly", "status": True, "accessTokenLifeTime": 3600,
                                "clientAuthentication": {"authType": "SECRET"},
                                "clientResources": [{"id": "rs-1", "name": "Zscaler APIs", "defaultApi": True,
                                                     "selectedScopes": [{"id": "sc-ro", "name": "zs:config:zia:acme:Read Only"}]}]},
                        "c-self": {"id": "c-self", "name": "This app", "status": True, "clientAuthentication": {"authType": "SECRET"},
                                   "clientResources": []}}
        self.secrets: Dict[str, List[Dict[str, Any]]] = {"c-1": [{"id": "s-old", "createdAt": 1, "expiresAt": 2}], "c-self": []}

    def new_id(self) -> int:
        self._n += 1
        return self._n

    def writes(self) -> List[Any]:
        return [s for s in self.sent if s[0] in ("POST", "PUT", "DELETE") and s[1] != "pacFiles/validate"]


class Client:
    """The SDK client's shape: .zia and .zid (alias .zidentity); _client_id as the OneAPI client keeps it."""

    def __init__(self, t: Optional[Tenant] = None, own: str = "c-self"):
        self.tenant = t or Tenant()
        self.zia = Zia(self.tenant)
        self.zid = Zid(self.tenant)
        self.zidentity = self.zid
        self._client_id = own
