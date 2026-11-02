"""A fake tenant for the rule CSV and sync tests: the sample tenant
(sample_tenant.py, made up) served by offline_tenant to the real SDK
services, with the rule-order semantics of ZIA and ZPA the planner relies
on, and the ZPA access policy writes the SDK sends (policySet/{id}/rule,
/reorder). No network: every request is answered from memory, and every
write is recorded in `writes_seen` so a test can prove none was sent."""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Tuple

import offline_tenant as ot
import sample_tenant

ZIA_ORDERED = ("/zia/api/v1/firewallFilteringRules", "/zia/api/v1/urlFilteringRules")
ZPA = "/zpa/mgmtconfig/v1/admin/customers/{customerId}"
ZPA_LIST = ZPA + "/policySet/rules/policyType/ACCESS_POLICY"
POLICY_SET = "9001"


class FakeStore(ot.OfflineStore):
    """The sample tenant, writable, with ordered rule lists: a rule written
    at order N goes to position N and the others shift down; a delete closes
    the gap (assumed ZIA and ZPA behaviour, as the planner assumes it)."""

    def __init__(self, source_id: str = "sample", mutate=None):
        resp = sample_tenant.responses()
        # The rule CSV and sync tests are written against the sample's own
        # Cloud Firewall rules by position; Zscaler's predefined Office 365
        # One Click rule (added to the sample for the Microsoft 365 app
        # service matching) is left out here so those positions hold.
        fw = "/zia/api/v1/firewallFilteringRules"
        key = next((k for k in resp if k.endswith(fw)), None)
        if key:
            gone = [r for r in resp[key] if r.get("name") == "Office 365 One Click Rule"]
            resp[key] = [r for r in resp[key] if r not in gone]
            for g in gone:   # the rules below it move up, as before it was added
                for r in resp[key]:
                    if not r.get("defaultRule") and isinstance(r.get("order"), int) and r["order"] > g.get("order", 0):
                        r["order"] -= 1
        if mutate:
            mutate(resp)
        table = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in resp.items()}
        super().__init__(source_id, "sample", table, sample_tenant.meta(), writable=True)
        self.writes_seen: List[Tuple[str, str, Any]] = []
        self.gets: List[str] = []

    # ── ZIA ──
    @staticmethod
    def _renumber(coll: List[Dict[str, Any]], moved: Optional[Dict[str, Any]] = None, at: Any = None, key: str = "order") -> None:
        movable = [r for r in coll if not r.get("defaultRule")]
        movable.sort(key=lambda r: (int(r.get(key) or 0), r is not moved))
        if moved is not None:
            movable.remove(moved)
            movable.insert(max(0, min(len(movable), int(at) - 1)), moved)
        for i, r in enumerate(movable, 1):
            r[key] = i if key == "order" else str(i)

    def zpa_rules(self) -> List[Dict[str, Any]]:
        return self.responses[ZPA_LIST]["body"]["list"]

    def answer_get(self, url: str, params: Optional[Dict[str, Any]] = None):
        path = ot.normalize_path(url)
        self.gets.append(path)
        if path == ZPA + "/policySet/policyType/ACCESS_POLICY":
            return 200, {"id": POLICY_SET, "name": "Global_Policy", "policyType": "1"}
        m = re.fullmatch(re.escape(ZPA) + r"/policySet/" + POLICY_SET + r"/rule/([^/]+)", path)
        if m:
            got = next((r for r in self.zpa_rules() if str(r["id"]) == m.group(1)), None)
            return (200, copy.deepcopy(got)) if got else (404, {"code": "resource.not.found", "message": "not found"})
        return super().answer_get(url, params)

    def answer_write(self, method: str, url: str, body: Any = None):
        path = ot.normalize_path(url)
        self.writes_seen.append((method, path, copy.deepcopy(body)))
        with self._lock:
            base = next((b for b in ZIA_ORDERED if path == b or path.startswith(b + "/")), None)
            if base is not None:
                return self._zia(method, path, base, body)
            if path.startswith(ZPA + "/policySet/" + POLICY_SET + "/"):
                return self._zpa(method, path, body)
        return super().answer_write(method, url, body)

    def _zia(self, method: str, path: str, base: str, body: Any):
        coll = self.responses[base]["body"]
        if method == "POST" and path == base:
            obj = copy.deepcopy(body)
            obj["id"] = max([int(r["id"]) for r in coll] + [90000]) + 1
            coll.append(obj)
            self._renumber(coll, obj, obj.get("order") or 10 ** 6)
            self.writes += 1
            return 200, copy.deepcopy(obj)
        rid = path.rsplit("/", 1)[1]
        item = next((r for r in coll if str(r["id"]) == rid), None)
        if item is None:
            return 404, {"code": "RESOURCE_NOT_FOUND", "message": "not found"}
        if method == "PUT":
            new_order = (body or {}).get("order", item.get("order"))
            item.update(copy.deepcopy(body))
            item["id"] = int(rid)
            if not item.get("defaultRule"):
                self._renumber(coll, item, new_order)
            self.writes += 1
            return 200, copy.deepcopy(item)
        if method == "DELETE":
            coll.remove(item)
            self._renumber(coll)
            self.writes += 1
            return 204, {}
        return 400, {"message": "not modelled"}

    def _zpa(self, method: str, path: str, body: Any):
        rules = self.zpa_rules()
        tail = path.split("/policySet/" + POLICY_SET + "/", 1)[1]
        if method == "POST" and tail == "rule":
            obj = copy.deepcopy(body)
            obj["id"] = str(max([int(r["id"]) for r in rules] + [90000]) + 1)
            obj["ruleOrder"] = str(len(rules) + 1)
            rules.append(obj)
            self.writes += 1
            return 200, copy.deepcopy(obj)
        if method == "PUT" and tail == "reorder":
            ids = [str(x) for x in (body or [])]
            by_id = {str(r["id"]): r for r in rules}
            new = [by_id[i] for i in ids if i in by_id] + [r for r in sorted(rules, key=lambda r: int(r["ruleOrder"])) if str(r["id"]) not in ids]
            for i, r in enumerate(new, 1):
                r["ruleOrder"] = str(i)
            rules[:] = new
            self.writes += 1
            return 204, {}
        m = re.fullmatch(r"rule/([^/]+)", tail)
        if not m:
            return 400, {"message": "not modelled"}
        item = next((r for r in rules if str(r["id"]) == m.group(1)), None)
        if item is None:
            return 404, {"code": "resource.not.found", "message": "not found"}
        if method == "PUT":
            keep = {"id": item["id"], "ruleOrder": item["ruleOrder"]}
            item.clear()
            item.update(copy.deepcopy(body), **keep)      # a ZPA PUT replaces the rule
            self.writes += 1
            return 204, {}
        if method == "DELETE":
            rules.remove(item)
            for i, r in enumerate(sorted(rules, key=lambda r: int(r["ruleOrder"])), 1):
                r["ruleOrder"] = str(i)
            self.writes += 1
            return 204, {}
        return 400, {"message": "not modelled"}


def client(mutate=None, source_id: str = "sample") -> Tuple[FakeStore, Any]:
    st = FakeStore(source_id, mutate)
    return st, ot.OfflineSdkClient(st, ot.creds_for(st))
