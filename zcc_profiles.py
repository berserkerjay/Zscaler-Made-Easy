"""Read complete Client Connector profile inventories without hiding failures."""
from __future__ import annotations

APP_ENDPOINT = "/zcc/papi/public/v1/application-profiles"
FORWARDING_ENDPOINT = "/zcc/papi/public/v1/webForwardingProfile/listByCompany"
PAGE_SIZE = 100


def profile_items(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and not body.get("error"):
        for key in ("policies", "list", "items", "data", "records"):
            if isinstance(body.get(key), list):
                return body[key]
    raise ValueError("profile response did not contain a profile list")


def read_profiles(get, endpoint, *, cancel=None):
    """Read every page, rejecting partial, malformed and repeated inventories."""
    items, seen = [], set()
    for page in range(1, 1001):
        if cancel:
            cancel()
        body, code = get(endpoint, {"page": page, "pageSize": PAGE_SIZE})
        if code not in (200, 204):
            return body, code
        if code == 204:
            return items, 200
        try:
            batch = profile_items(body)
            if any(not isinstance(p, dict) for p in batch):
                raise ValueError("profile list contained an invalid item")
            import json
            signature = json.dumps(batch, sort_keys=True)
            if batch and signature in seen:
                raise ValueError("profile pagination repeated a page; inventory is incomplete")
            seen.add(signature)
            items.extend(batch)
            total = body.get("totalCount", body.get("total_count")) if isinstance(body, dict) else None
            if total is not None:
                total = int(total)
                if total < 0 or total < len(items):
                    raise ValueError("invalid profile total count")
                if len(items) == total:
                    return items, 200
                if not batch:
                    raise ValueError("profile pagination ended before the total count")
            elif len(batch) < PAGE_SIZE:
                return items, 200
        except (ValueError, TypeError) as exc:
            return {"error": str(exc), "path": endpoint}, 0
    return {"error": "profile pagination limit reached; inventory is incomplete", "path": endpoint}, 0
