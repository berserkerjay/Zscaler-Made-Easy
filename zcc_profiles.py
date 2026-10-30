"""Read complete Client Connector profile inventories without hiding failures."""
from __future__ import annotations

from zcc_evaluation import code_text

APP_ENDPOINT = "/zcc/papi/public/v1/application-profiles"
FORWARDING_ENDPOINT = "/zcc/papi/public/v1/webForwardingProfile/listByCompany"
PAGE_SIZE = 100
PLATFORM_TYPES = {"ios": 1, "android": 2, "windows": 3, "macos": 4, "linux": 5}


def read_app_profiles(get, *, cancel=None):
    """Explicitly request every OS; preserve successes and per-platform failures."""
    import json
    items, seen, errors, statuses = [], set(), [], {}
    for platform, device_type in PLATFORM_TYPES.items():
        batch, code = read_profiles(get, "/zcc/webPolicies", cancel=cancel, params={"deviceType": device_type})
        statuses[platform] = "read" if code == 200 else "unverified"
        if code != 200:
            reason = batch.get("error", "") if isinstance(batch, dict) else ""
            errors.append(f"/zcc/webPolicies ({platform}, deviceType={device_type}): HTTP {code} {reason}".strip())
            continue
        for source in batch:
            p = dict(source)
            fields = {k.replace("_", "").lower(): v for k, v in p.items()}
            os_type = next((fields[k] for k in ("devicetype", "os", "platform", "ostype") if fields.get(k) not in (None, "")), None)
            if os_type is None:
                p["deviceType"] = device_type
                os_type = device_type
            os_key = code_text(os_type)
            os_key = {"win": "windows", "mac": "macos", "osx": "macos"}.get(os_key, os_key)
            os_key = {str(v): k for k, v in PLATFORM_TYPES.items()}.get(os_key, os_key)
            key = (os_key, str(p["id"])) if p.get("id") is not None else (os_key, json.dumps(p, sort_keys=True))
            if key not in seen:
                seen.add(key)
                items.append(p)
    return items, errors, statuses


def profile_items(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and not body.get("error"):
        for key in ("policies", "list", "items", "data", "records"):
            if isinstance(body.get(key), list):
                return body[key]
    raise ValueError("profile response did not contain a profile list")


def read_profiles(get, endpoint, *, cancel=None, params=None):
    """Read every page, rejecting partial, malformed and repeated inventories."""
    items, seen = [], set()
    for page in range(1, 1001):
        if cancel:
            cancel()
        body, code = get(endpoint, dict(params or {}, page=page, pageSize=PAGE_SIZE))
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
