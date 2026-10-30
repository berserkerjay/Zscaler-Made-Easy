#!/usr/bin/env python3
"""
Zscaler OneAPI Endpoint Discovery
===================================
Probes every plausible API path against a real tenant to find:
  1. Which endpoints exist (200 vs 404 vs 403)
  2. What the actual JSON field names are
  3. Which endpoints require legacy auth vs OneAPI

Run this ONCE against your tenant, review the output, then update
dlp_assessment_full_auto.py with the correct paths and field names.

Usage:
    python discover_endpoints.py --config tenant.json
    python discover_endpoints.py --config tenant.json --output discovery.json

The output holds field names and value types only, never a value from the
tenant (the first item of /zcc/devices is a person's device), and is
written owner-only. Only GET requests are sent; no redirect is followed,
so neither the client secret nor the access token can be sent to another
host.
"""

import json, sys, time, argparse
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("pip install requests"); sys.exit(1)

import safe_files
import tenant_auth
import zscaler_clouds


def _base_url(cloud):
    """The OneAPI gateway for the tenant's cloud (zscaler_clouds)."""
    return zscaler_clouds.api_base(cloud) + "/v1"


def _token_url(vd, cloud):
    """The OAuth2 token endpoint for the tenant's cloud (zscaler_clouds)."""
    return zscaler_clouds.token_url(vd, cloud)

# ── Every plausible endpoint path to probe ─────────────────────────
# Organized by product and feature area
# Many are guesses — the discovery script will tell you which are real

PROBE_PATHS = {
    # ZIA — DLP
    "zia_web_dlp_rules":         ["/zia/webDlpRules", "/zia/dlpRules", "/zia/dlp/rules", "/zia/web_dlp_rules"],
    "zia_endpoint_dlp_rules":    ["/zia/endpointDlpRules", "/zia/endpointDlp/rules", "/zia/endpoint_dlp_rules"],
    "zia_dlp_dictionaries":      ["/zia/dlpDictionaries", "/zia/dlp/dictionaries", "/zia/dlp_dictionaries"],
    "zia_dlp_engines":           ["/zia/dlpEngines", "/zia/dlp/engines"],
    "zia_dlp_edm":               ["/zia/dlpEdm", "/zia/dlp/edm", "/zia/dlpExactDataMatch"],
    "zia_dlp_idm":               ["/zia/dlpIdm", "/zia/dlp/idm", "/zia/dlpIdmProfiles"],
    "zia_dlp_notification":      ["/zia/dlpNotificationTemplates", "/zia/notificationTemplates", "/zia/dlp/notificationTemplates"],
    "zia_endpoint_dlp_resources":["/zia/endpointDlpResources", "/zia/endpointDlp/resources"],
    "zia_dlp_advanced":          ["/zia/advancedSettings", "/zia/dlpAdvancedSettings", "/zia/dlp/advancedSettings"],
    "zia_casb_dlp_rules":        ["/zia/casbDlpRules", "/zia/casb/dlpRules", "/zia/casbDlp/rules"],

    # ZIA — SSL
    "zia_ssl_inspection":        ["/zia/sslInspectionRules", "/zia/sslPolicy", "/zia/ssl/rules", "/zia/sslInspection/rules"],

    # ZIA — URL / Cloud App
    "zia_url_filtering":         ["/zia/urlFilteringRules", "/zia/urlFilteringPolicy/rules", "/zia/url_filtering_rules"],
    "zia_url_categories":        ["/zia/urlCategories", "/zia/url/categories"],
    "zia_cloud_app_rules":       ["/zia/cloudApplicationRules", "/zia/cloudAppControl/rules", "/zia/cloudapp/rules"],
    "zia_firewall_rules":        ["/zia/firewallRules", "/zia/firewall/rules"],

    # ZIA — Incident / Workflow
    "zia_icap_servers":          ["/zia/icapServers", "/zia/icap/servers", "/zia/incidentReceivers"],
    "zia_workflow_automation":   ["/zia/workflowAutomation", "/zia/workflows", "/zia/workflow/rules"],
    "zia_nss_feeds":             ["/zia/nssFeeds", "/zia/nssFeed", "/zia/nss/feeds"],

    # ZIA — Admin / Device
    "zia_admin_roles":           ["/zia/adminRoles", "/zia/adminAndRoleManagement", "/zia/admin/roles"],
    "zia_device_posture":        ["/zia/devicePostureProfiles", "/zia/posture/profiles"],
    "zia_isolation_profile":     ["/zia/isolationProfile", "/zia/isolation/profiles", "/zia/browserIsolation/profiles"],

    # ZIA — Email
    "zia_email_dlp":             ["/zia/emailDlpRules", "/zia/emailSecurityRules", "/zia/email/dlpRules"],

    # ZIA — PAC
    "zia_pac_files":             ["/zia/pacFiles", "/zia/pac/files"],

    # ZCC — App Profiles
    "zcc_app_profiles":          ["/zcc/appProfiles", "/zcc/app_profiles", "/zcc/profiles"],
    "zcc_forwarding_profiles":   ["/zcc/forwardingProfiles", "/zcc/forwarding_profiles", "/zcc/fwdProfiles"],
    "zcc_devices":               ["/zcc/devices", "/zcc/enrolledDevices", "/zcc/device/list"],
    "zcc_posture_profiles":      ["/zcc/postureProfiles", "/zcc/posture/profiles"],

    # ZPA (if scoped)
    "zpa_app_segments":          ["/zpa/appSegments", "/zpa/application/segments"],
    "zpa_policies":              ["/zpa/policySet/rules", "/zpa/policies"],
}


def authenticate(client_id, client_secret, vanity_domain, cloud):
    """Get OAuth2 token via OneAPI OAuth2 endpoint."""
    url = _token_url(vanity_domain, cloud)
    resp = requests.post(
        url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": "https://api.zscaler.com",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
        allow_redirects=False,   # a 307/308 would repeat the POST, secret included, to another host
    )
    if 300 <= resp.status_code < 400:
        raise RuntimeError(f"the token endpoint answered a redirect (HTTP {resp.status_code}); it was not followed")
    resp.raise_for_status()
    return resp.json()["access_token"]


def _shape(value):
    """A value's type, never the value: what the output keeps."""
    return type(value).__name__


def probe(base_url, token, paths, sleep=time.sleep):
    """Probe a list of paths and return the first that works. Records the
    status, the field names and their value types (never a value)."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    results = []

    for path in paths:
        url = f"{base_url}{path}"
        try:
            resp = requests.get(url, headers=headers, timeout=15, allow_redirects=False)
            sleep(0.3)

            result = {
                "path": path,
                "status": resp.status_code,
                "works": resp.status_code in (200, 204),
            }

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        result["type"] = "array"
                        result["count"] = len(data)
                        if data:
                            result["sample_keys"] = [str(k) for k in data[0].keys()] if isinstance(data[0], dict) else []
                            result["first_item_types"] = ({str(k): _shape(v) for k, v in list(data[0].items())[:50]}
                                                          if isinstance(data[0], dict) else _shape(data[0]))
                    elif isinstance(data, dict):
                        result["type"] = "object"
                        result["keys"] = [str(k) for k in data.keys()]
                        result["types"] = {str(k): _shape(v) for k, v in list(data.items())[:50]}
                    else:
                        result["type"] = type(data).__name__
                except ValueError:
                    result["type"] = "non-json"
                    result["length"] = len(resp.content or b"")

            elif resp.status_code == 204:
                result["type"] = "empty (204)"

            elif resp.status_code == 401:
                result["note"] = "Unauthorized — token may lack this resource scope"

            elif resp.status_code == 403:
                result["note"] = "Forbidden — API role doesn't have permission for this endpoint"

            elif resp.status_code == 404:
                result["note"] = "Not found — endpoint doesn't exist on this cloud/version"

            elif resp.status_code == 429:
                result["note"] = "Rate limited"
                sleep(5)

            elif 300 <= resp.status_code < 400:
                result["note"] = "Redirect: not followed (the access token is never sent to another host)"

            results.append(result)

        except requests.exceptions.RequestException as e:
            results.append({"path": path, "status": 0, "works": False, "error": tenant_auth.redact_tokens(str(e))[:300]})

    return results


def load_config(path):
    """The tenant JSON file: an object with client_id, client_secret and
    vanity_domain (cloud optional, production by default). ValueError,
    naming what is missing (never a value), for anything else."""
    try:
        with open(path, encoding="utf-8") as f:
            cfg = safe_files.strict_json_loads(f.read(1_000_001))
    except OSError as e:
        raise ValueError(f"the config file could not be read ({type(e).__name__})") from None
    except (ValueError, RecursionError):
        raise ValueError("the config file is not valid JSON") from None
    if not isinstance(cfg, dict):
        raise ValueError("the config file must be a JSON object")
    missing = [k for k in ("client_id", "client_secret", "vanity_domain") if not str(cfg.get(k) or "").strip()]
    if missing:
        raise ValueError("the config file lacks " + ", ".join(missing))
    zscaler_clouds.check_vanity(cfg["vanity_domain"])
    return cfg


def main():
    parser = argparse.ArgumentParser(description="Zscaler OneAPI Endpoint Discovery")
    parser.add_argument("--config", required=True, help="JSON config file with credentials")
    parser.add_argument("--output", default="discovery.json", help="Output file")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
        cloud = zscaler_clouds.normalize(cfg.get("cloud"))
        base_url = _base_url(cloud)
    except ValueError as e:
        print(f"Cannot start: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"\n{'='*60}")
    print("  ZSCALER ONEAPI ENDPOINT DISCOVERY")
    print(f"  Cloud: {cloud}  Base: {base_url}")
    print(f"{'='*60}\n")

    # Authenticate
    print("  Authenticating...", end=" ", flush=True)
    try:
        token = authenticate(cfg["client_id"], cfg["client_secret"], cfg["vanity_domain"], cloud)
        print("OK\n")
    except Exception as e:
        print(f"FAILED: {tenant_auth.mask_secrets(str(e), cfg)}")
        sys.exit(1)

    # Probe all endpoint groups
    discovery = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cloud": cloud,
            "base_url": base_url,
            "org": cfg.get("org_name", ""),
        },
        "endpoints": {},
        "summary": {"working": [], "forbidden": [], "not_found": [], "errors": []},
    }

    probed = 0

    for feature, paths in PROBE_PATHS.items():
        print(f"  [{feature}] Probing {len(paths)} path(s)...", end=" ", flush=True)
        results = probe(base_url, token, paths)

        working = [r for r in results if r["works"]]
        discovery["endpoints"][feature] = {
            "paths_tried": [r["path"] for r in results],
            "working_path": working[0]["path"] if working else None,
            "results": results,
        }

        if working:
            w = working[0]
            print(f"✓ {w['path']} ({w.get('type', '?')}, {w.get('count', '?')} items)")
            discovery["summary"]["working"].append({
                "feature": feature,
                "path": w["path"],
                "type": w.get("type"),
                "count": w.get("count"),
                "sample_keys": w.get("sample_keys", []),
            })
        else:
            best = results[0] if results else {}
            status = best.get("status", "?")
            if status == 403:
                print("✗ 403 Forbidden (need API role permission)")
                discovery["summary"]["forbidden"].append(feature)
            elif status == 404:
                print("✗ 404 Not Found (endpoint doesn't exist)")
                discovery["summary"]["not_found"].append(feature)
            else:
                print(f"✗ HTTP {status}")
                discovery["summary"]["errors"].append(feature)

        probed += len(paths)

    # Save (owner-only: it names what the API client can read)
    with safe_files.private_open(args.output, "w", encoding="utf-8") as f:
        json.dump(discovery, f, indent=2, default=str)

    # Print summary
    w = discovery["summary"]["working"]
    f403 = discovery["summary"]["forbidden"]
    f404 = discovery["summary"]["not_found"]

    print(f"\n{'='*60}")
    print("  DISCOVERY COMPLETE")
    print(f"  Working: {len(w)}  |  Forbidden: {len(f403)}  |  Not Found: {len(f404)}")
    print(f"{'='*60}\n")

    if w:
        print("  WORKING ENDPOINTS (use these in dlp_assessment_full_auto.py):\n")
        for ep in w:
            keys_preview = ", ".join(ep.get("sample_keys", [])[:8])
            print(f"    {ep['feature']:35s}  {ep['path']}")
            if keys_preview:
                print(f"    {'':35s}  Keys: {keys_preview}")
        print()

    if f403:
        print("  FORBIDDEN (add these API Resources to your ZIdentity client):\n")
        for feat in f403:
            print(f"    {feat}")
        print()

    if f404:
        print("  NOT FOUND (may not be available on OneAPI yet):\n")
        for feat in f404:
            print(f"    {feat}")
        print()

    print(f"  Full results saved to: {args.output}\n")
    print("  NEXT STEPS:")
    print("  1. Open discovery.json")
    print("  2. For each working endpoint, check 'sample_keys' — these are the real JSON field names")
    print("  3. Update dlp_assessment_full_auto.py with the correct paths and field names")
    print("  4. For 403 endpoints, add the missing API Resources to your ZIdentity API Client")
    print("  5. For 404 endpoints, these features may require legacy API auth or aren't available yet\n")


if __name__ == "__main__":
    main()
