#!/usr/bin/env python3
"""
SDK-backed Client Adapter for DLP Assessment Engine
=====================================================
Drop-in replacement for the raw-HTTP Client class that uses
the official zscaler-sdk-python under the hood.

Benefits over raw HTTP:
  - OAuth2 handled automatically (token refresh, expiry)
  - Rate limiting and retries built-in
  - Pagination handled by SDK
  - Consistent field names from SDK models
  - Environment variable credential support

The adapter translates cl.get(path) calls into SDK method calls
so the 150+ check functions need zero changes.

Usage:
    from sdk_client import SdkClient

    cl = SdkClient(client_id, client_secret, vanity_domain, cloud)
    result = cl.auth()
    data, status = cl.get("/zia/webDlpRules")
"""

import os
import logging
from typing import Any, Dict, Optional, Tuple

from zscaler import ZscalerClient

logger = logging.getLogger("dlp_assessment.sdk_client")


def _to_dicts(items: list) -> list:
    """Convert SDK model objects to plain dicts."""
    out = []
    for item in items:
        if hasattr(item, "as_dict"):
            out.append(item.as_dict())
        elif isinstance(item, dict):
            out.append(item)
        else:
            out.append(vars(item) if hasattr(item, "__dict__") else item)
    return out


def _sdk_call(method, *args, **kwargs) -> Tuple[Any, int]:
    """
    Call an SDK method and convert its (data, response, error) tuple
    into the (data, status_code) format the check functions expect.
    """
    try:
        result = method(*args, **kwargs)
        # SDK returns (data, ZscalerAPIResponse, Optional[Exception])
        data, response, error = result

        if error is not None:
            logger.warning("SDK error on %s: %s", method.__name__, error)
            return {"error": str(error)}, 0

        if data is None:
            return [], 204

        if isinstance(data, list):
            return _to_dicts(data), 200
        elif hasattr(data, "as_dict"):
            return data.as_dict(), 200
        else:
            return data, 200

    except Exception as e:
        logger.error("SDK call failed (%s): %s", method.__name__, e)
        return {"error": str(e)}, 0


class SdkClient:
    """
    Drop-in replacement for the raw-HTTP Client class.

    Maps cl.get(path) calls to zscaler-sdk-python SDK methods.
    All 150+ check functions work unchanged.
    """

    def __init__(self, client_id: str, client_secret: str,
                 vanity_domain: str, cloud: str):
        self._config = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "vanityDomain": vanity_domain,
            "cloud": cloud,
        }
        self._zs: Optional[ZscalerClient] = None
        self._cache: Dict[str, Tuple[Any, int]] = {}
        self._route_map: Optional[dict] = None

    def auth(self):
        """Authenticate with Zscaler. Returns True on success, (False, msg) on failure."""
        try:
            self._zs = ZscalerClient(self._config)
            self._zs.authenticate()
            self._route_map = self._build_route_map()
            return True
        except Exception as e:
            logger.error("Authentication failed: %s", e)
            return (False, str(e))

    def _build_route_map(self) -> dict:
        """
        Build a mapping from API endpoint paths to SDK method calls.
        This is the core translation layer.
        """
        zs = self._zs
        return {
            # --- ZIA: DLP ---
            "/zia/webDlpRules":             lambda: _sdk_call(zs.zia.dlp_web_rules.list_rules),
            "/zia/dlpDictionaries":          lambda: _sdk_call(zs.zia.dlp_dictionary.list_dicts),
            "/zia/dlpEngines":              lambda: _sdk_call(zs.zia.dlp_engine.list_dlp_engines),
            "/zia/dlpNotificationTemplates": lambda: _sdk_call(zs.zia.dlp_templates.list_dlp_templates),
            "/zia/notificationTemplates":    lambda: _sdk_call(zs.zia.dlp_templates.list_dlp_templates),
            "/zia/endpointDlpResources":     lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_icap_servers),
            "/zia/endpointDlp/resources":    lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_icap_servers),
            "/zia/dlpEdm":                  lambda: _sdk_call(zs.zia.dlp_resources.list_edm_schemas),
            "/zia/dlpIdm":                  lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_idm_profiles),
            "/zia/dlpIdmProfiles":          lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_idm_profiles),

            # --- ZIA: SSL ---
            "/zia/sslInspectionRules":       lambda: _sdk_call(zs.zia.ssl_inspection_rules.list_rules),

            # --- ZIA: URL / Cloud App ---
            "/zia/urlFilteringRules":        lambda: _sdk_call(zs.zia.url_filtering.list_rules),
            "/zia/urlCategories":            lambda: _sdk_call(zs.zia.url_categories.list_categories),
            "/zia/cloudApplicationRules":    lambda: _sdk_call(zs.zia.cloudappcontrol.list_rules, "STREAMING_MEDIA"),

            # --- ZIA: Isolation ---
            "/zia/isolationProfile":         lambda: _sdk_call(zs.zia.cloud_browser_isolation.list_isolation_profiles),

            # --- ZIA: PAC ---
            "/zia/pacFiles":                lambda: _sdk_call(zs.zia.pac_files.list_pac_files),

            # --- ZIA: CASB ---
            "/zia/casbDlpRules":            lambda: _sdk_call(zs.zia.casb_dlp_rules.list_all_rules),

            # --- ZIA: Advanced Settings ---
            "/zia/advancedSettings":         lambda: _sdk_call(zs.zia.advanced_settings.get_advanced_settings),
            "/zia/dlpAdvancedSettings":      lambda: _sdk_call(zs.zia.advanced_settings.get_advanced_settings),

            # --- ZIA: NSS ---
            "/zia/nssFeeds":                lambda: _sdk_call(zs.zia.cloud_nss.list_nss_feed),
            "/zia/nssFeed":                 lambda: _sdk_call(zs.zia.cloud_nss.list_nss_feed),
            "/zia/nssServers":              lambda: _sdk_call(zs.zia.nss_servers.list_nss_servers),

            # --- ZIA: ICAP / Incident Receivers ---
            "/zia/icapServers":              lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_icap_servers),
            "/zia/incidentReceivers":        lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_incident_receiver),
            "/zia/incidentReceiverServers":  lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_incident_receiver),

            # --- ZIA: Admin ---
            "/zia/adminRoles":              lambda: _sdk_call(zs.zia.admin_roles.list_roles),
            "/zia/adminAndRoleManagement":  lambda: _sdk_call(zs.zia.admin_roles.list_roles),

            # --- ZIA: Tenancy ---
            "/zia/tenancyRestrictionProfile": lambda: _sdk_call(zs.zia.tenancy_restriction_profile.list_restriction_profile),

            # --- ZIA: Device Management ---
            "/zia/devicePostureProfiles":    lambda: _sdk_call(zs.zia.device_management.list_device_groups),

            # --- ZCC: Client Connector ---
            "/zcc/devices":                 lambda: _sdk_call(zs.zcc.devices.list_devices),
            "/zcc/forwardingProfiles":      lambda: _sdk_call(zs.zcc.forwarding_profile.list_by_company),
        }

    def get(self, endpoint: str, params: Optional[dict] = None) -> Tuple[Any, int]:
        """
        Fetch data from a Zscaler API endpoint.

        Uses SDK methods where available, falls back to raw HTTP
        for endpoints not yet covered by the SDK (e.g. /zcc/appProfiles).

        Returns (data, status_code) to match the original Client interface.
        """
        # Cache check
        cache_key = f"{endpoint}|{params or {}}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Ensure authenticated
        if self._zs is None:
            a = self.auth()
            if a is not True:
                return {"error": str(a)}, 0

        # Try SDK route
        if self._route_map and endpoint in self._route_map:
            result = self._route_map[endpoint]()
            self._cache[cache_key] = result
            return result

        # Fallback: raw HTTP via SDK's request executor
        result = self._raw_get(endpoint, params)
        self._cache[cache_key] = result
        return result

    def _raw_get(self, endpoint: str, params: Optional[dict] = None) -> Tuple[Any, int]:
        """
        Fallback for endpoints not yet in the SDK (e.g. /zcc/appProfiles).
        Uses the SDK's internal HTTP client so auth is still managed.
        """
        try:
            executor = self._zs.get_request_executor()
            request = executor.create_request(
                method="GET",
                endpoint=endpoint,
                params=params,
            )
            response, error = executor.execute(request)

            if error is not None:
                logger.warning("Raw GET %s error: %s", endpoint, error)
                return {"error": str(error)}, 0

            if response is None:
                return [], 204

            status = response.get_status() if hasattr(response, "get_status") else 200
            body = response.get_body() if hasattr(response, "get_body") else response

            if isinstance(body, dict) and "list" in body:
                body = body["list"]
            elif isinstance(body, str):
                import json
                try:
                    body = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    pass

            if isinstance(body, list):
                body = _to_dicts(body)

            return body, status if status else 200

        except Exception as e:
            logger.warning("Raw GET %s failed: %s", endpoint, e)
            return {"error": str(e), "status": 0}, 0

    def close(self):
        """Clean up the SDK client."""
        if self._zs is not None:
            try:
                if hasattr(self._zs, "__exit__"):
                    self._zs.__exit__(None, None, None)
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def from_env() -> SdkClient:
    """
    Create an SdkClient from environment variables.
    Supports:
      ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET,
      ZSCALER_VANITY_DOMAIN, ZSCALER_CLOUD
    """
    return SdkClient(
        client_id=os.environ["ZSCALER_CLIENT_ID"],
        client_secret=os.environ["ZSCALER_CLIENT_SECRET"],
        vanity_domain=os.environ["ZSCALER_VANITY_DOMAIN"],
        cloud=os.environ.get("ZSCALER_CLOUD", "zscloud"),
    )
