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

import logging
from typing import Any, Dict, Optional, Tuple

from zscaler import ZscalerClient

logger = logging.getLogger("dlp_assessment.sdk_client")

SDK_REQUEST_TIMEOUT = 90   # seconds per tenant request, as dlp_api_server.SDK_REQUEST_TIMEOUT


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
            msg = _scrub(error)
            logger.warning("SDK error on %s: %s", _name(method), msg)
            return {"error": msg}, 0

        if data is None:
            return [], 204

        if isinstance(data, list):
            return _to_dicts(data), 200
        elif hasattr(data, "as_dict"):
            return data.as_dict(), 200
        else:
            return data, 200

    except Exception as e:
        msg = _scrub(e)
        logger.error("SDK call failed (%s): %s", _name(method), msg)
        return {"error": msg}, 0


def _name(method: Any) -> str:
    """A callable's name for the log; a partial or a mock has none."""
    return str(getattr(method, "__name__", None) or type(method).__name__)


def _scrub(error: Any) -> str:
    """An SDK error as text with every access token, JSON Web Token, Basic
    credential and session id masked (tenant_auth.redact_tokens): an API
    error page may echo the request's Authorization header, and this text is
    logged and returned (CWE-532). SdkClient.get masks its own credentials too."""
    import tenant_auth
    return tenant_auth.redact_tokens(str(error))


def _cloud_app_rules(zs) -> Tuple[Any, int]:
    """Cloud App Control rules of every rule type as one list, each tagged
    with its type: the API lists them per type (/webApplicationRules/{type})."""
    from dlp_assessment_full_auto import _CAC_TYPES
    out, answered, first = [], False, None
    for t in _CAC_TYPES:
        data, code = _sdk_call(zs.zia.cloudappcontrol.list_rules, t)
        first = first if first is not None else (data, code)
        if code in (200, 204):
            answered = True
            out.extend(dict(r, type=r.get("type") or t) if isinstance(r, dict) else r for r in (data or []))
    return (out, 200) if answered else first


class SdkClient:
    """
    Drop-in replacement for the raw-HTTP Client class.

    Maps cl.get(path) calls to zscaler-sdk-python SDK methods.
    All 150+ check functions work unchanged.
    """

    def __init__(self, client_id: str, client_secret: str,
                 vanity_domain: str, cloud: str, *,
                 auth_method: str = "", username: str = "", password: str = "", api_key: str = ""):
        # The SDK's `cloud` is the OneAPI environment (beta / gov / govus),
        # not the ZIA cloud name: a commercial tenant on zscloud.net or
        # zscalerten.net signs in at zslogin.net and calls api.zsapi.net.
        import tenant_auth
        import zscaler_clouds
        try:
            env = zscaler_clouds.environment(cloud)
        except ValueError:
            env = None
        self._config = {
            "clientId": client_id,
            "clientSecret": client_secret,
            "vanityDomain": vanity_domain,
            "cloud": env or "production",
            # Bounded waits, as the web app's client has (dlp_api_server.
            # SDK_REQUEST_TIMEOUT): without them the SDK sends with no HTTP
            # timeout at all and a silent tenant holds the call forever.
            "requestTimeout": SDK_REQUEST_TIMEOUT,
            "rateLimit": {"maxRetries": 2, "maxRetrySeconds": 30},
        }
        # Either sign-in (tenant_auth): OneAPI, or the classic ZIA API with
        # auth_method="legacy" (username, password, API key; ZIA only).
        self._creds = tenant_auth.normalize({"auth_method": auth_method, "cloud": cloud, "vanity_domain": vanity_domain,
                                             "client_id": client_id, "client_secret": client_secret,
                                             "username": username, "password": password, "api_key": api_key})
        self._zs: Optional[ZscalerClient] = None
        self._cache: Dict[str, Tuple[Any, int]] = {}
        self._route_map: Optional[dict] = None

    def auth(self):
        """Authenticate with Zscaler. Returns True on success, (False, msg) on failure."""
        import tenant_auth
        try:
            if self._creds["auth_method"] == tenant_auth.LEGACY:
                self._zs = tenant_auth.build_legacy_sdk_client(self._creds, timeout=SDK_REQUEST_TIMEOUT)
            else:
                # The vanity domain becomes the sign-in host's first labels
                # and may come from an MCP tool argument: anything but a DNS
                # name ('evil.example/?') would post the client secret to
                # another host, so it is refused before the SDK is built.
                import zscaler_clouds
                zscaler_clouds.check_vanity(self._config["vanityDomain"])
                tenant_auth.bound_sdk_sign_in()   # the SDK's token request has no timeout of its own
                self._zs = ZscalerClient(self._config)
                self._zs.authenticate()
            self._route_map = self._build_route_map()
            return True
        except Exception as e:
            msg = tenant_auth.mask_secrets(str(e), self._creds)
            logger.error("Authentication failed: %s", msg)
            return (False, msg)

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
            "/zia/dlpExactDataMatchSchemas": lambda: _sdk_call(zs.zia.dlp_resources.list_edm_schemas),
            "/zia/idmprofile":              lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_idm_profiles),

            # --- ZIA: SSL ---
            "/zia/sslInspectionRules":       lambda: _sdk_call(zs.zia.ssl_inspection_rules.list_rules),

            # --- ZIA: URL / Cloud App ---
            "/zia/urlFilteringRules":        lambda: _sdk_call(zs.zia.url_filtering.list_rules),
            "/zia/urlCategories":            lambda: _sdk_call(zs.zia.url_categories.list_categories),
            "/zia/cloudApplicationRules":    lambda: _cloud_app_rules(zs),

            # --- ZIA: Isolation ---
            "/zia/browserIsolation/profiles": lambda: _sdk_call(zs.zia.cloud_browser_isolation.list_isolation_profiles),

            # --- ZIA: PAC ---
            "/zia/pacFiles":                lambda: _sdk_call(zs.zia.pac_files.list_pac_files),

            # --- ZIA: CASB ---
            "/zia/casbDlpRules/all":        lambda: _sdk_call(zs.zia.casb_dlp_rules.list_all_rules),
            "/zia/emailDlpRules":           lambda: _sdk_call(zs.zia.outbound_email_dlp_rules.list_rules),

            # --- ZIA: Advanced Settings ---
            "/zia/advancedSettings":         lambda: _sdk_call(zs.zia.advanced_settings.get_advanced_settings),

            # --- ZIA: NSS ---
            "/zia/nssFeeds":                lambda: _sdk_call(zs.zia.cloud_nss.list_nss_feed),
            "/zia/nssServers":              lambda: _sdk_call(zs.zia.nss_servers.list_nss_servers),
            "/zia/nssCollectors":           lambda: _sdk_call(zs.zia.nss_collectors.list_collectors),

            # --- ZIA: Governance (configAudit and subscriptions stay on the raw
            # GET below: the SDK reshapes their bodies) ---
            "/zia/alertSubscriptions":      lambda: _sdk_call(zs.zia.alert_subscriptions.list_alert_subscriptions),
            "/zia/remoteAssistance":        lambda: _sdk_call(zs.zia.remote_assistance.get_remote_assistance),
            "/zia/passwordExpiry/settings": lambda: _sdk_call(zs.zia.admin_roles.get_password_expiry_settings),

            # --- ZIA: ICAP / Incident Receivers ---
            "/zia/icapServers":              lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_icap_servers),
            "/zia/incidentReceiverServers":  lambda: _sdk_call(zs.zia.dlp_resources.list_dlp_incident_receiver),

            # --- ZIA: Admin ---
            "/zia/adminRoles":              lambda: _sdk_call(zs.zia.admin_roles.list_roles),

            # --- ZIA: Tenancy ---
            "/zia/tenancyRestrictionProfile": lambda: _sdk_call(zs.zia.tenancy_restriction_profile.list_restriction_profile),

            # --- ZIA: Device Management ---
            "/zia/deviceGroups":            lambda: _sdk_call(zs.zia.device_management.list_device_groups),

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
        data, code = self._get(endpoint, params)
        if isinstance(data, dict) and isinstance(data.get("error"), str):
            import tenant_auth
            data = dict(data, error=tenant_auth.mask_secrets(data["error"], self._creds))
        return data, code

    def _get(self, endpoint: str, params: Optional[dict] = None) -> Tuple[Any, int]:
        # Cache check
        cache_key = f"{endpoint}|{params or {}}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Ensure authenticated
        if self._zs is None:
            a = self.auth()
            if a is not True:
                return {"error": a[1] if isinstance(a, tuple) and len(a) == 2 else str(a)}, 0

        if endpoint in ("/zcc/appProfiles", "/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/forwardingProfile"):
            from zcc_profiles import read_profiles
            result = self._zcc_profile_page(endpoint, params) if params else read_profiles(self._zcc_profile_page, endpoint)
            self._cache[cache_key] = result
            return result

        # SaaS application tenants: the filters (active only, email tenants
        # only) are query parameters, so this route takes them.
        if endpoint == "/zia/pacFiles":
            qp = {"page": (params or {}).get("page", 1), "page_size": (params or {}).get("pageSize", 100)}
            result = _sdk_call(self._zs.zia.pac_files.list_pac_files, query_params=qp)
            self._cache[cache_key] = result
            return result

        if endpoint == "/zia/casbTenant/lite":
            qp = {"active_only": str((params or {}).get("activeOnly", "")).lower() == "true"}
            if (params or {}).get("appType"):
                qp["app_type"] = str(params["appType"])
            result = _sdk_call(self._zs.zia.saas_security_api.list_casb_tenant_lite, query_params=qp)
            self._cache[cache_key] = result
            return result

        # Try SDK route
        if self._route_map and endpoint in self._route_map:
            result = self._route_map[endpoint]()
            self._cache[cache_key] = result
            return result

        # Fallback: raw HTTP via SDK's request executor
        result = self._raw_get(endpoint, params)
        self._cache[cache_key] = result
        return result

    def _zcc_profile_page(self, endpoint, params=None):
        """Use wire responses so wrapper totals and nested policy fields survive SDK versions."""
        from dlp_assessment_full_auto import _resolve_candidates
        if self._creds.get("auth_method") == "legacy":
            return {"error": "Client Connector requires a OneAPI sign-in"}, 404
        try:
            executor = self._zs.get_request_executor()
            for route in _resolve_candidates(endpoint):
                request, error = executor.create_request("GET", route, {}, {}, params=params or {})
                if error:
                    return {"error": str(error), "path": route}, 0
                response, error = executor.execute(request)
                code = response.get_status() if response is not None else 0
                if code in (400, 404, 405):
                    continue
                if error:
                    return {"error": str(error), "path": route}, code or 0
                if response is None:
                    return {"error": "profile API returned no response", "path": route}, 0
                return response.get_body(), code or 200
            return {"error": "profile API route not available", "path": route}, code
        except Exception as exc:
            return {"error": str(exc)}, 0

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
                elif callable(getattr(type(self._zs), "close", None)):
                    # The classic API (tenant_auth.LegacyZiaClient) has no
                    # __exit__: close() ends its JSESSIONID session at ZIA
                    # rather than leaving it signed in (CWE-613).
                    self._zs.close()
            except Exception:
                pass
            self._zs = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def from_env() -> SdkClient:
    """
    Create an SdkClient from environment variables (tenant_auth.ENV):
      ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET, ZSCALER_VANITY_DOMAIN,
      ZSCALER_CLOUD for OneAPI; ZSCALER_AUTH_METHOD=legacy with
      ZSCALER_USERNAME, ZSCALER_PASSWORD, ZSCALER_API_KEY for the classic API.
    """
    import tenant_auth
    c = tenant_auth.from_env()
    return SdkClient(client_id=c["client_id"], client_secret=c["client_secret"], vanity_domain=c["vanity_domain"],
                     cloud=c["cloud"] or "production", auth_method=c["auth_method"], username=c["username"],
                     password=c["password"], api_key=c["api_key"])
