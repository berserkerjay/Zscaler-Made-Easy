"""The access rule of every route in team server mode (team_server.py).

Deny by default: TeamAccessMiddleware refuses (403) any route that has no
rule here, and tests/test_team_server.py enumerates every route the app
registers and fails, naming it, when one has none. A new route gets its
rule in the same change that adds it.

Rules (the least a person must hold):

    public    no sign-in: the sign-in itself, liveness, the page shells
              (the HTML and its assets; every bit of data on a page comes
              from an /api/ route with its own rule)
    session   any signed-in person: catalogues and calculations on what the
              page sends, with no tenant data of the server's
    read      read a tenant, or the reports and records of one
    plan      prepare a change (preflight, preview, a change request), or
              edit the app's own notes about a tenant (notes, POV, snapshots)
    apply     change a tenant (apply, remove, undo, import, migrate)
    approve   decide on someone else's change (four-eyes)
    admin     the server itself: accounts, tenant profiles, settings,
              updates, and views across every tenant
    scim      SCIM 2.0 provisioning: the SCIM bearer token, not a session

":profile" after read / plan means the request must name the tenant
profile (path, query or body `profile_id`); an administrator is exempt.

Whenever a request names a tenant profile (`profile_id` in the path, the
query or a JSON body), the person must hold the rule's action there (read
at least). Whenever it names a stored report, job, plan, change request,
deployment, operation, snapshot or proposal queue (team_server.
RESOURCE_PARAMS), the person must own it or hold that action on its
tenant profile.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

PUBLIC, SESSION, READ, PLAN, APPLY, APPROVE, ADMIN, SCIM = "public", "session", "read", "plan", "apply", "approve", "admin", "scim"
RULES = (PUBLIC, SESSION, READ, PLAN, APPLY, APPROVE, ADMIN, SCIM)

# Mounted static files (StaticFiles at /static): the page assets.
MOUNT_RULES: Dict[str, str] = {"/static": PUBLIC}

ROUTE_RULES: Dict[str, str] = {
    # ── sign-in and the page shells ──
    "GET /api/ping": PUBLIC,
    "GET /api/auth/status": PUBLIC,
    "POST /api/auth/unlock": PUBLIC,          # refused in team mode by the handler
    "GET /api/auth/sso/login": PUBLIC,
    "GET /api/auth/sso/callback": PUBLIC,
    "POST /api/auth/logout": PUBLIC,
    "POST /api/auth/team/login": PUBLIC,
    "POST /api/auth/team/passkey/options": PUBLIC,
    "POST /api/auth/team/passkey/login": PUBLIC,
    "POST /api/auth/team/passkey/enroll": PUBLIC,   # needs the one-use ceremony a right password returned
    "GET /api/auth/saml/login": PUBLIC,
    "POST /api/auth/saml/acs": PUBLIC,      # the identity provider's POST; verified in full, signs nobody in by itself
    "GET /api/auth/saml/finish": PUBLIC,    # needs the sign-in's binding cookie
    "GET /api/auth/saml/metadata": PUBLIC,
    "GET /login": PUBLIC,
    "GET /": PUBLIC,
    "GET /app.css": PUBLIC,
    "GET /favicon.ico": PUBLIC,
    "GET /help": PUBLIC,
    "GET /permissions": PUBLIC,
    "GET /simple": PUBLIC,
    "GET /report/queue": PUBLIC,
    "GET /report/zpa": PUBLIC,
    "GET /report/browser": PUBLIC,
    "GET /report/device-posture": PUBLIC,
    "GET /report/digest": PUBLIC,
    "GET /report/health": PUBLIC,
    "GET /report/exports": PUBLIC,
    "GET /report/operations": PUBLIC,
    "GET /report/todo": PUBLIC,
    "GET /report/insights": PUBLIC,
    "GET /report/beacon": PUBLIC,
    "GET /report/advanced": PUBLIC,
    "GET /report/deploy-flow": PUBLIC,
    "GET /report/evalall": PUBLIC,
    "GET /report/logs": PUBLIC,
    "GET /report/vendor": PUBLIC,
    "GET /report/compliance": PUBLIC,
    "GET /report/fleet": PUBLIC,
    "GET /report/view": PUBLIC,
    "GET /report/flow": PUBLIC,
    "GET /report/bypass": PUBLIC,
    "GET /report/plugin": PUBLIC,
    "GET /report/traffic-logs": PUBLIC,
    "GET /report/ztw": PUBLIC,
    "GET /report/soc-review": PUBLIC,
    "GET /report/api-map": PUBLIC,
    "GET /report/other-products": PUBLIC,
    "GET /report/aiguard": PUBLIC,
    "GET /report/dataflow": PUBLIC,
    "GET /report/live": PUBLIC,
    "GET /report/audit": PUBLIC,
    "GET /report/capacity": PUBLIC,
    "GET /report/motion": PUBLIC,
    "GET /report/shadow": PUBLIC,
    "GET /report/posture": PUBLIC,
    "GET /report/self-heal": PUBLIC,
    "GET /report/path": PUBLIC,
    "GET /report/pov": PUBLIC,
    "GET /report/sslflow": PUBLIC,
    "GET /report/sslcoverage": PUBLIC,
    "GET /report/team": PUBLIC,

    # ── the team server itself ──
    "GET /api/team/me": SESSION,
    "POST /api/team/me/password": SESSION,
    "POST /api/team/me/passkeys/options": SESSION,
    "POST /api/team/me/passkeys": SESSION,
    "DELETE /api/team/me/passkeys/{passkey_id}": SESSION,
    "GET /api/team/overview": ADMIN,
    "POST /api/team/users": ADMIN,
    "POST /api/team/users/{user_id}": ADMIN,
    "DELETE /api/team/users/{user_id}": ADMIN,
    "POST /api/team/users/{user_id}/password": ADMIN,
    "POST /api/team/users/{user_id}/unlock": ADMIN,
    "DELETE /api/team/users/{user_id}/passkeys": ADMIN,
    "POST /api/team/grants": ADMIN,
    "POST /api/team/sign-in": ADMIN,
    "POST /api/team/sign-in/test-saml": ADMIN,
    "POST /api/team/scim-token": ADMIN,
    "POST /api/team/store-key/rotate": ADMIN,
    "POST /api/team/share": SESSION,          # only the owner or an administrator may share (team_server.share)
    "GET /api/team/share": SESSION,
    "DELETE /api/team/scim-token": ADMIN,
    "GET /api/scim/v2/ServiceProviderConfig": SCIM,
    "GET /api/scim/v2/ResourceTypes": SCIM,
    "GET /api/scim/v2/Schemas": SCIM,
    "GET /api/scim/v2/Users": SCIM,
    "POST /api/scim/v2/Users": SCIM,
    "GET /api/scim/v2/Users/{scim_id}": SCIM,
    "PUT /api/scim/v2/Users/{scim_id}": SCIM,
    "PATCH /api/scim/v2/Users/{scim_id}": SCIM,
    "DELETE /api/scim/v2/Users/{scim_id}": SCIM,
    "GET /api/scim/v2/Groups": SCIM,
    "POST /api/scim/v2/Groups": SCIM,
    "GET /api/scim/v2/Groups/{scim_id}": SCIM,
    "PUT /api/scim/v2/Groups/{scim_id}": SCIM,
    "PATCH /api/scim/v2/Groups/{scim_id}": SCIM,
    "DELETE /api/scim/v2/Groups/{scim_id}": SCIM,

    # ── catalogues, help and calculations on what the page sends ──
    "GET /api/remediation/catalog": SESSION,
    "GET /api/best-practices": SESSION,
    "GET /api/best-practices/crawl/status": SESSION,
    "GET /api/dlp-packs": SESSION,
    "GET /api/dlp-packs/{pack_id}": SESSION,
    "GET /api/dlp-packs/{pack_id}/terraform": SESSION,
    "GET /api/guidance/sources": SESSION,
    "GET /api/saas-apps": SESSION,
    "POST /api/dlp-packs/jobs/stop-before-start": SESSION,
    "GET /api/write-mode": SESSION,
    "GET /api/tenant/session": SESSION,       # the person's own signed-in tenant (tenant_session): bound to them and their browser, never a credential
    "DELETE /api/tenant/session": SESSION,    # forgets the person's own signed-in tenant; reaches no tenant
    "GET /api/tenant-profiles": SESSION,     # the list is filtered to the profiles the person may read
    "GET /api/vertical-scope": SESSION,
    "GET /api/offline/status": SESSION,
    "POST /api/offline/sample": SESSION,
    "POST /api/offline/leave": SESSION,
    # (wave 9) a rehearsed plan applied to this browser's in-memory copy of the sample tenant or an opened snapshot; nothing reaches a tenant or a file
    "POST /api/offline/simulate/operation": SESSION,
    "POST /api/offline/simulate/pov-build": SESSION,
    "POST /api/offline/simulation/discard": SESSION,
    "GET /api/block-page/themes": SESSION,         # local block page themes; no tenant
    "GET /api/block-page/export": SESSION,
    "POST /api/pov/posture": "plan:profile",       # records a score on the profile's own POV; no tenant read
    "POST /api/block-page/preview": SESSION,
    "PUT /api/block-page/theme": PLAN,             # edits the app's own saved themes; applying one is a Bulk changes operation
    "DELETE /api/block-page/theme": PLAN,
    "POST /api/zia-baseline/selection": SESSION,   # saves or checks a baseline selection the page sends; reads and writes no tenant
    "POST /api/tenant-profiles/snapshots/open-file": SESSION,
    "GET /api/pack-library": SESSION,
    "POST /api/pack-library/preview": SESSION,
    "GET /api/pack-library/{pack_id}/terraform.zip": SESSION,
    "GET /api/pack-library/{pack_id}/bundle": SESSION,
    "POST /api/report/xlsx": SESSION,
    "GET /api/exports/columns": SESSION,
    "GET /api/operations/plugins": SESSION,
    "GET /api/browser-extension.zip": SESSION,
    "GET /api/secure-by-design": SESSION,
    "GET /api/quality-score": SESSION,
    "GET /api/quality-score/report.md": SESSION,
    "GET /api/permissions/required": SESSION,
    "GET /api/readiness/catalog": SESSION,
    "GET /api/branding": SESSION,
    "GET /api/health": SESSION,
    "GET /api/checks": SESSION,
    "GET /api/checks/export": SESSION,
    "GET /api/frameworks": SESSION,
    "POST /api/compliance": SESSION,
    "POST /api/compliance/drilldown": SESSION,
    "POST /api/compliance/report": SESSION,
    "GET /api/compliance/report/{report_id}": SESSION,
    "GET /api/compliance/export/{report_id}": SESSION,
    "GET /api/logs/catalogue": SESSION,
    "POST /api/logs/analyze": SESSION,
    "GET /api/vendor-migrate/vendors": SESSION,
    "POST /api/vendor-migrate/inventory": SESSION,
    "POST /api/vendor-migrate/compile": SESSION,
    "POST /api/vendor-migrate/workspace": SESSION,
    "POST /api/benchmarks": SESSION,
    "POST /api/benchmarks/export": SESSION,
    "POST /api/migrate/optimize": SESSION,
    "POST /api/migrate/upload": SESSION,
    "POST /api/migrate/reorder": SESSION,
    "POST /api/migrate/analyze": SESSION,
    "POST /api/migrate/plan": SESSION,
    # (wave 7) catalogues and calculations on what the page sends: no tenant data of the server's
    "GET /api/rule-csv/format": SESSION,
    "POST /api/rule-csv/validate": SESSION,             # checks a file; reads no tenant
    "GET /api/compliance-profiles": SESSION,
    "GET /api/compliance-profiles/{key}": SESSION,
    "POST /api/compliance-pack": SESSION,               # files from the build on screen; nothing read or written
    "POST /api/compliance-pack/file": SESSION,
    "GET /api/compliance-pack/{key}/{file_id}": SESSION,
    "POST /api/compliance/profile-view": SESSION,       # the results the page sends, read against a profile
    "POST /api/vendor-migrate/panos/plan": SESSION,     # an uploaded PAN-OS export turned into a plan; no tenant
    "GET /api/zscaler-ranges": SESSION,                 # Zscaler's public IP ranges kept on this server
    "POST /api/zscaler-ranges/build": SESSION,
    "POST /api/zscaler-ranges/download": SESSION,
    "GET /api/m365-endpoints": SESSION,                 # Microsoft's public endpoint list kept on this server
    "GET /api/vendor-endpoints": SESSION,               # other providers' endpoint lists kept on this server
    "GET /api/tenant-terraform/catalogue": SESSION,
    "GET /api/traffic-logs/info": SESSION,              # the formats and limits
    "GET /api/traffic-logs/siem": SESSION,              # query templates built from what the page sends
    "GET /api/aiguard/prompts": SESSION,                # the made-up test prompts
    "POST /api/migrate/export": SESSION,
    "GET /api/scope/prerequisites": SESSION,
    "POST /api/report/docx": SESSION,
    "POST /api/report/findings-csv": SESSION,
    "GET /api/zcc/install/catalog": SESSION,
    "GET /api/reference": SESSION,
    "GET /reference/embed/{slug}": SESSION,
    "GET /reference/{slug}": SESSION,
    "POST /api/posture/analyze": SESSION,
    "POST /api/posture/project": SESSION,
    "POST /api/posture/summary": SESSION,
    "GET /api/posture/settings": SESSION,
    "GET /api/pov/catalog": SESSION,
    "GET /api/pov/kit/{file_id}": SESSION,
    "GET /api/updates/sources": SESSION,

    # ── read a tenant, or its reports and records ──
    "POST /api/diagnose/zcc": READ,
    "POST /api/detection-health": READ,
    "POST /api/live-feed": READ,
    "GET /api/proposals": READ,
    "GET /api/proposals/export": READ,
    "POST /api/proposals/{tenant}/{pid}/preview": READ,
    "GET /api/change-queue": READ,           # filtered to the person's tenant profiles
    "GET /api/change-queue/export": READ,    # filtered too
    "GET /api/change-queue/{rid}": READ,
    "POST /api/change-queue/{rid}/comment": READ,
    "POST /api/zpa/analysis/start": READ,
    "POST /api/zpa/diagnose": READ,
    "GET /api/zpa/report/{report_id}": READ,
    "GET /api/zpa/report/{report_id}/export": READ,
    "POST /api/browser-security/start": READ,
    "GET /api/browser-security/report/{report_id}": READ,
    "GET /api/browser-security/report/{report_id}/export": READ,
    "POST /api/device-posture/start": READ,
    "GET /api/device-posture/report/{report_id}": READ,
    "GET /api/device-posture/report/{report_id}/export": READ,
    "GET /api/detection-health/export/{report_id}": READ,
    "GET /api/detection-health/{report_id}": READ,
    "POST /api/rate-check": READ,
    "POST /api/dlp-packs/removal/inventory": READ,
    "GET /api/dlp-packs/jobs/{job_id}": READ,
    "POST /api/dlp-packs/jobs/{job_id}/cancel": READ,
    "POST /api/tenant/check": READ,
    "GET /api/tenant-profiles/{profile_id}": READ,
    "POST /api/tenant-profiles/snapshots/{snapshot_id}/open": READ,
    "GET /api/tenant-profiles/snapshots/{snapshot_id}/download": READ,
    "POST /api/tenant-profiles/snapshots/compare/start": READ,
    "POST /api/dlp-packs/journey": READ,
    "POST /api/dlp-packs/baseline-status": READ,
    "POST /api/dlp-packs/terraform": READ,
    "POST /api/dlp-packs/terraform/start": READ,
    "POST /api/dlp-packs/export/start": READ,
    "GET /api/dlp-packs/jobs/{job_id}/download": READ,
    "GET /api/deployments": READ,            # filtered
    "POST /api/dlp-packs/{pack_id}/verify": READ,
    "POST /api/dlp-packs/inventory/start": READ,
    "GET /api/dlp-packs/plan/{report_id}/export": READ,
    "POST /api/exports/policies/start": READ,
    "POST /api/exports/urls/start": READ,
    "POST /api/exports/url-categories/analyze/start": READ,
    "GET /api/exports/plans": READ,          # filtered to the person's own and their profiles'
    "POST /api/exports/locations/start": READ,
    "POST /api/exports/client-connector/start": READ,
    "POST /api/operations/objects/start": READ,
    "POST /api/operations/objects": READ,
    "GET /api/operations": READ,             # filtered
    "GET /api/operations/{op_id}": READ,
    "GET /api/operations/jobs/{job_id}/plan.pdf": READ,
    "GET /api/operations/jobs/{job_id}/request": READ,
    "POST /api/console-index": READ,
    "GET /api/console-index/cached": "read:profile",
    "GET /api/workspace/notes": "read:profile",
    "POST /api/insights/start": READ,
    "POST /api/insights": READ,
    "GET /api/insights/export/{report_id}": READ,
    "POST /api/readiness/start": READ,
    "POST /api/dlp/efficacy": READ,
    "POST /api/dlp/efficacy/export": READ,
    "POST /api/dlp/efficacy/test": READ,
    "POST /api/migrate/status": READ,
    "POST /api/migrate/status/manual": READ,
    "POST /api/migrate/fetch": READ,
    "POST /api/assess": READ,
    "POST /api/zcc/fleet/start": READ,
    "GET /api/zcc/fleet/{job_id}/diff": READ,
    "GET /api/zcc/fleet/{job_id}/export": READ,
    "POST /api/zcc/install": READ,
    "GET /api/report/bypass/{report_id}": READ,
    "GET /api/report/bypass/export/{report_id}": READ,
    "POST /api/report/bypass": READ,
    "POST /api/report/bypass/export": READ,
    "POST /api/report/data-flow": READ,
    "GET /api/report/data-flow/{report_id}": READ,
    "POST /api/report/data-flow/{report_id}/trace": READ,
    "POST /api/report/data-flow/{report_id}/port-check": READ,
    "GET /api/report/data-flow/export/{report_id}": READ,
    "POST /api/path-analyzer/batch/start": READ,
    "GET /api/path-analyzer/batch/{job_id}/host": READ,
    "GET /api/path-analyzer/batch/{job_id}/export": READ,
    "POST /api/bulk-test/start": READ,
    "GET /api/bulk-test/{job_id}/export": READ,
    "GET /api/bulk-test/{job_id}/list": READ,
    "GET /api/bulk-test/fix/{fix_id}": READ,
    "POST /api/audit-timeline/start": READ,   # this app's own audit entries filtered to the person's profiles
    "GET /api/audit-timeline/{job_id}/export": READ,
    "GET /api/audit/search": READ,           # this app's own audit log, filtered to the person's profiles
    "POST /api/postmortem": READ,
    "POST /api/cite": READ,   # local catalogue; no tenant
    "POST /api/capacity-review": READ,
    "GET /api/journal": "read:profile",   # own audit entries and deployments, filtered to the person's profiles
    "GET /api/audit/export": READ,            # the person's own view of the audit log (filtered to their profiles)
    "POST /api/shadow-rules/start": READ,
    "POST /api/shadow-rules": READ,
    "GET /api/shadow-rules/jobs/{job_id}/export": READ,
    "POST /api/self-heal/tenant/scan": READ,
    "POST /api/self-heal/tenant/view": READ,
    "POST /api/flow/scenario": READ,
    "POST /api/pov/open": "read:profile",
    "POST /api/pov/export": "read:profile",
    "POST /api/pov/report": "read:profile",
    "POST /api/path-analyzer/start": READ,
    "POST /api/path-analyzer": READ,
    "POST /api/path-analyzer/identities": READ,
    "POST /api/report/ssl-flow": READ,
    "GET /api/report/ssl-flow/{report_id}": READ,
    "GET /api/report/ssl-flow/export/{report_id}": READ,
    "POST /api/ssl-coverage/start": READ,
    "GET /api/ssl-coverage/history": READ,
    "GET /api/ssl-coverage/{report_id}": READ,
    "GET /api/ssl-coverage/export/{report_id}": READ,
    # (wave 7) reads of a tenant, or of the records kept for one
    "GET /api/config-backups": READ,
    "GET /api/config-backups/{backup_id}/download": READ,
    "POST /api/config-backups/diff": READ,
    "POST /api/config-backups/diff-live/start": READ,
    "GET /api/config-templates/{template_id}/download": READ,
    "POST /api/operations/lookup": READ,
    "POST /api/operations/zcc/domain-users.csv": READ,
    "POST /api/operations/zdx/deeptrace/follow/start": READ,
    "GET /api/operations/jobs/{job_id}/devices.csv": READ,
    "POST /api/rule-csv/export": READ,
    "GET /api/plugins/pages/{slug}": READ,              # a local plugin's read-only page (its own per-person allow-list too)
    "GET /api/compliance/report/{report_id}/profile/{key}": READ,
    "POST /api/zcc/fleet/{job_id}/dns-records": READ,
    "POST /api/bulk-test/fix/{fix_id}/prove/start": READ,
    "POST /api/category-lookup/start": READ,
    "POST /api/path-analyzer/zpa-identity": READ,
    "POST /api/scim/overview": READ,
    "POST /api/path-analyzer/devices": READ,
    "POST /api/path-analyzer/devices/detail": READ,
    "POST /api/path-analyzer/compare/start": READ,
    "GET /api/path-analyzer/compare/{job_id}/export": READ,
    "POST /api/path-analyzer/test-from-here": READ,     # one destination, explicit click, rate-limited (path_probe)
    "POST /api/tenant-terraform/start": READ,           # reads the tenant into Terraform files; writes nothing
    "POST /api/tenant-health/start": READ,
    "GET /api/tenant-health/latest": READ,
    "POST /api/zcc/fleet/import": READ,                 # the Client Connector Portal's exports, uploaded; no sign-in
    "POST /api/zcc/fleet/{job_id}/sites": READ,         # sites grouped from a finished read
    "GET /api/zcc/fleet/history": READ,
    "GET /api/zcc/fleet/history/compare": READ,
    "POST /api/traffic-logs/analyze": READ,             # uploaded logs (users, hosts): a record its maker owns
    "GET /api/traffic-logs/report/{report_id}": READ,
    "GET /api/traffic-logs/report/{report_id}/export": READ,
    "GET /api/traffic-logs/saved": READ,
    "POST /api/traffic-logs/saved/{saved_name}/open": READ,
    "POST /api/ztw/start": READ,
    "POST /api/soc-review/rbac/start": READ,
    "POST /api/soc-review/telemetry/start": READ,
    "GET /api/soc-review/report/{report_id}": READ,
    # Tenant API map (tenant_api_map.py): a whole-tenant read like the other read jobs (data flow, SSL coverage, SOC review): `read`,
    # so the shared sign-in works and a person needs read on the tenant profile; the plan is a calculation on what the page sends.
    "POST /api/tenant-api-map/plan": SESSION,
    "POST /api/tenant-api-map/start": READ,
    "GET /api/tenant-api-map/saved": READ,
    "GET /api/tenant-api-map/export/{report_id}": READ,
    "GET /api/tenant-api-map/{report_id}": READ,
    "GET /api/ztw/report/{report_id}": READ,
    "GET /api/ztw/report/{report_id}/export": READ,
    "POST /api/other-products/start": READ,
    "GET /api/other-products/report/{report_id}": READ,
    "GET /api/other-products/report/{report_id}/export": READ,
    "POST /api/zwa/incident": READ,                     # one incident's metadata (never its evidence)
    "POST /api/zwa/audit-log": READ,
    "POST /api/aiguard/inventory": READ,
    "POST /api/aiguard/test-prompt": READ,              # one made-up prompt to AI Guard's detection API; nothing is kept
    "POST /api/zdx/cloudpath": READ,
    "POST /api/zdx/analysis/status": READ,
    "POST /api/zcc/device-details": READ,
    "POST /api/zcc/disable-reasons": READ,

    # ── prepare a change, or edit the app's own notes about a tenant ──
    "POST /api/remediation/plan": PLAN,
    "POST /api/dlp-packs/preflight": PLAN,
    "POST /api/change-queue/deploy": PLAN,
    "POST /api/change-queue/removal": PLAN,
    "POST /api/change-queue/recipe": PLAN,
    "POST /api/change-queue/{rid}/withdraw": PLAN,
    "POST /api/dlp-packs/removal/preflight": PLAN,
    "POST /api/tenant-profiles/snapshots/{snapshot_id}/delete": PLAN,
    "POST /api/tenant-profiles/snapshots/save/start": PLAN,
    "POST /api/operations/preview/start": PLAN,
    "POST /api/operations/preview": PLAN,
    "POST /api/operations/{op_id}/undo/preview/start": PLAN,
    "POST /api/operations/{op_id}/undo/preview": PLAN,
    "POST /api/workspace/notes": "plan:profile",
    "POST /api/journal": "plan:profile",
    "DELETE /api/workspace/notes": "plan:profile",
    "POST /api/bulk-test/{job_id}/fix": PLAN,
    "POST /api/pov/create": "plan:profile",
    "POST /api/pov/update": "plan:profile",
    "POST /api/pov/delete": "plan:profile",
    "POST /api/pov/import": "plan:profile",
    "POST /api/pov/templates": PLAN,
    "DELETE /api/pov/templates/{template_id}": PLAN,
    "POST /api/pov/prove/start": "plan:profile",
    "POST /api/pov/insights/start": "plan:profile",
    "POST /api/pov/build/defaults": PLAN,               # the build's parts from the intake (no tenant write)
    "POST /api/pov/build/preview/start": PLAN,
    "POST /api/pov/build/preview": PLAN,
    "POST /api/pov/build/undo/preview/start": PLAN,
    # (wave 7) backups, templates and the remembered compliance choice: the app's own records of a tenant
    "POST /api/config-backups/save/start": PLAN,
    "POST /api/config-cache/refresh/start": PLAN,
    "POST /api/config-backups/from-snapshot": PLAN,
    "POST /api/config-backups/{backup_id}/delete": PLAN,
    "POST /api/config-backups/rehearse": PLAN,          # a restore planned against a saved copy, never applied
    "POST /api/config-templates/export": PLAN,
    "POST /api/config-templates/import": PLAN,
    "POST /api/config-templates/{template_id}/delete": PLAN,
    "POST /api/compliance-profiles/choice": "plan:profile",
    "POST /api/zcc/fleet/{job_id}/history": PLAN,       # keeps a counts-only snapshot of a read (the app's own record)
    "POST /api/zcc/fleet/history/forget": PLAN,
    "POST /api/tenant-api-map/forget": PLAN,           # removes the app's own saved maps of a tenant
    "DELETE /api/traffic-logs/report/{report_id}": PLAN,
    "POST /api/traffic-logs/report/{report_id}/save": PLAN,   # keeps a traffic log report on this server
    "DELETE /api/traffic-logs/saved/{saved_name}": PLAN,

    # ── change a tenant ──
    "POST /api/remediation/execute": APPLY,
    "POST /api/change-queue/{rid}/apply": APPLY,
    "POST /api/proposals/{tenant}/{pid}/apply": APPLY,
    "POST /api/proposals/{tenant}/{pid}/rollback": APPLY,
    "POST /api/dlp-packs/removal/apply": APPLY,
    "POST /api/dlp-packs/removal/apply/start": APPLY,
    "POST /api/dlp-packs/apply": APPLY,
    "POST /api/dlp-packs/apply/start": APPLY,
    "POST /api/deployments/{dep_id}/undo": APPLY,
    "POST /api/dlp-packs/{pack_id}/import": APPLY,
    "POST /api/operations/apply/start": APPLY,
    "POST /api/operations/apply": APPLY,
    "POST /api/operations/zpa/provisioning-key": APPLY,
    "POST /api/migrate/enable": APPLY,
    "POST /api/migrate/delete-all": APPLY,
    "POST /api/migrate/post": APPLY,
    "POST /api/self-heal/tenant/heal": APPLY,
    "POST /api/pov/build/apply/start": APPLY,
    "POST /api/pov/build/undo/apply/start": APPLY,
    "POST /api/zdx/analysis/start": APPLY,              # starts a ZDX score analysis on the tenant (a write; typed phrase)
    "POST /api/zdx/analysis/stop": APPLY,
    # (wave 7) secrets held in memory for, or revealed by, a change: only for those who may change the tenant
    "POST /api/operations/zpa/ba-certificate": APPLY,
    "POST /api/operations/zidentity/secret": APPLY,
    "POST /api/zcc/otp": APPLY,                          # a device's one-time passwords: a sensitive read guarded like a write
    "POST /api/zcc/passwords": ADMIN,                    # tamper passwords revealed on demand: administrators only (off by default)
    "GET /api/data-check": ADMIN,                       # the data folder self-check: paths and store names, administrators only
    "POST /api/data-check/repair": ADMIN,               # removes stale lock and temporary files only

    # ── decide on someone else's change ──
    "POST /api/change-queue/{rid}/approve": APPROVE,
    "POST /api/change-queue/{rid}/reject": APPROVE,
    "POST /api/proposals/{tenant}/{pid}/decide": APPROVE,
    "POST /api/self-heal/tenant/accept": APPROVE,

    # ── the server itself, and views across every tenant ──
    "POST /api/best-practices/crawl": ADMIN,
    # (wave 9) the traffic logs' watched folder and syslog listener: server-wide settings, a network listener and its shared buffer
    "GET /api/traffic-logs/watch": ADMIN,
    "POST /api/traffic-logs/watch": ADMIN,
    "POST /api/traffic-logs/watch/run": ADMIN,
    "GET /api/delivery": ADMIN,                           # delivery + DNS push settings (never a password)
    "POST /api/delivery/settings": ADMIN,
    "PUT /api/delivery/credential/{target_id}": ADMIN,    # straight to the OS credential store
    "POST /api/delivery/test/{target_id}": ADMIN,
    "POST /api/delivery/send": ADMIN,
    "POST /api/dns-push/settings": ADMIN,
    "POST /api/dns-push/run": ADMIN,
    "GET /api/traffic-logs/syslog": ADMIN,
    "POST /api/traffic-logs/syslog/start": ADMIN,
    "POST /api/traffic-logs/syslog/stop": ADMIN,
    "POST /api/traffic-logs/syslog/clear": ADMIN,
    "POST /api/traffic-logs/syslog/analyze": ADMIN,
    "POST /api/dlp-packs/{pack_id}/from-tenant": ADMIN,
    "GET /api/digests": ADMIN,
    "POST /api/digests/run": ADMIN,
    "GET /api/digests/{digest_id}": ADMIN,
    "GET /api/detection-health/schedule": ADMIN,
    "POST /api/write-mode": ADMIN,
    "POST /api/tenant-profiles": ADMIN,
    "DELETE /api/tenant-profiles/{profile_id}": ADMIN,
    "POST /api/dlp-packs/upload": ADMIN,
    "POST /api/pack-library/upload": ADMIN,
    "POST /api/pack-library/{pack_id}/remove": ADMIN,
    "GET /api/upstream-check": ADMIN,
    "GET /api/beacon": ADMIN,
    "GET /api/beacon/status": ADMIN,
    "POST /api/beacon/run": ADMIN,
    "POST /api/beacon/stop": ADMIN,
    "POST /api/beacon/scope": ADMIN,
    "GET /api/readiness/latest": ADMIN,
    "GET /api/app/update/status": ADMIN,
    "POST /api/app/update": ADMIN,
    "POST /api/app/restart": ADMIN,
    "PUT /api/posture/settings": ADMIN,
    "GET /api/self-heal": ADMIN,
    "POST /api/self-heal/run": ADMIN,
    "POST /api/self-heal/tenant/auto-apply": ADMIN,
    "POST /api/updates/check": ADMIN,
    "POST /api/updates/reset-cache": ADMIN,
    # (wave 7) server settings, unattended schedules and jobs that span tenant profiles
    "POST /api/config-backups/schedule": ADMIN,         # unattended read-only backups on a timer
    "GET /api/sync-jobs": ADMIN,                        # a sync job names a source and several target profiles
    "GET /api/sync-jobs/awaiting-approval": READ,       # filtered to the person's tenant profiles
    "GET /api/sync-jobs/{jid}": ADMIN,
    "POST /api/sync-jobs": ADMIN,
    "DELETE /api/sync-jobs/{jid}": ADMIN,
    "POST /api/sync-jobs/{jid}/enabled": ADMIN,
    "POST /api/sync-jobs/{jid}/run": ADMIN,
    "GET /api/app/update/notify": ADMIN,
    "PUT /api/app/update/notify": ADMIN,
    "GET /api/plugins": ADMIN,
    "PUT /api/plugins/settings": ADMIN,
    "POST /api/plugins/approve": ADMIN,
    "POST /api/plugins/revoke": ADMIN,
    "PUT /api/zscaler-ranges/settings": ADMIN,          # outbound fetches of this server
    "POST /api/zscaler-ranges/fetch": ADMIN,
    "POST /api/zscaler-ranges/import": ADMIN,
    "DELETE /api/zscaler-ranges": ADMIN,
    "PUT /api/m365-endpoints/settings": ADMIN,
    "POST /api/m365-endpoints/refresh": ADMIN,
    "POST /api/m365-endpoints/import": ADMIN,
    "DELETE /api/m365-endpoints": ADMIN,
    "PUT /api/vendor-endpoints/settings": ADMIN,
    "POST /api/vendor-endpoints/refresh": ADMIN,
    "POST /api/vendor-endpoints/import": ADMIN,
    "DELETE /api/vendor-endpoints/{provider}": ADMIN,
    "GET /api/api-calls": ADMIN,                        # every API call this server made, across tenants
    "GET /api/api-calls/export": ADMIN,
}


def rule_for(method: str, path_template: str) -> Optional[Tuple[str, bool]]:
    """(rule, needs a named profile) for a route, or None when it has no rule."""
    m = "GET" if method.upper() == "HEAD" else method.upper()
    raw = ROUTE_RULES.get(f"{m} {path_template}")
    if raw is None:
        return None
    rule, _, flag = raw.partition(":")
    return rule, flag == "profile"
