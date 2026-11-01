// ── What's new: a * after the label of each new feature ───────────────
// The manifest below is the one list of what is new. Each feature names the
// CHANGELOG.md release it came in ("release", the heading's date), a short
// plain label, what it is (the words after "New in the <date> update: "),
// the CHANGELOG phrases it covers, and where it shows ("marks": the page and
// the item: a control, a sidebar item, a page title or a heading). "shown"
// says when a mark's item appears later (after a read, in a dialog).
//
// Only the features of the newest two releases are marked ("keep"): add the
// next release to "releases", with its features, and the oldest set stops
// showing. A CHANGELOG release with nothing to mark goes in "skipped" with
// the reason, and pushes nothing out (tests/test_new_marks.py checks both
// lists against CHANGELOG.md).
//
// This file only says which item is new: it puts the words on the item
// (data-wn-new). The help marks (hover_help.js) draw the superscript * after
// it, a button of its own named "New in this version: <item>", whose pop-up
// says "New in the <date> update: …", beside the item's ? help mark. It also
// puts the legend "* New in this version" in the page header (the sidebar
// foot on the home page), and "Hide new marks" in Advanced settings, kept in
// this browser only. Every word is set with textContent, never as HTML.
window.WHATS_NEW = {
  "keep": 2,
  "releases": {
    "2026-11-01": "Outside-tool gaps closed: Client Connector Terraform settings, Excel device lists, traffic logs without uploading, more assistant tools",
    "2026-10-31": "Every comparison row green: a deeper Path analyzer, Category lookup and more builders"
  },
  "skipped": {
    "2026-10-30": "The new name everywhere, ZIA admin ranking in the rule decisions (no new control) and the help and new marks themselves: a * on the marks would push 2026-10-28 out, so this release is not marked and the two releases above stay"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "zcc-excel-list", "release": "2026-11-01", "label": "Excel device lists",
      "what": "Remove devices from a list now takes the Client Connector portal's Excel export (.xlsx), read safely on the server.",
      "changelog": ["Excel device lists"],
      "marks": [{ "page": "/report/operations", "at": "#admListFile", "shown": "in Build new, Remove devices from a list" }]
    },
    {
      "id": "zcc-domain-users", "release": "2026-11-01", "label": "Download the domain's user names",
      "what": "Download the user names enrolled under one user domain as a CSV, after ticking that you need the personal data.",
      "changelog": ["Download the domain's user names"],
      "marks": [{ "page": "/report/operations", "at": "#admDomainUsers", "shown": "in Build new, Remove devices from a list" }]
    },
    {
      "id": "tl-no-upload", "release": "2026-11-01", "label": "Read logs without uploading",
      "what": "A daily report from a watched folder and an optional syslog listener, both off until you turn them on.",
      "changelog": ["Read logs without uploading", "Daily report from a folder", "Syslog listener"],
      "marks": [{ "page": "/report/traffic-logs", "at": "#tlAutoH" }]
    },
    {
      "id": "dns-windows", "release": "2026-11-01", "label": "Windows DNS Server output",
      "what": "The DNS records for client hostnames as Windows DNS Server conditional forwarders (PowerShell or dnscmd).",
      "changelog": ["Windows DNS Server output"],
      "marks": [{ "page": "/report/fleet", "at": "#zfDnsWinPs" }]
    },
    {
      "id": "tf-zcc", "release": "2026-11-01", "label": "Client Connector Terraform (beta provider)",
      "what": "The whole-tenant Terraform export writes Client Connector fail-open, device cleanup, web privacy, notification templates and ZIA posture profiles with the beta provider pinned exactly.",
      "changelog": ["Client Connector Terraform"],
      "marks": [{ "page": "/report/exports", "at": "#exTfZccBeta" }]
    },
    {
      "id": "category-lookup", "release": "2026-10-31", "label": "Category lookup",
      "what": "Category lookup on the Path analyzer: a URL, host or category's ZIA categories and every rule that names them, in evaluation order.",
      "changelog": ["Category lookup"],
      "marks": [{ "page": "/report/path", "at": "#tab-cat" }]
    },
    {
      "id": "ucaas-one-click", "release": "2026-10-31", "label": "UCaaS one-click",
      "what": "UCaaS one-click in the ZIA baseline: Zoom, Microsoft Teams, Webex, RingCentral, GoTo and Talkdesk, with the same preview, gates, read-back and Undo.",
      "changelog": ["UCaaS one-click"],
      "marks": [{ "page": "/report/operations", "at": "#zbUcaasH", "shown": "after picking the UCaaS one-click area in the ZIA security baseline" }]
    },
    {
      "id": "m365-endpoint-list", "release": "2026-10-31", "label": "Microsoft 365 endpoint list",
      "what": "Microsoft's published list of Microsoft 365 sites and addresses, fetched when you turn it on or imported from a file, so the Office 365 One Click rule is matched instead of unknown.",
      "changelog": ["Microsoft 365 endpoint list", "Fetch Microsoft's list", "Fetch now", "Import the list from a file", "Remove the list"],
      "marks": [
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#m365\"]" },
        { "page": "/report/advanced", "at": "#advM365H" },
        { "page": "/report/advanced", "at": "#advM365On" },
        { "page": "/report/advanced", "at": "#advM365Fetch" },
        { "page": "/report/advanced", "at": "#advM365File" },
        { "page": "/report/advanced", "at": "#advM365Remove" }
      ]
    },
    {
      "id": "m365-app-services", "release": "2026-10-31", "label": "Microsoft 365 app service groups",
      "what": "The Path analyzer, its what-if and Test a list match the Office 365 One Click rule's app service group by host name and address, and say why.",
      "changelog": ["Microsoft 365 app service groups are matched", "Test a list"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" },
        { "page": "/report/path", "at": "#tab-list" }
      ]
    },
    {
      "id": "m365-shadowed", "release": "2026-10-31", "label": "Shadowed rules and the One Click rule",
      "what": "Shadowed rules finds a later firewall rule whose sites are all Microsoft 365 endpoints, hidden by the Office 365 One Click rule.",
      "changelog": ["Shadowed rules"],
      "marks": [{ "page": "/report/shadow", "at": ".rp-hero h1" }]
    },
    {
      "id": "rule-editor", "release": "2026-10-31", "label": "Edit a rule",
      "what": "Edit a rule on Bulk changes: create, edit, duplicate or delete one ZIA rule with a form per rule type, a plain-language preview, its placement and rank, and Undo.",
      "changelog": ["Edit a rule", "Create it enabled", "Create a rule", "Duplicate a rule", "Delete a rule"],
      "marks": [
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"rule_edit\"]", "shown": "under Build new" },
        { "page": "/report/operations", "at": "#reType", "shown": "after Read from the tenant in Edit a rule" }
      ]
    },
    {
      "id": "dns-ips-state", "release": "2026-10-31", "label": "DNS and IPS rules",
      "what": "Enable or disable rules now covers DNS Control and IPS rules.",
      "changelog": ["Enable or disable DNS and IPS rules"],
      "marks": [{ "page": "/report/operations", "at": "#opPolicy", "shown": "after Read from the tenant in Enable or disable rules" }]
    },
    {
      "id": "zpa-segment-edit", "release": "2026-10-31", "label": "Edit a ZPA application segment",
      "what": "Edit one ZPA application segment's settings and ports, or enable or disable it.",
      "changelog": ["Edit a ZPA application segment"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"zpa_segment_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "app-objects", "release": "2026-10-31", "label": "Cloud app instances and tenancy restrictions",
      "what": "Browse cloud application instances and tenancy restriction profiles, and create or edit one.",
      "changelog": ["Cloud app instances and tenancy restrictions"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"app_object_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "proxy-chaining", "release": "2026-10-31", "label": "Proxy chaining",
      "what": "Create or edit a proxy for proxy chaining, see the gateways that use it and the portal steps a gateway needs.",
      "changelog": ["Proxy chaining"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"proxy_chain_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "config-restore", "release": "2026-10-31", "label": "Backups, restore and clone",
      "what": "Backups of ZIA, ZPA and Client Connector, a field-by-field compare, restore and clone with a plan, a fresh backup first and Undo, and templates for any tenant.",
      "changelog": ["Configuration backups", "Compare field by field", "Restore and clone", "Templates", "Scheduled backups", "Configuration cache", "Rehearsal", "Licence check"],
      "marks": [
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"config_restore_zia\"]", "shown": "after the page lists the builders" },
        { "page": "/report/operations", "at": "#crSave", "shown": "after Read from the tenant on a restore type" }
      ]
    },
    {
      "id": "zpa-identity-whatif", "release": "2026-10-31", "label": "ZPA identity in the what-if",
      "what": "The what-if takes a ZPA identity: pick the IdP, look a user's SCIM groups up and type SAML or SCIM attribute values, and ZPA's access policy says which identity condition decided.",
      "changelog": ["ZPA identity in the Path analyzer"],
      "marks": [
        { "page": "/report/path", "at": "#paWhatIf > summary" },
        { "page": "/report/path", "at": "#paZidH", "shown": "after Analyze with a ZPA identity" }
      ]
    },
    {
      "id": "zpa-identity-list", "release": "2026-10-31", "label": "ZPA identity column",
      "what": "Test a list takes a ZPA identity per row: the IdP, a SCIM user name and attribute values.",
      "changelog": ["ZPA identity column"],
      "marks": [{ "page": "/report/path", "at": "#tab-list" }]
    },
    {
      "id": "zpa-builder-identity", "release": "2026-10-31", "label": "Access rules for SCIM groups and SAML attributes",
      "what": "The ZPA builder's access rule can allow only users in SCIM groups or with SAML attribute values picked from the tenant.",
      "changelog": ["Access rules for SCIM groups and SAML attributes"],
      "marks": [{ "page": "/report/operations", "at": "#zbWho > legend", "shown": "in ZPA policy rules, Only some users" }]
    },
    {
      "id": "admin-zpa", "release": "2026-10-31", "label": "ZPA day-to-day admin",
      "what": "Change App Connectors, Service Edges, their groups and PRA and user portals (health first, rename, on or off, move, update schedule), delete them with a typed confirmation, make a provisioning key shown once, and rotate Browser Access certificates.",
      "changelog": ["ZPA day-to-day admin", "ZPA provisioning keys", "ZPA Browser Access certificates"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zpa_infra_update\"]", "shown": "in Build new" },
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zpa_ba_certificate\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "admin-zcc", "release": "2026-10-31", "label": "Client Connector day-to-day admin",
      "what": "Remove or force remove devices, one user's or a whole list in batches within the hourly API budget, manage custom bypass apps, and set who gets ZPA and ZDX.",
      "changelog": ["Client Connector day-to-day admin", "Remove devices from a list", "Custom bypass apps and entitlements"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zcc_device_bulk_remove\"]", "shown": "in Build new" },
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zcc_entitlements\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "admin-zdx", "release": "2026-10-31", "label": "ZDX deep trace and look-ups",
      "what": "Start a ZDX deep trace on a user's device, follow it and see its results; look up users, devices and their health, and application scores.",
      "changelog": ["ZDX deep trace and look-ups"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zdx_deeptrace_start\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "rank-inherit", "release": "2026-10-31", "label": "Admin rank of new rules",
      "what": "Rules a change creates or moves take the admin rank they need when Admin Ranking is on, never one the API client cannot assign; the preview says each rule's rank and why, and the read-back checks what ZIA stored.",
      "changelog": ["Rank inherited, not fixed at 7", "Never a rank the API client cannot assign", "Preview", "Read-back", "Undo", "Use rank 0", "Admin rank of the rules this change places"],
      "marks": [{ "page": "/report/operations", "at": "#opRankH", "shown": "in a preview that places a rule" }]
    },
    {
      "id": "compliance-profile", "release": "2026-10-31", "label": "Compliance profile",
      "what": "One compliance choice (FedRAMP Moderate or High, CMMC Level 2, Federal Zero Trust, IRS 1075, GovRAMP or a framework) drives the baseline, the policy packs offered, the AI Guard profile and the compliance pack.",
      "changelog": ["Compliance profile"],
      "marks": [{"page": "/report/operations", "at": "#zbCompliance", "shown": "after Read from the tenant, in ZIA security baseline"}]
    },
    {
      "id": "every-rule-mapped", "release": "2026-10-31", "label": "Every rule mapped",
      "what": "Every rule the build creates maps to a control of the profile, or carries a reason code; Check the mapping counts them.",
      "changelog": ["Every rule mapped"],
      "marks": [{"page": "/report/operations", "at": "#zbCpCheck", "shown": "after picking a compliance profile"}]
    },
    {
      "id": "compliance-pack", "release": "2026-10-31", "label": "Compliance pack",
      "what": "A control mapping report, a policy export, a test plan by control and synthetic DLP test files, as local files.",
      "changelog": ["Compliance pack"],
      "marks": [{"page": "/report/operations", "at": "button[data-zb-cp-file=\"compliance-pack.zip\"]", "shown": "after picking a compliance profile"}]
    },
    {
      "id": "irs-fti-pack", "release": "2026-10-31", "label": "IRS 1075 FTI Pack",
      "what": "A policy pack for federal tax information: FTI markings and return data, monitor-only and disabled.",
      "changelog": ["IRS 1075 FTI Pack"],
      "marks": [{"page": "/report/operations", "at": "#zbCpSummary a.rp-btn[href*=\"simple=deploy\"]", "shown": "after picking IRS Publication 1075"}]
    },
    {
      "id": "aiguard-federal", "release": "2026-10-31", "label": "AI Guard federal profiles",
      "what": "NIST SP 800-53, NIST SP 800-171 / CMMC and IRS 1075 detection profiles, following the compliance profile.",
      "changelog": ["AI Guard federal profiles"],
      "marks": [{"page": "/report/operations", "at": "#aigProfile", "shown": "in AI Guard detection policy"}]
    },
    {
      "id": "profile-view", "release": "2026-10-31", "label": "Read against a profile",
      "what": "Read this assessment against a compliance profile: each control met, partially met, not met or not tested.",
      "changelog": ["Read against a profile"],
      "marks": [{"page": "/report/compliance", "at": "#cpProfileH"}]
    },
    {
      "id": "federal-preset", "release": "2026-10-31", "label": "Federal and public sector preset",
      "what": "A Federal and public sector vertical and a compliance profile in the POV intake; Simple mode asks which compliance rules apply.",
      "changelog": ["Federal and public sector preset"],
      "marks": [
        {"page": "/simple", "at": "input[name=\"smProfile\"]", "shown": "in the Protect task"},
        {"page": "/report/pov", "at": "select[data-pv-compliance]", "shown": "in the POV intake"}
      ]
    },
    {
      "id": "zia-governance-checks", "release": "2026-10-31", "label": "Governance checks",
      "what": "ZIA platform checks of Zscaler's own configuration audit, the alert subscriptions and NSS log streaming (N/A when NSS is not licensed); recipients are counted, never listed.",
      "changelog": ["ZIA governance and audit checks", "Zscaler's configuration audit", "Alert subscriptions", "NSS server health", "Log streaming out of ZIA", "N/A when not licensed"],
      "marks": [{ "page": "/", "at": "#scopeField input.scope-cb[value=\"zia_extras\"]", "shown": "on the Scope page" }]
    },
    {
      "id": "rbac-admin-access", "release": "2026-10-31", "label": "Admin password expiry and Support access",
      "what": "RBAC checks of the ZIA admin password expiry and of how long Zscaler Support may sign in to the admin portal.",
      "changelog": ["Admin password expiry", "Zscaler Support access"],
      "marks": [{ "page": "/", "at": "#scopeField input.scope-cb[value=\"rbac\"]", "shown": "on the Scope page" }]
    },
    {
      "id": "zpa-rbac-audit", "release": "2026-10-31", "label": "ZPA admin and RBAC audit",
      "what": "The RBAC checks now cover ZPA administration: admins and their second factor, SSO-only sign-in, full-access roles, read-only roles, API keys, break-glass accounts, microtenant admins, provisioning keys, and Privileged Remote Access credentials and approvals. Read-only; key and password values are never read into results.",
      "changelog": ["ZPA admin and RBAC audit", "ZPA admins and second factor", "SSO-only admin sign-in", "Full-access and read-only roles", "ZPA API keys",
                    "Break-glass accounts", "Microtenant admins", "Provisioning keys", "Privileged Remote Access credentials and approvals"],
      "marks": [
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"rbac\"]", "shown": "on the Scope assessment step" }
      ]
    },
    {
      "id": "rules-csv", "release": "2026-10-31", "label": "Rules from a spreadsheet",
      "what": "Rules from a spreadsheet on Bulk changes: export Cloud Firewall, URL filtering or ZPA access policy rules as CSV, edit them offline and import the file as a previewed plan of adds, updates, moves and (only if you tick it) deletes, with the write gates, read-back and Undo.",
      "changelog": ["Rules from a spreadsheet", "Read from the tenant", "Download the rules as CSV", "Preview", "Remove rules not in the file", "Create new rules enabled"],
      "marks": [{ "page": "/report/operations", "at": "#rcExport", "shown": "after Read from the tenant, with Rules from a spreadsheet picked" }]
    },
    {
      "id": "scheduled-sync", "release": "2026-10-31", "label": "Scheduled sync",
      "what": "Scheduled sync on the change queue: a job keeps target tenants' rules in step with a source by filing a plan per target for four-eyes approval; nothing is applied until a named writer applies it.",
      "changelog": ["Scheduled sync", "Run now", "Bulk change plan"],
      "marks": [{ "page": "/report/queue", "at": "#syH" }]
    },
    {
      "id": "admin-zia-directory", "release": "2026-10-31", "label": "ZIA users, groups and departments",
      "what": "Day-to-day admin on Bulk changes: find ZIA users by name, add users, change their department and groups, and add, rename or delete groups and departments, with the same preview, write gates, read-back and Undo. A delete asks its name typed.",
      "changelog": ["ZIA users, groups and departments", "Day-to-day admin", "DELETE <name>"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds > legend" },
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zia_directory\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "admin-zia-pac", "release": "2026-10-31", "label": "ZIA PAC files",
      "what": "Hosted PAC files on Bulk changes: view each file and its versions, validate a PAC (parsed here, never run, and checked by ZIA), add a staged version, create or clone a file, switch the active version, with a line diff in the preview.",
      "changelog": ["ZIA PAC files"],
      "marks": [{ "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zia_pac\"]", "shown": "once the page lists the operation types" }]
    },
    {
      "id": "admin-zid", "release": "2026-10-31", "label": "ZIdentity users and API clients",
      "what": "ZIdentity users (find, add disabled, disable, enable, delete) and API clients (their scopes; a new client with only the scopes you tick, its secret shown once; rotate a secret, disable, enable or delete a client).",
      "changelog": ["ZIdentity users and API clients", "ROTATE <name>"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zid_users\"]", "shown": "once the page lists the operation types" },
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zid_api_clients\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "panos-migration", "release": "2026-10-31", "label": "Firewall and private access (Palo Alto Networks)",
      "what": "Migrate from another vendor reads a PAN-OS configuration export and builds a plan for Bulk changes: Cloud Firewall rules with their IP groups and network services, ZPA segments for GlobalProtect access, and every item that cannot be carried, with the reason.",
      "changelog": ["Firewall and private access", "Download the ZPA segments CSV"],
      "marks": [{ "page": "/report/vendor", "at": "#vmPanH" }]
    },
    {
      "id": "fw-import", "release": "2026-10-31", "label": "Firewall import from Palo Alto Networks",
      "what": "A Build new operation that creates the migration plan's groups, services and disabled Cloud Firewall rules, previewed against the tenant and undone by deleting what it created.",
      "changelog": ["Firewall import from Palo Alto Networks", "Open in Bulk changes"],
      "marks": [{ "page": "/report/vendor", "at": "#panOpen" }]
    },
    {
      "id": "local-plugins", "release": "2026-10-31", "label": "Local plugins",
      "what": "Off by default: Python packages an admin approves by their exact SHA-256 can add Bulk changes operations and read-only pages, always through the same gates.",
      "changelog": ["Local plugins", "Approve this hash"],
      "marks": [{ "page": "/report/advanced", "at": "#advPlugH" }]
    },
    {
      "id": "update-notify", "release": "2026-10-31", "label": "Update notifications",
      "what": "Say once per version, by e-mail or webhook (the digests' channel), when a newer version of the app is out. Off by default.",
      "changelog": ["Update notifications"],
      "marks": [{ "page": "/report/advanced", "at": "#advUpdNotify" }]
    },
    {
      "id": "net-dns-records", "release": "2026-10-31", "label": "DNS records for client hostnames",
      "what": "One DNS name per enrolled device for ZPA client-to-client access, as Unbound, BIND and CSV files to download. Built from the fleet read; nothing is applied.",
      "changelog": ["DNS records for client hostnames", "Build the records"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfDnsH" },
        { "page": "/report/fleet", "at": "#zfDnsBuild" }
      ]
    },
    {
      "id": "net-ip-ranges", "release": "2026-10-31", "label": "Zscaler IP ranges and allowlists",
      "what": "Zscaler's published IP ranges and host names for your cloud, joined per region, as firewall allowlists: plain list, CSV, Palo Alto lists, JSON or a Microsoft 365-style list. Fetching is off until you turn it on; files can be imported instead.",
      "changelog": ["Zscaler IP ranges and allowlists", "Fetch from config.zscaler.com", "Fetch now", "Import", "Forget the kept feeds", "Build the allowlist"],
      "marks": [
        { "page": "/report/exports", "at": "#exRgH" },
        { "page": "/report/exports", "at": "#exRgFetchOn" },
        { "page": "/report/exports", "at": "#exRgFetch" },
        { "page": "/report/exports", "at": "#exRgImport" },
        { "page": "/report/exports", "at": "#exRgBuild" }
      ]
    },
    {
      "id": "zcc-bypass-path", "release": "2026-10-31", "label": "Client Connector bypasses on the Path analyzer",
      "what": "The Path analyzer's Client Connector step checks every bypass in order (VPN gateways, destination bypasses, IP-based applications, Z-Tunnel 1.0 and 2.0) and names the one that decided.",
      "changelog": ["Client Connector bypasses on the Path analyzer", "VPN gateway bypass", "IP-based application bypass", "Z-Tunnel 1.0 and 2.0"],
      "marks": [{ "page": "/report/path", "at": "li.pm-hop[data-module=\"zcc\"] > .df-hop-h > strong", "shown": "after a destination is analyzed" }]
    },
    {
      "id": "zcc-tamper-passwords", "release": "2026-10-31", "label": "Tamper protection passwords",
      "what": "The Client Connector profile builder can set the app profile's uninstall, turn-off and log-out passwords: typed, sent once and never kept.",
      "changelog": ["Tamper protection passwords"],
      "marks": [{ "page": "/report/operations", "at": "#zcPwH", "shown": "once the Client Connector form is read" }]
    },
    {
      "id": "zcc-device-otp", "release": "2026-10-31", "label": "One-time passwords for a device",
      "what": "The fleet page shows a device's Client Connector one-time passwords for the help desk, once, for 60 seconds, after the assessor's name and a typed confirmation; never kept.",
      "changelog": ["One-time passwords for a device", "rate limit"],
      "marks": [{ "page": "/report/fleet", "at": "#zfOtpH" }]
    },
    {
      "id": "path-device", "release": "2026-10-31", "label": "Trace a user's device",
      "what": "Pick a user's enrolled device from the Client Connector Portal; the Path analyzer then uses its platform, the app profile the Portal reports for it and its client version, and says what is unknown.",
      "changelog": ["Trace a user's device"],
      "marks": [{ "page": "/report/path", "at": "#paDevice > summary" }]
    },
    {
      "id": "path-compare", "release": "2026-10-31", "label": "Compare two identities",
      "what": "The same destination for two identities, side by side, step by step, with the step where they diverge marked; CSV and JSON.",
      "changelog": ["Compare two identities"],
      "marks": [{ "page": "/report/path", "at": "#paCompare > summary" }]
    },
    {
      "id": "path-test-from-here", "release": "2026-10-31", "label": "Test from here",
      "what": "One click tests the destination from the computer running this app (name lookup, connect, TLS certificate) and compares it with the prediction.",
      "changelog": ["Test from here"],
      "marks": [{ "page": "/report/path", "at": "#paProbeRun", "shown": "after Analyze" }]
    },
    {
      "id": "list-fix", "release": "2026-10-31", "label": "Fix rows from Test a list",
      "what": "Fix selected now fixes Cloud Firewall, DNS Control and ATP rows too: IP destination groups, a new disabled rule or an existing one, the ATP allow and deny lists, each change explained and linked to its rows, then Prove it tests the rows again. IP destination groups and the ATP lists can also be changed on their own.",
      "changelog": ["Fix rows from Test a list", "Fix selected", "IP destination group change", "ATP allow and deny lists", "Prove it", "What this changes, in plain words", "Rows this fixes"],
      "marks": [
        { "page": "/report/path", "at": "#tab-list" },
        { "page": "/report/path", "at": "#plFix", "shown": "after a list is tested" },
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"list_fix\"]" },
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"ip_group_edit\"]" },
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"atp_list_edit\"]" }
      ]
    },
    {
      "id": "team-server",
      "release": "2026-10-31",
      "label": "Team server",
      "what": "The team server page: who you are and what you may do on each tenant profile, and for an administrator the accounts, roles and access per tenant profile.",
      "changelog": [
        "Team server",
        "Four-eyes with real people"
      ],
      "marks": [
        {
          "page": "/report/team",
          "at": "#tmMeH"
        },
        {
          "page": "/report/team",
          "at": ".rp-hero h1"
        }
      ]
    },
    {
      "id": "team-sign-in",
      "release": "2026-10-31",
      "label": "Sign in",
      "what": "Each person signs in with their own account on a team server, with lockout after wrong passwords, or through SSO.",
      "changelog": [
        "Sign in"
      ],
      "marks": [
        {
          "page": "/login",
          "at": "#lgGo"
        }
      ]
    },
    {
      "id": "team-scim",
      "release": "2026-10-31",
      "label": "SCIM provisioning",
      "what": "Your identity provider adds and removes accounts and groups through SCIM 2.0, with a token shown once.",
      "changelog": [
        "SCIM 2.0"
      ],
      "marks": [
        {
          "page": "/report/team",
          "at": ".rp-hero h1"
        }
      ]
    },
    {
      "id": "team-https",
      "release": "2026-10-31",
      "label": "HTTPS built in",
      "what": "HTTPS with your certificate, a self-signed one or Let's Encrypt, store encryption with key rotation, and FIPS mode.",
      "changelog": [
        "HTTPS built in",
        "Encryption at rest and FIPS mode"
      ],
      "marks": [
        {
          "page": "/report/team",
          "at": ".rp-hero h1"
        }
      ]
    },
    {
      "id": "team-share",
      "release": "2026-10-31",
      "label": "Share templates and plans",
      "what": "Your POV templates and saved deploy plans are yours; share them with people and groups.",
      "changelog": [
        "Shared templates and saved plans"
      ],
      "marks": [
        {
          "page": "/report/team",
          "at": "#tmShareH"
        },
        {
          "page": "/report/team",
          "at": "#tmShKind"
        }
      ]
    },
    {
      "id": "tenant-terraform", "release": "2026-10-31", "label": "Whole tenant as Terraform",
      "what": "Export from tenant as Terraform: ZIA, ZPA, Cloud & Branch Connector and Client Connector objects in scope as workspaces for the official providers, with import blocks to adopt the tenant without recreating anything, or as a clone with every rule disabled.",
      "changelog": ["Export from tenant as Terraform (whole tenant)", "Adopt or clone", "Keep each rule's state", "References, not ids", "No secrets, no surprises"],
      "marks": [{ "page": "/report/exports", "at": "#exTenantTf" }]
    },
    {
      "id": "fleet-import", "release": "2026-10-31", "label": "Import the portal's CSV exports",
      "what": "No device permission? Import the Device Details and Service Status exports from the Client Connector Portal and see the fleet without the API.",
      "changelog": ["Import the portal's CSV exports"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openFleetTab()\"]" },
        { "page": "/report/fleet", "at": "#zfImportH" }
      ]
    },
    {
      "id": "fleet-version-health", "release": "2026-10-31", "label": "Service health by version",
      "what": "ZIA, ZPA and ZDX active per Client Connector version, with the versions far below the fleet flagged.",
      "changelog": ["Service health by version"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfVerH", "shown": "after a read" }
      ]
    },
    {
      "id": "fleet-profile-health", "release": "2026-10-31", "label": "Health per app and forwarding profile",
      "what": "ZIA, ZPA and ZDX active per app profile and per forwarding profile, with the devices on each.",
      "changelog": ["Health per app and forwarding profile"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfProfHealthH", "shown": "after a read" }
      ]
    },
    {
      "id": "fleet-last-seen", "release": "2026-10-31", "label": "Last-seen histogram",
      "what": "How long ago each registered device was last seen: under 1 day, 1 to 7 days, 7 to 30 days, over 30 days, never.",
      "changelog": ["Last-seen histogram"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfSeenH", "shown": "after a read" }
      ]
    },
    {
      "id": "fleet-sites", "release": "2026-10-31", "label": "Site grouping",
      "what": "Devices counted per site, from the first letters of the host name, the part before a separator, or a list of site prefixes.",
      "changelog": ["Site grouping"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfSiteH", "shown": "after a read" }
      ]
    },
    {
      "id": "fleet-history", "release": "2026-10-31", "label": "Fleet history and trends",
      "what": "Save each read (counts only, on this computer), follow the trend of ZIA, ZPA and ZDX and compare any two reads.",
      "changelog": ["Fleet history and trends"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfHistH", "shown": "after a read" }
      ]
    },
    {
      "id": "fleet-pdf", "release": "2026-10-31", "label": "Fleet PDF report",
      "what": "The fleet page as a PDF report, counts only, beside the Excel and CSV exports.",
      "changelog": ["Fleet PDF report"],
      "marks": [
        { "page": "/report/fleet", "at": "#zfExpPdf" }
      ]
    },
    {
      "id": "traffic-session-logs", "release": "2026-10-31", "label": "Traffic and session logs",
      "what": "Upload ZPA LSS and ZIA NSS logs: sessions and failures over time with every failure reason in plain words, connector and Service Edge health, anomalies, and for ZIA blocks, rules hit, DLP, threats and SSL inspection.",
      "changelog": ["Traffic and session logs", "Connector and Service Edge health", "Anomalies", "Untrusted input, in memory only"],
      "marks": [{ "page": "/", "at": "button[onclick=\"openTrafficLogsTab()\"]" }]
    },
    {
      "id": "traffic-logs-custom-format", "release": "2026-10-31", "label": "Custom NSS feed formats",
      "what": "Paste a custom NSS feed's output format and its lines are split by it.",
      "changelog": ["Custom NSS feed formats"],
      "marks": [{ "page": "/report/traffic-logs", "at": "#tlFormatBox > summary" }]
    },
    {
      "id": "traffic-logs-saved", "release": "2026-10-31", "label": "Saved reports, counts only",
      "what": "Save an analysis as a file only you can read on this computer; downloads and saved reports are counts only unless you include names.",
      "changelog": ["Saved reports", "Counts only"],
      "marks": [{ "page": "/report/traffic-logs", "at": "#tlSavedBox > summary" }]
    },
    {
      "id": "traffic-logs-siem", "release": "2026-10-31", "label": "SIEM queries",
      "what": "The same questions as Splunk, Microsoft Sentinel and Elastic queries to copy.",
      "changelog": ["SIEM queries"],
      "marks": [{ "page": "/report/traffic-logs", "at": "#tlSiemH" }]
    },
    {
      "id": "readiness-tenant-checks", "release": "2026-10-31", "label": "Readiness: pending activation and SSL rule order",
      "what": "Readiness also says, with the steps to fix it, when ZIA changes are saved but not activated and when the SSL inspection rule order stops rules from applying.",
      "changelog": ["Readiness: pending activation and SSL rule order"],
      "marks": [
        { "page": "/", "at": "#rdConnect .rd-h", "shown": "after Authenticate" }
      ]
    },
    {
      "id": "tenant-health", "release": "2026-10-31", "label": "Tenant health",
      "what": "Tenant health: ZIA changes waiting for activation, the SSL rule order, certificates close to expiry with your own thresholds, and App Connector groups with no connector. Read-only.",
      "changelog": ["Tenant health", "certificate expiry thresholds"],
      "marks": [
        { "page": "/report/health", "at": "#thH" }
      ]
    },
    {
      "id": "api-calls", "release": "2026-10-31", "label": "API calls",
      "what": "Every Zscaler API call this app made since it started: path with ids masked, answer, time taken, retries and rate-limit waits, per run, with a CSV or JSON export. No body, token or secret.",
      "changelog": ["API calls", "export as CSV or JSON", "API calls of this run"],
      "marks": [
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#apicalls\"]" },
        { "page": "/report/advanced", "at": "#advApiH" },
        { "page": "/report/advanced", "at": "#advApiJob" },
        { "page": "/report/operations", "at": "#opApiCalls", "shown": "after a change is applied" }
      ]
    },
    {
      "id": "zdx-probe-tiers", "release": "2026-10-31", "label": "ZDX probes fitted to the tier",
      "what": "ZDX probe setup starts from a tier: Strict watches the most apps every 5 minutes, Balanced the Microsoft 365 core every 10, Permissive sign-in every 15, Healthcare adds Zoom.",
      "changelog": ["ZDX probes fitted to the tier"],
      "marks": [
        { "page": "/report/operations", "at": "#zdxTierH", "shown": "in ZDX probe setup" }
      ]
    },
    {
      "id": "pov-build", "release": "2026-10-31", "label": "POV build",
      "what": "The POV planner's Build tab: one plan across the builders the POV needs, one dry run with one plan hash, and one typed confirmation that applies every part in a safe order.",
      "changelog": ["POV build: one plan, one dry run, one apply", "Build tab"],
      "marks": [{ "page": "/report/pov", "at": "#tab-build" }]
    },
    {
      "id": "pov-build-dry-run", "release": "2026-10-31", "label": "One dry run",
      "what": "Every part of the POV build planned as one dry run: a section per product, every object before and after, one plan hash.",
      "changelog": ["One dry run"],
      "marks": [{ "page": "/report/pov", "at": "#pbPreview", "shown": "on the Build tab, after the intake" }]
    },
    {
      "id": "pov-build-confirm", "release": "2026-10-31", "label": "One typed confirmation",
      "what": "One phrase applies the whole POV build; it stops at the first part that does not apply.",
      "changelog": ["One typed confirmation"],
      "marks": [{ "page": "/report/pov", "at": "#pbPhrase", "shown": "after a dry run on the live tenant" }]
    },
    {
      "id": "pov-build-undo", "release": "2026-10-31", "label": "Undo everything applied so far",
      "what": "The Undo of a POV build: what it applied, latest part first, as one dry run and one confirmation.",
      "changelog": ["Undo everything applied so far"],
      "marks": [{ "page": "/report/pov", "at": "#pvBuild button.pb-undo-build", "shown": "after a build is applied" }]
    },
    {
      "id": "pov-build-choices", "release": "2026-10-31", "label": "Load choices from the tenant",
      "what": "Reads the certificates and Inspect rules the SSL certificates and AI Guard parts pick from.",
      "changelog": ["Load choices from the tenant"],
      "marks": [{ "page": "/report/pov", "at": "#pvBuild button.pb-choices", "shown": "when SSL certificates or AI Guard routing is ticked" }]
    },
    {
      "id": "rehearsal", "release": "2026-10-31", "label": "Rehearsal on sample or offline data",
      "what": "Every builder and Bulk changes type makes its full plan and dry run on the sample tenant and on an opened snapshot, labelled a rehearsal; nothing is ever applied there.",
      "changelog": ["Rehearsal on the sample tenant and snapshots"],
      "marks": [{ "page": "/report/operations", "at": "#opPreview" }]
    },
    {
      "id": "rehearsal-packs", "release": "2026-10-31", "label": "Rehearsal in Deploy policy packs",
      "what": "A policy pack's preview on the sample tenant or a snapshot says it is a rehearsal; deploying there is refused.",
      "changelog": ["Rehearsal in Deploy policy packs"],
      "marks": [{ "page": "/", "at": "#dzRehearsal", "shown": "after a preview on the sample tenant or a snapshot" }]
    },
    {
      "id": "zpa-segment-fields", "release": "2026-10-31", "label": "ZPA segment settings in bulk",
      "what": "Set the same fields on many ZPA application segments at once, Browser Access, PRA and inspection segments included, with the preview, write gates, read-back and Undo.",
      "changelog": ["ZPA segment settings in bulk", "Browser Access, PRA and inspection segments", "server groups and port ranges", "exact Undo"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"zpa_segment_fields\"]", "shown": "once the page has listed the operations" }]
    },
    {
      "id": "analyzer-continue", "release": "2026-10-31", "label": "Category analyzer: 20,000 URLs a run and Continue",
      "what": "The custom URL category analyzer looks up 20,000 URLs a run with progress, and Continue looks up the rest, up to 100,000.",
      "changelog": ["Continue in the URL category analyzer", "20,000 URLs a run", "progress and a stop on rate limits"],
      "marks": [{ "page": "/report/exports", "at": "#exAnalyze" }]
    },
    {
      "id": "retired-endpoint-pack", "release": "2026-10-31", "label": "Why the Endpoint DLP pack is gone",
      "what": "The pack library says why the PCI-only Endpoint DLP pack was retired and which packs cover endpoints now.",
      "changelog": ["Why the Endpoint DLP pack is gone"],
      "marks": [{ "page": "/report/advanced", "at": "#advRetired > strong" }]
    },
    {
      "id": "zpa-policy-completeness", "release": "2026-10-31", "label": "ZPA policy completeness",
      "what": "ZPA analysis reads every ZPA policy type and checks inspection, client forwarding bypasses, Privileged Remote Access, redirection, unmanaged-device isolation, business continuity and Branch and Cloud Connectors; the assessment has six new ZPA checks.",
      "changelog": ["Every ZPA policy type is read", "AppProtection inspection", "Client forwarding bypass", "Privileged Remote Access",
                    "Redirection", "Unmanaged-device access", "Infrastructure in the diagnostics", "Six new assessment checks"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openZpaTab()\"]" },
        { "page": "/report/zpa", "at": ".rp-hero h1" },
        { "page": "/report/zpa", "at": "#zpRun" }
      ]
    },
    {
      "id": "zia-forwarding-checks", "release": "2026-10-31", "label": "Forwarding and traffic path checks",
      "what": "Ten ZIA platform checks on how traffic leaves: forwarding rules that go around ZIA, proxy chaining without a fallback, ZPA and dedicated IP gateways, data centre exclusions, GRE tunnel data centre diversity, IPv6, NAT control, Virtual Service Edge redundancy and DNS gateway failover.",
      "changelog": ["Forwarding and traffic path checks", "Forwarding around ZIA", "Proxy chaining fallback", "ZPA gateways", "Data centre exclusions", "GRE tunnel diversity", "IPv6 handling", "Dedicated IP gateway failover", "NAT control scope", "Virtual Service Edge redundancy", "DNS gateway failover"],
      "marks": [{ "page": "/", "at": "#scopeField input.scope-cb[value=\"zia_extras\"]", "shown": "on the Scope page" }]
    },
    {
      "id": "path-forwarding-step", "release": "2026-10-31", "label": "Path analyzer: Forwarding control",
      "what": "The Path analyzer's last ZIA step says how ZIA sends allowed traffic on (direct, proxy chaining, ZPA, a dedicated IP or dropped), with the gateway's fallback, any NAT control rewrite, IPv6 and data centre exclusions.",
      "changelog": ["Forwarding control step"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" },
        { "page": "/report/path", "at": "#paFramework > summary" }
      ]
    },
    {
      "id": "threat-saas-checks", "release": "2026-10-31", "label": "Threat protection and SaaS Security checks",
      "what": "The assessment now scores the threat protection settings (Sandbox hash list, custom IPS signatures, mobile, FTP, notifications, alerts, risk profiles, Browser Control, domain fronting, SafeSearch) and SaaS Security malware coverage, under ZIA platform.",
      "changelog": ["Threat protection checks", "SaaS Security hygiene", "URL and app settings", "Browser Control", "Not licensed is not a failure", "Offline too"],
      "marks": [{ "page": "/", "at": ".scope-cb[value=\"zia_extras\"]", "shown": "on the Scope page" }]
    },
    {
      "id": "sandbox-hashes", "release": "2026-10-31", "label": "Sandbox file hashes",
      "what": "Block files your incident response confirmed as malicious by their MD5 hash, with a preview, a typed confirmation, a read-back and Undo.",
      "changelog": ["Sandbox file hashes"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"zia_sandbox_hashes\"]", "shown": "once the builders load" }]
    },
    {
      "id": "cloud-app-sanction", "release": "2026-10-31", "label": "Sanction or unsanction cloud apps",
      "what": "Sanction or unsanction cloud apps in Bulk changes: up to 100 apps at once, with each app's state, risk and traffic from ZIA Insights, the typed phrase, the read-back and an Undo that puts each app back as it was.",
      "changelog": ["Sanction or unsanction cloud apps", "Exact Undo"],
      "marks": [{ "page": "/report/operations", "at": "#opSanction" }]
    },
    {
      "id": "shadow-it-checks", "release": "2026-10-31", "label": "Shadow IT and SaaS checks",
      "what": "Three assessment checks from ZIA Insights: high-risk unsanctioned apps that still carry traffic, high-risk apps nobody has decided on, and sanctioned SaaS apps with no SaaS Security API tenant.",
      "changelog": ["High-risk unsanctioned apps still carry traffic", "High-risk apps with no sanction decision", "Sanctioned SaaS apps with no SaaS Security API tenant"],
      "marks": [{ "page": "/", "at": "button[onclick=\"openInsightsTab()\"]" }]
    },
    {
      "id": "insights-sections", "release": "2026-10-31", "label": "More Traffic insights",
      "what": "Traffic insights now also shows web threats by class and super-category, firewall traffic by location and network service, security incidents by location, and IoT and unmanaged device counts.",
      "changelog": ["Web threats by class and super-category", "Firewall traffic by location and network service", "Security incidents by location", "IoT and unmanaged devices"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openInsightsTab()\"]" },
        { "page": "/report/insights", "at": "#tiRun" }
      ]
    },
    {
      "id": "cloud-connector", "release": "2026-10-31", "label": "Cloud & Branch Connector",
      "what": "The Cloud & Branch Connector page and eight checks: connector groups and versions, forwarding rules that send workload traffic DIRECT, gateways, locations, activation, admins and API keys, with a link into the Path analyzer's workload trace.",
      "changelog": ["Cloud & Branch Connector page", "Cloud & Branch Connector", "Eight assessment checks", "Workload path link", "Trace in the Path analyzer", "Never read into a result", "Snapshots and the sample tenant"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openCloudConnectorTab()\"]" },
        { "page": "/report/ztw", "at": ".rp-hero h1" },
        { "page": "/report/path", "at": ".rp-hero h1" }
      ]
    },
    {
      "id": "other-products", "release": "2026-10-31", "label": "Other Zscaler products",
      "what": "Read-only coverage of Zero Trust Branch, External attack surface (EASM), Business Insights, Zero Trust Cellular and Microsegmentation: what the tenant has, in plain words, and best-practice checks, each behind its own Scope page box.",
      "changelog": ["Other Zscaler products", "Zero Trust Branch", "External attack surface (EASM)", "Business Insights", "Zero Trust Cellular",
                    "Microsegmentation", "Five new Scope page boxes", "20 new checks", "Sample tenant and snapshots"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openOtherProductsTab()\"]" },
        { "page": "/report/other-products", "at": "#opRun" }
      ]
    },
    {
      "id": "aiguard-page", "release": "2026-10-31", "label": "AI Guard page",
      "what": "The AI Guard page: its detection policies, policy match rules, LLM applications and credential names (never a key), read only when AI Guard is ticked.",
      "changelog": ["AI Guard page", "AI Guard"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAiGuardTab()\"]" },
        { "page": "/report/aiguard", "at": ".rp-hero h1" }
      ]
    },
    {
      "id": "aiguard-test-prompt", "release": "2026-10-31", "label": "Test a prompt",
      "what": "Test a prompt: send one made-up prompt from a fixed list to AI Guard and see what each detector did. Nothing you type is ever sent.",
      "changelog": ["Test a prompt"],
      "marks": [
        { "page": "/report/aiguard", "at": "#agTestH" }
      ]
    },
    {
      "id": "zwa-incidents-in-depth", "release": "2026-10-31", "label": "Incidents in depth",
      "what": "Incidents in depth on the FP/TP detection ratio page: one Workflow Automation incident's details, triggers, change history and tickets (metadata only), and the Workflow Automation audit log.",
      "changelog": ["Incidents in depth", "Details"],
      "marks": [
        { "page": "/report/health", "at": "#zwaH" }
      ]
    },
    {
      "id": "zwa-close-false-positives", "release": "2026-10-31", "label": "Close as false positives",
      "what": "Close as false positives: close a noisy rule's or destination's open Workflow Automation incidents through Bulk changes, with the typed phrase and your name in each incident's note.",
      "changelog": ["Close as false positives", "Close DLP incidents as false positives"],
      "marks": [
        { "page": "/report/health", "at": "a.dh-close", "shown": "after the report, on a noisy rule or destination" }
      ]
    },
    {
      "id": "zdx-cloud-path", "release": "2026-10-31", "label": "ZDX cloud path",
      "what": "The path ZDX measured to an application, leg by leg, next to the predicted path: time, loss, hops and tunnel. No device or person is named.",
      "changelog": ["ZDX cloud path"],
      "marks": [
        {"page": "/report/path", "at": "#zdxCpH"}
      ]
    },
    {
      "id": "zdx-score-analysis", "release": "2026-10-31", "label": "ZDX score analysis",
      "what": "A ZDX score analysis of one application on one device, to find why it is slow. It needs the write gates and the phrase START ANALYSIS, and is rate-limited.",
      "changelog": ["ZDX score analysis"],
      "marks": [
        {"page": "/report/path", "at": "#zdxRcaH", "shown": "after opening the ZDX panel"}
      ]
    },
    {
      "id": "builders-zid-zcc-live", "release": "2026-10-31", "label": "Group members and live app profile changes",
      "what": "New Bulk changes operations: ZIdentity group members, and turning Client Connector app profiles on or off or changing their DNS and tunnel settings.",
      "changelog": ["ZIdentity group members", "Client Connector app profiles on or off", "Client Connector app profile settings"],
      "marks": [
        {"page": "/report/operations", "at": "#opBuildKinds > legend", "shown": "after the builders load"}
      ]
    },
    {
      "id": "zcc-device-details", "release": "2026-10-31", "label": "Device details",
      "what": "One Client Connector device's service state by its device id: services, versions, strict enforcement, anti-tampering and trust. Ids stay hidden.",
      "changelog": ["Device details"],
      "marks": [
        {"page": "/report/fleet", "at": "#zfDeviceH"}
      ]
    },
    {
      "id": "zcc-disable-reasons", "release": "2026-10-31", "label": "Disable-reason counts",
      "what": "How often Client Connector was switched off, per reason, device type and service, on screen or as a CSV. No user or device is listed.",
      "changelog": ["Disable-reason counts"],
      "marks": [
        {"page": "/report/fleet", "at": "#zfDisableH"}
      ]
    }
  ]
};
// ── end of the manifest ──

(function () {
  'use strict';
  if (window.WhatsNew) return;
  const M = window.WHATS_NEW || {};
  const KEY = 'zme_hide_new_marks';
  const DATE = /^\d{4}-\d{2}-\d{2}$/;
  const norm = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();

  // ── Which features are marked ───────────────────────────────────────
  // The newest `keep` releases (default 2), newest first: the dates in
  // "releases" and on the features, so a release with nothing to mark still
  // pushes the oldest set out.
  function releases(m) {
    m = m || M;
    const keep = Math.max(1, Number(m.keep) || 2);
    const named = Object.keys(m.releases || {});
    const dates = Array.from(new Set(named.concat((m.features || []).map(f => f && f.release)).filter(d => typeof d === 'string' && DATE.test(d))));
    return dates.sort().reverse().slice(0, keep);
  }
  function active(m) {
    m = m || M;
    const keep = releases(m);
    return (m.features || []).filter(f => f && keep.indexOf(f.release) >= 0 && Array.isArray(f.marks));
  }
  function sentence(f) { return words([f]); }
  // "New in the <date> update: <what>", one line per release, newest first.
  function words(features) {
    const by = {};
    features.forEach(f => { (by[f.release] = by[f.release] || []).push(norm(f.what)); });
    return Object.keys(by).sort().reverse().map(d => `New in the ${d} update: ${by[d].join(' ')}`).join(' ');
  }
  function pageKey() {
    const forced = document.documentElement.getAttribute('data-hh-page');
    if (forced) return forced;
    return (location.pathname || '/').replace(/\/+$/, '') || '/';
  }
  function hidden() {
    try { return window.localStorage.getItem(KEY) === '1'; } catch (e) { return false; }
  }
  function setHidden(on) {
    try { if (on) window.localStorage.setItem(KEY, '1'); else window.localStorage.removeItem(KEY); } catch (e) { /* storage blocked: this page only */ }
    forced = on ? 'hide' : 'show';
    refresh();
  }
  let forced = '';   // the choice made on this page when storage is blocked
  const isHidden = () => (forced ? forced === 'hide' : hidden());

  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function all(sel) {
    try { return Array.from(document.querySelectorAll(sel)); } catch (e) { return []; }
  }

  // ── Saying which item is new ────────────────────────────────────────
  // The items on this page: element → the features it shows.
  function plan() {
    const page = pageKey(), out = new Map();
    active().forEach(f => f.marks.forEach(mk => {
      if (!mk || mk.page !== page || typeof mk.at !== 'string') return;
      all(mk.at).forEach(el => {
        if (el.closest('[data-hh-ui]')) return;
        const list = out.get(el) || [];
        if (list.indexOf(f) < 0) list.push(f);
        out.set(el, list);
      });
    }));
    return out;
  }
  function unmark(el) { el.removeAttribute('data-wn-new'); el.removeAttribute('data-wn-for'); }
  function legendFor() {
    const anchors = (M.legend && (M.legend[pageKey()] || M.legend['*'])) || [];
    for (const sel of anchors) { const a = all(sel)[0]; if (a) return a; }
    return null;
  }
  function placeLegend() {
    const at = legendFor();
    if (!at) return;
    const have = document.querySelector('.wn-legend');
    if (have && have.parentElement === at) return;
    if (have) have.remove();
    const p = make('p', 'wn-legend');
    const star = make('span', 'wn-legend-mark', '*');
    star.setAttribute('aria-hidden', 'true');
    p.append(star, document.createTextNode(' New in this version'));
    if (at.id === 'dbFoot') at.insertBefore(p, at.firstChild); else at.appendChild(p);
  }

  // Take every "new" and the legend off the page.
  function clear() {
    all('.wn-legend').forEach(n => n.remove());
    all('[data-wn-for]').forEach(unmark);
  }
  function apply() {
    if (isHidden()) { clear(); return 0; }
    const want = plan();
    all('[data-wn-for]').forEach(el => { if (!want.has(el)) unmark(el); });
    want.forEach((features, el) => {
      const text = words(features);
      if (el.getAttribute('data-wn-new') !== text) el.setAttribute('data-wn-new', text);
      if (!el.hasAttribute('data-wn-for')) el.setAttribute('data-wn-for', '');
    });
    if (want.size) placeLegend(); else all('.wn-legend').forEach(n => n.remove());
    return want.size;
  }
  let queued = false;
  function soon() {
    if (queued) return;
    queued = true;
    (window.requestAnimationFrame || (f => window.setTimeout(f, 16)))(() => { queued = false; apply(); });
  }
  function refresh() { clear(); apply(); toggle(); }

  // ── "Hide new marks" in Advanced settings (this browser only) ───────
  function toggle() {
    if (pageKey() !== '/report/advanced') return;
    const after = document.getElementById('advGlassNote');
    if (!after) return;
    let box = document.getElementById('advWnHide');
    if (!box) {
      const lead = make('p', 'adv-lead', 'A * after a name marks a feature from the newest two updates. Point at it, or click it, to read what is new. Hide the marks if you do not need them; the choice is kept in this browser only.');
      lead.id = 'advWnLead';
      const lab = make('label', 'adv-switch');
      lab.htmlFor = 'advWnHide';
      box = make('input');
      box.type = 'checkbox';
      box.id = 'advWnHide';
      box.setAttribute('aria-describedby', 'advWnLead');
      box.addEventListener('change', () => setHidden(box.checked));
      lab.append(box, make('span', null, 'Hide new marks'));
      after.insertAdjacentElement('afterend', lead);
      lead.insertAdjacentElement('afterend', lab);
    }
    box.checked = isHidden();
  }

  function start() {
    if (!document.body) { document.addEventListener('DOMContentLoaded', start, { once: true }); return; }
    toggle();
    apply();
    new MutationObserver(soon).observe(document.body, { subtree: true, childList: true });
    window.addEventListener('storage', e => { if (e.key === KEY || e.key === null) { forced = ''; refresh(); } });
  }

  window.WhatsNew = { manifest: M, KEY, releases, active, sentence, words, pageKey, hidden: isHidden, setHidden, apply, clear, refresh };
  start();
})();
