"""Migrate from another DLP: a fail-closed converter from a vendor's policy
export to disabled ZIA DLP objects, one adapter per source vendor.

Four adapters: Symantec DLP (Broadcom, the Enforce XML export), Forcepoint
DLP (the Security Manager's policy export zip or REST JSON), Netskope
(the Real-time Protection policy export, JSON or CSV, with dictionary
CSVs) and Skyhigh Security (the Policy Templates zip or SSE policy JSON).
Each adapter reads its vendor's file types into the same inventory shape,
and each carries an API cross-reference: which source object and field
lands on which ZIA object and field, through which ZIA API call and
Terraform resource, and how (generated, reviewed, attested, by hand, or
not at all), so a migration can be planned end to end from the page.

The contract, unchanged from the stand-alone tool this grew from:

* **Inventory** reads the export (read-only, DTD/entities refused, zips
  opened in memory) and lists every policy with its id and name, bound to
  the export's SHA-256, plus the detection facets recognised from the
  export's element or key names. The vendor's semantics are not
  interpreted beyond that.
* **Decisions** are a reviewed JSON mapping: every source policy needs
  approved translations (one target rule per channel it is carried to:
  web, endpoint, SaaS Security API or email, each with named engines and
  the channel's own fields) or an approved retirement / exclusion with a
  reason; dictionaries and engines are spelled out and approved one by
  one. The decisions carry the export's SHA-256, so a changed export
  invalidates them until reviewed.
* **Compile** is fail-closed: any unmapped or unapproved object blocks the
  run (a report with the questions, no Terraform); a ready run emits
  native `.tf.json` for the zscaler/zia provider in which every rule, on
  every channel, is DISABLED. Enabling, ordering with the tenant's existing rules,
  applying and activating are separate change-control steps done
  elsewhere (the Terraform hand-off, Deploy policy packs).

Nothing here contacts a tenant or writes to one."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# The same Terraform and provider constraints as the pack hand-off, so the two
# converters cannot drift: a `~>` constraint in the configuration, the exact
# build fixed by the team's .terraform.lock.hcl.
from pack_terraform import PROVIDER_SOURCE, PROVIDER_VERSION, TERRAFORM_VERSION  # noqa: E402
SAFE_ACTIONS = ("BLOCK", "CONFIRM", "ALLOW")
MATCH_TYPES = ("MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE")
MAX_EXPORT_BYTES = 32 * 1024 * 1024
WEB_RULE_LIMIT = 127

# ── ZIA targets: the objects every adapter lands on ────────────────────
# ZIA API v1 (https://zsapi.<cloud>.net/api/v1, or OneAPI
# https://api.zsapi.net/zia/api/v1) and the zscaler/zia Terraform provider.
ZIA_TARGETS: Dict[str, Dict[str, str]] = {
    "dictionary": {"object": "dlpDictionaries", "api": "GET /dlpDictionaries · POST /dlpDictionaries · PUT /dlpDictionaries/{id} · POST /dlpDictionaries/validateDlpPattern",
                   "terraform": "zia_dlp_dictionaries"},
    "predefined": {"object": "dlpDictionaries (predefined, custom=false)", "api": "GET /dlpDictionaries/lite · GET /dlpDictionaries/{id}/predefinedIdentifiers",
                   "terraform": "data zia_dlp_dictionaries (by name) · data zia_dlp_dictionary_predefined_identifiers"},
    "edm": {"object": "dlpDictionaries (dictionaryType EXACT_DATA_MATCH) + EDM schema", "api": "GET /dlpExactDataMatchSchemas · GET /dlpExactDataMatchSchemas/lite (schemas are built by the Index Tool VM, not by the API)",
            "terraform": "data zia_dlp_edm_schema · zia_dlp_dictionaries (exact_data_match_details)"},
    "idm": {"object": "dlpDictionaries (dictionaryType INDEXED_DATA_MATCH) + IDM profile", "api": "GET /idmprofile · GET /idmprofile/lite (profiles are built by the Index Tool VM)",
            "terraform": "data zia_dlp_idm_profile · zia_dlp_dictionaries (idm_profile_match_accuracy)"},
    "engine": {"object": "dlpEngines", "api": "GET /dlpEngines · POST /dlpEngines · PUT /dlpEngines/{id} · GET /dlpEngines/lite", "terraform": "zia_dlp_engines"},
    "rule": {"object": "webDlpRules", "api": "GET /webDlpRules · POST /webDlpRules · PUT /webDlpRules/{id} · GET /webDlpRules/lite", "terraform": "zia_dlp_web_rules"},
    "endpoint_rule": {"object": "endPointDlpRules (Endpoint DLP)", "api": "GET /endPointDlpRules · POST /endPointDlpRules · PUT /endPointDlpRules/{id} · GET /endPointDlpRules/lite",
                      "terraform": "zia_endpoint_dlp_rules · data zia_eun_user_confirmation_template_product (CONFIRM)"},
    "saas_rule": {"object": "casbDlpRules (SaaS Security API)", "api": "GET /casbDlpRules · POST /casbDlpRules · PUT /casbDlpRules/{id} · GET /casbTenant/lite (onboarded tenants)",
                  "terraform": "zia_casb_dlp_rules · data zia_casb_tenant"},
    "email_rule": {"object": "emailDlpRules (Outbound Email DLP)", "api": "GET /emailDlpRules · POST /emailDlpRules · PUT /emailDlpRules/{id} · GET /casbTenant/lite (onboarded email tenants)",
                   "terraform": "zia_outbound_email_dlp · data zia_casb_tenant"},
    "channels": {"object": "webDlpRules · endPointDlpRules · casbDlpRules · emailDlpRules (one target rule per channel)",
                 "api": "POST /webDlpRules · POST /endPointDlpRules · POST /casbDlpRules · POST /emailDlpRules",
                 "terraform": "zia_dlp_web_rules · zia_endpoint_dlp_rules · zia_casb_dlp_rules · zia_outbound_email_dlp"},
    "template": {"object": "dlpNotificationTemplates", "api": "GET /dlpNotificationTemplates · POST /dlpNotificationTemplates", "terraform": "zia_dlp_notification_templates"},
    "identity": {"object": "webDlpRules.users / groups / departments / locations / locationGroups", "api": "GET /users · GET /groups · GET /departments · GET /locations (ids for the rule's criteria)",
                 "terraform": "zia_dlp_web_rules.users / groups / departments / locations (id blocks)"},
    "apps": {"object": "webDlpRules.cloudApplications / urlCategories", "api": "GET /cloudApplications/lite · GET /urlCategories/lite", "terraform": "zia_dlp_web_rules.cloud_applications / url_categories"},
    "receiver": {"object": "webDlpRules.icapServer / zscalerIncidentReceiver / auditor", "api": "GET /icapServers · GET /incidentReceiverServers · GET /auditors", "terraform": "data zia_dlp_icap_servers · data zia_dlp_incident_receiver_servers"},
    "activate": {"object": "configuration activation", "api": "POST /status/activate (never called by this tool)", "terraform": "zia_activation_status"},
}


def _row(facet: str, source_object: str, source_field: str, target: str, zia_field: str, carried: str, note: str = "") -> Dict[str, str]:
    t = ZIA_TARGETS[target]
    return {"facet": facet, "source_object": source_object, "source_field": source_field, "zia_object": t["object"], "zia_field": zia_field,
            "zia_api": t["api"], "terraform": t["terraform"], "carried": carried, "note": note}


# How a row is carried: generated (the compile emits it from the
# decisions), reviewed (a person writes it in the decisions file),
# attested (built by hand in ZIA and attested in the decisions), manual
# (set on the rule after apply; the efficacy mapping scores it 0),
# dropped (no ZIA equivalent).
CARRIED = ("generated", "reviewed", "attested", "manual", "dropped")

# ── Target channels: the ZIA rule a decision can land on ───────────────
# The same conventions the policy packs deploy with (pack_channels and
# pack_terraform; tests pin the parity): every rule DISABLED, the
# channel's own action vocabulary, its API limits, its required fields.
ENDPOINT_TRUST_LEVELS = ("UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST")
ENDPOINT_TRANSFER_METHODS = ("REMOVABLE_DRIVE_TRANSFER", "NETWORK_DRIVE_TRANSFER", "APPLICATION_FILE_ACCESS", "PRINTING")
SAAS_RULE_TYPES = ("OFLCASB_DLP_FILE", "OFLCASB_DLP_EMAIL", "OFLCASB_DLP_CRM", "OFLCASB_DLP_ITSM",
                   "OFLCASB_DLP_COLLAB", "OFLCASB_DLP_REPO", "OFLCASB_DLP_STORAGE", "OFLCASB_DLP_GENAI")
TARGETS: Dict[str, Dict[str, Any]] = {
    "web": {"label": "Inline Web DLP", "resource": "zia_dlp_web_rules", "zia": "rule", "covers": ("web",),
            "actions": ("BLOCK", "CONFIRM", "ALLOW"), "monitor": "ALLOW", "max_engines": 4, "name_max": None, "rank": None, "needs": (),
            "fields": "protocols HTTP/HTTPS; the rule applies to Any user and location (scope_acknowledged_any)"},
    "endpoint": {"label": "Endpoint DLP (Client Connector)", "resource": "zia_endpoint_dlp_rules", "zia": "endpoint_rule", "covers": ("endpoint",),
                 "actions": ("ALLOW", "BLOCK", "CONFIRM"), "monitor": "ALLOW", "max_engines": 4, "name_max": None, "rank": 7, "needs": ("data_transfer_method",),
                 "fields": ("data_transfer_method: one of " + ", ".join(ENDPOINT_TRANSFER_METHODS) + " (one per rule; copy the entry for another method); "
                            "device_trust_levels optional (default all four: " + ", ".join(ENDPOINT_TRUST_LEVELS) + "); CONFIRM binds the tenant's Endpoint DLP "
                            "user-confirmation template through a Terraform variable")},
    "saas": {"label": "SaaS Security API DLP (out-of-band CASB)", "resource": "zia_casb_dlp_rules", "zia": "saas_rule", "covers": ("saas-api",),
             "actions": ("OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW"), "monitor": "OFLCASB_DLP_REPORT_INCIDENT", "max_engines": 4, "name_max": 31, "rank": 7,
             "needs": ("saas_type", "tenants"),
             "fields": ("saas_type: one of " + ", ".join(SAAS_RULE_TYPES) + "; tenants: the onboarded SaaS application tenant names (Administration > SaaS Application "
                        "Tenants) or the word \"variable\" to fill the ids in at terraform plan; the rule ships as report-incident (SaaS remediations such as "
                        "quarantine or remove sharing go in designed_action and are set in the portal once incidents are reviewed); target_name at most 31 characters")},
    "email": {"label": "Outbound Email DLP", "resource": "zia_outbound_email_dlp", "zia": "email_rule", "covers": ("email",),
              "actions": ("ALLOW", "BLOCK"), "monitor": "ALLOW", "max_engines": 4, "name_max": None, "rank": None, "needs": ("tenants",),
              "fields": ("tenants: the onboarded email tenant names or \"variable\"; action ALLOW or BLOCK (the zscaler/zia provider accepts ALLOW, BLOCK or "
                         "QUARANTINE on an email rule, not CUSTOMHEADERINSERTION), so a custom header goes in designed_action (CUSTOMHEADERINSERTION) with "
                         "custom_header, recorded in the report and set in the portal once incidents are reviewed")},
}
_CHANNEL_KINDS = ("web", "email", "endpoint", "saas-api", "cloud-download", "ftp")


def _channel_kind(text: str) -> str:
    """The channel vocabulary word a source mention belongs to (web, email,
    endpoint, saas-api, cloud-download), from the adapter's normalised text
    or from the raw protocol name; anything else is "other"."""
    t = str(text).strip().lower()
    for k in _CHANNEL_KINDS:
        if t == k or t.startswith(k + " ") or t.startswith(k + "("):
            return k
    norm = _norm_channel(text)
    return norm.split(" (", 1)[0] if norm != str(text).strip() else "other"

# ── Vendors ────────────────────────────────────────────────────────────
# One entry per source product: the file types its export produces
# (`files`, what the page accepts), how to get them, the source API the
# fields come from, and the cross-reference from its objects and fields to
# ZIA's. Source field names follow each vendor's published export and API
# guide at the time the adapter was written; the inventory lists every key
# it does not recognise so a newer export is mapped rather than misread.
VENDORS: Dict[str, Dict[str, Any]] = {
    "symantec": {
        "name": "Symantec DLP (Broadcom)", "prefix": "sym",
        "export": "Enforce policy export (XML, Policy Export/Import format)",
        "accepts": [".xml"], "status": "available",
        "files": [{"ext": ".xml", "what": "Enforce Policy Export/Import XML: one file, every selected policy with its detection rules, response rules, policy groups and exceptions"}],
        "how": "In the Enforce console export the policies (Manage > Policies > Policy List > Export); or fetch the XML from your tenant's documented export URL with the command-line fetcher.",
        "coverage": "Custom phrase/pattern dictionaries, explicitly reviewed engine expressions and ZIA web, endpoint, SaaS Security API and email DLP rules (one decision per channel). Detection, response, exception, scope, EDM and IDM semantics are not inferred from the XML; each needs a reviewed decision.",
        "source_api": {"name": "Symantec DLP Enforce REST API", "base": "https://<Enforce server>/ProtectManager/webservices/v2 (Incident Reporting and Update API)",
                       "auth": "Enforce user with the Incident Reporting role; HTTPS basic or SAML session",
                       "calls": ["Policy Export/Import: Manage > Policies > Policy List > Export (XML); there is no policy read API, the XML is the source",
                                 "Incident Reporting API: GET /incidents (query and details) for the before/after incident comparison in monitor mode"]},
        "crossref": [
            _row("content_patterns", "Policy > detection rule > Content Matches Keyword / Regular Expression", "keyword, regex (with minMatches)", "dictionary", "phrases[].phrase, patterns[].pattern (dictionaryType PATTERNS_AND_PHRASES, customPhraseMatchType)", "generated",
                 "spelled out in the decisions' dictionaries; 256 phrases and 8 patterns per dictionary, patterns validated by the API"),
            _row("data_identifiers", "Content Matches Data Identifier (predefined)", "dataIdentifier name", "predefined", "a predefined dictionary chosen by name", "attested", "Zscaler ships ~120 predefined dictionaries; pick the one that matches and attest it"),
            _row("edm", "Exact Data Matching profile", "EDM profile, columns, match count", "edm", "EDM schema + dictionary", "attested", "the Index Tool VM indexes the source data set; the schema is chosen in the dictionary"),
            _row("idm", "Indexed Document Matching profile", "IDM profile, similarity %", "idm", "IDM profile + dictionary (match accuracy)", "attested", ""),
            _row("ml", "Vector Machine Learning profile", "VML profile", "predefined", "ML predefined dictionary where one exists", "attested", ""),
            _row("match_thresholds", "Detection rule minMatches / count", "minMatches, match count", "engine", "engineExpression ((D<dict>.S > n)); AND/OR between conditions", "reviewed", "strict 'more than n': a Symantec minMatches of 3 is .S > 2"),
            _row("channel", "Policy > protocol / endpoint destination", "protocol (HTTP, HTTPS, FTP, SMTP, endpoint)", "channels", "one decision per target channel: web (protocols HTTP/HTTPS), email (email_tenants), endpoint (data_transfer_method), saas (type, cloud_app_tenants)", "generated", "HTTP/HTTPS → web; SMTP → email; endpoint destinations → endpoint (one transfer method per rule); cloud storage at rest → saas; FTP has no DLP rule beyond the web rule's FTP_RULE"),
            _row("identity_scope", "Policy group, sender / recipient / user conditions", "policyGroup, sender, recipient, user, group", "identity", "users, groups, departments, locations", "manual", "the generated rule applies to Any; set the criteria on the rule after apply"),
            _row("file_conditions", "Attachment / file type, size, name conditions", "attachmentFileType, fileSize, fileName", "rule", "fileTypes, minSize", "manual", ""),
            _row("exceptions", "Detection rule exceptions", "exception conditions", "rule", "excludedUsers / excludedGroups / excludedDepartments; sub-rules; DLP Advanced Settings", "dropped", ""),
            _row("response_action", "Response rules", "action (Block, Notify, Quarantine, Encrypt)", "rule", "action BLOCK / CONFIRM / ALLOW / ICAP_RESPONSE; auditor; notificationTemplate", "generated", "the approved action only; notify, quarantine and encrypt responses are not carried"),
            _row("severity", "Policy severity", "severity", "rule", "severity RULE_SEVERITY_LOW / MEDIUM / HIGH / INFO", "manual", ""),
        ],
    },
    "forcepoint": {
        "name": "Forcepoint DLP", "prefix": "fp",
        "export": "Security Manager policy export (zip of one JSON per policy) or REST policy JSON",
        "accepts": [".zip", ".json"], "status": "available",
        "files": [{"ext": ".zip", "what": "Policy export: one <policy name>.json per policy plus policy_names_metadata.txt; classifiers and resources as further JSON files when included at export; refused if password-protected"},
                  {"ext": ".json", "what": "One policy, a list of policies, or a REST API response (GET /dlp/rest/v1/policy/…) in the same field names"}],
        "how": "Export from the Forcepoint Security Manager (Main > Policy Management > DLP Policies > Export): a zip of one <policy name>.json per policy plus policy_names_metadata.txt. Leave the password off and include classifiers and resources, so keyword, regex and dictionary items travel with the policies. A policy JSON fetched from the REST API (GET /dlp/rest/v1/policy/…) is accepted too.",
        "coverage": "Policies, rules and their classifiers (key phrase, regex and dictionary classifiers with their items when the export includes classifier definitions; predefined and script classifiers as identifiers; file and database fingerprinting as IDM and EDM; machine-learning classifiers), thresholds (threshold_type / threshold_value_from / UNIQUE), destination channels, sources, exceptions, action plans and severity, read from the JSON field names. Target rules on every channel: web, endpoint (one transfer method per rule), SaaS Security API and email, one decision per channel.",
        "source_api": {"name": "Forcepoint DLP REST API (Security Manager)", "base": "https://<Forcepoint Security Manager>:9443/dlp/rest/v1",
                       "auth": "POST /auth/refresh-token (username and password headers) → refresh token; POST /auth/access-token (refresh-token header) → access token sent as Authorization: Bearer",
                       "calls": ["GET /policy/… : policy list and one policy's rules, classifiers, thresholds, sources, destinations (the same JSON the export zip carries)",
                                 "POST /policy/… : create or update a policy (used on the Forcepoint side only; this tool never writes to it)",
                                 "Rule severity and action, and rule exception calls under /policy/rule/…",
                                 "POST /incidents : incident query for the before/after comparison in monitor mode",
                                 "This tool's `fetch` command can GET one policy JSON with the Bearer access token (no redirects, size-capped, written 0600)"]},
        "crossref": [
            _row("content_patterns", "Rule classifier (key phrase, regex, dictionary; predefined false)", "rules[].classifiers[].classifier_name → classifier definition phrases / patterns / terms", "dictionary", "phrases[].phrase, patterns[].pattern (PATTERNS_AND_PHRASES)", "generated",
                 "items are read when the export includes the classifier definitions; 256 phrases and 8 patterns per ZIA dictionary, regex validated by the API"),
            _row("data_identifiers", "Rule classifier predefined true / script classifier", "classifier_name, predefined", "predefined", "a predefined dictionary chosen by name", "attested", "Forcepoint's predefined classifiers map to Zscaler's predefined dictionaries one by one; attest each"),
            _row("edm", "Database fingerprinting classifier", "fingerprint (database / structured)", "edm", "EDM schema + dictionary", "attested", "re-index the source table with the Index Tool VM"),
            _row("idm", "File fingerprinting classifier", "fingerprint (file / unstructured)", "idm", "IDM profile + dictionary", "attested", ""),
            _row("ml", "Machine learning classifier", "classifier_type machine_learning", "predefined", "ML predefined dictionary where one exists", "attested", ""),
            _row("match_thresholds", "Classifier threshold and rule part count", "threshold_type CHECK_GREATER_THAN, threshold_value_from, threshold_calculate_type UNIQUE, parts_count_type", "engine", "engineExpression ((D<dict>.S > n)) or .U > n for unique matches; condition_relation_type AND / OR between classifiers", "reviewed", ""),
            _row("channel", "Rule destinations", "rules[].destinations (HTTP, HTTPS, FTP, Email, Endpoint removable media, printing, LAN, cloud apps)", "channels", "one decision per target channel: HTTP/HTTPS → web; Email → email; removable media / printing / LAN → endpoint (REMOVABLE_DRIVE_TRANSFER, PRINTING, NETWORK_DRIVE_TRANSFER, one per rule); sanctioned cloud apps at rest → saas", "generated", "each destination family becomes its own DISABLED rule; approve one decision per channel"),
            _row("identity_scope", "Rule sources", "rules[].sources (users, groups, endpoints, networks)", "identity", "users, groups, departments, locations", "manual", "the generated rule applies to Any"),
            _row("file_conditions", "File properties classifier, destination file size", "file_properties (type, size, name)", "rule", "fileTypes, minSize", "manual", ""),
            _row("exceptions", "Rule exceptions", "exceptions (sources, destinations, classifiers exempted)", "rule", "excludedUsers / excludedGroups / excludedDepartments; sub-rules", "dropped", ""),
            _row("response_action", "Rule action plan", "action_plan (Block All, Permit, Quarantine, Encrypt, Confirm) or action", "rule", "action BLOCK / CONFIRM / ALLOW / ICAP_RESPONSE; auditor; notificationTemplate", "generated", "the approved action only; quarantine and encrypt are not carried"),
            _row("severity", "Rule severity", "rules[].severity (LOW, MEDIUM, HIGH, CRITICAL)", "rule", "severity RULE_SEVERITY_LOW / MEDIUM / HIGH", "manual", ""),
            _row("policy", "Policy on / off, level, data type", "enabled, policy_level.level, policy_level.data_type", "rule", "state (always DISABLED here); level and data type have no ZIA field", "dropped", "enable and order the rule after apply, under change control"),
        ],
    },
    "netskope": {
        "name": "Netskope DLP", "prefix": "nsk",
        "export": "Real-time Protection policy export (JSON or CSV) plus dictionary CSVs, in one zip",
        "accepts": [".zip", ".json", ".csv"], "status": "available",
        "files": [{"ext": ".json", "what": "Real-time Protection policies export (Policies > Real-time Protection > Export), or DLP profile / rule / entity JSON where the tenant's REST API v2 exposes it"},
                  {"ext": ".csv", "what": "The same policy export as CSV (policy name, status, source, destination, activities, profile, action), or one custom dictionary per file (one keyword or regex per line, regex dictionaries hold at most 25 entries)"},
                  {"ext": ".zip", "what": "The policy export together with every dictionary CSV and any profile / rule JSON, so entities, thresholds and dictionary items are read with the policies"}],
        "how": "Export from the tenant: Policies > Real-time Protection > Export (JSON or CSV). Put it in a zip together with each custom dictionary's CSV (Policies > Profiles > DLP > Dictionaries) and, where your tenant's REST API v2 exposes them, the DLP profile and rule JSON, so entities, thresholds and dictionary items are read with the policies.",
        "coverage": "Real-time Protection policies (name, status, source, destination apps and categories, activities, DLP profile, action, severity), DLP profiles (rules, file filters), DLP rules (predefined entities as identifiers, custom dictionary and regex entities with their items from the dictionary CSVs, count and percentage thresholds, severity), fingerprint and ML classifiers, read from the JSON keys and CSV columns. Target rules on every channel: web for Real-time Protection, saas for API-enabled Protection, endpoint and email where the policy names them, one decision per channel.",
        "source_api": {"name": "Netskope REST API v2", "base": "https://<tenant>.goskope.com/api/v2",
                       "auth": "Netskope-Api-Token header (a REST API v2 token from Settings > Tools > REST API v2, scoped to the endpoints used)",
                       "calls": ["Real-time Protection policies: no create or read endpoint; export them from the UI (Policies > Real-time Protection > Export, JSON or CSV)",
                                 "DLP profiles, rules, entities and dictionaries: Policies > Profiles > DLP in the UI; dictionaries export as CSV; a policy endpoint appears in the tenant's Swagger (Settings > Tools > REST API v2 > Swagger) when enabled for the tenant",
                                 "GET /events/dataexport/events/incident and /events/dataexport/events/alert (type dlp): incidents for the before/after comparison in monitor mode",
                                 "GET /policy/urllist, /policy/domainfronting, /policy/npa/…: the other policy families, not DLP"]},
        "crossref": [
            _row("policy", "Real-time Protection policy", "name, status, profile (DLP profile)", "rule", "name, state (always DISABLED here), dlpEngines[] (1-4 engines from the profile's rules)", "generated", "the profile → rules → entities chain becomes dictionaries and engines in the decisions file"),
            _row("content_patterns", "Custom dictionary (keyword or regex) referenced by a DLP rule entity", "dictionary CSV entries; entity name", "dictionary", "phrases[].phrase, patterns[].pattern (PATTERNS_AND_PHRASES)", "generated", "keyword dictionaries → phrases (256 per dictionary); regex dictionaries → patterns (8 per dictionary, validated by the API)"),
            _row("data_identifiers", "DLP rule entity (predefined identifier, 3000+)", "rules[].entities[].name", "predefined", "a predefined dictionary chosen by name", "attested", "Netskope's identifiers map to Zscaler's ~120 predefined dictionaries many to one; attest what is covered"),
            _row("edm", "Fingerprint / exact match classifier (structured)", "fingerprint, exact match", "edm", "EDM schema + dictionary", "attested", ""),
            _row("idm", "Document fingerprint classifier (unstructured)", "fingerprint (document)", "idm", "IDM profile + dictionary", "attested", ""),
            _row("ml", "ML classifier (résumés, source code, tax forms, …)", "ml classifier name", "predefined", "ML predefined dictionary where one exists", "attested", ""),
            _row("match_thresholds", "DLP rule count / percentage thresholds and AND / OR", "count, threshold, percentage, operator", "engine", "engineExpression ((D<dict>.S > n)); AND / OR", "reviewed", "percentage thresholds have no ZIA equivalent: choose a count"),
            _row("channel", "Activities and destination", "activities (Upload, Post, Share, Download, …), destination apps / categories; API-enabled Protection policies", "channels", "upload / post / share (webmail included: it is browser traffic) → web (protocols HTTP/HTTPS, cloudApplications, urlCategories); API-enabled Protection → saas (casbDlpRules type by app family, cloud_app_tenants); the organisation's outbound mail → email", "generated", "downloads are not inspected by ZIA web DLP unless dlpDownloadScanEnabled; one decision per target channel"),
            _row("identity_scope", "Source", "source: users, user groups, OUs, locations", "identity", "users, groups, departments, locations", "manual", "the generated rule applies to Any"),
            _row("file_conditions", "DLP profile file filters", "file_filters: file types, size", "rule", "fileTypes, minSize", "manual", ""),
            _row("exceptions", "Policy exclusions", "exclude users / apps / activities", "rule", "excludedUsers / excludedGroups / excludedDepartments; sub-rules", "dropped", ""),
            _row("response_action", "Policy action", "action (Allow, Block, User Alert / coach, Quarantine, Legal hold, Encrypt)", "rule", "action ALLOW / BLOCK / CONFIRM (User Alert ≈ CONFIRM); auditor; notificationTemplate", "generated", "the approved action only; quarantine, legal hold and encrypt are not carried"),
            _row("severity", "DLP rule severity", "severity (Low, Medium, High, Critical)", "rule", "severity RULE_SEVERITY_LOW / MEDIUM / HIGH", "manual", ""),
            _row("notification", "User alert template", "user notification / template", "template", "notificationTemplate (dlpNotificationTemplates)", "manual", ""),
        ],
    },
    "skyhigh": {
        "name": "Skyhigh Security DLP", "prefix": "sky",
        "export": "Policy Templates export (zip) or SSE Policy API JSON, plus dictionary exports",
        "accepts": [".zip", ".json", ".xml"], "status": "available",
        "files": [{"ext": ".zip", "what": "Policy Templates export (Policy > DLP Policies > Policy Templates > Export): rule groups (at most 50) and rules with their classifications, conditions and response actions, at most 64 KB; dictionaries are not in it, add each dictionary's export to the same zip"},
                  {"ext": ".json", "what": "One policy or a list from the SSE Policy API (policy types 0 = API DLP, 1 = Proxy DLP)"},
                  {"ext": ".xml", "what": "A policy template member in XML, read by the same element names"}],
        "how": "Export from Skyhigh: Policy > DLP Policies > Policy Templates > Export (a zip of at most 50 rule groups and 64 KB; dictionaries are not synced into it, so add each dictionary's export to the same zip). A policy JSON from the SSE Policy API is accepted too.",
        "coverage": "Policy templates: rule groups, rules and their classifications (keywords with proximity, dictionaries with scores, advanced patterns / regex, pre-canned classifications as identifiers, IDM and EDM, ML), thresholds, the policy type (API DLP or Proxy DLP), applies-to users and groups, file conditions, exceptions, response actions and severity, read from the JSON keys or XML element names. Target rules on every channel: web for Proxy DLP, saas for API DLP, endpoint and email where the template names them, one decision per channel.",
        "source_api": {"name": "Skyhigh SSE Policy API and Policy Templates", "base": "https://<Skyhigh SSE console for your region>/… (the SSE API reference gives the path for your tenant's region)",
                       "auth": "API token from the SSE console (Settings > API), sent as a bearer token",
                       "calls": ["Policy Templates: Policy > DLP Policies > Policy Templates > Import / Export (zip, at most 50 rule groups and 64 KB; dictionaries are exported separately)",
                                 "Policy API: list and get DLP policies (policy types 0 = API DLP, 1 = Proxy DLP); create and update are Skyhigh-side only",
                                 "Incidents API: DLP incidents for the before/after comparison in monitor mode"]},
        "crossref": [
            _row("policy", "Policy template / rule group", "policy name, rule_groups[].name, policy_type (0 API DLP, 1 Proxy DLP)", "rule", "name, state (always DISABLED here)", "generated", "one ZIA rule per Proxy DLP (web) or API DLP (saas) rule group or rule, as the decisions say"),
            _row("content_patterns", "Keyword classification (200-character proximity)", "classifications[] type keyword: keywords, proximity", "dictionary", "phrases[].phrase; proximity on the dictionary", "generated", ""),
            _row("content_patterns", "Dictionary classification (scored entries −99..999)", "dictionary entries with scores", "dictionary", "phrases[].phrase", "generated", "ZIA counts occurrences, it has no per-term score: the engine threshold replaces the dictionary's score threshold"),
            _row("content_patterns", "Advanced pattern (regex) classification", "classifications[] type advanced_pattern / regex: pattern", "dictionary", "patterns[].pattern (8 per dictionary, validated by the API)", "generated", ""),
            _row("data_identifiers", "Pre-canned classification (82 built in, 2000 max)", "classifications[] predefined / built-in", "predefined", "a predefined dictionary chosen by name", "attested", ""),
            _row("idm", "Indexed Document Match classification", "IDM", "idm", "IDM profile + dictionary", "attested", ""),
            _row("edm", "Structured / exact data classification", "EDM", "edm", "EDM schema + dictionary", "attested", ""),
            _row("ml", "ML classification", "ml", "predefined", "ML predefined dictionary where one exists", "attested", ""),
            _row("match_thresholds", "Rule conditions: counts, minimum score, proximity", "count, threshold, minimum score", "engine", "engineExpression ((D<dict>.S > n)); AND / OR", "reviewed", ""),
            _row("channel", "Policy type and services", "policy_type (1 Proxy DLP = web; 0 API DLP = SaaS), services / cloud services", "channels", "Proxy DLP → web (protocols HTTP/HTTPS, cloudApplications); API DLP → saas (casbDlpRules type by service family, cloud_app_tenants)", "generated", "one decision per target channel"),
            _row("identity_scope", "Applies to", "users, groups", "identity", "users, groups, departments", "manual", "the generated rule applies to Any"),
            _row("file_conditions", "File conditions", "content type, file size, file name", "rule", "fileTypes, minSize", "manual", ""),
            _row("exceptions", "Exceptions / exclusions", "exceptions", "rule", "excludedUsers / excludedGroups / excludedDepartments; sub-rules", "dropped", ""),
            _row("response_action", "Response actions by rule-group severity", "response (Block, Coach / notify, Quarantine, Delete, Encrypt)", "rule", "action BLOCK / CONFIRM / ALLOW; auditor; notificationTemplate", "generated", "the approved action only; quarantine, delete and encrypt are not carried"),
            _row("severity", "Rule group severity", "severity", "rule", "severity RULE_SEVERITY_LOW / MEDIUM / HIGH", "manual", ""),
        ],
    },
}


def vendors() -> List[Dict[str, Any]]:
    return [dict(v, id=k) for k, v in VENDORS.items()]


def vendor(vendor_id: str) -> Dict[str, Any]:
    v = VENDORS.get(str(vendor_id or "").strip().lower())
    if not v:
        raise ValueError(f"Unknown vendor: {vendor_id!r}. Known: {', '.join(VENDORS)}")
    if v["status"] != "available":
        raise ValueError(f"{v['name']}: adapter not built yet. It needs a real export sample and a mapping decision before anything is converted.")
    return dict(v, id=str(vendor_id).strip().lower())


def crossref(vendor_id: str) -> Dict[str, Any]:
    """The vendor's API cross-reference: source object and field → ZIA
    object, field, API call and Terraform resource, with how each is
    carried; the same table the page shows and the report carries."""
    v = VENDORS[str(vendor_id).strip().lower()]
    return {"vendor": str(vendor_id).strip().lower(), "vendor_name": v["name"], "files": v["files"], "source_api": v["source_api"],
            "rows": v["crossref"], "carried": {"generated": "the compile emits it from the decisions file", "reviewed": "a person writes it in the decisions file",
                                                "attested": "built by hand in ZIA and attested in the decisions file", "manual": "set on the rule after apply; scored 0 by the efficacy mapping",
                                                "dropped": "no ZIA equivalent"},
            "zia_targets": ZIA_TARGETS}


# ── Upload helpers ─────────────────────────────────────────────────────
def decode_upload(f: Dict[str, Any]) -> bytes:
    """The bytes of an uploaded file ({name, content, encoding})."""
    content = f.get("content") or ""
    if str(f.get("encoding") or "").lower() == "base64":
        try:
            data = base64.b64decode(content, validate=False)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"{f.get('name') or 'file'}: not valid base64 ({e})")
    else:
        data = str(content).encode("utf-8")
    if len(data) > MAX_EXPORT_BYTES:
        raise ValueError(f"{f.get('name') or 'file'}: larger than {MAX_EXPORT_BYTES // (1024 * 1024)} MiB")
    return data


# ── Symantec adapter: inventory ────────────────────────────────────────
def _tag(e) -> str:
    return e.tag.rsplit("}", 1)[-1]


def _direct_text(node, field: str) -> Optional[str]:
    for child in node:
        if _tag(child).lower() == field.lower():
            return (child.text or "").strip()
    return None


# ── Detection facets: what a source policy is made of ─────────────────
# The export's schema is not interpreted; facets are recognised from the
# element names (and the text they carry) under each policy. The facet
# list is what the efficacy mapping scores: each facet found in the
# source is either carried by the ZIA translation, carried in part,
# dropped, or attested by a reviewer. Weights say how much of a policy's
# detection each facet is; only facets present in the source count.
FACETS: Dict[str, Dict[str, Any]] = {
    "content_patterns": {"name": "Keywords, phrases and regular expressions", "weight": 25,
                         "tags": ("keyword", "phrase", "regex", "regularexpression", "pattern", "contentmatches", "matchkeyword"),
                         "zia": "Patterns & Phrases dictionaries referenced by the rule's engines",
                         "how": "the source's keyword and regex items against the phrases and patterns in the approved dictionaries the rule's engines reference"},
    "data_identifiers": {"name": "Predefined data identifiers", "weight": 15, "tags": ("dataidentifier", "identifier", "datatype", "classifier"),
                         "zia": "Zscaler's ~120 predefined dictionaries (not created by this adapter)",
                         "how": "not computable: a predefined dictionary is chosen by hand; a reviewer attests which identifiers are covered"},
    "edm": {"name": "Exact Data Match", "weight": 10, "tags": ("edm", "exactdata", "exactmatch"), "zia": "EDM dictionary from the Index Tool VM",
            "how": "not computable: EDM needs the Index Tool VM and a template; attested when built"},
    "idm": {"name": "Indexed Document Match", "weight": 10, "tags": ("idm", "indexeddocument", "documentmatch", "fingerprint"), "zia": "IDM dictionary from the Index Tool VM",
            "how": "not computable: IDM needs the Index Tool VM and a template; attested when built"},
    "ml": {"name": "Machine-learning / vector classifiers", "weight": 5, "tags": ("vml", "machinelearning", "vector", "mlclassifier", "classification"),
           "zia": "ML predefined dictionaries where one exists", "how": "not computable: attested when an ML dictionary is chosen"},
    "match_thresholds": {"name": "Match counts and thresholds", "weight": 5, "tags": ("mincount", "matchcount", "minmatches", "threshold", "count", "occurrence"),
                         "zia": "the engine expression's strict \"more than N\"",
                         "how": "carried when every referenced engine expression carries a numeric threshold"},
    "channel": {"name": "Channels and protocols", "weight": 10, "tags": ("protocol", "channel", "destination", "endpointdestination", "network", "application", "app"),
                "zia": "Web, Endpoint, SaaS Security API and Email DLP rules (one target rule per channel)",
                "how": "the share of the source's channel mentions (web, email, endpoint, SaaS API; downloads are never inspected) that the approved target rules cover"},
    "identity_scope": {"name": "Users, groups, senders and recipients", "weight": 8, "tags": ("sender", "recipient", "user", "group", "department", "policygroup", "scope"),
                       "zia": "the rule's users / groups / departments criteria",
                       "how": "dropped: the generated rule applies to Any (that is what scope_acknowledged_any acknowledges)"},
    "file_conditions": {"name": "File type, size and name conditions", "weight": 4, "tags": ("filetype", "filesize", "filename", "attachment", "mimetype", "extension"),
                        "zia": "the rule's file types and size limits", "how": "dropped: not emitted by this adapter; set on the rule by hand"},
    "exceptions": {"name": "Exceptions", "weight": 4, "tags": ("exception", "exclude", "exempt", "whitelist", "allowlist"),
                   "zia": "Exclude subexpressions and DLP Advanced Settings exemptions", "how": "dropped: not emitted by this adapter"},
    "response_action": {"name": "Response rules and actions", "weight": 4, "tags": ("response", "action", "block", "notify", "quarantine", "encrypt", "remediat"),
                        "zia": "the rule's action (Allow / Block / Confirm) plus auditor and template",
                        "how": "carried when the rule's action is approved; notifications, quarantine and encryption responses are not carried"},
    "severity": {"name": "Severity", "weight": 2, "tags": ("severity", "priority", "risk"), "zia": "rule severity", "how": "dropped: not emitted by this adapter"},
}
_WEB_PROTOCOL_RE = re.compile(r"\b(https?|web|ftp|browser|upload)\b", re.I)
_THRESHOLD_RE = re.compile(r">\s*\d+")


_FACET_ORDER = ("edm", "idm", "ml", "data_identifiers") + tuple(k for k in FACETS if k not in ("edm", "idm", "ml", "data_identifiers"))


def _facet_of(tag: str) -> Optional[str]:
    """The facet an element name belongs to; the specific detection types
    win over the generic content match (contentMatchesDataIdentifier is an
    identifier, not a keyword)."""
    t = tag.lower()
    for key in _FACET_ORDER:
        if any(needle in t for needle in FACETS[key]["tags"]):
            return key
    return None


def _policy_facets(node) -> Dict[str, Any]:
    """Facets recognised under one policy element: per facet the element
    count and, for a few, the item texts that the scoring compares. The
    unrecognised element names are listed so a reviewer sees what was
    ignored."""
    found: Dict[str, Dict[str, Any]] = {}
    unknown: set = set()
    for el in node.iter():
        if el is node:
            continue
        tag = _tag(el)
        key = _facet_of(tag)
        if key is None:
            if tag.lower() not in ("id", "name", "description", "activestatus", "rule", "rules", "detectionrules", "condition", "conditions", "policy", "value", "values", "item", "items"):
                unknown.add(tag)
            continue
        f = found.setdefault(key, {"elements": 0, "items": [], "texts": []})
        f["elements"] += 1
        text = " ".join((el.text or "").split())
        if text:
            f["texts"].append(text[:200])
            if key == "content_patterns" and el.tag.lower().endswith(("keyword", "phrase", "regex", "regularexpression", "pattern")):
                f["items"].append(text[:200])
        for k, v in el.attrib.items():
            if key == "channel" and v:
                f["texts"].append(str(v)[:100])
    for f in found.values():
        f["items"] = f["items"][:512]
        f["texts"] = f["texts"][:64]
    return {"facets": found, "unrecognised": sorted(unknown)[:40]}


def inventory_bytes(data: bytes, source_name: str = "export.xml") -> Dict[str, Any]:
    """Symantec XML export → {source_file, sha256, policies}. Read-only;
    DTDs and entities are refused before parsing."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entities are not accepted")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"Not well-formed XML: {e}")
    policies = []
    for node in root.iter():
        if _tag(node).lower() != "policy":
            continue
        ident = node.get("id") or node.get("policyId") or _direct_text(node, "id")
        name = node.get("name") or _direct_text(node, "name")
        if not ident or not name:
            continue
        entry = {"id": str(ident), "name": name, "active_status": _direct_text(node, "activeStatus"),
                 "child_tags": sorted({_tag(c) for c in node})}
        entry.update(_policy_facets(node))
        policies.append(entry)
    if not policies:
        raise ValueError("No policy elements with an id and name were found; provide an export fixture")
    ids = [p["id"] for p in policies]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate policy IDs in export")
    return {"source_file": os.path.basename(str(source_name or "export.xml")), "sha256": hashlib.sha256(data).hexdigest(),
            "policies": sorted(policies, key=lambda x: x["id"])}


def inventory_xml(path) -> Dict[str, Any]:
    p = Path(path)
    return inventory_bytes(p.read_bytes(), p.name)


# ── Shared readers for the JSON, CSV and zip exports ───────────────────
ZIP_MEMBER_LIMIT = 512
_TEXT_MEMBERS = (".json", ".xml", ".csv", ".txt")


def _is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _unzip(data: bytes, source_name: str) -> List[Tuple[str, bytes]]:
    """The text members of an uploaded zip, read in memory: (member name,
    bytes). Password-protected archives, more than ZIP_MEMBER_LIMIT members
    and archives that expand beyond MAX_EXPORT_BYTES are refused. Nothing is
    written to disk."""
    import io
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        raise ValueError(f"{source_name}: not a zip archive ({e})")
    members: List[Tuple[str, bytes]] = []
    total = 0
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > ZIP_MEMBER_LIMIT:
            raise ValueError(f"{source_name}: more than {ZIP_MEMBER_LIMIT} files in the archive")
        for info in infos:
            if info.flag_bits & 0x1:
                raise ValueError(f"{source_name}: the archive is password-protected; export it again without a password")
            total += info.file_size
            if total > MAX_EXPORT_BYTES:
                raise ValueError(f"{source_name}: the archive expands beyond {MAX_EXPORT_BYTES // (1024 * 1024)} MiB")
            base = info.filename.rsplit("/", 1)[-1]
            if not base.lower().endswith(_TEXT_MEMBERS) or base.startswith(".") or "__MACOSX" in info.filename:
                continue
            members.append((info.filename, zf.read(info)))
    if not members:
        raise ValueError(f"{source_name}: the archive holds no .json, .xml, .csv or .txt file")
    return members


def _text(data: bytes, name: str) -> str:
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"{name}: not UTF-8 or UTF-16 text")


def _load_json(data: bytes, name: str) -> Any:
    try:
        return json.loads(_text(data, name))
    except json.JSONDecodeError as e:
        raise ValueError(f"{name}: not valid JSON ({e.msg} at line {e.lineno})")


def _csv_rows(data: bytes, name: str) -> List[List[str]]:
    import csv
    import io
    text = _text(data, name)
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = [[c.strip() for c in r] for r in csv.reader(io.StringIO(text), dialect)]
    return [r for r in rows if any(r)]


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(k).strip().lower()).strip("_")


def _csv_records(rows: List[List[str]]) -> List[Dict[str, str]]:
    """Header row → records keyed by the normalised column names."""
    header = [_norm_key(c) or f"col{i}" for i, c in enumerate(rows[0])]
    return [{(header[i] if i < len(header) else f"col{i}"): c for i, c in enumerate(r)} for r in rows[1:]]


def _xml_root(data: bytes, name: str):
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError(f"{name}: DTD/entities are not accepted")
    try:
        return ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"{name}: not well-formed XML ({e})")


def _xml_to_obj(el) -> Any:
    """An XML element as the JSON-shaped object the key walker reads:
    attributes and children as keys, repeated children as lists, text as
    the value of a leaf (or "#text" beside children)."""
    obj: Dict[str, Any] = dict(el.attrib)
    text = " ".join((el.text or "").split())
    kids = list(el)
    if not kids and not obj:
        return text
    for c in kids:
        t = _tag(c)
        val = _xml_to_obj(c)
        if t in obj:
            if not isinstance(obj[t], list):
                obj[t] = [obj[t]]
            obj[t].append(val)
        else:
            obj[t] = val
    if text:
        obj["#text"] = text
    return obj


# ── Facets from JSON keys (the JSON twin of _policy_facets) ────────────
class _Facets:
    """Accumulates {facet: {elements, items, texts}} exactly as the XML
    walker does, so the efficacy mapping scores every vendor the same way."""

    def __init__(self) -> None:
        self.found: Dict[str, Dict[str, Any]] = {}
        self.unknown: set = set()

    def add(self, key: str, texts=(), items=(), n: int = 1) -> None:
        f = self.found.setdefault(key, {"elements": 0, "items": [], "texts": []})
        f["elements"] += n
        for t in texts:
            t = " ".join(str(t).split())
            if t:
                f["texts"].append(t[:200])
        for t in items:
            t = " ".join(str(t).split())
            if t:
                f["items"].append(t[:200])

    def result(self) -> Dict[str, Any]:
        for f in self.found.values():
            f["items"] = f["items"][:512]
            f["texts"] = f["texts"][:64]
        return {"facets": self.found, "unrecognised": sorted(self.unknown)[:40]}


# Keys that carry identity, bookkeeping or structure, never detection.
_JSON_IGNORE = frozenset((
    "id", "name", "description", "enabled", "status", "state", "active", "created", "created_at", "created_by", "modified", "modified_at", "modified_by",
    "updated", "updated_at", "version", "position", "order", "uuid", "type", "value", "values", "items", "rule", "rules", "policy", "policies",
    "policy_name", "policy_id", "rule_name", "rule_id", "predefined_policy", "condition_relation_type", "operator", "relation", "comment", "comments",
    "notes", "tags", "owner", "last_modified", "policy_level", "level", "data_type", "data", "text", "title", "label", "index", "count_of_rules",
    "rule_groups", "rule_group", "rulegroups", "rulegroup", "profile_name", "profile_id", "template", "templates", "results", "total", "page",
))
_ITEM_KEY_RE = re.compile(r"(keyword|phrase|regex|regular_?expression|pattern|term|entr(y|ies)|string|expression|value)s?$", re.I)


def _facet_of_key(key: str) -> Optional[str]:
    """_facet_of over a JSON key with its separators removed, so
    file_types reads as filetype and threshold_value_from as threshold."""
    return _facet_of(re.sub(r"[^a-z0-9]", "", str(key).lower()))


def _scalars(v: Any) -> List[str]:
    if isinstance(v, bool):
        return []
    if isinstance(v, (str, int, float)):
        return [str(v)]
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int, float)) and not isinstance(x, bool)]
    return []


def _empty(v: Any) -> bool:
    return v is None or (isinstance(v, (str, list, dict)) and not v)


def _walk_json(node: Any, fx: _Facets, special=None, overrides: Optional[Dict[str, str]] = None, ignore=frozenset(), inherit: Optional[str] = None) -> None:
    """Facets recognised in a JSON policy from its key names, the way
    _policy_facets reads element names: each key is classified with the
    same FACETS tags (an adapter's overrides first), the scalar values
    under it become the facet's texts (and its items for keyword / regex
    keys), and keys recognised as nothing are listed. Everything under a
    classified key belongs to that facet (an exception's sources are part
    of the exception). Empty values are not counted. `special(key, value,
    fx)` lets an adapter take a whole subtree (a classifier list) and
    return True when it did."""
    if isinstance(node, list):
        for x in node:
            _walk_json(x, fx, special, overrides, ignore, inherit)
        return
    if not isinstance(node, dict):
        return
    for k, v in node.items():
        key = str(k)
        kl = _norm_key(key)
        if _empty(v):
            continue
        if inherit:
            sc = _scalars(v)
            if sc:
                fx.add(inherit, texts=[_norm_channel(x) for x in sc] if inherit == "channel" else sc,
                       items=sc if inherit == "content_patterns" and _ITEM_KEY_RE.search(kl) else (), n=0)
            _walk_json(v, fx, special, overrides, ignore, inherit)
            continue
        if special and special(kl, v, fx):
            continue
        facet = (overrides or {}).get(kl) or (None if kl in ignore or kl in _JSON_IGNORE else _facet_of_key(kl))
        if facet is None:
            if kl not in _JSON_IGNORE and kl not in ignore and not isinstance(v, (dict, list)) and not kl.startswith("#"):
                fx.unknown.add(key)
            _walk_json(v, fx, special, overrides, ignore)
            continue
        sc = _scalars(v)
        fx.add(facet, texts=[_norm_channel(x) for x in sc] if facet == "channel" else sc, items=sc if facet == "content_patterns" and _ITEM_KEY_RE.search(kl) else ())
        _walk_json(v, fx, special, overrides, ignore, inherit=facet)


def _items_of(obj: Dict[str, Any]) -> List[str]:
    """The keyword / regex / dictionary items spelled out in a classifier,
    entity or classification object, whichever key the vendor used."""
    out: List[str] = []
    for k, v in obj.items():
        if not _ITEM_KEY_RE.search(_norm_key(k)) or _norm_key(k) in ("value", "values"):
            continue
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, str):
                    out.append(x)
                elif isinstance(x, dict):
                    for kk in ("phrase", "keyword", "term", "pattern", "regex", "value", "entry", "text", "name"):
                        if isinstance(x.get(kk), str):
                            out.append(x[kk])
                            break
    return out


def _thresholds_of(obj: Dict[str, Any]) -> List[str]:
    out = []
    for k, v in obj.items():
        kl = _norm_key(k)
        if any(w in kl for w in ("threshold", "count", "occurrence", "min_", "minimum", "percentage", "proximity", "score")) and isinstance(v, (int, float, str)) and not isinstance(v, bool):
            if str(v).strip():
                out.append(f"{kl} {v}")
    return out


# Order matters: the specific families first, so an endpoint "Network
# share" is endpoint, not web, and webmail is web, not email.
_CHANNEL_WORDS = (
    (("endpoint", "removable", "usb", "print", "clipboard", "network share", "network drive", "local drive", "device", "screen", "lan"), "endpoint"),
    (("webmail",), "web"),
    (("smtp", "email", "e-mail", "mail", "exchange", "outlook", "gmail"), "email"),
    (("api", "saas", "cloud storage", "casb", "at rest", "api-enabled", "api enabled"), "saas-api"),
    (("download", "view", "preview"), "cloud-download"),
    (("ftp",), "ftp"),
    (("http", "https", "web", "browser", "upload", "post", "share", "form", "proxy"), "web"),
)


def _norm_channel(text: str, default: Optional[str] = None) -> str:
    """A source channel, activity or policy type in the vocabulary the
    efficacy mapping scores: web, email, endpoint, saas-api,
    cloud-download, with the source's own word kept in parentheses."""
    t = str(text).strip()
    low = t.lower()
    for words, kind in _CHANNEL_WORDS:
        if any(w in low for w in words):
            return f"{kind} ({t})"
    return f"{default} ({t})" if default else t


def _policy_id(obj: Dict[str, Any], name: str, prefix: str, keys=("policy_id", "policyid", "id", "uuid", "policy_uuid")) -> str:
    for k in keys:
        for kk, v in obj.items():
            if _norm_key(kk) == k and isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
                return str(v).strip()
    return f"{prefix}-{slug(name)}"


def _policy_name(obj: Dict[str, Any], keys=("policy_name", "policyname", "name", "title", "rule_group_name")) -> Optional[str]:
    for k in keys:
        for kk, v in obj.items():
            if _norm_key(kk) == k and isinstance(v, str) and v.strip():
                return v.strip()
    return None


def _policy_status(obj: Dict[str, Any]) -> Optional[str]:
    for kk, v in obj.items():
        k = _norm_key(kk)
        if k in ("enabled", "active", "is_enabled"):
            if isinstance(v, bool):
                return "enabled" if v else "disabled"
            if isinstance(v, str):
                return "enabled" if v.strip().lower() in ("true", "yes", "enabled", "on", "1") else "disabled"
        if k in ("status", "state", "policy_status") and isinstance(v, str):
            return v.strip().lower()
    return None


def _find_policies(obj: Any, is_policy, list_keys=("policies", "policy", "data", "items", "results", "templates", "policy_templates", "policytemplates", "rule_groups", "rulegroups")) -> List[Dict[str, Any]]:
    """Every policy object in a JSON export: the object itself, a list of
    them, or a wrapper with a list under one of the usual keys."""
    if isinstance(obj, dict):
        if is_policy(obj):
            return [obj]
        for kk, v in obj.items():
            if _norm_key(kk) in list_keys and isinstance(v, (list, dict)):
                found = _find_policies(v, is_policy, list_keys)
                if found:
                    return found
        return []
    if isinstance(obj, list):
        out: List[Dict[str, Any]] = []
        for x in obj:
            out.extend(_find_policies(x, is_policy, list_keys))
        return out
    return []


def _finish(policies: List[Dict[str, Any]], data: bytes, source_name: str, default_name: str, what: str) -> Dict[str, Any]:
    if not policies:
        raise ValueError(f"No {what} found in {os.path.basename(str(source_name or default_name))}; check the export and its file type")
    ids = [p["id"] for p in policies]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate policy IDs in export: " + ", ".join(sorted({i for i in ids if ids.count(i) > 1})[:5]))
    return {"source_file": os.path.basename(str(source_name or default_name)), "sha256": hashlib.sha256(data).hexdigest(),
            "policies": sorted(policies, key=lambda x: x["id"])}


# ── Forcepoint adapter ─────────────────────────────────────────────────
# The Security Manager exports a zip of <policy name>.json files (one per
# policy) plus policy_names_metadata.txt, optionally with the classifier
# and resource definitions; the REST API returns the same policy JSON
# (policy_name, enabled, policy_level, rules[] with rule_name, enabled,
# severity, action_plan, parts_count_type, condition_relation_type,
# classifiers[] with classifier_name, predefined, threshold_type,
# threshold_value_from, threshold_calculate_type, sources, destinations,
# exceptions).
_FP_OVERRIDES = {"sources": "identity_scope", "source": "identity_scope", "endpoints": "identity_scope", "endpoint_groups": "identity_scope",
                 "destinations": "channel", "destination": "channel", "channels": "channel", "channel": "channel",
                 "action_plan": "response_action", "action_plans": "response_action", "actionplan": "response_action", "action": "response_action",
                 "file_properties": "file_conditions", "exceptions": "exceptions", "exception": "exceptions"}
_FP_IGNORE = frozenset(("parts_count_type", "classifier_name", "classifier_type", "predefined", "position", "resource_name", "resources"))


def _fp_classifier_facet(c: Dict[str, Any]) -> str:
    ctype = re.sub(r"[^a-z]", "", str(c.get("classifier_type") or c.get("type") or c.get("kind") or "").lower())
    if "fingerprint" in ctype or "idm" in ctype or "document" in ctype:
        return "edm" if any(w in ctype for w in ("database", "db", "structured", "edm", "table")) else "idm"
    if "edm" in ctype or "database" in ctype or "exactdata" in ctype:
        return "edm"
    if "machine" in ctype or ctype in ("ml", "mlclassifier", "machinelearning"):
        return "ml"
    if "file" in ctype or "property" in ctype or "properties" in ctype:
        return "file_conditions"
    if c.get("predefined") is True or "script" in ctype or "predefined" in ctype or "builtin" in ctype:
        return "data_identifiers"
    if ctype in ("keyphrase", "keyphrases", "regex", "regularexpression", "regularexpressions", "dictionary", "pattern", "keyword", "keywords", "phrase", "custom"):
        return "content_patterns"
    if c.get("predefined") is False or _items_of(c):
        return "content_patterns"
    return "data_identifiers"


def _fp_special(defs: Dict[str, Dict[str, Any]]):
    def special(kl: str, v: Any, fx: _Facets) -> bool:
        if kl not in ("classifiers", "classifier", "content_classifiers", "content_classifier") or not isinstance(v, (list, dict)):
            return False
        for c in (v if isinstance(v, list) else [v]):
            if isinstance(c, str):
                c = {"classifier_name": c}
            if not isinstance(c, dict):
                continue
            name = str(c.get("classifier_name") or c.get("name") or "").strip()
            merged = dict(defs.get(name.lower(), {}), **c) if name else c
            facet = _fp_classifier_facet(merged)
            items = _items_of(merged) if facet == "content_patterns" else []
            fx.add(facet, texts=[name] if name else (), items=items)
            th = [f"{merged.get('threshold_type') or 'CHECK_GREATER_THAN'} {merged[k]}" + (f" {merged['threshold_calculate_type']}" if merged.get("threshold_calculate_type") else "")
                  for k in merged if _norm_key(k).startswith("threshold_value") and isinstance(merged[k], (int, float, str)) and not isinstance(merged[k], bool) and str(merged[k]).strip()]
            if th:
                fx.add("match_thresholds", texts=th)
        return True
    return special


def _fp_is_policy(d: Dict[str, Any]) -> bool:
    keys = {_norm_key(k) for k in d}
    return "policy_name" in keys or ("rules" in keys and ("name" in keys or "policy_id" in keys)) or ("name" in keys and "rules" in keys)


def _fp_is_classifier_file(obj: Any) -> bool:
    items = obj if isinstance(obj, list) else obj.get("classifiers") if isinstance(obj, dict) else None
    return isinstance(items, list) and bool(items) and all(isinstance(x, dict) and ("classifier_name" in x or "classifier_type" in x) and "rules" not in x for x in items)


def inventory_forcepoint(data: bytes, source_name: str = "policies.zip") -> Dict[str, Any]:
    """Forcepoint policy export (zip of one JSON per policy, or one policy
    / list / REST response as JSON) → the inventory."""
    members: List[Tuple[str, Any]] = []
    if _is_zip(data):
        for mname, mdata in _unzip(data, source_name):
            if mname.lower().endswith(".json"):
                members.append((mname, _load_json(mdata, mname)))
    else:
        members.append((source_name, _load_json(data, source_name)))
    defs: Dict[str, Dict[str, Any]] = {}
    for _mname, obj in members:
        if _fp_is_classifier_file(obj):
            for c in (obj if isinstance(obj, list) else obj["classifiers"]):
                defs[str(c.get("classifier_name") or c.get("name") or "").lower()] = c
    special = _fp_special(defs)
    policies: List[Dict[str, Any]] = []
    for mname, obj in members:
        if _fp_is_classifier_file(obj):
            continue
        for pobj in _find_policies(obj, _fp_is_policy):
            name = _policy_name(pobj) or Path(mname).stem
            fx = _Facets()
            _walk_json(pobj, fx, special, _FP_OVERRIDES, _FP_IGNORE)
            entry = {"id": _policy_id(pobj, name, "fp"), "name": name, "active_status": _policy_status(pobj), "child_tags": sorted(str(k) for k in pobj),
                     "source_member": mname if _is_zip(data) else None, "rules": [str(r.get("rule_name") or r.get("name") or "") for r in (pobj.get("rules") or []) if isinstance(r, dict)][:64]}
            entry.update(fx.result())
            policies.append(entry)
    return _finish(policies, data, source_name, "policies.zip", "Forcepoint policies (policy_name with rules)")


# ── Netskope adapter ───────────────────────────────────────────────────
# Real-time Protection policies export as JSON or CSV (policy name,
# status, source, destination, activities, DLP profile, action); DLP
# profiles link rules, rules link entities (predefined identifiers or
# custom dictionaries) with count / percentage thresholds; custom
# dictionaries export as one CSV per dictionary, one keyword or regex per
# line. All of it may arrive in one zip.
_NSK_OVERRIDES = {"activities": "channel", "activity": "channel", "destination": "channel", "destinations": "channel", "app": "channel", "apps": "channel",
                  "application": "channel", "applications": "channel", "cloud_app": "channel", "category": "channel", "categories": "channel",
                  "app_categories": "channel", "policy_type": "channel", "source": "identity_scope", "sources": "identity_scope", "users": "identity_scope",
                  "user_groups": "identity_scope", "organizational_units": "identity_scope", "ous": "identity_scope", "action": "response_action",
                  "actions": "response_action", "file_filters": "file_conditions", "filters": "file_conditions", "constraints": "file_conditions",
                  "exclude": "exceptions", "excluded": "exceptions", "exclusions": "exceptions", "fingerprint": "edm", "fingerprints": "edm",
                  "ml_classifier": "ml", "ml_classifiers": "ml", "classifier": "ml", "classifiers": "ml", "user_notification": "response_action", "template": "response_action"}
_NSK_IGNORE = frozenset(("profile", "profiles", "dlp_profile", "dlp_profiles", "dlp_rule", "dlp_rules", "entities", "identifiers", "data_identifiers", "dictionary", "dictionaries", "policy_name"))
_NSK_POLICY_COLS = ("policy_name", "name", "action", "activities", "profile", "dlp_profile", "profiles")


def _nsk_entity_facet(e: Dict[str, Any], dicts: Dict[str, Dict[str, Any]]) -> Tuple[str, List[str]]:
    name = str(e.get("name") or e.get("entity") or e.get("identifier") or "").strip()
    etype = re.sub(r"[^a-z]", "", str(e.get("type") or e.get("entity_type") or e.get("kind") or "").lower())
    d = dicts.get(name.lower())
    if d is not None or e.get("custom") is True or etype in ("dictionary", "customdictionary", "regex", "keyword", "custom"):
        items = (d or {}).get("entries") or _items_of(e)
        return "content_patterns", list(items)
    if "fingerprint" in etype or "exact" in etype or "edm" in etype:
        return "edm", []
    if "document" in etype or "idm" in etype:
        return "idm", []
    if "ml" in etype or "classifier" in etype:
        return "ml", []
    return "data_identifiers", []


def _nsk_special(dicts: Dict[str, Dict[str, Any]], profiles: Dict[str, Any], rules: Dict[str, Any], refs: Dict[str, List[str]], depth: List[int]):
    def walk_named(kind: str, names: List[str], fx: _Facets) -> None:
        table = profiles if kind == "profiles" else rules
        for n in names:
            n = str(n).strip()
            if not n:
                continue
            refs.setdefault(kind, []).append(n)
            obj = table.get(n.lower())
            if obj is None:
                refs.setdefault("unresolved", []).append(f"{kind[:-1]}: {n}")
                continue
            if depth[0] > 6:
                continue
            depth[0] += 1
            try:
                _walk_json(obj, fx, special, _NSK_OVERRIDES, _NSK_IGNORE)
            finally:
                depth[0] -= 1

    def special(kl: str, v: Any, fx: _Facets) -> bool:
        if kl in ("profile", "profiles", "dlp_profile", "dlp_profiles"):
            names = _scalars(v) if not isinstance(v, str) else re.split(r"[,;|]\s*", v)
            names = names or [str(x.get("name")) for x in (v if isinstance(v, list) else []) if isinstance(x, dict) and x.get("name")]
            walk_named("profiles", names, fx)
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, dict):
                    _walk_json(x, fx, special, _NSK_OVERRIDES, _NSK_IGNORE)
            return True
        if kl in ("dlp_rule", "dlp_rules", "rules") and (isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))):
            walk_named("rules", re.split(r"[,;|]\s*", v) if isinstance(v, str) else v, fx)
            return True
        if kl in ("entities", "identifiers", "data_identifiers", "entity", "identifier") and isinstance(v, (list, dict, str)):
            for e in (v if isinstance(v, list) else [v]):
                if isinstance(e, str):
                    e = {"name": e}
                if not isinstance(e, dict):
                    continue
                facet, items = _nsk_entity_facet(e, dicts)
                name = str(e.get("name") or e.get("entity") or e.get("identifier") or "").strip()
                if facet == "content_patterns" and name:
                    refs.setdefault("dictionaries", []).append(name)
                fx.add(facet, texts=[name] if name else (), items=items)
                th = _thresholds_of(e)
                if th:
                    fx.add("match_thresholds", texts=th)
            return True
        if kl in ("dictionary", "dictionaries") and isinstance(v, (str, list)):
            for n in (re.split(r"[,;|]\s*", v) if isinstance(v, str) else _scalars(v)):
                d = dicts.get(str(n).strip().lower())
                refs.setdefault("dictionaries", []).append(str(n).strip())
                fx.add("content_patterns", texts=[n], items=(d or {}).get("entries") or [])
            return True
        if kl in ("activities", "activity", "destination", "destinations", "app", "apps", "application", "applications", "cloud_app", "category", "categories", "app_categories", "policy_type"):
            vals = re.split(r"[,;|]\s*", v) if isinstance(v, str) else _scalars(v)
            default = "web" if kl != "policy_type" else None
            kind = "cloud-download" if kl in ("activities", "activity") else None
            fx.add("channel", texts=[_norm_channel(x, default) if not kind or not any(w in x.lower() for w in ("download", "view", "preview")) else f"cloud-download ({x})" for x in vals if str(x).strip()])
            if isinstance(v, (dict, list)):
                _walk_json(v, fx, special, _NSK_OVERRIDES, _NSK_IGNORE, inherit="channel")
            return True
        return False
    return special


def _nsk_is_policy(d: Dict[str, Any]) -> bool:
    keys = {_norm_key(k) for k in d}
    return bool(keys & {"policy_name"}) or ("name" in keys and bool(keys & {"action", "activities", "profile", "dlp_profile", "profiles", "dlp_profiles", "destination"}))


def _nsk_dictionary_from_csv(rows: List[List[str]], stem: str) -> Dict[str, Any]:
    entries = [r[0] for r in rows if r and r[0]]
    if entries and _norm_key(entries[0]) in ("keyword", "keywords", "regex", "entry", "entries", "term", "terms", "value", "values", "pattern", "patterns", "dictionary"):
        entries = entries[1:]
    return {"name": stem, "entries": entries[:512]}


def inventory_netskope(data: bytes, source_name: str = "policies.zip") -> Dict[str, Any]:
    """Netskope Real-time Protection policies (JSON or CSV), with the DLP
    profile / rule JSON and the dictionary CSVs that came with them → the
    inventory. Profiles and rules are joined to the policies by name."""
    members: List[Tuple[str, bytes]] = _unzip(data, source_name) if _is_zip(data) else [(source_name, data)]
    dicts: Dict[str, Dict[str, Any]] = {}
    profiles: Dict[str, Any] = {}
    rules: Dict[str, Any] = {}
    policy_objs: List[Tuple[str, Dict[str, Any]]] = []
    for mname, mdata in members:
        low = mname.lower()
        stem = Path(mname).stem
        if low.endswith(".json"):
            obj = _load_json(mdata, mname)
            if isinstance(obj, dict):
                for kk, v in obj.items():
                    k = _norm_key(kk)
                    if k in ("profiles", "dlp_profiles") and isinstance(v, list):
                        profiles.update({str(x.get("name", "")).lower(): x for x in v if isinstance(x, dict) and x.get("name")})
                    elif k in ("rules", "dlp_rules") and isinstance(v, list) and all(isinstance(x, dict) and not _nsk_is_policy(x) for x in v):
                        rules.update({str(x.get("name", "")).lower(): x for x in v if isinstance(x, dict) and x.get("name")})
                    elif k in ("dictionaries", "dlp_dictionaries") and isinstance(v, list):
                        for x in v:
                            if isinstance(x, dict) and x.get("name"):
                                dicts[str(x["name"]).lower()] = {"name": x["name"], "entries": _items_of(x) or _scalars(x.get("entries"))}
            for p in _find_policies(obj, _nsk_is_policy):
                policy_objs.append((mname, p))
        elif low.endswith(".csv"):
            rows = _csv_rows(mdata, mname)
            if not rows:
                continue
            header = {_norm_key(c) for c in rows[0]}
            if len(rows[0]) > 1 and header & set(_NSK_POLICY_COLS):
                for rec in _csv_records(rows):
                    if _nsk_is_policy(rec):
                        policy_objs.append((mname, rec))
            else:
                d = _nsk_dictionary_from_csv(rows, stem)
                dicts[stem.lower()] = d
    policies: List[Dict[str, Any]] = []
    for mname, pobj in policy_objs:
        name = _policy_name(pobj) or Path(mname).stem
        refs: Dict[str, List[str]] = {}
        fx = _Facets()
        _walk_json(pobj, fx, _nsk_special(dicts, profiles, rules, refs, [0]), _NSK_OVERRIDES, _NSK_IGNORE)
        entry = {"id": _policy_id(pobj, name, "nsk"), "name": name, "active_status": _policy_status(pobj), "child_tags": sorted(str(k) for k in pobj),
                 "source_member": mname if _is_zip(data) else None, "references": {k: sorted(set(v))[:32] for k, v in refs.items()}}
        entry.update(fx.result())
        policies.append(entry)
    snap = _finish(policies, data, source_name, "policies.zip", "Netskope Real-time Protection policies (policy name with action, activities or profile)")
    snap["dictionaries"] = sorted(({"name": d["name"], "entries": len(d.get("entries") or [])} for d in dicts.values()), key=lambda x: x["name"].lower())
    snap["profiles"] = sorted(p.get("name", "") for p in profiles.values())
    return snap


# ── Skyhigh adapter ────────────────────────────────────────────────────
# Policy Templates export (zip; JSON or XML members with rule groups →
# rules → classifications, conditions, response actions) or SSE Policy
# API JSON (policy types 0 = API DLP, 1 = Proxy DLP).
_SKY_OVERRIDES = {"response": "response_action", "responses": "response_action", "response_actions": "response_action", "actions": "response_action", "action": "response_action",
                  "remediation": "response_action", "users": "identity_scope", "groups": "identity_scope", "user_groups": "identity_scope", "applies_to": "identity_scope",
                  "content_type": "file_conditions", "content_types": "file_conditions", "size": "file_conditions", "file": "file_conditions", "files": "file_conditions",
                  "exclusions": "exceptions", "exclusion": "exceptions", "exceptions": "exceptions", "exception": "exceptions", "fingerprint": "idm", "structured": "edm",
                  "minimum_score": "match_thresholds", "min_score": "match_thresholds", "score_threshold": "match_thresholds", "proximity": "match_thresholds"}
# Services (Box, Salesforce, …) are the apps a policy watches, not the
# channel: the policy type says whether the policy is Proxy DLP (web) or
# API DLP (SaaS), so services are not counted against the web share.
_SKY_IGNORE = frozenset(("classifications", "classification", "content_classifications", "conditions", "condition", "policy_type", "policytype", "score",
                         "services", "service", "cloud_services", "cloud_service"))


def _sky_class_facet(c: Dict[str, Any]) -> str:
    ctype = re.sub(r"[^a-z]", "", " ".join(str(c.get(k) or "") for k in ("type", "classification_type", "classificationType", "kind", "category")).lower())
    if any(w in ctype for w in ("idm", "indexeddocument", "document", "unstructured")):
        return "idm"
    if any(w in ctype for w in ("edm", "structured", "exactdata", "exact")):
        return "edm"
    if any(w in ctype for w in ("ml", "machine", "model")):
        return "ml"
    if c.get("predefined") is True or c.get("built_in") is True or c.get("builtin") is True or any(w in ctype for w in ("precanned", "predefined", "builtin", "system")):
        return "data_identifiers"
    if any(w in ctype for w in ("keyword", "dictionary", "advancedpattern", "regex", "pattern", "custom")) or _items_of(c):
        return "content_patterns"
    return "data_identifiers"


def _sky_special(kl: str, v: Any, fx: _Facets) -> bool:
    if kl in ("classifications", "classification", "content_classifications", "data_identifiers") and isinstance(v, (list, dict, str)):
        for c in (v if isinstance(v, list) else [v]):
            if isinstance(c, str):
                c = {"name": c}
            if not isinstance(c, dict):
                continue
            facet = _sky_class_facet(c)
            name = str(c.get("name") or c.get("classification_name") or c.get("#text") or "").strip()
            fx.add(facet, texts=[name] if name else (), items=_items_of(c) if facet == "content_patterns" else [])
            th = _thresholds_of(c)
            if th:
                fx.add("match_thresholds", texts=th)
        return True
    if kl in ("policy_type", "policytype"):
        kind = {"0": "saas-api (API DLP)", "1": "web (Proxy DLP)"}.get(str(v).strip())
        fx.add("channel", texts=[kind or _norm_channel(str(v))])
        return True
    return False


def _sky_is_policy(d: Dict[str, Any]) -> bool:
    keys = {_norm_key(k) for k in d}
    return bool(keys & {"policy_name", "policyname"}) or ("name" in keys and bool(keys & {"rule_groups", "rulegroups", "rule_group", "rulegroup", "rules", "rule", "policy_type", "policytype", "classifications", "classification"}))


def inventory_skyhigh(data: bytes, source_name: str = "policy-templates.zip") -> Dict[str, Any]:
    """Skyhigh Policy Templates export (zip of JSON / XML), or one policy /
    list as JSON or XML → the inventory."""
    members: List[Tuple[str, bytes]] = _unzip(data, source_name) if _is_zip(data) else [(source_name, data)]
    policies: List[Dict[str, Any]] = []
    for mname, mdata in members:
        low = mname.lower()
        stripped = mdata.lstrip()
        if low.endswith(".xml") or (not low.endswith((".json", ".csv", ".txt")) and stripped.startswith(b"<")):
            root = _xml_root(mdata, mname)
            obj = {_tag(root): _xml_to_obj(root)}
        elif low.endswith(".json") or stripped.startswith((b"{", b"[")):
            obj = _load_json(mdata, mname)
        else:
            continue
        for pobj in _find_policies(obj, _sky_is_policy, list_keys=("policies", "policy", "data", "items", "results", "templates", "policy_templates", "policytemplates", "policytemplate", "policy_template", "dlp_policies", "dlppolicies")):
            name = _policy_name(pobj) or Path(mname).stem
            fx = _Facets()
            _walk_json(pobj, fx, _sky_special, _SKY_OVERRIDES, _SKY_IGNORE)
            groups = pobj.get("rule_groups") or pobj.get("ruleGroups") or pobj.get("ruleGroup") or pobj.get("rule_group") or []
            groups = groups if isinstance(groups, list) else [groups]
            entry = {"id": _policy_id(pobj, name, "sky"), "name": name, "active_status": _policy_status(pobj), "child_tags": sorted(str(k) for k in pobj),
                     "source_member": mname if _is_zip(data) else None, "rule_groups": [str(g.get("name") or "") for g in groups if isinstance(g, dict)][:64]}
            entry.update(fx.result())
            policies.append(entry)
    return _finish(policies, data, source_name, "policy-templates.zip", "Skyhigh policies (a policy name with rule groups, rules or classifications)")


# ── One entry point: the vendor decides the reader ─────────────────────
READERS = {"symantec": inventory_bytes, "forcepoint": inventory_forcepoint, "netskope": inventory_netskope, "skyhigh": inventory_skyhigh}


def inventory_export(vendor_id: str, data: bytes, source_name: str = "") -> Dict[str, Any]:
    v = vendor(vendor_id)
    ext = os.path.splitext(str(source_name or ""))[1].lower()
    if ext and ext not in v["accepts"]:
        raise ValueError(f"{v['name']}: {ext} files are not an export this adapter reads; it accepts {', '.join(v['accepts'])}")
    snap = READERS[v["id"]](data, source_name or ("export" + (v["accepts"][0] if v["accepts"] else "")))
    snap["vendor"] = v["id"]
    return snap


def decisions_template(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """A starting decisions file for this export: the SHA-256 filled in,
    every source policy listed with nothing approved, and one worked
    dictionary and engine to copy. Every field is reviewed by a person."""
    return {
        "_help": ("Review every policy: either approved target-rule translations (one entry per target channel: web, endpoint, saas or email, "
                  "each with the channel's action, 1-4 engine_refs, a unique order from 1 within that channel, scope_acknowledged_any true "
                  "because the generated rule applies to Any user/location, and the channel's own fields listed under _channels) or one approved "
                  "retired/out_of_scope disposition with a reason. To carry a source policy to more than one channel, copy its entry and change "
                  "the channel. Dictionaries and engines are spelled out here and approved one by one; {{dict:ID}} in an engine expression "
                  "references a dictionary below. A changed export SHA-256 invalidates this file."),
        "_channels": {k: {"label": v["label"], "terraform": v["resource"], "actions": list(v["actions"]), "monitor_action": v["monitor"],
                          "fields": v["fields"], "required": list(v["needs"]), "max_engines": v["max_engines"], "name_max": v["name_max"]}
                      for k, v in TARGETS.items()},
        "source_sha256": snapshot["sha256"],
        "source_file": snapshot.get("source_file", ""),
        "dictionaries": [{"id": "example_context", "name": "EXAMPLE_CONTEXT", "approved": False, "description": "Migrated from the source DLP",
                          "match_type": "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "phrases": ["example phrase"], "patterns": ["example[ -]?[0-9]{6,10}"]}],
        "engines": [{"id": "example_engine", "name": "EXAMPLE_ENGINE", "approved": False, "description": "Migrated from the source DLP",
                     "zia_expression": "((D{{dict:example_context}}.S > 1))"}],
        "policies": [{"source_id": p["id"], "source_name": p["name"], "disposition": "", "reason": "", "channel": "web", "approved": False,
                      "scope_acknowledged_any": False, "action": "", "order": i + 1, "engine_refs": [], "target_name": p["name"],
                      # The efficacy mapping computes what it can from the export and the
                      # decisions; facets it cannot compute (predefined identifiers, EDM,
                      # IDM, ML) count as 0 unless a reviewer attests them here: true,
                      # false or a fraction 0-1, with a note.
                      "attest": {k: {"carried": False, "note": ""} for k in sorted(p.get("facets") or {}) if FACETS[k]["how"].startswith("not computable")}}
                     for i, p in enumerate(snapshot["policies"])],
    }


# ── Efficacy mapping ───────────────────────────────────────────────────
def _clamp(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _facet_score(key: str, src: Dict[str, Any], pol: Dict[str, Any], dict_items: int, engine_exprs: List[str], attest: Dict[str, Any]) -> Dict[str, Any]:
    """One facet's score in [0, 1] with the arithmetic that produced it.
    `basis` says whether the number was computed, attested or fixed."""
    spec = FACETS[key]
    at = attest.get(key) if isinstance(attest, dict) else None
    if isinstance(at, dict) and at.get("carried") not in (None, ""):
        c = at["carried"]
        val = 1.0 if c is True else 0.0 if c is False else _clamp(c) if isinstance(c, (int, float)) else 0.0
        return {"score": val, "basis": "attested", "detail": f"reviewer attested {val:.0%}" + (f": {at.get('note')}" if at.get("note") else "")}
    if key == "content_patterns":
        n = len(src.get("items") or []) or src.get("elements", 0)
        if n <= 0:
            return {"score": 0.0, "basis": "computed", "detail": "no keyword or regex items readable in the export"}
        val = _clamp(dict_items / n)
        return {"score": val, "basis": "computed", "detail": f"{dict_items} phrases and patterns in the referenced dictionaries ÷ {n} keyword and regex items in the source = {val:.0%}"}
    if key == "match_thresholds":
        if not engine_exprs:
            return {"score": 0.0, "basis": "computed", "detail": "no engine referenced"}
        with_t = sum(1 for e in engine_exprs if _THRESHOLD_RE.search(e))
        val = with_t / len(engine_exprs)
        return {"score": val, "basis": "computed", "detail": f"{with_t} of {len(engine_exprs)} referenced engine expressions carry a numeric threshold = {val:.0%}"}
    if key == "channel":
        targets = list(pol.get("targets") or [])
        covered = {k for t in targets for k in TARGETS.get(t, {}).get("covers", ())}
        texts = src.get("texts") or []
        if not texts:
            return {"score": 1.0 if targets else 0.0, "basis": "computed",
                    "detail": (f"no channel named in the source; the approved {', '.join(targets)} rule is taken as the whole channel") if targets else "no channel named in the source and no target rule approved"}
        kinds = [_channel_kind(t) for t in texts]
        hit = sum(1 for k in kinds if k in covered)
        val = hit / len(texts)
        missed = sorted({k for k in kinds if k not in covered and k != "other"})
        unknown = [t for t, k in zip(texts, kinds) if k == "other"]
        note = ""
        if missed:
            hints = {"cloud-download": "downloads are never inspected by DLP", "ftp": "add FTP_RULE to the web rule's protocols by hand"}
            note = "; not covered: " + ", ".join(k + (f" ({hints[k]})" if k in hints else "") for k in missed)
            if any(k not in hints for k in missed):
                note += " (approve a target rule on that channel)"
        if unknown:
            note += f"; {len(unknown)} mention{'s' if len(unknown) != 1 else ''} not recognised as a channel: " + ", ".join(unknown[:5])
        return {"score": val, "basis": "computed", "detail": f"{hit} of {len(texts)} channel mentions are covered by the approved target rules ({', '.join(targets) or 'none'}) = {val:.0%}{note}"}
    if key == "response_action":
        ok = bool(pol.get("action_ok"))
        return {"score": 1.0 if ok else 0.0, "basis": "computed", "detail": ("action " + str(pol.get("action_text")) + " approved; notification, quarantine and encryption responses are not carried") if ok else "no approved action on every target"}
    if key in ("identity_scope", "file_conditions", "exceptions", "severity"):
        return {"score": 0.0, "basis": "fixed", "detail": spec["how"]}
    return {"score": 0.0, "basis": "fixed", "detail": spec["how"] + " (nothing attested)"}


def efficacy(snapshot: Dict[str, Any], decisions: Dict[str, Any], res: Dict[str, Dict[str, Any]], emitted: Optional[set] = None) -> Dict[str, Any]:
    """How much of each source policy's detection the ZIA translation
    carries, as a weighted percentage over the facets the export exposes,
    with the arithmetic per facet. Retired and out-of-scope policies are
    listed but not scored; a policy whose export carries no recognisable
    detection facet is "not computable", never a number."""
    by_id = {p["id"]: p for p in snapshot["policies"]}
    dict_sizes = {slug(d.get("id", "")): len(d.get("phrases") or []) + len(d.get("patterns") or [])
                  for d in decisions.get("dictionaries", []) or [] if d.get("approved")}
    engines = {slug(e.get("id", "")): e.get("zia_expression", "") or "" for e in decisions.get("engines", []) or [] if e.get("approved")}
    rows = []
    tot_w = tot_s = 0.0
    # One source policy may have several decisions, one per target channel;
    # the policy is scored once, over everything its approved targets carry.
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for p in decisions.get("policies", []) or []:
        groups.setdefault(str(p.get("source_id", "")), []).append(p)
    for sid, plist in groups.items():
        src = by_id.get(sid)
        if not src:
            continue
        disp = next((p["disposition"] for p in plist if p.get("disposition") in ("retired", "out_of_scope")), None)
        if disp:
            rows.append({"source_id": sid, "name": src["name"], "status": disp, "fidelity": None, "facets": [], "targets": [], "note": "not scored: the policy is not being carried over"})
            continue
        facets = src.get("facets") or {}
        if not facets:
            rows.append({"source_id": sid, "name": src["name"], "status": "not_computable", "fidelity": None, "facets": [], "targets": [],
                         "note": "the export carries no recognisable detection element for this policy (only id, name and status), so no percentage is claimed"})
            continue
        # A decision counts only when the compile produced its rule (emitted);
        # without that list (a stand-alone call) an approved, well-formed
        # decision counts.
        def carried(p: Dict[str, Any]) -> bool:
            if emitted is not None:
                return (sid, str(p.get("channel"))) in emitted
            return p.get("approved") is True and p.get("channel") in TARGETS and p.get("action") in TARGETS[p["channel"]]["actions"]
        ok = [p for p in plist if carried(p)]
        refs = list(dict.fromkeys(slug(x) for p in ok for x in (p.get("engine_refs") or []) if isinstance(x, str)))
        exprs = [engines[r] for r in refs if r in engines]
        dict_items = 0
        for e in exprs:
            for m in re.finditer(r"zia_dlp_dictionaries\.([a-z0-9_]+)\.id|\{\{dict:([A-Za-z0-9_-]+)\}\}", e):
                dict_items += dict_sizes.get(slug(m.group(1) or m.group(2)), 0)
        approved_targets = [str(p.get("channel")) for p in ok]
        pol = {"targets": list(dict.fromkeys(approved_targets)),
               "action_ok": bool(ok) and len(ok) == len(plist),
               "action_text": ", ".join(f"{p.get('channel')}: {p.get('action')}" + ("" if carried(p) else " (blocked)") for p in plist)}
        # Attestations are merged across a policy's decisions: the template
        # pre-fills every copy with carried false, so a value a reviewer set
        # on any copy (true or a fraction, with its note) wins over that.
        attest: Dict[str, Any] = {}
        for p in plist:
            for k, v in (p.get("attest") or {}).items() if isinstance(p.get("attest"), dict) else ():
                if not isinstance(v, dict):
                    continue
                informative = v.get("carried") not in (None, "", False)
                if k not in attest or (informative and attest[k].get("carried") in (None, "", False)):
                    attest[k] = v
        frows = []
        w_sum = s_sum = 0.0
        for key in FACETS:
            if key not in facets:
                continue
            sc = _facet_score(key, facets[key], pol, dict_items, exprs, attest)
            w = FACETS[key]["weight"]
            w_sum += w; s_sum += w * sc["score"]
            frows.append({"facet": key, "name": FACETS[key]["name"], "weight": w, "source_elements": facets[key]["elements"],
                          "source_sample": (facets[key].get("items") or facets[key].get("texts") or [])[:5],
                          "zia": FACETS[key]["zia"], "score": round(sc["score"], 4), "points": round(w * sc["score"], 2), "basis": sc["basis"], "detail": sc["detail"]})
        fid = round(s_sum / w_sum * 100, 1) if w_sum else None
        tot_w += w_sum; tot_s += s_sum
        rows.append({"source_id": sid, "name": src["name"], "status": "translated" if ok and len(ok) == len(plist) else "not_approved", "fidelity": fid,
                     "points": round(s_sum, 2), "weight": round(w_sum, 2), "facets": frows, "unrecognised": src.get("unrecognised") or [], "targets": pol["targets"],
                     "note": f"{s_sum:.1f} of {w_sum:.0f} weighted points carried = {fid}%" if fid is not None else ""})
    overall = round(tot_s / tot_w * 100, 1) if tot_w else None
    scored = [r for r in rows if r["fidelity"] is not None]
    return {"overall_fidelity": overall, "scored_policies": len(scored), "policies": rows,
            "method": ("Per policy: every detection facet recognised in the export (by element name) is scored 0-1 against what the "
                       "decisions carry (computed where the export and the decisions expose the numbers, attested by a reviewer for "
                       "predefined identifiers, EDM, IDM and ML, fixed at 0 for what this adapter never emits), weighted by the facet's "
                       "share of a policy's detection; fidelity = weighted points carried ÷ weighted points present. A policy with "
                       "several target rules (web, endpoint, SaaS API, email) is scored once over all of them. Overall = the same "
                       "ratio over every scored policy. Retired policies and exports with no recognisable detection element are not "
                       "scored and no number is claimed for them."),
            "weights": {k: v["weight"] for k, v in FACETS.items()},
            "note": (f"{overall}% of the recognised detection across {len(scored)} scored polic{'y' if len(scored) == 1 else 'ies'} is carried by the translation."
                     if overall is not None else "Not computable: no scored policy exposes a detection facet the mapping can measure.")}


# ── Compile (vendor-agnostic) ──────────────────────────────────────────
from dlp_importer import DICT_DESCRIPTION_MAX, ENGINE_DESCRIPTION_MAX, fit_description  # noqa: E402


def _fit(text: str, limit: int) -> str:
    """A description within ZIA's limit for the object, counted in UTF-8
    bytes as ZIA and the provider count it (they refuse longer)."""
    return fit_description(str(text or ""), "", limit)


def rule_label(prefix: str, source_id: str, channel: str = "web") -> str:
    """The Terraform label of a migrated rule: the vendor prefix, the source
    id, then the channel for every target but web. Kept exactly as earlier
    versions wrote it (a Symantec id "sym-101" is sym_sym_101), so a
    migration someone already applied keeps its resource addresses; and
    injective, since every label carries the prefix once in front."""
    return slug(f"{prefix}_{source_id}" + ("" if channel == "web" else f"_{channel}"))


def slug(s: str) -> str:
    x = re.sub(r"[^a-z0-9_]", "_", str(s).lower()).strip("_")
    if not x or x[0].isdigit():
        x = "obj_" + x
    return x[:60]


def _lit(s: Any) -> str:
    """A literal string for Terraform JSON, where every string is a
    template: `${` and `%{` from a reviewed name or phrase are escaped so
    they are text, never an interpolation."""
    return str(s).replace("${", "$${").replace("%{", "%%{")


def compile_export(snapshot: Dict[str, Any], decisions: Dict[str, Any], prefix: str = "sym", vendor_id: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(terraform, report). The report's `ready` is True only when every
    source policy has an approved disposition or translation and every
    referenced object was generated; the Terraform is deployable only then."""
    if not isinstance(decisions, dict):
        raise ValueError("Decisions must be a JSON object")
    if decisions.get("source_sha256") != snapshot["sha256"]:
        raise ValueError("Decision file source_sha256 does not match export; review source changes")
    by_id = {p["id"]: p for p in snapshot["policies"]}
    selected = decisions.get("policies", []) or []
    # One decision per source policy and target channel (a policy carried to
    # web and email is two entries); a disposition is one entry on its own.
    pairs = [(str(p.get("source_id", "")), str(p.get("channel") or "") if p.get("disposition") not in ("retired", "out_of_scope") else "disposition") for p in selected]
    if len(set(pairs)) != len(pairs):
        dup = sorted({f"{s} ({c})" for s, c in pairs if pairs.count((s, c)) > 1})
        raise ValueError("Duplicate decision for the same source_id and channel: " + ", ".join(dup))
    per_source: Dict[str, int] = {}
    for s, _c in pairs:
        per_source[s] = per_source.get(s, 0) + 1
    # A disposition and target rules for the same source: the whole source
    # is questioned once and none of its entries is compiled.
    mixed = {s for s, c in pairs if c == "disposition" and per_source[s] > 1}
    asked_mixed: set = set()
    emitted: set = set()   # (source_id, channel) pairs that produced a rule; the efficacy mapping credits only these
    res: Dict[str, Dict[str, Any]] = {"zia_dlp_dictionaries": {}, "zia_dlp_engines": {}, "zia_dlp_web_rules": {}}
    for spec in TARGETS.values():
        res.setdefault(spec["resource"], {})
    data_blocks: Dict[str, Dict[str, Any]] = {}
    variables: Dict[str, Dict[str, Any]] = {}
    vendor_id = vendor_id or snapshot.get("vendor") or "symantec"
    origin = f"{(VENDORS.get(vendor_id) or {}).get('name', vendor_id)} export {snapshot['sha256'][:12]}"
    default_desc = f"Migrated from {origin}."   # pushed to the tenant: never names DLP-Check (rule 2)
    report: Dict[str, Any] = {"source_sha256": snapshot["sha256"], "provider_version": PROVIDER_VERSION, "vendor": vendor_id,
                              "semantic_equivalence": "manual_review_required_native_export_not_interpreted",
                              "converted": [], "questions": [], "blocked": [], "dispositions": []}

    def question(source_id, reason, kind="ASK"):
        report["questions"].append({"source_id": source_id, "kind": kind, "reason": reason})
        report["blocked"].append(source_id)

    for d in decisions.get("dictionaries", []) or []:
        key = slug(d.get("id", ""))
        if key in res["zia_dlp_dictionaries"]:
            raise ValueError("Duplicate dictionary slug: " + key)
        phrases, patterns = d.get("phrases", []) or [], d.get("patterns", []) or []
        if (d.get("approved") is not True or not isinstance(d.get("name"), str) or not d["name"].strip() or not isinstance(phrases, list) or not isinstance(patterns, list)
                or not (phrases or patterns) or len(phrases) > 256 or len(patterns) > 8):
            question(d.get("id", "?"), "Dictionary requires approval (true), name, content and valid item limits")
            continue
        if any(not isinstance(x, str) or not 0 < len(x) <= 128 for x in phrases) or any(not isinstance(x, str) or not 0 < len(x) <= 256 for x in patterns):
            question(d.get("id", "?"), "Dictionary phrase/pattern length invalid")
            continue
        obj: Dict[str, Any] = {"name": _lit(d["name"]), "description": _lit(_fit(d.get("description") or default_desc, DICT_DESCRIPTION_MAX)),
                               "dictionary_type": "PATTERNS_AND_PHRASES",
                               "custom_phrase_match_type": d.get("match_type", "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY")}
        if obj["custom_phrase_match_type"] not in MATCH_TYPES:
            question(d.get("id", "?"), "Unknown ZIA custom phrase match type")
            continue
        if phrases:
            obj["phrases"] = [{"phrase": _lit(x), "action": "PHRASE_COUNT_TYPE_ALL"} for x in phrases]
        if patterns:
            obj["patterns"] = [{"pattern": _lit(x), "action": "PATTERN_COUNT_TYPE_UNIQUE"} for x in patterns]
        res["zia_dlp_dictionaries"][key] = obj

    for e in decisions.get("engines", []) or []:
        key = slug(e.get("id", ""))
        if key in res["zia_dlp_engines"]:
            raise ValueError("Duplicate engine slug: " + key)
        expr = e.get("zia_expression", "") or ""
        if e.get("approved") is not True or not isinstance(e.get("name"), str) or not e["name"].strip() or not isinstance(expr, str) or not expr:
            question(e.get("id", "?"), "Engine name, approved expression and approval (true) required")
            continue
        missing: List[str] = []

        def sub(m):
            ref = slug(m.group(1))
            if ref not in res["zia_dlp_dictionaries"]:
                missing.append(m.group(1))
            return "${zia_dlp_dictionaries." + ref + ".id}"
        expr2 = re.sub(r"\{\{dict:([A-Za-z0-9_-]+)\}\}", sub, expr)
        if missing or "{{" in expr2 or "${" in expr:
            question(e.get("id", "?"), "Unresolved dictionary reference or unsafe interpolation: " + ", ".join(missing))
            continue
        res["zia_dlp_engines"][key] = {"name": _lit(e["name"]), "description": _lit(_fit(e.get("description") or default_desc, ENGINE_DESCRIPTION_MAX)),
                                       "engine_expression": expr2, "custom_dlp_engine": True}

    for p in selected:
        source_id = str(p.get("source_id", ""))
        if source_id not in by_id:
            raise ValueError("Decision references absent source policy: " + source_id)
        if source_id in mixed:
            if source_id not in asked_mixed:
                question(source_id, "A retired or out-of-scope policy cannot also have target rules; keep one decision for it")
                asked_mixed.add(source_id)
            continue
        if p.get("disposition") in ("retired", "out_of_scope"):
            if p.get("approved") is not True or not isinstance(p.get("reason"), str) or not p["reason"].strip():
                question(source_id, "Retirement or exclusion needs approval (true) and a reason")
            else:
                report["dispositions"].append({"source_id": source_id, "disposition": p["disposition"], "reason": p["reason"]})
            continue
        channel = str(p.get("channel") or "")
        spec = TARGETS.get(channel)
        if not spec:
            question(source_id, f"Channel must be one of {', '.join(TARGETS)}: {channel!r}", "UNSUPPORTED")
            continue
        engines = p.get("engine_refs") or []
        if not isinstance(engines, list) or any(not isinstance(x, str) or not x.strip() for x in engines):
            question(source_id, "engine_refs must be a list of engine ids from this file")
            continue
        if (p.get("approved") is not True or p.get("scope_acknowledged_any") is not True or p.get("action") not in spec["actions"]
                or not 1 <= len(engines) <= spec["max_engines"] or not isinstance(p.get("order"), int) or isinstance(p.get("order"), bool) or p["order"] < 1):
            question(source_id, f"{spec['label']} rule needs approved: true, scope_acknowledged_any: true, an action from {', '.join(spec['actions'])}, "
                                f"1-{spec['max_engines']} engines and a positive order"
                                + ("; a SaaS remediation goes in designed_action" if channel == "saas" else "")
                                + ("; a custom header goes in designed_action (CUSTOMHEADERINSERTION) with custom_header: the zscaler/zia provider "
                                   "accepts ALLOW, BLOCK or QUARANTINE on an email rule, not CUSTOMHEADERINSERTION" if channel == "email" else ""))
            continue
        missing_engines = [x for x in engines if slug(x) not in res["zia_dlp_engines"]]
        if missing_engines:
            question(source_id, "Engine not generated: " + ", ".join(missing_engines))
            continue
        name = p.get("target_name") or by_id[source_id]["name"]
        if not isinstance(name, str) or not name.strip():
            question(source_id, "target_name must be the rule's name as text")
            continue
        name = name.strip()
        if spec["name_max"] and len(name) > spec["name_max"]:
            question(source_id, f"{spec['label']} rule name '{name}' is {len(name)} characters; ZIA allows {spec['name_max']}. Set a shorter target_name")
            continue
        key = rule_label(prefix, source_id, channel)
        if key in res[spec["resource"]]:
            raise ValueError(f"Duplicate {channel} rule slug: " + key)
        src_name = str(by_id[source_id].get("name") or "")[:80]
        rule: Dict[str, Any] = {"name": _lit(name), "description": _lit(_fit(f"Migrated from {origin}, source policy {source_id} ({src_name}); reviewed decision.", 255)),
                                "action": p["action"], "order": p["order"], "state": "DISABLED", "without_content_inspection": False,
                                "dlp_engines": [{"id": ["${zia_dlp_engines." + slug(x) + ".id}" for x in engines]}]}
        if spec["rank"] is not None:
            rule["rank"] = spec["rank"]
        problem = _channel_fields(channel, p, key, rule, data_blocks, variables)
        if problem:
            question(source_id, problem)
            continue
        res[spec["resource"]][key] = rule
        emitted.add((source_id, channel))
        entry = {"source_id": source_id, "channel": channel, "target": f"{spec['resource']}.{key}", "state": "DISABLED", "action": p["action"]}
        if p.get("designed_action"):
            entry["designed_action"] = str(p["designed_action"])
            if channel == "email" and isinstance(p.get("custom_header"), str) and p["custom_header"].strip():
                entry["custom_header"] = p["custom_header"].strip()
        report["converted"].append(entry)
    selected_ids = {str(p.get("source_id", "")) for p in selected}
    for source_id in by_id:
        if source_id not in selected_ids:
            question(source_id, "No reviewed disposition or translation")
    # Orders are checked on a run with nothing blocked: a blocked rule leaves
    # a gap that the questions already explain, and the ready run rechecks.
    if not report["blocked"]:
        for channel, spec in TARGETS.items():
            orders = [v["order"] for v in res[spec["resource"]].values()]
            if len(set(orders)) != len(orders) or sorted(orders) != list(range(1, len(orders) + 1)):
                raise ValueError(f"Generated {channel} rule orders must be unique and contiguous starting at 1")
            if channel == "web" and len(orders) > WEB_RULE_LIMIT:
                raise ValueError(f"ZIA API web-rule limit exceeded ({WEB_RULE_LIMIT})")
    tf = {"//": f"Generated by DLP-Check from a reviewed {origin} (decisions bound to its SHA-256). Every rule ships DISABLED. "
                "Credentials come from ZSCALER_CLIENT_ID / ZSCALER_CLIENT_SECRET / ZSCALER_VANITY_DOMAIN / ZSCALER_CLOUD.",
          "terraform": {"required_version": TERRAFORM_VERSION, "required_providers": {"zia": {"source": PROVIDER_SOURCE, "version": PROVIDER_VERSION}}},
          "provider": {"zia": {}}, "resource": {k: v for k, v in res.items() if v}}
    if data_blocks:
        tf["data"] = data_blocks
    if variables:
        tf["variable"] = variables
    report["ready"] = not report["blocked"]
    report["efficacy"] = efficacy(snapshot, decisions, res, emitted=emitted)
    if vendor_id in VENDORS:
        xr = crossref(vendor_id)
        report["crossref"] = {"vendor": vendor_id, "source_api": xr["source_api"], "rows": xr["rows"], "carried": xr["carried"]}
    report["counts"] = {"source_policies": len(by_id), "converted_rules": len(report["converted"]),
                        "converted_by_channel": {ch: sum(1 for c in report["converted"] if c["channel"] == ch) for ch in TARGETS},
                        "blocked_policies_or_objects": len(report["questions"]),
                        "dictionaries": len(res["zia_dlp_dictionaries"]), "engines": len(res["zia_dlp_engines"]),
                        "dispositions": len(report["dispositions"])}
    return tf, report


def _channel_fields(channel: str, p: Dict[str, Any], key: str, rule: Dict[str, Any], data_blocks: Dict[str, Dict[str, Any]], variables: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Fill the channel's own attributes into `rule` (and the data sources
    and variables they need) from the decision; return the question that
    blocks the rule when a required field is missing or invalid."""
    if channel == "web":
        rule["protocols"] = ["HTTPS_RULE", "HTTP_RULE"]
        return None
    if channel == "endpoint":
        dtm = p.get("data_transfer_method")
        if dtm not in ENDPOINT_TRANSFER_METHODS:
            return f"Endpoint DLP rule needs data_transfer_method, one of {', '.join(ENDPOINT_TRANSFER_METHODS)} (one per rule; copy the entry for another method)"
        levels = p.get("device_trust_levels") or list(ENDPOINT_TRUST_LEVELS)
        if not isinstance(levels, list) or not levels or any(x not in ENDPOINT_TRUST_LEVELS for x in levels):
            return f"device_trust_levels must be a non-empty list from {', '.join(ENDPOINT_TRUST_LEVELS)}"
        rule["data_transfer_method"] = dtm
        rule["device_trust_levels"] = list(levels)
        if p["action"] == "CONFIRM":
            # ZIA requires a user-confirmation template for CONFIRM; the tenant's ENDPOINT_DLP one is looked up by name at plan time.
            data_blocks.setdefault("zia_eun_user_confirmation_template_product", {})["endpoint_dlp"] = {"product": "ENDPOINT_DLP", "name": "${var.endpoint_dlp_user_confirmation_template_name}"}
            variables["endpoint_dlp_user_confirmation_template_name"] = {"type": "string", "default": None,
                                                                         "description": "User Confirmation template for Endpoint DLP CONFIRM rules; null uses the tenant's default ENDPOINT_DLP template."}
            rule["uc_template_id"] = "${data.zia_eun_user_confirmation_template_product.endpoint_dlp.id}"
        return None
    if channel == "saas":
        t = p.get("saas_type")
        if t not in SAAS_RULE_TYPES:
            return f"SaaS Security API rule needs saas_type, one of {', '.join(SAAS_RULE_TYPES)}"
        rule["type"] = t
        rule["collaboration_scope"] = ["ANY"]
        return _tenants(p, key, rule, "cloud_app_tenants", "SaaS application", data_blocks, variables)
    if channel == "email":
        if str(p.get("designed_action") or "") == "CUSTOMHEADERINSERTION":
            header = p.get("custom_header")
            if not isinstance(header, str) or not header.strip() or len(header) > 128:
                return "designed_action CUSTOMHEADERINSERTION needs custom_header (the header text, up to 128 characters)"
        return _tenants(p, key, rule, "email_tenants", "email", data_blocks, variables)
    return f"Channel {channel!r} has no target adapter"


def _tenants(p: Dict[str, Any], key: str, rule: Dict[str, Any], block: str, what: str, data_blocks: Dict[str, Dict[str, Any]], variables: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """SaaS / email tenants: names of onboarded tenants become
    zia_casb_tenant data lookups; the word "variable" leaves the ids to a
    Terraform variable filled in at plan time. Anything else blocks."""
    want = p.get("tenants")
    if isinstance(want, str) and want.strip().lower() == "variable":
        # The same two variables per channel the pack Terraform uses: a map of
        # rule name -> ids with a default list for every rule not named, and a
        # plan-time check that says which rule still needs its ids.
        kind = "saas" if block == "cloud_app_tenants" else "email"
        variables[f"{kind}_tenant_ids"] = {"type": "map(list(number))", "default": {}, "nullable": False,
                                           "description": f"Onboarded {what} tenant ids per rule name (Administration > SaaS Application Tenants); "
                                                          f"a rule not listed here uses {kind}_tenant_ids_default."}
        variables[f"{kind}_tenant_ids_default"] = {"type": "list(number)", "default": [], "nullable": False,
                                                   "description": f"Onboarded {what} tenant ids for every {what} rule not listed in {kind}_tenant_ids."}
        name_lit = '"' + str(rule["name"]).replace("\\", "\\\\").replace('"', '\\"') + '"'
        expr = f"lookup(var.{kind}_tenant_ids, {name_lit}, var.{kind}_tenant_ids_default)"
        rule[block] = [{"id": "${" + expr + "}"}]
        rule["lifecycle"] = [{"precondition": [{"condition": "${length(" + expr + ") > 0}",
                                                "error_message": f"Rule {rule['name']}: set {kind}_tenant_ids[{name_lit}] or {kind}_tenant_ids_default to the ids "
                                                                 f"of the onboarded {what} tenants (Administration > SaaS Application Tenants)."}]}]
        return None
    if isinstance(want, list) and want and all(isinstance(x, str) and x.strip() for x in want):
        ids = []
        lookups = data_blocks.setdefault("zia_casb_tenant", {})
        for n in dict.fromkeys(x.strip() for x in want):
            # One data block per distinct tenant name: two names that slug alike get their own labels.
            base = lbl = slug("tenant_" + n)
            i = 2
            while lbl in lookups and lookups[lbl]["tenant_name"] != _lit(n):
                lbl = f"{base}_{i}"
                i += 1
            lookups[lbl] = {"tenant_name": _lit(n)}
            ids.append("${data.zia_casb_tenant." + lbl + ".tenant_id}")
        rule[block] = [{"id": ids}]
        return None
    return f"tenants must list the onboarded {what} tenant names, or be the word \"variable\" to fill the ids in at terraform plan"


def workspace_files(tf: Dict[str, Any], report: Dict[str, Any], vendor_name: str, source_file: str = "") -> Dict[str, str]:
    """The compiled Terraform as the reviewable workspace a platform team
    commits: the same file layout as the pack hand-off (terraform.tf,
    providers.tf, variables.tf, dictionaries.tf, engines.tf, rules.tf,
    locals.tf, outputs.tf, README.md, .gitignore, terraform.tfvars.example),
    fmt-clean HCL, plus migration-report.json for the review record."""
    import pack_terraform as pt
    counts = report.get("counts") or {}
    note = (f"Generated by DLP-Check from a reviewed {vendor_name} export"
            + (f" (`{source_file}`" if source_file else " (")
            + f"{', ' if source_file else ''}SHA-256 `{str(report.get('source_sha256', ''))[:12]}…`): "
            f"{counts.get('converted_rules', 0)} rules from {counts.get('source_policies', 0)} source policies, "
            f"{counts.get('dispositions', 0)} retired or out of scope. `migration-report.json` beside these files is the review record "
            "(every conversion, question and efficacy figure).")
    files = pt.render_json_workspace(tf, title=f"{vendor_name} migration", source_note=note)
    files["migration-report.json"] = json.dumps(dict({"//": "Written by DLP-Check: the review record of this migration."}, **report),
                                                indent=2, ensure_ascii=False) + "\n"
    return files


def workspace_zip(result: Dict[str, Any]) -> bytes:
    """compile_upload's result (ready) as one zip, one folder."""
    import pack_terraform as pt
    if not result.get("terraform"):
        raise ValueError("Blocked: answer the questions in the migration report, then compile again.")
    files = workspace_files(result["terraform"], result["report"], result.get("vendor_name") or result.get("vendor") or "",
                            (result.get("snapshot") or {}).get("source_file") or "")
    return pt.zip_workspaces({f"{result.get('vendor') or 'vendor'}-migration": files})


# ── The page's two calls ───────────────────────────────────────────────
def inventory_upload(vendor_id: str, export_file: Dict[str, Any]) -> Dict[str, Any]:
    v = vendor(vendor_id)
    data = decode_upload(export_file)
    snapshot = inventory_export(v["id"], data, export_file.get("name") or "")
    return {"vendor": v["id"], "vendor_name": v["name"], "snapshot": snapshot, "decisions_template": decisions_template(snapshot), "crossref": crossref(v["id"])}


def compile_upload(vendor_id: str, export_file: Dict[str, Any], decisions: Any) -> Dict[str, Any]:
    v = vendor(vendor_id)
    data = decode_upload(export_file)
    snapshot = inventory_export(v["id"], data, export_file.get("name") or "")
    if isinstance(decisions, dict) and "content" in decisions and "policies" not in decisions:
        try:
            decisions = json.loads(decode_upload(decisions).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Decisions file is not valid JSON: {e}")
    tf, report = compile_export(snapshot, decisions, prefix=v["prefix"], vendor_id=v["id"])
    return {"vendor": v["id"], "vendor_name": v["name"],
            "snapshot": {"source_file": snapshot["source_file"], "sha256": snapshot["sha256"], "policy_count": len(snapshot["policies"])},
            "report": report, "terraform": tf if report["ready"] else None}


# ── Command line: the same steps, plus the export fetcher ──────────────
def fetch_export(url: str, token: str, out, header: str = "Authorization: Bearer") -> int:
    """One authenticated HTTPS GET of a tenant's documented export URL
    (Symantec's export URL, a Forcepoint REST policy, a Netskope REST API
    v2 call with its Netskope-Api-Token header). Refuses redirects (the
    token must not follow to another origin), caps the response at
    MAX_EXPORT_BYTES, accepts XML or JSON only, writes mode 0600."""
    import urllib.request
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Only HTTPS URLs are accepted")
    if not token:
        raise ValueError("Token is missing")
    hname, _, hprefix = str(header or "Authorization: Bearer").partition(":")
    hname = hname.strip() or "Authorization"
    if not re.fullmatch(r"[A-Za-z0-9-]+", hname):
        raise ValueError("The token header name must be a plain HTTP header name")
    req = urllib.request.Request(url, headers={hname: (hprefix.strip() + " " + token).strip(), "Accept": "application/json, application/xml"}, method="GET")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        data = response.read(MAX_EXPORT_BYTES + 1)
    if len(data) > MAX_EXPORT_BYTES or not data.lstrip().startswith((b"<", b"{", b"[")):
        raise ValueError("Response exceeds the size limit or is not XML or JSON")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    out.chmod(0o600)
    return 0


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Migrate from another DLP: inventory an export, compile reviewed decisions to disabled ZIA Terraform.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory", help="List the export's policies and write a decisions template")
    inv.add_argument("export", type=Path)
    inv.add_argument("--vendor", default="symantec")
    inv.add_argument("--out", type=Path, default=Path("build"))
    comp = sub.add_parser("compile", help="Compile reviewed decisions; Terraform is written only when every policy is decided")
    comp.add_argument("export", type=Path)
    comp.add_argument("--decisions", type=Path, required=True)
    comp.add_argument("--vendor", default="symantec")
    comp.add_argument("--out", type=Path, default=Path("build"))
    fe = sub.add_parser("fetch", help="Fetch an XML or JSON export from the tenant's documented export URL or REST API (token from an environment variable)")
    fe.add_argument("--url", required=True)
    fe.add_argument("--token-env", required=True)
    fe.add_argument("--header", default="Authorization: Bearer", help="How the token is sent: 'Authorization: Bearer' (default; Symantec, Forcepoint access token) or 'Netskope-Api-Token'")
    fe.add_argument("--out", required=True, type=Path)
    xr = sub.add_parser("crossref", help="Print the vendor's API cross-reference (source object/field → ZIA object/field, API call, Terraform)")
    xr.add_argument("--vendor", default="symantec")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "fetch":
            token = os.environ.get(args.token_env)
            if not token:
                ap.error("Token environment variable is missing")
            fetch_export(args.url, token, args.out, header=args.header)
            print("Saved export to", args.out)
            return 0
        v = vendor(args.vendor)
        if args.cmd == "crossref":
            print(json.dumps(crossref(v["id"]), indent=2, ensure_ascii=False))
            return 0
        snapshot = inventory_export(v["id"], Path(args.export).read_bytes(), Path(args.export).name)
        _write_json(args.out / "source-inventory.json", snapshot)
        if args.cmd == "inventory":
            _write_json(args.out / "decisions.template.json", decisions_template(snapshot))
            print("Inventory and a decisions template written. Review every policy, then run compile.")
            return 0
        tf, report = compile_export(snapshot, json.loads(args.decisions.read_text()), prefix=v["prefix"], vendor_id=v["id"])
        _write_json(args.out / "migration-report.json", report)
        if report["ready"]:
            _write_json(args.out / "main.tf.json", tf)
            import pack_terraform as pt
            pt.write_workspace(workspace_files(tf, report, v["name"], Path(args.export).name), str(args.out / "terraform"))
            print("READY: disabled Terraform written (main.tf.json, and the same as an HCL workspace in terraform/); "
                  "review and run terraform init/validate/plan in one of them, not both.")
            return 0
        (args.out / "main.tf.json").unlink(missing_ok=True)
        import pack_terraform as pt
        pt.remove_generated(str(args.out / "terraform"), names=("README.md", ".gitignore", "terraform.tfvars.example", "migration-report.json"))
        print("BLOCKED: see migration-report.json; no deployable Terraform emitted.", file=sys.stderr)
        return 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
