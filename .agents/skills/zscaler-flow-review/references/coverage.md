# Coverage checklist

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Use this as a starting matrix; discover the actual supported API families before changing code. Endpoint names outside the confirmed examples below must be verified, not guessed.

| Service | Configuration and evidence to account for | Flow use |
| --- | --- | --- |
| ZIdentity / authentication | Cloud gateway, client roles/scopes, ZPA customer ID, supported products | Establish readable services; keep classic ZIA-only authentication explicit |
| Client Connector | Application profiles, forwarding profiles, trusted networks, device inventory/details, assignments, posture, bypasses, DNS/PAC, failover | Device-to-service entry point; platform and network branches |
| ZIA | Locations/GRE/IPsec or explicit proxy entry, PAC, SSL, URL and cloud-app controls, firewall/DNS, file type, DLP rules/engines/dictionaries | Internet route and policy decisions; inspection prerequisites |
| ZPA | Application segments/groups, server groups/servers, App Connectors/groups, Service Edges where relevant, access/forwarding policies, identity and posture conditions, inspection/isolation when applicable | Private-app branch, reachability and policy; do not substitute ZIA web policy |
| ZDX | Monitored applications, devices/users, scores, alerts and supported web/cloud-path/device probes | Experience overlay and troubleshooting, with time-bound joins |
| DLP evidence | Endpoint, inline web, SaaS API and email channels; incident receivers, notification templates, Workflow Automation incidents and supported logs | Explain enforcement and evidence delivery separately from routing |

For every view, state which rows are read, linked and rendered; why other rows are out of scope or not applicable; and which missing integrations prevent a conclusion. If the user requests full coverage, produce a gap list and implement the authorized gaps rather than marking unimplemented services integrated.

## Confirmed Client Connector routes

Verified against official SDK source on 2026-10-04. Reverify when applying this skill to a newer SDK/API generation.

- App profile list: `GET /zcc/papi/public/v1/application-profiles`. The wire response uses `policies` and `totalCount`; SDK methods may discard wrapper metadata. Supports pagination and device-type filtering.
- App profile detail: `GET /zcc/papi/public/v1/application-profiles/{profileId}`.
- Forwarding inventory: `GET /zcc/papi/public/v1/webForwardingProfile/listByCompany`. Supports pagination.
- Link the app's `forwardingProfileId` to the forwarding object's `id`; support documented SDK snake_case forms and older name/object references without overriding an explicit unmatched ID.
- Preserve `forwardingProfileActions` for ZIA and `forwardingProfileZpaActions` for ZPA. A unified-tunnel object can contain separate `actionTypeZIA` and `actionTypeZPA` fields. Interpret only verified enum values.
- Older app-profile routes may be supported by particular tenants. Try legacy candidates only for route/schema incompatibility confirmed by the API, never to bypass a permission denial.

Primary sources:

- [Official Python application-profile API](https://github.com/zscaler/zscaler-sdk-python/blob/master/zscaler/zcc/application_profiles.py)
- [Official Python forwarding-profile API](https://github.com/zscaler/zscaler-sdk-python/blob/master/zscaler/zcc/forwarding_profile.py)
- [Official SDK repository: additional service APIs](https://github.com/zscaler/zscaler-sdk-python)
- [Client Connector app profiles](https://help.zscaler.com/zscaler-client-connector/about-zscaler-client-connector-app-profiles)
- [Forwarding profiles](https://help.zscaler.com/zscaler-client-connector/about-forwarding-profiles)

## Evidence contract

For each hop or overlay, keep `service`, `source`, `object_id`, `object_name`, `read_at`, `scope`, `status`, `linked_from` and the fields that actually explain the decision. Fit existing project schemas rather than imposing these exact names. Distinguish `verified`, `candidate`, `conditional`, `unverified`, `out_of_scope`, `not_applicable` and `unsupported` behavior in UI and exports.

For live incidents, link a profile or ZDX probe only when the API supplies sufficient correlation evidence. Otherwise expose tenant configuration references separately, with their read time and a clear statement that they are not the incident's measured route.
