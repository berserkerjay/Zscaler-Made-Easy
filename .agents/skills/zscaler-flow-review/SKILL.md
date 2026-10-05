---
name: zscaler-flow-review
description: Review or repair end-to-end Zscaler flow analysis and API integration across ZIA, Client Connector, ZPA, and ZDX, including Data Flow Map, Path Analysis, and Live DLP. Use for cross-service flow completeness and evidence tracing, rather than unrelated Zscaler configuration changes.
---

# Zscaler flow review

Review the entire relevant flow, and trace every displayed decision back to an API response and a linked configuration object. Read [references/coverage.md](references/coverage.md) when building the coverage matrix or changing integrations.

## Establish the source and coverage

Identify the active repository, branch, working-tree changes, running version, supported authentication modes, installed SDK version, tenant cloud, and requested views. Reuse suitable local checkouts; keep experiments isolated. Inspect the current code and tests before editing. Do not mistake a historical review copy for the running application.

Inventory the official APIs relevant to the requested flow. Verify routes, SDK methods, response wrappers, field names, enums, pagination and permissions against current Zscaler documentation, official SDK source and read-only tenant responses where authorized. Record API/version differences and fallback rules. Never invent endpoint names or infer undocumented numeric enums.

Proactively inspect returned response shapes to find gaps in downstream consumers. Request every platform explicitly, normalize DEVICE_TYPE_* values, and preserve the app's nested onNetPolicy ID before flattening. Resolve the forwarding inventory by that ID when the top-level reference is null. Respect enableUnifiedTunnel before consuming unified actions. Link PAC content by its referenced URL; unrelated tenant PAC files are inventory, not evidence for the selected route. Recheck names, references, visibility labels and all affected views after normalization changes.

Build a service-by-view matrix for Data Flow Map, Path Analysis, Live DLP and other requested views. For each relevant API family, record the caller, normalized model, linked object IDs, consumed fields, display location, test coverage and a status: integrated, gap, unverified, unsupported, out of scope or not applicable. An API reader existing in the repository does not prove that a flow consumes it. Account for every relevant API in every requested view; justify applicability rather than forcing every product into every traffic path.

## Trace the branches

Follow device/user context → Client Connector app profile → its linked forwarding profile → selected network action → Internet/ZIA or private application/ZPA branch → applicable policies → DLP action and evidence delivery. Overlay ZDX device, application and path telemetry where correlation is supported. Keep Endpoint, SaaS API and Email DLP on their own channels rather than treating them as inline web traffic.

Resolve profiles using IDs before names, retain platform and policy precedence, and consider user/group/device assignments. Multiple eligible profiles without identity evidence are candidates, not proof of the applied profile. Do not select the only forwarding profile just because it is the only one returned. Read full inventories and required detail objects; reject incomplete pages, repeated pages and malformed successful responses.

Keep ZIA forwarding actions separate from ZPA actions, including unified-tunnel objects. Use the correct trusted, off-trusted, VPN-trusted or split-VPN branch. Preserve the relevant PAC/proxy, bypass, DNS, failover and tunnel settings. Unknown forwarding must make downstream conclusions conditional; an assumed tunnel must never become a verified route.

ZDX is experience telemetry, not an enforcement policy. Workflow Automation incidents are observed DLP events, not a complete transaction feed. Correlate services using supported device/user/application IDs, tenant identity and timestamps; expose missing joins and clock/window differences. Never attribute a tenant profile to a live incident without device or assignment evidence.

## Integrate consistently

Prefer shared readers, normalization and evidence models across views. Each decision should carry service, endpoint/source, object ID and name, read time, relevant network/platform and evidence status. Keep raw values narrowly allowlisted for diagnostics; never export profile passwords, policy tokens or credentials. Support camelCase and SDK snake_case without losing nested fields or false values.

Preserve the Scope page and tenant isolation. Do not read excluded services or products covered by another vendor. Cache by tenant and scope with a bounded lifetime, disclose read time, and invalidate incompatible snapshots after schema changes. Failed reads must remain unverified and retryable; successful empty results are distinct. Authentication failure, insufficient permissions, unavailable route, rate limiting and missing configuration require different explanations.

Configuration context and observed live routing must be visibly distinguished. Missing APIs, licenses, permissions, tenant identifiers or telemetry must be named as gaps instead of silently omitted or scored as weaknesses. Do not generate traffic, modify tenant policies, deploy, merge or publish merely because this skill is invoked; honor authorization in the current task.

## Verify and deliver

Test observable behavior: current and legacy routes, authorization failures without inappropriate fallback, every page and partial failures, platform/assignment selection, exact forwarding links, network branches, ZIA/ZPA separation, ZDX joins, scope exclusions, tenant/cache separation, unavailable evidence and exported/UI references. Test downstream consumers, not only helpers. Use fixtures or authorized read-only probes; label tenant verification separately from simulated tests.

For code changes, run at least 100 relevant test cases before applying changes to main when the user requests the 100-test gate. Do not count repeated executions or trivial variants as distinct coverage. Repair failures, review the final diff, check that main has not advanced, then apply only the verified change within the user's authorization. Report test counts, skips/failures, commit/PR or local-main state, actual tenant validation and remaining integration gaps. Never claim all APIs are integrated based on a matrix or a green test run alone.
