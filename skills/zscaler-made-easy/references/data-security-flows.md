# Data security flows, in short

How data protection works in a Zscaler tenant, channel by channel, and how
to walk back when DLP did not act. The app draws the same flows on its
Data security architecture reference pages
(`static/reference/dsa_flows.js`). Use this page to explain, and the tools
to check the tenant.

## The detection chain (every channel)

1. **Dictionary**: finds a kind of data (card numbers, SSNs, keywords, an
   indexed record set or document set). It only counts matches; it never
   decides.
2. **Engine**: an expression over dictionary counts, for example
   `(D1.S > 1) AND (D7.S > 0)`. `explain_dlp` reads it in words. An engine is
   only usable on the channels it is enabled for.
3. **Channel rule**: says where the engine applies (users, groups,
   locations, apps, categories, file types) and what to do: block, confirm,
   allow (log only) and so on.
4. **Action and log**: the rule acts and the transaction is logged.
5. **Evidence**: only when the rule forwards it (Incident Receiver or
   cloud-to-cloud) does a copy reach the customer's storage, and only then
   does Workflow Automation open an incident. NSS and SIEM feeds never feed
   Workflow Automation, and Workflow Automation never feeds the SIEM.

So "no incident" can mean "no match" or "the rule does not forward
evidence". `explain_dlp` shows `sends_evidence_to_incident_receiver`.

## Inline web (and GenAI)

Order on the way out: traffic forwarding (Client Connector app and
forwarding profile, or PAC, or a tunnel) → SSL inspection → Cloud App
Control → URL filtering → threat checks → File Type Control → content
extraction → dictionaries → engines → DLP rule action → log, user notice and
evidence. `path_check` walks this order for one destination; `data_flow`
for every traffic class.

- If the traffic is bypassed before ZIA (app profile bypass, PAC DIRECT,
  forwarding "none", ZPA carries it), no ZIA control sees it.
- If SSL inspection does not decrypt it, DLP sees no content on HTTPS.
- An earlier block (URL filtering, Cloud App Control) means DLP never runs.
- With rule order, the first matching DLP rule decides; with "evaluate all
  rules", the most restrictive action wins.

## Endpoint DLP

The Endpoint DLP module on the device sees activity (removable media,
printing, network shares, cloud sync, apps). Exemptions apply first; every
endpoint rule is evaluated and the most restrictive action wins; the user
is notified locally; evidence follows the rule's forwarding. It needs the
module installed and the policy synced, and it works only on the platforms
Zscaler supports for it.

## Email DLP

Outbound mail is routed from the mail platform to Zscaler by a smart host.
Zscaler scans it per recipient, the most restrictive rule wins, and it
writes a verdict into the message headers. **The mail platform enforces the
verdict** with its own transport rules; if those are missing, nothing is
blocked even though the verdict says block.

## SaaS (API, data at rest)

Zscaler scans sanctioned SaaS tenants through their APIs: the tenant must be
onboarded and authorised, a scan must be started, and only data in the scan
window is read. Findings and actions (quarantine, revoke sharing) follow the
SaaS rules. Nothing here is inline: a blocked upload is never a SaaS rule.

## Walkbacks: why didn't DLP act?

Stop at the first link that fails, and say which tool showed it.

**Inline web**: SSL inspection (did it decrypt?) → DLP exemptions → an
earlier module's decision → the rule's criteria (user, group, app,
category, file type) → the engine (would it fire on this content? sizes and
counts) → content extraction (file type supported, size) → rule order or
shadowing (`rule_precedence`) → the rule's action (log only?) → policy
activated?

**Endpoint**: module installed → platform supported → policy synced →
exemption or one-time override → the rule targets this user and device →
the engine is enabled for the endpoint channel → every rule evaluated (a
stricter rule wins) → antivirus or EDR interference.

**Email**: the platform enforces the verdict → mail routed through the smart
host → the tenant header is present → the return path → no mail loop →
quarantine supported for that action.

**SaaS**: scan started → SaaS tenant status healthy → the data is in the
scan window → the rule targets this tenant and content → a cut-off date
reset.

**Workflow Automation (no incident)**: the integration is healthy → the rule
forwards evidence → to the same storage Workflow Automation reads → the
storage event reaches it → the Incident Receiver is healthy → the channel is
connected → the admin's view is not restricted.

## Configuration is not traffic

Everything above that the tools answer from configuration says what the
tenant is set to do. To prove what happened, use observed sources:
`dlp_incidents` (DLP incidents only), `traffic_summary` (aggregates only),
or the customer's own logs (siem-queries.md).
