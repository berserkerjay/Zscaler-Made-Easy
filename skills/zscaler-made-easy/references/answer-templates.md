# Answer templates

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Plain words, short sentences, the answer first. Fill the `<...>` parts from
the tool's `data`; leave out a line that has nothing to say. End every answer
with the source line.

**Source line** (always):
> Source: `<tool>` on `<tenant>` (`<source>`), read `<read_at>`. Configuration
> only, unless it says observed.

On the sample tenant add: "This is the made-up sample tenant, not yours."

## Why was X blocked? / Is X allowed?

> **<X> is <blocked | allowed | bypassed | only logged> <for user Y> <on the
> network and platform>.** <verdict.headline, in your words>
>
> How it gets there: <step> → <step> → <deciding step>: rule *<rule>*
> (order <n>, <action>).
>
> Not certain: <certainty_reasons or what_if.depends_on, one line each>.
> Not assessed: <not_in_scope>.
>
> To change it: <fixes[0].action> in <where>. You make this change in the app
> or the portal; I can only read.

## Why didn't DLP catch this?

Walk the chain in order and stop at the first link that fails (see
data-security-flows.md, "walkbacks"):

> DLP did not act because **<the first failing link>**.
>
> 1. Did the traffic reach ZIA? <path_check steps: forwarding, PAC, ZPA>.
> 2. Was it decrypted? <verdict.decrypted; ssl_coverage cause if not>.
> 3. Did a DLP rule apply to it? <the candidate rules and their criteria>.
> 4. Would the engine fire on this content? <explain_dlp: in_one_sentence>.
> 5. Is the rule blocking or only logging? <action>.
>
> Check what really happened: <one SIEM query>.

## Is our DLP covering <channel>?

> **<Channel> is <covered | partly covered | not covered>.**
> <n> rules are enabled on it; <the strongest action>. <data_flow outcome for
> the traffic classes of that channel>.
>
> Gaps: <weak_points with severity>. <ssl_coverage causes for web and GenAI>.
>
> First fix: <the highest-risk fix>.

## Which rule wins? Are rules shadowed?

> **<Policy> uses <rule order | evaluate all rules (most restrictive wins)>.**
> <n> of <m> rules can never act:
> - *<rule>* (order <n>) is <kind> by *<shadowed_by>*: <fix>.
>
> Nothing is changed by this check; move, fix or delete the rules in the
> Zscaler portal (or the app's own pages, with their preview and
> confirmation).

## What is not inspected?

> **<class_coverage_pct>% of the kinds of web traffic are inspected.** Left
> encrypted: <not inspected classes>.
>
> Causes, highest risk first: <cause> set by <rule or profile> (<risk>).
>
> Recovery plan: 1. <step> (<where>). 2. <step> ...

## What DLP incidents are happening?

> **<n> DLP incidents in the last <minutes> minutes**, <enforced> enforced,
> <monitor> only logged, <unknown> unknown. Busiest rule: *<rule>*
> (<n>, configured to <action>). <distinct_users> different users (not named).
>
> This feed shows DLP incidents only; URL filtering and firewall decisions
> are in the web log (see the SIEM queries).

## Can a user reach a private app? (ZPA)

> **<outcome in words>.** Segment *<segment>* matches <destination:port>; access
> rule *<rule>* decides <for this user context>.
> Earlier rules that did not match: *<rule>* (<why>).
> Served by <server groups> through <connector groups> (<reachable>).

## Is the fleet healthy?

> **<n> devices, <registered> registered.** <alerts with counts, worst first>.
> Profiles with failing checks: <profile: checks>.
> Fix first: <fix_first[0].title>.

## What changed?

> **<added> added, <removed> removed, <changed> changed** between <from> and
> <to>. Biggest changes: <list: names>. Lists read on one side only are not
> counted as emptied.

## Compliance

> **<framework>: <status>** (<alignment_pct>% of the mapped checks pass; this
> is not a share of the framework). Not met: <control> (checks <ids>).
> Run from the assessment of <assessment_at>.

## When the answer is unknown

> I can't tell <what> because <the part> was not read: <reason, from the
> refusal or not_in_scope>. <How to fix it>. Everything else above stands.
