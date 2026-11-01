# SIEM query templates

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

The tools read configuration and a few observed sources. To prove what
really happened to one user or destination, the admin runs a query in
their own log store. These are templates: give the admin the query text;
you do not run it, and no tool connects to a SIEM.

**Check the field names first.** Field names depend on the feed: a Nanolog
Streaming Service (NSS) or Cloud NSS feed's output format is chosen by the
admin, and each SIEM's add-on renames fields. The names below follow
Zscaler's common Splunk and Microsoft Sentinel (CEF) feed formats; they are
**assumed, not verified against this tenant**. Every section starts with a
query that shows one event, so the admin can match the names before using
the rest. Replace `<...>` placeholders; keep time windows short.

What each log holds:

| Log | Has | Does not have |
|---|---|---|
| ZIA web log (NSS web) | every web transaction: user, URL, category, action, rule, DLP engine and dictionaries when DLP matched | content; anything ZIA never saw (bypassed traffic) |
| ZIA firewall log (NSS firewall) | non-web sessions through the Cloud Firewall: addresses, ports, rule, action | URLs |
| ZIA DNS log (NSS DNS) | DNS requests and the DNS Control rule and action | the connection that followed |
| ZPA user activity (Log Streaming Service) | private app connections: user, application, segment, policy, status and reason | internet traffic |
| Workflow Automation | DLP incidents (the `dlp_incidents` tool) | nothing from it reaches NSS or the SIEM |

## Splunk (NSS web feed)

Look at one event (match field names):

```spl
index=<zscaler_index> sourcetype=zscalernss-web | head 1
```

What happened to one destination (why was X blocked?):

```spl
index=<zscaler_index> sourcetype=zscalernss-web url="*<host>*" earliest=-24h
| stats count by action, rulelabel, ruletype, urlcategory, reason
| sort -count
```

One user and one destination (only when the admin is entitled to look):

```spl
index=<zscaler_index> sourcetype=zscalernss-web user="<user>" url="*<host>*" earliest=-24h
| table _time, action, rulelabel, ruletype, urlcategory, reason, dlpengine, dlpdictionaries
```

What a DLP rule did (did it block or only log?):

```spl
index=<zscaler_index> sourcetype=zscalernss-web dlpengine!="None" dlpengine=* earliest=-7d
| stats count by rulelabel, action, dlpengine
| sort -count
```

Traffic that reached ZIA without being decrypted (pair with `ssl_coverage`):

```spl
index=<zscaler_index> sourcetype=zscalernss-web earliest=-24h
| stats count by urlcategory, ssldecrypted
| where ssldecrypted!="Yes"
```

A rule that never matches (pair with `rule_precedence`):

```spl
index=<zscaler_index> sourcetype=zscalernss-web rulelabel="<rule name>" earliest=-30d
| stats count, latest(_time) as last_seen by action
```

Firewall and DNS (non-web traffic):

```spl
index=<zscaler_index> sourcetype=zscalernss-fw dest_ip="<ip>" earliest=-24h
| stats count by action, rulelabel, dest_port, proto
```

```spl
index=<zscaler_index> sourcetype=zscalernss-dns query="*<host>*" earliest=-24h
| stats count by action, rulelabel
```

## Microsoft Sentinel (CEF to CommonSecurityLog)

Look at one event (the custom string columns and their labels):

```kql
CommonSecurityLog
| where DeviceVendor == "Zscaler"
| take 1
```

The custom columns carry different fields per feed format; read the label
next to each value (for example `DeviceCustomString2Label`) and use the
column whose label is the field you want.

What happened to one destination:

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Zscaler" and DeviceProduct == "NSSWeblog"
| where RequestURL has "<host>"
| summarize count() by DeviceAction, Activity, DeviceCustomString2, DeviceCustomString2Label
| order by count_ desc
```

One user:

```kql
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DeviceVendor == "Zscaler" and DeviceProduct == "NSSWeblog"
| where SourceUserName =~ "<user>" and RequestURL has "<host>"
| project TimeGenerated, DeviceAction, RequestURL, Activity, AdditionalExtensions
```

DLP matches by engine (find the column labelled with the DLP engine first):

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Zscaler" and DeviceProduct == "NSSWeblog"
| extend Engine = case(DeviceCustomString6Label =~ "dlpeng", DeviceCustomString6, "")
| where isnotempty(Engine) and Engine != "None"
| summarize count() by Engine, DeviceAction
```

## ZPA (Log Streaming Service, user activity)

Look at one event:

```spl
index=<zpa_index> sourcetype=<zpa_user_activity_sourcetype> | head 1
```

Why could a user not reach a private app (pair with `zpa_path`):

```spl
index=<zpa_index> sourcetype=<zpa_user_activity_sourcetype> Host="<host>" earliest=-24h
| stats count by ConnectionStatus, InternalReason, Policy, Application
| sort -count
```

```kql
<ZPA user activity table>
| where TimeGenerated > ago(24h)
| where Host has "<host>"
| summarize count() by ConnectionStatus, InternalReason, Policy, Application
```

## Reading the results

- No events for a destination usually means the traffic never reached
  Zscaler (bypassed, direct, carried by another path), or the feed does not
  cover it. Check `path_check`'s steps before concluding anything.
- An `Allowed` web event with a DLP engine named means the rule only logs
  (its action is allow).
- Quote counts and times, not user names, unless the admin asks for one
  person and is entitled to see it.
