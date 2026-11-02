"""SIEM query templates for the questions the traffic and session log page answers.

The same questions as traffic_logs.py (sessions and failures over time, top
users, applications, connectors and destinations, failure reasons, connector
and Service Edge health, spikes, many failures for one user, new
destinations; and for ZIA blocked against allowed, categories, rules hit, DLP
and threat events, SSL inspection) as copyable text in three languages:
Splunk SPL, Microsoft Sentinel KQL and Elastic ES|QL.

The queries are text for the admin to copy; this module runs nothing and
contacts nothing. They are written for the field names the feeds send (the
NSS field names of a ZIA feed in JSON, the LSS field names of a ZPA feed).
A SIEM connector that renames fields (Splunk CIM, Sentinel CommonSecurityLog
or ASIM, Elastic ECS) needs the names changed in the query; the page says so.
Splunk's sourcetypes zscalernss-web / -fw / -dns are the Zscaler add-on's
defaults; the ZPA sourcetype, the Sentinel tables and the Elastic index
patterns are assumed placeholders the admin replaces.

Every value put into a query (a user name, a destination, an index or table
name) is checked or escaped for that language, so a hostile log value the
admin clicks cannot break out of its string literal (CWE-943).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

SIEMS = {"splunk": "Splunk SPL", "sentinel": "Microsoft Sentinel KQL", "elastic": "Elastic ES|QL"}

FAMILIES = {"zpa": "ZPA (LSS)", "zia_web": "ZIA web (NSS)", "zia_fw": "ZIA firewall (NSS)", "zia_dns": "ZIA DNS (NSS)"}

DEFAULT_SOURCE = {
    "splunk": {"zpa": "zscaler", "zia_web": "zscaler", "zia_fw": "zscaler", "zia_dns": "zscaler"},
    "sentinel": {"zpa": "ZscalerLSS_CL", "zia_web": "ZscalerNSSWeb_CL", "zia_fw": "ZscalerNSSFirewall_CL", "zia_dns": "ZscalerNSSDNS_CL"},
    "elastic": {"zpa": "logs-zscaler-zpa*", "zia_web": "logs-zscaler-web*", "zia_fw": "logs-zscaler-firewall*", "zia_dns": "logs-zscaler-dns*"},
}
SPLUNK_SOURCETYPE = {"zpa": "zscalerlss-zpa-*", "zia_web": "zscalernss-web", "zia_fw": "zscalernss-fw", "zia_dns": "zscalernss-dns"}

_SOURCE_OK = {
    "splunk": re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_*-]{0,79}$"),
    "sentinel": re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}$"),
    "elastic": re.compile(r"^[a-z0-9_*][a-z0-9_*.,:-]{0,119}$"),
}
MAX_HOURS = 24 * 92
MAX_VALUE = 200

NORMAL = ("OPEN_OR_ACTIVE_CONNECTION", "BRK_MT_CLOSED_FROM_CLIENT", "BRK_MT_CLOSED_FROM_ASSISTANT",
          "BRK_MT_TERMINATED_IDLE_TIMEOUT", "BRK_MT_TERMINATED_BRK_SWITCHED", "MT_CLOSED_TERMINATED")
_NORMAL_LIST = ", ".join(f'"{c}"' for c in NORMAL)

# user field and destination field per family (None: the question takes no filter of that kind)
_FIELDS = {"zpa": ("Username", "Host"), "zia_web": ("login", "host"), "zia_fw": ("login", "cdfqdn"), "zia_dns": ("login", "req")}

# Each question: id, family, title, and the three queries. Placeholders:
# {src} the source (Splunk base search, Sentinel table, Elastic index),
# {h} hours, {f} the optional filter, {normal} the normal-end reasons.
QUESTIONS: List[Dict[str, str]] = [
    # ── ZPA ──
    {"id": "zpa_sessions_over_time", "family": "zpa", "title": "ZPA sessions started per hour (User Status)",
     "splunk": '{src} SessionStatus="ZPN_STATUS_AUTHENTICATED"{f} earliest=-{h}h\n| timechart span=1h dc(SessionID) AS sessions',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where SessionStatus == "ZPN_STATUS_AUTHENTICATED"{f}\n| summarize sessions = dcount(SessionID) by bin(TimeGenerated, 1h)\n| render timechart',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND SessionStatus == "ZPN_STATUS_AUTHENTICATED"{f}\n| STATS sessions = COUNT_DISTINCT(SessionID) BY hour = DATE_TRUNC(1 hour, @timestamp)\n| SORT hour'},
    {"id": "zpa_failures_over_time", "family": "zpa", "title": "ZPA connection failures per hour (User Activity)",
     "splunk": '{src} InternalReason=* NOT InternalReason IN ({normal}){f} earliest=-{h}h\n| timechart span=1h dc(ConnectionID) AS failures',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(InternalReason) and InternalReason !in ({normal}){f}\n| summarize failures = dcount(ConnectionID) by bin(TimeGenerated, 1h)\n| render timechart',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND InternalReason IS NOT NULL AND InternalReason NOT IN ({normal}){f}\n| STATS failures = COUNT_DISTINCT(ConnectionID) BY hour = DATE_TRUNC(1 hour, @timestamp)\n| SORT hour'},
    {"id": "zpa_failure_reasons", "family": "zpa", "title": "ZPA failure reasons, most frequent first",
     "splunk": '{src} InternalReason=* NOT InternalReason IN ({normal}){f} earliest=-{h}h\n| stats dc(ConnectionID) AS failures dc(Username) AS users values(Application) AS apps BY InternalReason\n| sort - failures',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(InternalReason) and InternalReason !in ({normal}){f}\n| summarize failures = dcount(ConnectionID), users = dcount(Username), apps = make_set(Application, 5) by InternalReason\n| order by failures desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND InternalReason IS NOT NULL AND InternalReason NOT IN ({normal}){f}\n| STATS failures = COUNT_DISTINCT(ConnectionID), users = COUNT_DISTINCT(Username) BY InternalReason\n| SORT failures DESC'},
    {"id": "zpa_top_users", "family": "zpa", "title": "ZPA users with the most connections, with their failures",
     "splunk": '{src} ConnectionID=*{f} earliest=-{h}h\n| eval failed=if(isnotnull(InternalReason) AND NOT match(InternalReason, "^({normal_rx})$"), ConnectionID, null())\n| stats dc(ConnectionID) AS connections dc(failed) AS failures BY Username\n| sort - connections | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ConnectionID){f}\n| summarize connections = dcount(ConnectionID), failures = dcountif(ConnectionID, isnotempty(InternalReason) and InternalReason !in ({normal})) by Username\n| top 25 by connections',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ConnectionID IS NOT NULL{f}\n| STATS connections = COUNT_DISTINCT(ConnectionID) BY Username\n| SORT connections DESC\n| LIMIT 25'},
    {"id": "zpa_top_apps", "family": "zpa", "title": "ZPA applications with the most connections",
     "splunk": '{src} ConnectionID=*{f} earliest=-{h}h\n| stats dc(ConnectionID) AS connections dc(Username) AS users BY Application\n| sort - connections | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ConnectionID){f}\n| summarize connections = dcount(ConnectionID), users = dcount(Username) by Application\n| top 25 by connections',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ConnectionID IS NOT NULL{f}\n| STATS connections = COUNT_DISTINCT(ConnectionID), users = COUNT_DISTINCT(Username) BY Application\n| SORT connections DESC\n| LIMIT 25'},
    {"id": "zpa_top_connectors", "family": "zpa", "title": "App Connectors carrying the most connections, with failures",
     "splunk": '{src} ConnectionID=* Connector=*{f} earliest=-{h}h\n| eval failed=if(isnotnull(InternalReason) AND NOT match(InternalReason, "^({normal_rx})$"), ConnectionID, null())\n| stats dc(ConnectionID) AS connections dc(failed) AS failures BY Connector\n| sort - connections',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ConnectionID) and isnotempty(Connector){f}\n| summarize connections = dcount(ConnectionID), failures = dcountif(ConnectionID, isnotempty(InternalReason) and InternalReason !in ({normal})) by Connector\n| order by connections desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ConnectionID IS NOT NULL AND Connector IS NOT NULL{f}\n| STATS connections = COUNT_DISTINCT(ConnectionID) BY Connector\n| SORT connections DESC'},
    {"id": "zpa_top_destinations", "family": "zpa", "title": "ZPA destinations (host and port) with the most connections",
     "splunk": '{src} ConnectionID=*{f} earliest=-{h}h\n| stats dc(ConnectionID) AS connections dc(Username) AS users BY Host ServicePort\n| sort - connections | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ConnectionID){f}\n| summarize connections = dcount(ConnectionID), users = dcount(Username) by Host, ServicePort\n| top 25 by connections',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ConnectionID IS NOT NULL{f}\n| STATS connections = COUNT_DISTINCT(ConnectionID), users = COUNT_DISTINCT(Username) BY Host, ServicePort\n| SORT connections DESC\n| LIMIT 25'},
    {"id": "zpa_user_many_failures", "family": "zpa", "title": "Users with many ZPA failures (10 or more, at least half their connections)",
     "splunk": '{src} ConnectionID=*{f} earliest=-{h}h\n| eval failed=if(isnotnull(InternalReason) AND NOT match(InternalReason, "^({normal_rx})$"), ConnectionID, null())\n| stats dc(ConnectionID) AS connections dc(failed) AS failures BY Username\n| where failures >= 25 OR (failures >= 10 AND failures / connections >= 0.5)\n| sort - failures',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ConnectionID){f}\n| summarize connections = dcount(ConnectionID), failures = dcountif(ConnectionID, isnotempty(InternalReason) and InternalReason !in ({normal})) by Username\n| where failures >= 25 or (failures >= 10 and todouble(failures) / connections >= 0.5)\n| order by failures desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ConnectionID IS NOT NULL{f}\n| EVAL failed = CASE(InternalReason IS NOT NULL AND InternalReason NOT IN ({normal}), 1, 0)\n| STATS records = COUNT(*), failures = SUM(failed) BY Username\n| WHERE failures >= 25 OR (failures >= 10 AND failures * 2 >= records)\n| SORT failures DESC'},
    {"id": "zpa_new_destinations", "family": "zpa", "title": "ZPA destinations first seen in the last day",
     "splunk": '{src} Host=*{f} earliest=-{h}h\n| stats min(_time) AS first_seen dc(Username) AS users BY Host\n| where first_seen > relative_time(now(), "-24h")\n| convert ctime(first_seen)',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(Host){f}\n| summarize first_seen = min(TimeGenerated), users = dcount(Username) by Host\n| where first_seen > ago(24h)',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND Host IS NOT NULL{f}\n| STATS first_seen = MIN(@timestamp), users = COUNT_DISTINCT(Username) BY Host\n| WHERE first_seen > NOW() - 24 hours'},
    {"id": "zpa_auth_failures", "family": "zpa", "title": "ZPA sign-in failures by user (User Status)",
     "splunk": '{src} SessionStatus="ZPN_STATUS_AUTH_FAILED"{f} earliest=-{h}h\n| stats count AS failures latest(_time) AS last BY Username Platform\n| sort - failures | convert ctime(last)',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where SessionStatus == "ZPN_STATUS_AUTH_FAILED"{f}\n| summarize failures = count(), last = max(TimeGenerated) by Username, Platform\n| order by failures desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND SessionStatus == "ZPN_STATUS_AUTH_FAILED"{f}\n| STATS failures = COUNT(*), last = MAX(@timestamp) BY Username, Platform\n| SORT failures DESC'},
    {"id": "zpa_connector_health", "family": "zpa", "title": "App Connector health: last state, disconnects, CPU and memory (App Connector Status)",
     "splunk": '{src} Connector=* SessionStatus=* earliest=-{h}h\n| stats latest(SessionStatus) AS last_status latest(_time) AS last_seen count(eval(SessionStatus="ZPN_STATUS_DISCONNECTED")) AS disconnects count(eval(SessionStatus="ZPN_STATUS_AUTH_FAILED")) AS failed_signins max(CPUUtilization) AS max_cpu max(MemUtilization) AS max_mem values(Version) AS versions BY Connector ConnectorGroup\n| convert ctime(last_seen)',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(Connector) and isnotempty(SessionStatus)\n| summarize arg_max(TimeGenerated, SessionStatus), disconnects = countif(SessionStatus == "ZPN_STATUS_DISCONNECTED"), failed_signins = countif(SessionStatus == "ZPN_STATUS_AUTH_FAILED"), max_cpu = max(todouble(CPUUtilization)), max_mem = max(todouble(MemUtilization)), versions = make_set(Version, 5) by Connector, ConnectorGroup',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND Connector IS NOT NULL AND SessionStatus IS NOT NULL\n| EVAL down = CASE(SessionStatus == "ZPN_STATUS_DISCONNECTED", 1, 0), failed = CASE(SessionStatus == "ZPN_STATUS_AUTH_FAILED", 1, 0)\n| STATS last_seen = MAX(@timestamp), disconnects = SUM(down), failed_signins = SUM(failed), max_cpu = MAX(CPUUtilization), max_mem = MAX(MemUtilization) BY Connector, ConnectorGroup'},
    {"id": "zpa_pse_health", "family": "zpa", "title": "Private Service Edge health: last state, disconnects, CPU and memory",
     "splunk": '{src} ServiceEdge=* SessionStatus=* earliest=-{h}h\n| stats latest(SessionStatus) AS last_status latest(_time) AS last_seen count(eval(SessionStatus="ZPN_STATUS_DISCONNECTED")) AS disconnects max(CPUUtilization) AS max_cpu max(MemUtilization) AS max_mem BY ServiceEdge ServiceEdgeGroup\n| convert ctime(last_seen)',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ServiceEdge) and isnotempty(SessionStatus)\n| summarize arg_max(TimeGenerated, SessionStatus), disconnects = countif(SessionStatus == "ZPN_STATUS_DISCONNECTED"), max_cpu = max(todouble(CPUUtilization)), max_mem = max(todouble(MemUtilization)) by ServiceEdge, ServiceEdgeGroup',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ServiceEdge IS NOT NULL AND SessionStatus IS NOT NULL\n| EVAL down = CASE(SessionStatus == "ZPN_STATUS_DISCONNECTED", 1, 0)\n| STATS last_seen = MAX(@timestamp), disconnects = SUM(down), max_cpu = MAX(CPUUtilization), max_mem = MAX(MemUtilization) BY ServiceEdge, ServiceEdgeGroup'},
    {"id": "zpa_failure_spikes", "family": "zpa", "title": "Hours with a spike in ZPA failures (3 times the median, at least 10)",
     "splunk": '{src} InternalReason=* NOT InternalReason IN ({normal}){f} earliest=-{h}h\n| timechart span=1h dc(ConnectionID) AS failures\n| eventstats median(failures) AS usual\n| where failures >= 10 AND failures >= 3 * usual',
     "sentinel": 'let hourly = {src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(InternalReason) and InternalReason !in ({normal}){f}\n| summarize failures = dcount(ConnectionID) by hour = bin(TimeGenerated, 1h);\nlet usual = toscalar(hourly | summarize percentile(failures, 50));\nhourly\n| where failures >= 10 and failures >= 3 * usual',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND InternalReason IS NOT NULL AND InternalReason NOT IN ({normal}){f}\n| STATS failures = COUNT_DISTINCT(ConnectionID) BY hour = DATE_TRUNC(1 hour, @timestamp)\n| SORT failures DESC\n| LIMIT 20\n// compare with the usual hour: a spike is 3 times the median and at least 10'},
    # ── ZIA web ──
    {"id": "zia_blocked_vs_allowed", "family": "zia_web", "title": "ZIA web transactions blocked against allowed",
     "splunk": '{src}{f} earliest=-{h}h\n| stats count BY action\n| sort - count',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| summarize transactions = count() by action\n| order by transactions desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| STATS transactions = COUNT(*) BY action\n| SORT transactions DESC'},
    {"id": "zia_actions_over_time", "family": "zia_web", "title": "ZIA web transactions per hour, by action",
     "splunk": '{src}{f} earliest=-{h}h\n| timechart span=1h count BY action',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| summarize transactions = count() by action, bin(TimeGenerated, 1h)\n| render timechart',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| STATS transactions = COUNT(*) BY hour = DATE_TRUNC(1 hour, @timestamp), action\n| SORT hour'},
    {"id": "zia_top_categories", "family": "zia_web", "title": "Top URL categories, with how many were blocked",
     "splunk": '{src}{f} earliest=-{h}h\n| stats count AS transactions count(eval(action="Blocked")) AS blocked BY urlcat\n| sort - transactions | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| summarize transactions = count(), blocked = countif(action =~ "Blocked") by urlcat\n| top 25 by transactions',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| EVAL is_blocked = CASE(action == "Blocked", 1, 0)\n| STATS transactions = COUNT(*), blocked = SUM(is_blocked) BY urlcat\n| SORT transactions DESC\n| LIMIT 25'},
    {"id": "zia_rules_hit", "family": "zia_web", "title": "Rules hit: URL filtering, Cloud App Control and the blocking rule, by action",
     "splunk": '{src}{f} earliest=-{h}h\n| eval rule=coalesce(if(rulelabel="None", null(), rulelabel), if(urlfilterrulelabel="None", null(), urlfilterrulelabel), if(apprulelabel="None", null(), apprulelabel))\n| where isnotnull(rule)\n| stats count BY rule action\n| sort - count',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| extend rule = case(isnotempty(rulelabel) and rulelabel != "None", rulelabel, isnotempty(urlfilterrulelabel) and urlfilterrulelabel != "None", urlfilterrulelabel, apprulelabel)\n| where isnotempty(rule) and rule != "None"\n| summarize hits = count() by rule, action\n| order by hits desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| EVAL rule = CASE(rulelabel IS NOT NULL AND rulelabel != "None", rulelabel, urlfilterrulelabel IS NOT NULL AND urlfilterrulelabel != "None", urlfilterrulelabel, apprulelabel)\n| WHERE rule IS NOT NULL AND rule != "None"\n| STATS hits = COUNT(*) BY rule, action\n| SORT hits DESC'},
    {"id": "zia_dlp_events", "family": "zia_web", "title": "DLP events by engine, dictionary and action",
     "splunk": '{src} dlpeng=* dlpeng!="None"{f} earliest=-{h}h\n| stats count AS events dc(login) AS users BY dlpeng dlpdict action\n| sort - events',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(dlpeng) and dlpeng != "None"{f}\n| summarize events = count(), users = dcount(login) by dlpeng, dlpdict, action\n| order by events desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND dlpeng IS NOT NULL AND dlpeng != "None"{f}\n| STATS events = COUNT(*), users = COUNT_DISTINCT(login) BY dlpeng, dlpdict, action\n| SORT events DESC'},
    {"id": "zia_threat_events", "family": "zia_web", "title": "Threat events by threat name, category and action",
     "splunk": '{src} threatname=* threatname!="None"{f} earliest=-{h}h\n| stats count AS events dc(login) AS users values(host) AS hosts BY threatname malwarecat action\n| sort - events',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(threatname) and threatname != "None"{f}\n| summarize events = count(), users = dcount(login), hosts = make_set(host, 5) by threatname, malwarecat, action\n| order by events desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND threatname IS NOT NULL AND threatname != "None"{f}\n| STATS events = COUNT(*), users = COUNT_DISTINCT(login) BY threatname, malwarecat, action\n| SORT events DESC'},
    {"id": "zia_ssl_inspected", "family": "zia_web", "title": "SSL inspected against not inspected, and why not",
     "splunk": '{src} ssldecrypted=*{f} earliest=-{h}h\n| stats count BY ssldecrypted externalspr\n| sort - count',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(ssldecrypted){f}\n| summarize transactions = count() by ssldecrypted, externalspr\n| order by transactions desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND ssldecrypted IS NOT NULL{f}\n| STATS transactions = COUNT(*) BY ssldecrypted, externalspr\n| SORT transactions DESC'},
    {"id": "zia_top_destinations", "family": "zia_web", "title": "Top web destinations, with how many were blocked",
     "splunk": '{src}{f} earliest=-{h}h\n| stats count AS transactions count(eval(action="Blocked")) AS blocked dc(login) AS users BY host\n| sort - transactions | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| summarize transactions = count(), blocked = countif(action =~ "Blocked"), users = dcount(login) by host\n| top 25 by transactions',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| EVAL is_blocked = CASE(action == "Blocked", 1, 0)\n| STATS transactions = COUNT(*), blocked = SUM(is_blocked), users = COUNT_DISTINCT(login) BY host\n| SORT transactions DESC\n| LIMIT 25'},
    {"id": "zia_top_users_blocked", "family": "zia_web", "title": "Users with the most blocked web transactions",
     "splunk": '{src} action="Blocked"{f} earliest=-{h}h\n| stats count AS blocked dc(host) AS destinations BY login\n| sort - blocked | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where action =~ "Blocked"{f}\n| summarize blocked = count(), destinations = dcount(host) by login\n| top 25 by blocked',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND action == "Blocked"{f}\n| STATS blocked = COUNT(*), destinations = COUNT_DISTINCT(host) BY login\n| SORT blocked DESC\n| LIMIT 25'},
    {"id": "zia_new_destinations", "family": "zia_web", "title": "Web destinations first seen in the last day",
     "splunk": '{src} host=*{f} earliest=-{h}h\n| stats min(_time) AS first_seen count AS transactions BY host\n| where first_seen > relative_time(now(), "-24h")\n| convert ctime(first_seen)',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where isnotempty(host){f}\n| summarize first_seen = min(TimeGenerated), transactions = count() by host\n| where first_seen > ago(24h)',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND host IS NOT NULL{f}\n| STATS first_seen = MIN(@timestamp), transactions = COUNT(*) BY host\n| WHERE first_seen > NOW() - 24 hours'},
    {"id": "zia_block_spikes", "family": "zia_web", "title": "Hours with a spike in web blocks (3 times the median, at least 10)",
     "splunk": '{src} action="Blocked"{f} earliest=-{h}h\n| timechart span=1h count AS blocked\n| eventstats median(blocked) AS usual\n| where blocked >= 10 AND blocked >= 3 * usual',
     "sentinel": 'let hourly = {src}\n| where TimeGenerated > ago({h}h)\n| where action =~ "Blocked"{f}\n| summarize blocked = count() by hour = bin(TimeGenerated, 1h);\nlet usual = toscalar(hourly | summarize percentile(blocked, 50));\nhourly\n| where blocked >= 10 and blocked >= 3 * usual',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND action == "Blocked"{f}\n| STATS blocked = COUNT(*) BY hour = DATE_TRUNC(1 hour, @timestamp)\n| SORT blocked DESC\n| LIMIT 20\n// compare with the usual hour: a spike is 3 times the median and at least 10'},
    # ── ZIA firewall ──
    {"id": "zia_fw_rules", "family": "zia_fw", "title": "Cloud Firewall rules hit, by action",
     "splunk": '{src}{f} earliest=-{h}h\n| stats count AS sessions sum(inbytes) AS bytes_in sum(outbytes) AS bytes_out BY rulelabel action\n| sort - sessions',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| summarize sessions = count(), bytes_in = sum(tolong(inbytes)), bytes_out = sum(tolong(outbytes)) by rulelabel, action\n| order by sessions desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| STATS sessions = COUNT(*), bytes_in = SUM(inbytes), bytes_out = SUM(outbytes) BY rulelabel, action\n| SORT sessions DESC'},
    {"id": "zia_fw_destinations", "family": "zia_fw", "title": "Top firewall destinations (name or address, and port), with blocks",
     "splunk": '{src}{f} earliest=-{h}h\n| eval dest=coalesce(if(cdfqdn="None" OR cdfqdn="", null(), cdfqdn), cdip)\n| stats count AS sessions count(eval(match(action, "(?i)block|drop"))) AS blocked BY dest cdport nwsvc\n| sort - sessions | head 25',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h){f}\n| extend dest = iff(isempty(cdfqdn) or cdfqdn == "None", cdip, cdfqdn)\n| summarize sessions = count(), blocked = countif(action matches regex "(?i)block|drop") by dest, cdport, nwsvc\n| top 25 by sessions',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours{f}\n| EVAL dest = CASE(cdfqdn IS NULL OR cdfqdn == "None", cdip, cdfqdn)\n| STATS sessions = COUNT(*) BY dest, cdport, nwsvc\n| SORT sessions DESC\n| LIMIT 25'},
    # ── ZIA DNS ──
    {"id": "zia_dns_blocked", "family": "zia_dns", "title": "DNS queries blocked, by name and rule",
     "splunk": '{src} (reqaction="*BLOCK*" OR resaction="*BLOCK*"){f} earliest=-{h}h\n| stats count AS blocked dc(login) AS users BY req reqrulelabel resrulelabel domcat\n| sort - blocked',
     "sentinel": '{src}\n| where TimeGenerated > ago({h}h)\n| where reqaction contains "BLOCK" or resaction contains "BLOCK"{f}\n| summarize blocked = count(), users = dcount(login) by req, reqrulelabel, resrulelabel, domcat\n| order by blocked desc',
     "elastic": 'FROM {src}\n| WHERE @timestamp > NOW() - {h} hours AND (reqaction LIKE "*BLOCK*" OR resaction LIKE "*BLOCK*"){f}\n| STATS blocked = COUNT(*), users = COUNT_DISTINCT(login) BY req, reqrulelabel, resrulelabel, domcat\n| SORT blocked DESC'},
]

_BY_ID = {q["id"]: q for q in QUESTIONS}
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _clean(v: Any) -> str:
    return _CONTROL.sub("", str(v or "")).strip()[:MAX_VALUE]


def literal(siem: str, value: Any) -> str:
    """`value` as a double-quoted string literal of the SIEM's language.
    SPL, KQL and ES|QL all read backslash escapes inside double quotes, so
    the backslash and the quote are escaped and control characters (which
    could end a line of the query) are dropped."""
    v = _clean(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{v}"'


def _filter(siem: str, field: str, value: str) -> str:
    lit = literal(siem, value)
    if siem == "splunk":
        return f" {field}={lit}"
    if siem == "sentinel":
        return f"\n| where {field} == {lit}"
    return f" AND {field} == {lit}"


def source(siem: str, family: str, override: str = "") -> str:
    v = _clean(override) or DEFAULT_SOURCE[siem][family]
    if not _SOURCE_OK[siem].match(v):
        raise ValueError({"splunk": "The Splunk index name may hold letters, digits, _, - and * only.",
                          "sentinel": "The Sentinel table name may hold letters, digits and _ only, and starts with a letter or _.",
                          "elastic": "The Elastic index pattern may hold lower-case letters, digits, _, -, ., *, , and : only."}[siem])
    if siem == "splunk":
        return f"index={v} sourcetype={SPLUNK_SOURCETYPE[family]}"
    return v


def render(siem: str, qid: str, hours: int = 24, src: Optional[Dict[str, str]] = None, user: str = "", destination: str = "") -> Dict[str, Any]:
    if siem not in SIEMS:
        raise ValueError("Pick Splunk, Sentinel or Elastic.")
    q = _BY_ID.get(qid)
    if q is None:
        raise ValueError("Unknown question.")
    try:
        h = int(hours)
    except (TypeError, ValueError):
        raise ValueError("Hours must be a whole number.") from None
    if not 1 <= h <= MAX_HOURS:
        raise ValueError(f"Hours must be between 1 and {MAX_HOURS}.")
    fam = q["family"]
    ufield, dfield = _FIELDS[fam]
    f = ""
    if _clean(user):
        f += _filter(siem, ufield, user)
    if _clean(destination):
        f += _filter(siem, dfield, destination)
    no_filter = qid in ("zpa_connector_health", "zpa_pse_health")
    text = q[siem].format(src=source(siem, fam, (src or {}).get(fam, "")), h=h, f="" if no_filter else f, normal=_NORMAL_LIST,
                          normal_rx="|".join(NORMAL))
    return {"id": qid, "family": fam, "family_label": FAMILIES[fam], "title": q["title"], "siem": siem, "siem_label": SIEMS[siem],
            "query": text, "filtered": bool(f) and not no_filter}


def render_all(siem: str, hours: int = 24, src: Optional[Dict[str, str]] = None, user: str = "", destination: str = "") -> List[Dict[str, Any]]:
    return [render(siem, q["id"], hours, src, user, destination) for q in QUESTIONS]


def catalogue() -> Dict[str, Any]:
    return {"siems": SIEMS, "families": FAMILIES, "default_source": DEFAULT_SOURCE, "max_hours": MAX_HOURS,
            "questions": [{"id": q["id"], "family": q["family"], "title": q["title"]} for q in QUESTIONS],
            "note": ("Written for the field names the feeds send: the NSS field names of a ZIA feed in JSON and the LSS field names of a "
                     "ZPA feed. If your SIEM's connector renames fields (Splunk CIM, Sentinel CommonSecurityLog or ASIM, Elastic ECS), "
                     "change the names in the query. The Sentinel tables and Elastic index patterns are placeholders: put yours.")}
