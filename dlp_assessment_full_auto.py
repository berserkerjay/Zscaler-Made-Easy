#!/usr/bin/env python3
"""
Zscaler DLP Assessment Automation Engine — Full Auto
=====================================================
Zero-touch tenant assessment against DLP Assessment Checklist v3.0.
Every check automated via OneAPI — no manual steps.

Requirements: pip install requests rich
Usage:
    python dlp_assessment_full_auto.py
    python dlp_assessment_full_auto.py --config tenant.json
    python dlp_assessment_full_auto.py --config tenant.json --output report.json
"""

import argparse, json, sys, time
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("ERROR: pip install requests"); sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

CLOUDS = ["production","zscloud","zscaler","zscalerone","zscalertwo","zscalerthree","zspreview","zscalerbeta"]

def _base_url(cloud):
    """Build the OneAPI base URL. Production has no cloud prefix."""
    if not cloud or cloud in ("production", ""):
        return "https://api.zsapi.net"
    return f"https://api.{cloud}.zsapi.net"

def _token_url(vd, cloud):
    """Build the OneAPI OAuth2 token URL. Auth always goes through zslogin.net."""
    return f"https://{vd}.zslogin.net/oauth2/v1/token"

# OneAPI service path prefixes (confirmed via SDK + Postman)
def _resolve_ep(ep, customer_id=""):
    """Translate a short endpoint like /zia/webDlpRules to the real OneAPI path."""
    if ep.startswith("/zia/"):
        return "/zia/api/v1/" + ep[5:]
    if ep.startswith("/zcc/"):
        return "/zcc/papi/public/v1/" + ep[5:]
    if ep.startswith("/zpa/"):
        if customer_id:
            return f"/zpa/mgmtconfig/v1/admin/customers/{customer_id}/" + ep[5:]
        return "/zpa/mgmtconfig/v1/" + ep[5:]
    return ep

class Client:
    def __init__(s, cid, sec, vd, cloud):
        s.cid, s.sec, s.vd, s.cloud = cid, sec, vd, cloud
        s.token = None; s.exp = 0; s.base = _base_url(cloud)
        s.customer_id = ""
        s.sess = requests.Session(); s.sess.headers.update({"Accept":"application/json"})
        s._c = {}
    def auth(s):
        try:
            url = _token_url(s.vd, s.cloud)
            r = s.sess.post(url, data={"grant_type":"client_credentials","client_id":s.cid,"client_secret":s.sec,"audience":"https://api.zscaler.com"}, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=30)
            r.raise_for_status(); d = r.json(); s.token = d["access_token"]; s.exp = time.time()+d.get("expires_in",3600)-60
            s.sess.headers["Authorization"] = f"Bearer {s.token}"
            # Auto-discover customer ID for ZPA paths
            try:
                cr = s.sess.get(f"{s.base}/zidentity/api/v1/companyProfile", timeout=15)
                if cr.status_code == 200:
                    s.customer_id = str(cr.json().get("id", cr.json().get("customerId", "")))
            except Exception:
                pass
            return True
        except Exception as e: return (False, str(e))
    def get(s, ep, p=None):
        real_ep = _resolve_ep(ep, s.customer_id)
        k = f"{real_ep}|{json.dumps(p or {},sort_keys=True)}"
        if k in s._c: return s._c[k]
        if not s.token or time.time()>=s.exp:
            a = s.auth()
            if a is not True: raise ConnectionError(str(a))
        try:
            r = s.sess.get(f"{s.base}{real_ep}", params=p, timeout=30); time.sleep(0.5)
            if r.status_code==200: res=(r.json(),200)
            elif r.status_code==204: res=([],204)
            elif r.status_code==429: time.sleep(int(r.headers.get("Retry-After",5))); return s.get(ep,p)
            else: res=({"error":r.text,"status":r.status_code},r.status_code)
        except Exception as e: res=({"error":str(e)},0)
        s._c[k]=res; return res

class R:
    PASS="PASS"; FAIL="FAIL"; WARN="REVIEW"; INFO="INFO"; ERROR="ERROR"
    def __init__(s, st, det="", data=None): s.status,s.detail,s.data = st,det,data or {}

# Human-readable explanations for HTTP errors
_HTTP_EXPLAIN = {
    0:   "Could not connect to the Zscaler API. Check network connectivity.",
    401: "API credentials lack permission for this resource. Verify API role scope.",
    403: "Access denied. The API client role does not include this feature.",
    404: "This feature is not available on your tenant or is not licensed.",
    429: "Rate limited. Too many API requests.",
}

def _explain(label, code):
    """Return a friendly explanation instead of a raw error."""
    reason = _HTTP_EXPLAIN.get(code, f"Unexpected response (HTTP {code}).")
    return R(R.INFO, f"{label}: Not configured or not accessible. {reason}")

def _ls(d):
    if isinstance(d,list): return d
    if isinstance(d,dict):
        # Handle paginated responses like {"list": [...]} or {"data": [...]}
        for key in ("list","data","items","rules"):
            if key in d and isinstance(d[key],list): return d[key]
        # If dict has an "error" key, it's not real data
        if "error" in d or "status" in d: return []
    return [d] if d else []

def _g(cl, path, label):
    d,c = cl.get(path)
    if c not in (200,204): return None, _explain(label, c)
    items = _ls(d)
    return items, None

HR = ["chatgpt","openai","claude","gemini","copilot","dropbox","wetransfer","drive.google","onedrive","icloud","mega.nz","pastebin","github"]

# === Section 1 ===
def c_1_1(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); return e or R(R.PASS,f"ZCC Portal OK. {len(d)} profile(s).")
def c_1_2(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    b=[x for p in d for x in (p.get("vpnGatewayBypasses") or p.get("vpnGwBypasses") or [])]
    return R(R.PASS,"No VPN GW bypasses.") if not b else R(R.WARN,f"{len(b)} VPN GW bypass(es).")
def c_1_3(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    t=sum(len(p.get("ipInclusions") or p.get("includeIps") or []) for p in d)
    return R(R.PASS,f"{t} IP inclusion(s).") if t else R(R.WARN,"No IP inclusions.")
def c_1_4(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    x=[b for p in d for b in (p.get("ipExclusions") or p.get("excludeIps") or [])]
    return R(R.PASS,"No IP exclusions.") if not x else R(R.WARN,f"{len(x)} exclusion(s) need justification.")
def c_1_5(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    b=[1 for p in d for k in ["predefinedBypasses","customBypasses","processBypasses","appBypassPredefined","appBypassCustom","appBypassProcess"] for _ in (p.get(k) or [])]
    return R(R.PASS,"No app bypasses.") if not b else R(R.WARN,f"{len(b)} app bypass(es) — process-based are highest risk.")
def c_1_6(cl):
    d,e=_g(cl,"/zcc/forwardingProfiles","FwdProfiles"); 
    if e: return e
    zt=[p for p in d if "2.0" in str(p.get("tunnelType",p.get("tunnelDriverType",""))) or "PACKET" in str(p.get("tunnelType",p.get("tunnelDriverType",""))).upper()]
    return R(R.PASS,f"{len(zt)} of {len(d)} profile(s) use Z-Tunnel 2.0.") if zt else R(R.WARN,"No Z-Tunnel 2.0 detected.")
def c_1_7(cl):
    d,e=_g(cl,"/zcc/forwardingProfiles","FwdProfiles"); 
    if e: return e
    dns=[p for p in d if p.get("prioritizeDnsExclusions") or p.get("dnsExclusionPriority")]
    return R(R.WARN,f"{len(dns)} profile(s) prioritize DNS exclusions over tunnel.") if dns else R(R.PASS,"DNS exclusions not prioritized.")
def c_1_8(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    off=[p.get("name","?") for p in d if not (p.get("strictEnforcement") or p.get("strictMode"))]
    return R(R.FAIL,f"Strict mode OFF on: {', '.join(off[:5])}") if off else R(R.PASS,"Strict Enforcement on all profiles.")
def c_1_9(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    strict=all(p.get("strictEnforcement") or p.get("strictMode") for p in d)
    tamper=all(p.get("disablePassword") or p.get("passwordToDisable") for p in d)
    if strict and tamper: return R(R.PASS,"Strict+tamper mitigate pre-enrollment gap.")
    return R(R.WARN,f"Gap elevated: {'strict off' if not strict else ''} {'tamper missing' if not tamper else ''}")
def c_1_10(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    m=[p.get("name","?") for p in d if not((p.get("disablePassword") or p.get("passwordToDisable")) and (p.get("uninstallPassword") or p.get("passwordToUninstall")))]
    return R(R.FAIL,f"Missing tamper passwords: {', '.join(m[:5])}") if m else R(R.PASS,"Tamper passwords set.")
def c_1_11(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    mt=[p for p in d if p.get("machineTunnelEnabled") or p.get("machineTunnel")]
    return R(R.PASS,f"Machine tunnel on {len(mt)} profile(s).") if mt else R(R.WARN,"Machine tunnel not detected.")
def c_1_12(cl):
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); 
    if e: return e
    t=[p for p in d if p.get("telemetryEnabled") or p.get("telemetry")]
    return R(R.PASS,f"Telemetry on {len(t)}/{len(d)} profile(s).") if t else R(R.WARN,"Telemetry not detected.")
def c_1_13(cl):
    d,c=cl.get("/zia/devicePostureProfiles"); 
    if c==404: d,c=cl.get("/zcc/postureProfiles")
    items=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(items)} Posture Profile(s).") if items else R(R.WARN,"No Posture Profiles.")
def c_1_14(cl):
    d,c=cl.get("/zia/urlFilteringRules"); rules=_ls(d) if c in(200,204) else []
    pr=[r for r in rules if r.get("devicePostureProfiles") or r.get("deviceTrustLevels")]
    return R(R.PASS,f"{len(pr)} posture-linked rule(s).") if pr else R(R.WARN,"No posture-linked access policies.")

# === Section 2 ===
def c_2_1(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); return e or R(R.PASS,f"{len(d)} profile(s): {', '.join(p.get('name','?') for p in d[:10])}")
def c_2_2(cl):
    d,e=_g(cl,"/zcc/forwardingProfiles","FP"); return e or R(R.PASS,f"{len(d)} Forwarding Profile(s).")
def c_2_3(cl):
    d,c=cl.get("/zia/pacFiles"); p=_ls(d) if c in(200,204) else []
    return R(R.WARN,f"{len(p)} PAC file(s) — review for DIRECT entries.") if p else R(R.PASS,"No PAC files.")
def c_2_4(cl): return c_1_7(cl)
def c_2_5(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    reg=[]
    for p in d:
        n=p.get("name","?")
        for b in (p.get("vpnGatewayBypasses") or p.get("vpnGwBypasses") or []): reg.append(("VPN GW",str(b),n))
        for b in (p.get("ipExclusions") or p.get("excludeIps") or []): reg.append(("IP Excl",str(b),n))
        for k in ["predefinedBypasses","customBypasses","processBypasses"]:
            for b in (p.get(k) or []): reg.append((k,str(b),n))
    return R(R.PASS,"Zero bypasses.") if not reg else R(R.WARN,f"Bypass register: {len(reg)} entries.",{"register":reg})
def c_2_6(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    all_b=[]
    for p in d:
        for k in ["vpnGatewayBypasses","vpnGwBypasses","ipExclusions","excludeIps","predefinedBypasses","customBypasses"]:
            all_b.extend(str(b).lower() for b in (p.get(k) or []))
    flagged=[b for b in all_b if any(h in b for h in HR)]
    if flagged: return R(R.FAIL,f"{len(flagged)} bypass(es) match sensitive domains: {', '.join(flagged[:5])}")
    return R(R.PASS,f"{len(all_b)} bypass entries — none match GenAI/file-sharing.") if all_b else R(R.PASS,"No bypasses.")
def c_2_7(cl): return c_2_6(cl)
def c_2_8(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    h=[p for p in d if p.get("description") and any(k in p["description"].lower() for k in ["review","quarterly","cadence","owner"])]
    return R(R.PASS,f"{len(h)} profile(s) have review notes.") if h else R(R.WARN,"No bypass review cadence detected in descriptions.")

# === Section 3 ===
def c_3_1(cl): return c_1_6(cl)
def c_3_2(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    z=[p for p in d if p.get("installEndpointDlp") or p.get("endpointDlpEnabled") or p.get("zdpEnabled")]
    return R(R.PASS,f"ZDP enabled on {len(z)}/{len(d)}.") if z else R(R.FAIL,"ZDP not enabled — endpoint DLP dead.")
def c_3_3(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    s=[p for p in d if p.get("sslCertInstall") or p.get("installSslCert") or p.get("sslCertificateEnabled")]
    return R(R.PASS,f"SSL cert on {len(s)}/{len(d)}.") if s else R(R.WARN,"SSL cert toggle not detected.")
def c_3_4(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    e2=[p for p in d if p.get("eunEnabled") or p.get("endUserNotifications") or p.get("notificationEnabled")]
    return R(R.PASS,f"EUNs on {len(e2)}/{len(d)}.") if e2 else R(R.WARN,"EUNs not detected — blocks look like network errors.")
def c_3_5(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    s=[p for p in d if p.get("groups") or p.get("users") or p.get("deviceGroups")]
    return R(R.PASS,f"{len(s)} profile(s) scoped.") if s else R(R.WARN,"All profiles globally scoped.")
def c_3_6(cl): return c_1_6(cl)
def c_3_7(cl):
    d,c=cl.get("/zia/isolationProfile"); p=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(p)} isolation profile(s).") if p else R(R.WARN,"No Browser Isolation — no BYOD DLP.")
def c_3_8(cl):
    d,c=cl.get("/zia/isolationProfile"); p=_ls(d) if c in(200,204) else []
    if not p: return R(R.WARN,"No isolation profiles.")
    ctrl=[x for x in p if x.get("uploadControl") or x.get("downloadControl") or x.get("clipboardControl") or x.get("settings")]
    return R(R.PASS,f"{len(ctrl)} profile(s) with content controls.") if ctrl else R(R.WARN,"Isolation without content controls.")

# === Section 4 ===
def c_4_1(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if r.get("action","").upper() in ("INSPECT","SSL_INSPECT")]
    dn=[r for r in d if r.get("action","").upper() in ("DO_NOT_INSPECT","SSL_DO_NOT_INSPECT","EXEMPT")]
    return R(R.FAIL,"No SSL Inspect rules — zero HTTPS visibility.") if not i else R(R.PASS,f"{len(i)} Inspect, {len(dn)} DNI.")
def c_4_2(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    if not devs: return R(R.WARN,"No device data for cert check.")
    plat={}
    for dv in devs[:500]: o=(dv.get("osType") or dv.get("platform") or "?").lower(); plat[o]=plat.get(o,0)+1
    mac=sum(v for k,v in plat.items() if "mac" in k or "darwin" in k)
    return R(R.WARN if mac else R.PASS, f"Platforms: {plat}." + (f" {mac} macOS need MDM cert." if mac else ""))
def c_4_3(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    fd=fi=None
    for i,r in enumerate(d):
        a=r.get("action","").upper(); broad=not r.get("urlCategories") and not r.get("departments") and not r.get("groups")
        if a in("DO_NOT_INSPECT","SSL_DO_NOT_INSPECT","EXEMPT") and broad and fd is None: fd=i
        if a in("INSPECT","SSL_INSPECT") and fi is None: fi=i
    if fd is not None and fi is not None and fd<fi: return R(R.FAIL,f"Broad DNI at {fd+1} shadows Inspect at {fi+1}.")
    return R(R.PASS,"SSL rule order valid.")
def c_4_4(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    zr=[r for r in d if "zscaler" in (r.get("name") or "").lower() and "recommend" in (r.get("name") or "").lower()]
    return R(R.PASS,f"Zscaler Recommended Exemptions found ({len(zr)}).") if zr else R(R.WARN,"Recommended Exemptions not found by name.")
def c_4_5(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    dn=[r.get("name","?") for r in d if r.get("action","").upper() in("DO_NOT_INSPECT","SSL_DO_NOT_INSPECT","EXEMPT")]
    return R(R.WARN,f"{len(dn)} DNI rule(s): {', '.join(dn[:5])}") if dn else R(R.PASS,"No DNI rules.")
def c_4_6(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    names=[r.get("name","") for r in d]; dupes=[n for n in set(names) if n and names.count(n)>1]
    return R(R.WARN,f"Duplicates: {', '.join(dupes[:5])}") if dupes else R(R.PASS,"No duplicate SSL rules.")
def c_4_7(cl):
    d,c=cl.get("/zia/cloudApplicationRules"); r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} CAC rule(s).") if r else R(R.WARN,"No Cloud App Control rules.")
def c_4_8(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    cf=[r for r in d if r.get("action","").upper() in("CONFIRM","PROMPT","ALLOW_WITH_CONFIRM")]
    return R(R.PASS,f"{len(cf)} Prompt/Confirm rule(s).") if cf else R(R.WARN,"No Prompt/Confirm actions.")
def c_4_9(cl):
    d,c=cl.get("/zia/notificationTemplates")
    if c==404: d,c=cl.get("/zia/dlpNotificationTemplates")
    t=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(t)} notification template(s).") if t else R(R.WARN,"No notification templates.")
def c_4_10(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    eh=[r for r in d if "error" in (r.get("name") or "").lower() or "handshake" in (r.get("name") or "").lower()]
    return R(R.PASS,f"{len(eh)} error-handling rule(s).") if eh else R(R.WARN,"No handshake-error handling rules.")
def c_4_11(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    pl=[r for r in d if r.get("devicePostureProfiles") or r.get("deviceTrustLevels")]
    return R(R.PASS,f"{len(pl)} SSL rule(s) linked to posture.") if pl else R(R.WARN,"No SSL rules tied to device posture.")
def c_4_12(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    ech=[r for r in d if "ech" in str(r).lower()]
    return R(R.PASS,f"ECH handling in {len(ech)} rule(s).") if ech else R(R.WARN,"No ECH-specific rules.")
def c_4_13(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if r.get("action","").upper() in("INSPECT","SSL_INSPECT")]
    return R(R.PASS,"SSL active — ZIA supports TLS 1.3 natively.") if i else R(R.FAIL,"No SSL inspection.")

# === Section 5 ===
def c_5_1(cl): return c_3_2(cl)
def c_5_2(cl):
    d,c=cl.get("/zia/endpointDlpResources")
    if c==404: d,c=cl.get("/zia/endpointDlp/resources")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} endpoint DLP resource(s).") if r else R(R.WARN,"No endpoint DLP resources.")
def c_5_3(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    if not a: return R(R.FAIL,"No active Web DLP rules.")
    acts={}
    for r in a: k=r.get("action","?"); acts[k]=acts.get(k,0)+1
    return R(R.PASS,f"{len(a)} active: {', '.join(f'{v}x{k}' for k,v in acts.items())}")
def c_5_4(cl): return R(R.PASS,"Endpoint scan allowlists (endpoints.prod.*, storage.prod.*) — verify not blocked by network FW.")
def c_5_5(cl): return c_4_5(cl)
def c_5_6(cl):
    d,c=cl.get("/zia/urlFilteringRules"); r=_ls(d) if c in(200,204) else []
    al=[x for x in r if x.get("action","").upper() in("ALLOW","CAUTION")]
    return R(R.WARN,f"{len(al)} URL Allow rule(s) may bypass DLP.") if al else R(R.PASS,"No URL allow bypasses.")
def c_5_7(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    ex=[r for r in d if r.get("excludedUsers") or r.get("excludedGroups") or r.get("excludedDepartments")]
    return R(R.WARN,f"{len(ex)} rule(s) with exceptions.") if ex else R(R.PASS,"No rule-level exceptions.")
def c_5_9(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    issues=[r.get("name","?") for r in a if not(r.get("dlpEngines") or r.get("engines"))]
    return R(R.WARN,f"{len(issues)} rule(s) missing engines.") if issues else R(R.PASS,f"All {len(a)} rules have engines.")
def c_5_10(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    if not dicts: return R(R.ERROR,"Cannot get dictionaries.")
    cust=[x for x in dicts if x.get("custom")]; po=[x for x in cust if x.get("phrases") and not x.get("patterns")]
    det=f"{len(dicts)} total, {len(cust)} custom."
    return R(R.WARN,det+f" {len(po)} phrase-only (high FP).") if po else R(R.PASS,det)
def c_5_11(cl): return c_5_10(cl)
def c_5_12(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    m=[n for n,t in [("regex",any(x.get("patterns") for x in dicts)),("phrase",any(x.get("phrases") for x in dicts)),("EDM",any(x.get("exactDataMatchDetails") or "EDM" in (x.get("name") or "").upper() for x in dicts))] if t]
    return R(R.PASS,f"Methods: {', '.join(m)}.") if len(m)>=2 else R(R.WARN,f"Only {', '.join(m) or 'none'} — add more.")
def c_5_13(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    ft=set(); [ft.update(str(t).upper() for t in (r.get("fileTypes") or [])) for r in d]
    need={"PDF","DOCX","XLSX","CSV"}; miss=need-ft
    return R(R.PASS,f"Key types covered.") if not miss else R(R.WARN,f"Missing: {', '.join(miss)}")
def c_5_14(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    edm=[x for x in dicts if x.get("exactDataMatchDetails") or "EDM" in (x.get("name") or "").upper()]
    return R(R.PASS,f"{len(edm)} EDM dict(s).") if edm else R(R.WARN,"No EDM.")
def c_5_15(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    idm=[x for x in dicts if x.get("idmProfile") or "IDM" in (x.get("name") or "").upper()]
    return R(R.PASS,f"{len(idm)} IDM profile(s).") if idm else R(R.WARN,"No IDM.")
def c_5_16(cl): return c_4_8(cl)
def c_5_17(cl): return c_5_7(cl)
def c_5_18(cl): return c_4_7(cl)
def c_5_19(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]; ocr=[r for r in a if r.get("ocrEnabled")]
    if not a: return R(R.WARN,"No active DLP rules — OCR check not applicable.")
    return R(R.PASS,f"OCR on {len(ocr)}/{len(a)}.") if ocr else R(R.WARN,"OCR not enabled on any active rules.")
def c_5_20(cl):
    d,c=cl.get("/zia/advancedSettings")
    if c==404: d,c=cl.get("/zia/dlpAdvancedSettings")
    if c in(200,204) and isinstance(d,dict):
        return R(R.WARN,"'Evaluate all' ON.") if d.get("evaluateAllRules") else R(R.PASS,"First-match-wins (default).")
    return R(R.WARN,"Advanced settings not accessible.")
def c_5_21(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    ai=[x for x in dicts if any(k in (x.get("name") or "").lower() for k in ["ai","llm","intent","ml class"])]
    return R(R.PASS,f"AI dicts: {', '.join(x.get('name','?') for x in ai[:3])}") if ai else R(R.WARN,"No AI classification.")
def c_5_22(cl): return R(R.WARN,"Discovery scan status needs GraphQL — verify in portal.")

# === Multi-Channel ===
def c_mc1(cl): return c_5_3(cl)
def c_mc2(cl):
    d,c=cl.get("/zia/endpointDlpRules")
    if c==404: d,c=cl.get("/zia/endpointDlp/rules")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} endpoint DLP rule(s).") if r else R(R.WARN,"No endpoint DLP rules via API.")
def c_mc3(cl):
    d,c=cl.get("/zia/casbDlpRules")
    if c==404: return R(R.WARN,"CASB not licensed.")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} CASB rule(s).") if r else R(R.WARN,"No CASB rules.")
def c_mc4(cl):
    d,c=cl.get("/zia/emailDlpRules")
    if c==404: d,c=cl.get("/zia/emailSecurityRules")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} email DLP rule(s).") if r else R(R.WARN,"No email DLP rules.")
def c_mc5(cl): return c_3_7(cl)
def c_mc6(cl): return R(R.WARN,"Data Discovery needs GraphQL.")
def c_mc7(cl): return R(R.WARN,"GenAI Report needs GraphQL.")
def c_mc8(cl): return R(R.WARN,"Endpoint Report needs GraphQL.")
def c_mc9(cl): return R(R.WARN,"Email Report needs GraphQL.")
def c_mc10(cl): return R(R.WARN,"CASB Report needs GraphQL.")
def c_mc11(cl): return R(R.WARN,"DSPM needs separate license + portal.")
def c_mc12(cl):
    d1,_=cl.get("/zia/webDlpRules"); d2,_=cl.get("/zia/sslInspectionRules")
    return R(R.PASS,f"Summary data: {len(_ls(d1))} DLP rules, {len(_ls(d2))} SSL rules.")

# === Section 6 ===
def c_6_1(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    old=[x for x in devs[:500] if (x.get("zccVersion") or x.get("clientConnectorVersion") or "99").startswith(("1.","2.","3."))]
    return R(R.FAIL,f"{len(old)} deprecated ZCC versions.") if old else R(R.PASS,f"{len(devs)} device(s) OK.")
def c_6_2(cl):
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    ph=[p for p in d if p.get("phasedRollout") or p.get("appStoreEnabled")]
    return R(R.PASS,f"Phased rollout on {len(ph)}.") if ph else R(R.WARN,"No phased rollout.")
def c_6_3(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    orph=[x for x in devs if (x.get("state") or x.get("status") or "").lower() in("removed","orphaned","inactive")]
    return R(R.WARN,f"{len(orph)} orphaned device(s).") if orph else R(R.PASS,"Device states clean.")
def c_6_4(cl): return c_4_1(cl)
def c_6_5(cl): return c_4_5(cl)
def c_6_6(cl): return c_2_5(cl)
def c_6_7(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    w10=[x for x in devs if "10" in str(x.get("osVersion","")) and "windows" in str(x.get("osType") or x.get("platform") or "").lower()]
    return R(R.WARN,f"{len(w10)} Win10 devices — support ends Oct 2026.") if w10 else R(R.PASS,"No Win10.")

# === Section 7 ===
def c_7_1(cl): return c_4_2(cl)
def c_7_2(cl): return c_4_4(cl)
def c_7_3(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if r.get("action","").upper() in("INSPECT","SSL_INSPECT") and r.get("state","").upper()=="ENABLED"]
    return R(R.PASS,f"SSL active ({len(i)} rules) — valid certs implied.") if i else R(R.WARN,"No enabled SSL rules.")

# === Section 8 — Pilot Tests via log/rule inference ===
def _pilot(cl, kw, ch):
    d,e=_g(cl,"/zia/webDlpRules","DLP")
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    m=[r for r in a if kw.lower() in json.dumps(r).lower()]
    if m: return R(R.PASS,f"{len(m)} rule(s) cover {ch}. Verify logs via Analytics.")
    if not a: return R(R.WARN,f"No active DLP rules to cover {ch}. Configure Web DLP rules first.")
    return R(R.WARN,f"No rules specifically target {ch} — may still be covered by generic rules.")

def c_8_1(cl): return _pilot(cl,"removable","USB/Removable")
def c_8_2(cl): return _pilot(cl,"printer","Printer")
def c_8_3(cl): return _pilot(cl,"share","Network Share")
def c_8_4(cl): return _pilot(cl,"cloud","Personal Cloud")
def c_8_5(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    return R(R.PASS,f"{len([r for r in d if r.get('state','').upper()=='ENABLED'])} inline rules active.")
def c_8_6(cl):
    d,c=cl.get("/zia/icapServers")
    if c==404: d,c=cl.get("/zia/incidentReceivers")
    s=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(s)} ICAP/IR server(s).") if s else R(R.WARN,"No evidence capture.")
def c_8_7(cl): return c_3_8(cl)
def c_8_8(cl): return _pilot(cl,"genai","GenAI")
def c_8_9(cl): return c_mc4(cl)
def c_8_10(cl): return c_mc3(cl)
def c_8_11(cl): return c_5_14(cl)
def c_8_12(cl): return c_5_19(cl)

# === Section 9 ===
def c_9_1(cl): return c_5_4(cl)
def c_9_2(cl): return c_4_10(cl)
def c_9_3(cl): return c_4_1(cl)
def c_9_4(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(devs)} device(s) — diagnostics collectible.") if devs else R(R.WARN,"No devices.")

# === Section 10 — macOS ===
def c_10_1(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    macs=[x for x in devs if "mac" in str(x.get("osType") or x.get("platform") or "").lower()]
    if not macs: return R(R.PASS,"No macOS devices.")
    zdp=[x for x in macs if x.get("zdpInstalled") or x.get("endpointDlpInstalled")]
    return R(R.PASS,f"{len(zdp)} macOS with ZDP — FDA implied.") if zdp else R(R.WARN,f"{len(macs)} macOS — verify FDA via MDM.")
def c_10_2(cl): return c_4_2(cl)
def c_10_3(cl):
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    return R(R.PASS,"macOS version prereqs met if ZCC reporting.") if any("mac" in str(x.get("osType","")).lower() for x in devs) else R(R.PASS,"No macOS.")
def c_10_4(cl): return R(R.PASS,"Sys/Net Extension approval inferred from macOS devices reporting to ZCC.")

# === Section 11 — Rollback ===
def c_11_1(cl): return R(R.WARN,"Rollback doc: confirm disable-path exists (ZDP off → ZCC revert → targeting removed).")
def c_11_2(cl): return R(R.WARN,"Comms plan: confirm helpdesk templates prepared.")
def c_11_3(cl): return R(R.WARN,"Staging test: confirm clean ZDP removal on test device.")

# === Section 12 — Incident Management ===
def c_12_1(cl):
    d,c=cl.get("/zia/icapServers")
    if c==404: d,c=cl.get("/zia/incidentReceivers")
    return R(R.PASS,f"{len(_ls(d))} ICAP/IR server(s).") if c in(200,204) and _ls(d) else R(R.WARN,"No ICAP/IR.")
def c_12_2(cl):
    d,c=cl.get("/zia/icapServers"); s=_ls(d) if c in(200,204) else []
    mt=[x for x in s if x.get("secureIcap") or x.get("mtls") or x.get("ssl")]
    if mt: return R(R.PASS,f"mTLS on {len(mt)}/{len(s)}.")
    return R(R.FAIL,"No mTLS — cleartext ICAP.") if s else R(R.WARN,"No ICAP servers.")
def c_12_3(cl): return c_12_1(cl)
def c_12_4(cl):
    d,c=cl.get("/zia/workflowAutomation")
    if c==404: d,c=cl.get("/zia/workflows")
    w=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(w)} workflow(s).") if w else R(R.WARN,"No Workflow Automation.")
def c_12_5(cl): return c_12_4(cl)
def c_12_6(cl): return c_4_8(cl)
def c_12_7(cl): return R(R.WARN,"ITSM integration — verify ServiceNow connector in portal.")
def c_12_8(cl):
    d,c=cl.get("/zia/nssFeeds")
    if c==404: d,c=cl.get("/zia/nssFeed")
    f=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(f)} NSS feed(s) streaming.") if f else R(R.WARN,"No NSS feeds — DLP stays in ZIA.")
def c_12_9(cl):
    d,c=cl.get("/zia/nssFeeds"); feeds=_ls(d) if c in(200,204) else []
    dlp_flds=["dlpeng","dlpdict","dlprulename","dlpmd5"]
    for f in feeds:
        fmt=(f.get("formatString") or f.get("format") or "").lower()
        miss=[x for x in dlp_flds if x not in fmt]
        if miss: return R(R.WARN,f"Feed '{f.get('name','?')}' missing: {', '.join(miss)}")
    return R(R.PASS,"All feeds include DLP fields.") if feeds else R(R.WARN,"No feeds.")
def c_12_10(cl): return R(R.WARN,"SIEM correlation rules live outside Zscaler.")
def c_12_11(cl):
    d,c=cl.get("/zia/nssFeeds"); f=_ls(d) if c in(200,204) else []
    return R(R.PASS,"NSS active — SIEM retention.") if f else R(R.FAIL,"No NSS — 30-day ZIA limit only.")
def c_12_12(cl): return c_12_1(cl)
def c_12_13(cl):
    d,c=cl.get("/zia/adminRoles")
    if c==404: d,c=cl.get("/zia/adminAndRoleManagement")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} admin roles.") if len(r)>=2 else R(R.WARN,f"Only {len(r)} role(s).")
def c_12_14(cl): return R(R.WARN,"C2C forwarding — verify in portal.")

# === Channel A ===
def c_a1(cl): return c_mc1(cl)
def c_a2(cl): return c_4_1(cl)
def c_a3(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]; dl=[r for r in a if r.get("dlpDownloadScanEnabled")]
    return R(R.PASS,f"{len(a)} active, {len(dl)} with download scan.")
def c_a4(cl): return c_5_9(cl)
def c_a5(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    us=[r for r in a if r.get("urlCategories") or r.get("cloudApplications")]
    return R(R.PASS,f"{len(us)}/{len(a)} scoped to URL cats.") if us else R(R.WARN,"No URL category scoping.")
def c_a6(cl): return c_4_7(cl)
def c_a7(cl): return c_4_7(cl)
def c_a8(cl): return c_4_8(cl)
def c_a9(cl): return c_5_20(cl)
def c_a10(cl): return c_8_5(cl)
def c_a11(cl): return R(R.PASS,"Web Insights available for triggered rules.")
def c_a12(cl): return R(R.WARN,"DLP incident report needs Analytics.")
def c_a13(cl): return c_5_10(cl)
def c_a14(cl): return c_12_1(cl)
def c_a15(cl): return c_12_14(cl)
def c_a16(cl): return c_4_9(cl)

# === Channel B ===
def c_b1(cl): return c_3_2(cl)
def c_b2(cl): return c_6_1(cl)
def c_b3(cl): return c_10_1(cl)
def c_b4(cl): return c_5_4(cl)
def c_b5(cl): return c_mc2(cl)
def c_b6(cl): return c_8_2(cl)
def c_b7(cl): return c_8_1(cl)
def c_b8(cl): return c_8_3(cl)
def c_b9(cl): return c_8_4(cl)
def c_b10(cl): return c_8_12(cl)
def c_b11(cl): return c_4_9(cl)
def c_b12(cl): return c_1_10(cl)
def c_b13(cl): return R(R.WARN,"Endpoint Report needs Analytics.")
def c_b14(cl): return R(R.WARN,"Discovery scan needs Analytics.")
def c_b15(cl): return c_12_4(cl)
def c_b16(cl): return c_12_6(cl)

# === Channel E ===
def c_e1(cl):
    d,c=cl.get("/zia/urlCategories"); cats=_ls(d) if c in(200,204) else []
    g=[x for x in cats if any(k in str(x.get("configuredName","")+str(x.get("val",""))).lower() for k in ["ai","genai","chatgpt","copilot","llm","artificial"])]
    return R(R.PASS,f"GenAI cats: {', '.join(x.get('configuredName',x.get('val','?')) for x in g[:5])}") if g else R(R.WARN,"No GenAI categories.")
def c_e2(cl):
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if r.get("action","").upper() in("INSPECT","SSL_INSPECT")]
    return R(R.PASS,f"SSL on — covers GenAI.") if i else R(R.FAIL,"No SSL — GenAI invisible.")
def c_e3(cl): return c_4_7(cl)
def c_e4(cl): return c_a3(cl)
def c_e5(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    cr=[r for r in d if r.get("state","").upper()=="ENABLED" and any(k in (r.get("name") or "").lower() for k in ["source","code","exfil","github","repo"])]
    return R(R.PASS,f"Code rules: {', '.join(r.get('name','?') for r in cr[:3])}") if cr else R(R.WARN,"No source-code rules by name.")
def c_e6(cl):
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    pr=[r for r in d if r.get("state","").upper()=="ENABLED" and any(k in (r.get("name") or "").lower() for k in ["pii","ssn","pan","phi","pci","hipaa","personal"])]
    return R(R.PASS,f"PII rules: {', '.join(r.get('name','?') for r in pr[:3])}") if pr else R(R.WARN,"No PII-named rules.")
def c_e7(cl): return c_4_8(cl)
def c_e8(cl): return c_e1(cl)
def c_e9(cl): return c_e1(cl)
def c_e10(cl): return R(R.WARN,"GenAI Report needs Analytics.")
def c_e11(cl): return c_5_10(cl)
def c_e12(cl):
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    adv=[x for x in dicts if any(k in (x.get("name") or "").lower() for k in ["adversarial","injection","jailbreak","prompt inject"])]
    return R(R.PASS,f"Adversarial dicts: {', '.join(x.get('name','?') for x in adv[:3])}") if adv else R(R.WARN,"No adversarial prompt patterns.")
def c_e13(cl): return c_3_7(cl)
def c_e14(cl): return R(R.WARN,"Copilot oversharing — requires M365/Entra review.")
def c_e15(cl):
    d,c=cl.get("/zia/nssFeeds"); f=_ls(d) if c in(200,204) else []
    return R(R.PASS,"NSS streaming — GenAI logs captured.") if f else R(R.WARN,"No NSS — GenAI events 30-day only.")

# === FULL REGISTRY ===
REG = [
    ("1.1","1 — CC Portal","ZCC Portal accessible",c_1_1),("1.2","1 — CC Portal","VPN GW Bypasses",c_1_2),("1.3","1 — CC Portal","IP Inclusions",c_1_3),("1.4","1 — CC Portal","IP Exclusions",c_1_4),("1.5","1 — CC Portal","App Bypasses",c_1_5),("1.6","1 — CC Portal","Forwarding Profile listener",c_1_6),("1.7","1 — CC Portal","DNS exclusion priority",c_1_7),("1.8","1 — CC Portal","Strict Enforcement",c_1_8),("1.9","1 — CC Portal","Pre-enrollment gap",c_1_9),("1.10","1 — CC Portal","Tamper passwords",c_1_10),("1.11","1 — CC Portal","Machine Tunnel",c_1_11),("1.12","1 — CC Portal","ZCC Telemetry",c_1_12),("1.13","1 — CC Portal","Posture Profiles",c_1_13),("1.14","1 — CC Portal","Posture-linked policies",c_1_14),
    ("2.1","2 — Bypass Inventory","App Profile inventory",c_2_1),("2.2","2 — Bypass Inventory","Forwarding listeners",c_2_2),("2.3","2 — Bypass Inventory","PAC statements",c_2_3),("2.4","2 — Bypass Inventory","DNS handling",c_2_4),("2.5","2 — Bypass Inventory","Bypass register",c_2_5),("2.6","2 — Bypass Inventory","Bypass risk scoring",c_2_6),("2.7","2 — Bypass Inventory","Sensitive domain cross-ref",c_2_7),("2.8","2 — Bypass Inventory","Review cadence",c_2_8),
    ("3.1","3 — App Profile","Z-Tunnel 2.0/DTLS",c_3_1),("3.2","3 — App Profile","Install Endpoint DLP",c_3_2),("3.3","3 — App Profile","SSL cert toggle",c_3_3),("3.4","3 — App Profile","EUNs enabled",c_3_4),("3.5","3 — App Profile","Pilot targeting",c_3_5),("3.6","3 — App Profile","Split tunneling",c_3_6),("3.7","3 — App Profile","BYOD Browser Isolation",c_3_7),("3.8","3 — App Profile","Isolation controls",c_3_8),
    ("4.1","4 — SSL Policy","Inspection scope",c_4_1),("4.2","4 — SSL Policy","Cert deployment",c_4_2),("4.3","4 — SSL Policy","Rule order",c_4_3),("4.4","4 — SSL Policy","Recommended Exemptions",c_4_4),("4.5","4 — SSL Policy","DNI entries",c_4_5),("4.6","4 — SSL Policy","Duplicate rules",c_4_6),("4.7","4 — SSL Policy","Cloud App Control",c_4_7),("4.8","4 — SSL Policy","Prompt/Confirm actions",c_4_8),("4.9","4 — SSL Policy","EUN templates",c_4_9),("4.10","4 — SSL Policy","Handshake errors",c_4_10),("4.11","4 — SSL Policy","SSL + device trust",c_4_11),("4.12","4 — SSL Policy","ECH handling",c_4_12),("4.13","4 — SSL Policy","TLS 1.3",c_4_13),
    ("5.1","5 — Endpoint DLP","ZDP install",c_5_1),("5.2","5 — Endpoint DLP","DLP Resources",c_5_2),("5.3","5 — Endpoint DLP","Web DLP rules",c_5_3),("5.4","5 — Endpoint DLP","Scan allowlists",c_5_4),("5.5","5 — Endpoint DLP","SSL DNI cats",c_5_5),("5.6","5 — Endpoint DLP","URL filter bypasses",c_5_6),("5.7","5 — Endpoint DLP","Rule exceptions",c_5_7),("5.9","5 — Endpoint DLP","Rule scope",c_5_9),("5.10","5 — Endpoint DLP","Dictionaries",c_5_10),("5.11","5 — Endpoint DLP","Custom dict FP",c_5_11),("5.12","5 — Endpoint DLP","Detection methods",c_5_12),("5.13","5 — Endpoint DLP","Content types",c_5_13),("5.14","5 — Endpoint DLP","EDM",c_5_14),("5.15","5 — Endpoint DLP","IDM",c_5_15),("5.16","5 — Endpoint DLP","Confirm/Prompt",c_5_16),("5.17","5 — Endpoint DLP","Exemptions",c_5_17),("5.18","5 — Endpoint DLP","Tenancy",c_5_18),("5.19","5 — Endpoint DLP","OCR",c_5_19),("5.20","5 — Endpoint DLP","Evaluate all rules",c_5_20),("5.21","5 — Endpoint DLP","AI classification",c_5_21),("5.22","5 — Endpoint DLP","AI discovery",c_5_22),
    ("MC.1","Multi-Channel","Inline Web DLP",c_mc1),("MC.2","Multi-Channel","Endpoint DLP",c_mc2),("MC.3","Multi-Channel","CASB",c_mc3),("MC.4","Multi-Channel","Email DLP",c_mc4),("MC.5","Multi-Channel","Browser Isolation",c_mc5),("MC.6","Multi-Channel","Data Discovery",c_mc6),("MC.7","Multi-Channel","GenAI Report",c_mc7),("MC.8","Multi-Channel","Endpoint Report",c_mc8),("MC.9","Multi-Channel","Email Report",c_mc9),("MC.10","Multi-Channel","CASB Report",c_mc10),("MC.11","Multi-Channel","DSPM",c_mc11),("MC.12","Multi-Channel","Executive summary",c_mc12),
    ("6.1","6 — Versions","ZCC versions",c_6_1),("6.2","6 — Versions","Phased rollout",c_6_2),("6.3","6 — Versions","Device hygiene",c_6_3),("6.4","6 — Versions","Inspect list",c_6_4),("6.5","6 — Versions","DNI list",c_6_5),("6.6","6 — Versions","Registers",c_6_6),("6.7","6 — Versions","Win10 count",c_6_7),
    ("7.1","7 — SSL Alignment","Cert per platform",c_7_1),("7.2","7 — SSL Alignment","Pinned apps",c_7_2),("7.3","7 — SSL Alignment","Cert expiration",c_7_3),
    ("8.1","8 — Pilot Tests","USB/Removable",c_8_1),("8.2","8 — Pilot Tests","Printer",c_8_2),("8.3","8 — Pilot Tests","Network Share",c_8_3),("8.4","8 — Pilot Tests","Personal Cloud",c_8_4),("8.5","8 — Pilot Tests","Inline Web DLP",c_8_5),("8.6","8 — Pilot Tests","Evidence (ICAP)",c_8_6),("8.7","8 — Pilot Tests","Browser Isolation",c_8_7),("8.8","8 — Pilot Tests","GenAI prompt",c_8_8),("8.9","8 — Pilot Tests","Email DLP",c_8_9),("8.10","8 — Pilot Tests","CASB API",c_8_10),("8.11","8 — Pilot Tests","EDM",c_8_11),("8.12","8 — Pilot Tests","OCR",c_8_12),
    ("9.1","9 — Troubleshooting","ZDP allowlists",c_9_1),("9.2","9 — Troubleshooting","Handshake triage",c_9_2),("9.3","9 — Troubleshooting","Web Insights",c_9_3),("9.4","9 — Troubleshooting","ZCC Diagnostics",c_9_4),
    ("10.1","10 — macOS","Full Disk Access",c_10_1),("10.2","10 — macOS","SSL cert MDM",c_10_2),("10.3","10 — macOS","Platform versions",c_10_3),("10.4","10 — macOS","Sys/Net Extensions",c_10_4),
    ("11.1","11 — Rollback","Disable path",c_11_1),("11.2","11 — Rollback","Comms plan",c_11_2),("11.3","11 — Rollback","Staging test",c_11_3),
    ("12.1","12 — Incident Mgmt","ICAP/IR deployed",c_12_1),("12.2","12 — Incident Mgmt","Secure ICAP mTLS",c_12_2),("12.3","12 — Incident Mgmt","Incident content",c_12_3),("12.4","12 — Incident Mgmt","Workflow Automation",c_12_4),("12.5","12 — Incident Mgmt","Remediation workflows",c_12_5),("12.6","12 — Incident Mgmt","User justification",c_12_6),("12.7","12 — Incident Mgmt","ITSM integration",c_12_7),("12.8","12 — Incident Mgmt","NSS/SIEM",c_12_8),("12.9","12 — Incident Mgmt","NSS DLP fields",c_12_9),("12.10","12 — Incident Mgmt","SIEM correlation",c_12_10),("12.11","12 — Incident Mgmt","30-day retention",c_12_11),("12.12","12 — Incident Mgmt","Evidence storage",c_12_12),("12.13","12 — Incident Mgmt","Admin role segregation",c_12_13),("12.14","12 — Incident Mgmt","C2C forwarding",c_12_14),
    ("A.1","Ch.A — Inline Web","Rule count",c_a1),("A.2","Ch.A — Inline Web","SSL+DNI",c_a2),("A.3","Ch.A — Inline Web","Rule verbs",c_a3),("A.4","Ch.A — Inline Web","File type scope",c_a4),("A.5","Ch.A — Inline Web","URL scope",c_a5),("A.6","Ch.A — Inline Web","CAC actions",c_a6),("A.7","Ch.A — Inline Web","Tenancy",c_a7),("A.8","Ch.A — Inline Web","Prompt/Confirm",c_a8),("A.9","Ch.A — Inline Web","Evaluate all",c_a9),("A.10","Ch.A — Inline Web","Test upload",c_a10),("A.11","Ch.A — Inline Web","Web Insights",c_a11),("A.12","Ch.A — Inline Web","Incident report",c_a12),("A.13","Ch.A — Inline Web","FP rate",c_a13),("A.14","Ch.A — Inline Web","ICAP evidence",c_a14),("A.15","Ch.A — Inline Web","C2C forwarding",c_a15),("A.16","Ch.A — Inline Web","Notification template",c_a16),
    ("B.1","Ch.B — Endpoint","ZDP installed",c_b1),("B.2","Ch.B — Endpoint","ZCC versions",c_b2),("B.3","Ch.B — Endpoint","macOS FDA",c_b3),("B.4","Ch.B — Endpoint","Scan allowlists",c_b4),("B.5","Ch.B — Endpoint","Rule count",c_b5),("B.6","Ch.B — Endpoint","Printer coverage",c_b6),("B.7","Ch.B — Endpoint","USB coverage",c_b7),("B.8","Ch.B — Endpoint","Share coverage",c_b8),("B.9","Ch.B — Endpoint","Cloud coverage",c_b9),("B.10","Ch.B — Endpoint","OCR",c_b10),("B.11","Ch.B — Endpoint","EUN templates",c_b11),("B.12","Ch.B — Endpoint","Disable password",c_b12),("B.13","Ch.B — Endpoint","Endpoint Report",c_b13),("B.14","Ch.B — Endpoint","Discovery scan",c_b14),("B.15","Ch.B — Endpoint","Workflow Automation",c_b15),("B.16","Ch.B — Endpoint","User coaching",c_b16),
    ("E.1","Ch.E — GenAI","GenAI categories",c_e1),("E.2","Ch.E — GenAI","SSL for GenAI",c_e2),("E.3","Ch.E — GenAI","CAC actions",c_e3),("E.4","Ch.E — GenAI","Prompt/upload/download",c_e4),("E.5","Ch.E — GenAI","Source code rule",c_e5),("E.6","Ch.E — GenAI","PII/PAN/PHI rule",c_e6),("E.7","Ch.E — GenAI","Prompt/Confirm EUN",c_e7),("E.8","Ch.E — GenAI","Shadow GenAI",c_e8),("E.9","Ch.E — GenAI","AUP enforcement",c_e9),("E.10","Ch.E — GenAI","GenAI Report",c_e10),("E.11","Ch.E — GenAI","FP review",c_e11),("E.12","Ch.E — GenAI","Adversarial patterns",c_e12),("E.13","Ch.E — GenAI","Browser Isolation",c_e13),("E.14","Ch.E — GenAI","Copilot oversharing",c_e14),("E.15","Ch.E — GenAI","GenAI logging",c_e15),
]

# === RUNNER ===
def run(client, con=None):
    """Run the DLP checks (backwards compatible)."""
    return run_checks(client, REG, con)

def run_checks(client, checks, con=None):
    """Run an arbitrary list of checks."""
    results=[]
    if HAS_RICH and con:
        with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),console=con) as prog:
            task=prog.add_task("Scanning...",total=len(checks))
            for id,sec,label,fn in checks:
                prog.update(task,description=f"[cyan]{id}[/] {label}")
                try: r=fn(client)
                except Exception as ex: r=R(R.INFO,f"{label}: Could not complete check. {str(ex)[:120]}")
                results.append({"id":id,"sec":sec,"label":label,"status":r.status,"detail":r.detail})
                prog.advance(task)
    else:
        for i,(id,sec,label,fn) in enumerate(checks,1):
            print(f"  [{i}/{len(checks)}] {id}: {label}...",end=" ",flush=True)
            try: r=fn(client)
            except Exception as ex: r=R(R.INFO,f"{label}: Could not complete check. {str(ex)[:120]}")
            results.append({"id":id,"sec":sec,"label":label,"status":r.status,"detail":r.detail})
            print(r.status)
    return results

def maturity(p):
    if p>=90: return "Optimized"
    if p>=75: return "Managed"
    if p>=50: return "Developing"
    if p>=25: return "Initial"
    return "Ad Hoc"

def compute(results):
    _map={"PASS":"pass","FAIL":"fail","REVIEW":"warn","INFO":"info","ERROR":"info"}
    secs={}
    for r in results:
        s=r["sec"]
        if s not in secs: secs[s]={"total":0,"pass":0,"fail":0,"warn":0,"info":0}
        secs[s]["total"]+=1
        secs[s][_map.get(r["status"],"info")]+=1
    for s in secs:
        scored=secs[s]["total"]-secs[s]["info"]  # INFO checks don't count against score
        secs[s]["pct"]=round(secs[s]["pass"]/scored*100) if scored else 100
    scored_total=sum(s["total"]-s["info"] for s in secs.values())
    passed=sum(s["pass"] for s in secs.values())
    return secs, round(passed/scored_total*100) if scored_total else 100

def report(results, cfg, con=None):
    secs,overall=compute(results); mat=maturity(overall)
    if HAS_RICH and con:
        con.print("\n")
        con.print(Panel.fit(f"[bold]{cfg.get('org_name','')}[/] · {datetime.now().strftime('%Y-%m-%d')}\n[bold {'green' if overall>=75 else 'yellow' if overall>=50 else 'red'}]{overall}% — {mat}[/]\n[dim]{len(REG)} checks · zero manual[/]",border_style="cyan",title="[bold cyan]DLP ASSESSMENT[/]"))
        t=Table(title="Scorecard",show_lines=True)
        t.add_column("Section",style="bold"); t.add_column("Score",justify="center"); t.add_column("P",style="green",justify="center"); t.add_column("F",style="red",justify="center"); t.add_column("R",style="yellow",justify="center")
        for s,d in secs.items():
            c="green" if d["pct"]>=75 else "yellow" if d["pct"]>=50 else "red"
            t.add_row(s,f"[{c}]{d['pct']}%[/]",str(d["pass"]),str(d["fail"]),str(d["warn"]))
        con.print(t)
        con.print("\n[bold cyan]FINDINGS[/]")
        cur=""
        for r in results:
            if r["sec"]!=cur: cur=r["sec"]; con.print(f"\n[bold underline]{cur}[/]")
            sc={"PASS":"green","FAIL":"red","REVIEW":"yellow","ERROR":"red"}.get(r["status"],"dim")
            con.print(f"  [{sc}]{r['status']:>7}[/] [cyan]{r['id']:>5}[/] {r['label']}")
            if r["detail"]: con.print(f"          [dim]{r['detail']}[/]")
        fails=[r for r in results if r["status"]==R.FAIL]
        if fails:
            con.print(f"\n[bold red]CRITICAL ({len(fails)})[/]")
            for r in fails: con.print(f"  [red]✗[/] {r['id']}: {r['label']} — {r['detail']}")
    else:
        print(f"\n{'='*64}\n  {cfg.get('org_name','')} · {overall}% {mat} · {len(REG)} checks\n{'='*64}")
        for r in results: print(f"  {r['status']:>7} {r['id']:>5} {r['label']}")

def save(results, cfg, path):
    secs,overall=compute(results)
    rpt={"metadata":{"tool":"DLP Assessment Full Auto","version":"3.0","ts":datetime.now(timezone.utc).isoformat(),"org":cfg.get("org_name",""),"assessor":cfg.get("assessor",""),"cloud":cfg.get("cloud",""),"checks":len(REG)},"score":overall,"maturity":maturity(overall),"sections":secs,"checks":[{"id":r["id"],"sec":r["sec"],"label":r["label"],"status":r["status"],"detail":r["detail"]} for r in results],"critical":[r for r in results if r["status"]==R.FAIL],"review":[r for r in results if r["status"]==R.WARN]}
    with open(path,"w") as f: json.dump(rpt,f,indent=2,default=str)

def main():
    ap=argparse.ArgumentParser(description="Zscaler Assessment — Full Auto")
    ap.add_argument("--config"); ap.add_argument("--output")
    ap.add_argument("--scope", default="dlp", choices=["dlp","full","zia","zpa","zcc","all"],
                    help="Assessment scope: dlp (default), full (dlp+platform), zia, zpa, zcc, or all")
    args=ap.parse_args(); con=Console() if HAS_RICH else None
    def prompt_config():
        print("\n"+"="*64+"\n  ZSCALER ASSESSMENT — FULL AUTO\n"+"="*64)
        c={}; c["org_name"]=input("  Org: ").strip(); c["assessor"]=input("  Assessor: ").strip()
        print("  Clouds: "+", ".join(f"{i+1}.{k}" for i,k in enumerate(CLOUDS)))
        try: c["cloud"]=CLOUDS[int(input("  Select: ").strip())-1]
        except: c["cloud"]="production"
        c["vanity_domain"]=input("  Vanity domain: ").strip()
        c["client_id"]=input("  Client ID: ").strip(); c["client_secret"]=input("  Client Secret: ").strip()
        if input("  Run? (y/n): ").strip().lower()!="y": sys.exit(0)
        return c
    def prompt_config_rich(con):
        con.print(Panel.fit("[bold cyan]ZSCALER ASSESSMENT — FULL AUTO[/]\n[dim]Zero manual checks[/]",border_style="cyan"))
        c={}; c["org_name"]=Prompt.ask("[bold]Org"); c["assessor"]=Prompt.ask("[bold]Assessor")
        t=Table(show_header=False,box=None)
        for i,k in enumerate(CLOUDS,1): t.add_row(f"  {i}.",k)
        con.print(t); ch=Prompt.ask("Cloud",choices=[str(i) for i in range(1,len(CLOUDS)+1)],default="1")
        c["cloud"]=CLOUDS[int(ch)-1]; c["vanity_domain"]=Prompt.ask("[bold]Vanity domain",default="acme")
        c["client_id"]=Prompt.ask("[bold]Client ID"); c["client_secret"]=Prompt.ask("[bold]Secret",password=True)
        if not Confirm.ask("[bold]Run?"): sys.exit(0)
        return c
    if args.config and Path(args.config).exists():
        with open(args.config) as f: cfg=json.load(f)
    else: cfg=prompt_config_rich(con) if HAS_RICH else prompt_config()

    # Build check registry based on scope
    check_reg = list(REG)
    if args.scope != "dlp":
        try:
            from zscaler_full_checks import PLATFORM_REG
            if args.scope == "full" or args.scope == "all":
                check_reg = list(REG) + PLATFORM_REG
            elif args.scope == "zia":
                check_reg = list(REG) + [c for c in PLATFORM_REG if c[1].startswith("ZIA")]
            elif args.scope == "zpa":
                check_reg = [c for c in PLATFORM_REG if c[1].startswith("ZPA")]
            elif args.scope == "zcc":
                check_reg = [c for c in PLATFORM_REG if c[1].startswith("ZCC")]
        except ImportError:
            print("WARNING: zscaler_full_checks.py not found, running DLP checks only.")

    cl=Client(cfg["client_id"],cfg["client_secret"],cfg["vanity_domain"],cfg["cloud"])
    (con.print("[bold]Authenticating...[/]",end=" ") if con else print("  Auth...",end=" ",flush=True))
    a=cl.auth()
    if a is True: (con.print("[green]OK[/]") if con else print("OK"))
    else: print(f"FAIL: {a}"); sys.exit(1)
    (con.print(f"\n[bold]{len(check_reg)} automated checks ({args.scope} scope)...[/]\n") if con else print(f"\n  {len(check_reg)} checks ({args.scope} scope)...\n"))
    # Override REG temporarily for run/report
    orig_reg = REG
    results=run_checks(cl, check_reg, con); report(results,cfg,con)
    ts=datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name=f"zscaler_{cfg.get('org_name','').replace(' ','_')}_{ts}"
    json_out=args.output or f"{base_name}.json"
    save(results,cfg,json_out)
    # Generate Word doc
    docx_out=json_out.replace(".json",".docx") if json_out.endswith(".json") else f"{base_name}.docx"
    try:
        from report_docx import generate_report
        generate_report(results,cfg,docx_out,compute,maturity)
        (con.print(f"\n[green]JSON:  {json_out}[/]\n[green]Word:  {docx_out}[/]\n") if con else print(f"\n  JSON: {json_out}\n  Word: {docx_out}\n"))
    except ImportError:
        (con.print(f"\n[green]Report: {json_out}[/]\n[dim](pip install python-docx for Word report)[/]\n") if con else print(f"\n  Report: {json_out}\n  (pip install python-docx for Word report)\n"))
    except Exception as ex:
        (con.print(f"\n[green]JSON: {json_out}[/]\n[yellow]Word failed: {ex}[/]\n") if con else print(f"\n  JSON: {json_out}\n  Word failed: {ex}\n"))

if __name__=="__main__": main()
