# Assumed Zscaler behaviour (compiled — do not edit by hand)

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Every place the code relies on Zscaler behaviour it could not verify against the installed SDK or Zscaler's
documentation. A verify stage treats these as unproven; a spec that depends on one says so.

525 markers.

| File:line | Note |
|---|---|
| `admin_ops.py:91` | URL_MAX_LEN = 1024         # assumed ZIA limit for one custom URL |
| `admin_ops.py:716` | API stores it (assumed for ZIA and ZPA: the SDK passes names through), |
| `admin_ops.py:1049` | warning, assumed}}): the ranks an Undo puts back, or, with Admin Ranking |
| `admin_ops.py:1059` | out[rid] = {"rank": rk, "before": cur, "change": rk != cur, "assumed": False, "warning": "", |
| `admin_ops.py:1193` | asked_order=slots[desired.index(rid)], why=rk["why"], warning=rk.get("warning") or "", assumed=rk.get("assumed")) |
| `admin_ops.py:1578` | Overlap: a domain may sit in two segments only on ports that do not overlap (assumed ZPA rule; ZPA refuses the save otherwise). |
| `admin_rank.py:10` | Sources (what is relied on, and what is assumed): |
| `admin_rank.py:28` | Assumed (not confirmed in a source, said where it matters): |
| `admin_rank.py:56` | DEFAULT_RANK = LOWEST   # assumed: a rule without a rank is at the lowest rank |
| `admin_rank.py:128` | """The rule's admin rank, 0..7; DEFAULT_RANK when it has none (assumed).""" |
| `ai_guard.py:19` | What is verified against zscaler-sdk-python 1.11.3 and what is assumed is |
| `ai_guard.py:20` | listed in VERIFIED and ASSUMED below, and the page shows the assumptions. |
| `ai_guard.py:51` | ASSUMED = ( |
| `ai_guard.py:183` | "gateway_steps": list(GATEWAY_STEPS), "portal_steps": list(PORTAL_STEPS), "assumed": list(ASSUMED)} |
| `ai_guard.py:299` | """Root certificates for proxy chaining (raw GET, assumed path).""" |
| `ai_guard.py:411` | verified, assumed}. Never writes and never raises on a tenant answer.""" |
| `ai_guard.py:548` | "builder": BUILDER_PAGE, "verified": list(VERIFIED), "assumed": list(ASSUMED)} |
| `ai_guard.py:584` | create/update times are assumed from the other AI Guard models; the |
| `ai_guard.py:668` | "errors": {}, "verified": list(VERIFIED) + list(DEPTH_VERIFIED), "assumed": list(ASSUMED) + list(DEPTH_ASSUMED)} |
| `ai_guard.py:768` | "policy_id": pid, "verified": list(DEPTH_VERIFIED), "assumed": list(DEPTH_ASSUMED)} |
| `app_services.py:23` | names are assumed, as Zscaler does not publish them through the API), and |
| `app_services.py:25` | LOGMEIN, TALKDESK: vendor_endpoints, names assumed) the provider's list, |
| `app_services.py:27` | those lists (assumed from its One Click documentation). Every other app |
| `app_services.py:31` | so its group is taken to hold its endpoints on any port (assumed). |
| `app_services.py:34` | alternatives (any one is enough, assumed: they are one field in the |
| `app_services.py:60` | service areas they hold. Assumed: Zscaler's app service names are not in |
| `app_update.py:196` | fork or a mirror is never assumed to be the upstream repository.""" |
| `audit_timeline.py:167` | CORRELATE_SECONDS match with Zscaler Made Easy's own writes. Assumed: CST |
| `bulk_test.py:124` | SUSPICIOUS_DESTINATION; the others are assumed from ZIA's category list. |
| `bulk_test.py:128` | category costs little. Names this app already uses (ssl_flow) or assumed. |
| `compliance_pack.py:7` | the control catalogue with sources and the assumed flag |
| `compliance_pack.py:148` | return "; ".join(f"{c['id']}{' (assumed)' if c.get('assumed') else ''}" for c in m.get("controls") or []) |
| `compliance_pack.py:198` | MAP_COLUMNS = ["Source", "Area", "Rule", "Rule key", "Created", "Action", "Objective", "Controls", "Assumed", "Reason code", "Reason", |
| `compliance_pack.py:206` | _act(r["action"]), r["objective_label"], _ctrl_text(r), "yes" if any(c.get("assumed") for c in r["controls"]) else "", |
| `compliance_pack.py:211` | CTRL_COLUMNS = ["Control", "Title", "Source", "Baseline", "Rules that carry it out", "Assumed", "Why assumed"] |
| `compliance_pack.py:220` | "yes" if c.get("assumed") else "", c.get("assumed_why", "")] for c in ctx["controls"]] |
| `compliance_pack.py:245` | f"instead. A control marked <span class=\"a\">assumed</span> is not verified against its source (see the Controls table).</p>", |
| `compliance_pack.py:390` | c = cat.get(cid, {"id": cid, "title": "", "assumed": False}) |
| `compliance_pack.py:391` | out.append({"control": cid, "title": c.get("title", ""), "assumed": bool(c.get("assumed")), "tests": tests, |
| `compliance_pack.py:396` | TP_COLUMNS = ["Control", "Title", "Assumed", "Test", "Rule", "Source", "Steps", "Expected", "Evidence", "Result"] |
| `compliance_pack.py:403` | rows.append([c["control"], c["title"], "yes" if c["assumed"] else "", "", "", "", c["note"], "", "", ""]) |
| `compliance_pack.py:405` | rows.append([c["control"], c["title"], "yes" if c["assumed"] else "", t["id"], t["rule"], t["source"], t["steps"], t["expected"], |
| `compliance_pack.py:419` | mark = ' <span class="a">(assumed)</span>' if c["assumed"] else "" |
| `compliance_pack.py:749` | "Controls marked 'assumed' are not verified against their source; the mapping report lists why."] |
| `compliance_profiles.py:27` | What is sourced and what is assumed |
| `compliance_profiles.py:32` | `assumed: True` and an `assumed_why`; assumed() lists them all, and every |
| `compliance_profiles.py:171` | def _c(cid: str, title: str, source: str, baseline: str = "", assumed: str = "") -> Dict[str, Any]: |
| `compliance_profiles.py:172` | return {"id": cid, "title": title, "source": source, "baseline": baseline, "assumed": bool(assumed), "assumed_why": assumed} |
| `compliance_profiles.py:202` | assumed="SC-21 asks the resolver to verify the origin and integrity of answers (DNSSEC); whether the Zscaler Trusted Resolver " |
| `compliance_profiles.py:203` | "validates DNSSEC is not confirmed here, so crediting the DNS redirect to SC-21 is assumed."), |
| `compliance_profiles.py:254` | "m2209", assumed="The Data actions are summarised from memory of the memorandum; check the wording against section III.E."), |
| `compliance_profiles.py:258` | assumed="Crediting web malware and phishing blocking to the Devices pillar's threat protection function is this app's reading."), |
| `compliance_profiles.py:264` | assumed="Crediting web content isolation to Application Threat Protections is this app's reading."), |
| `compliance_profiles.py:268` | assumed="Crediting incident response checks to Automation and Orchestration is this app's reading."), |
| `compliance_profiles.py:271` | if _z["source"] == "m2209" and not _z["assumed"]: |
| `compliance_profiles.py:424` | "assumed": "GovRAMP's own Moderate control list is not checked here; it is taken as the NIST SP 800-53B Moderate baseline.", |
| `compliance_profiles.py:480` | if cid in _IRS_ENHANCEMENTS_UNVERIFIED and not x["assumed"]: |
| `compliance_profiles.py:481` | x["assumed"] = True |
| `compliance_profiles.py:496` | if profile_key == "GOVRAMP" and not c["assumed"]: |
| `compliance_profiles.py:497` | c["assumed"], c["assumed_why"] = True, PROFILES["GOVRAMP"]["assumed"] |
| `compliance_profiles.py:504` | assessment area maps to, with its source and assumed flag.""" |
| `compliance_profiles.py:526` | "assumed": False, "assumed_why": "", "area_level": True}) |
| `compliance_profiles.py:536` | out += [{"id": cid, "title": "", "source": ov["source"]["id"], "source_ref": ov["source"], "assumed": False, |
| `compliance_profiles.py:673` | "aiguard_name": ap.get("name", p["aiguard"]), "reuses": p["reuses"], "assumed_profile": p.get("assumed", ""), |
| `compliance_profiles.py:675` | "assumed_controls": [c["id"] for c in controls(profile_key) if c.get("assumed")]} |
| `compliance_profiles.py:689` | def assumed() -> List[Dict[str, str]]: |
| `compliance_profiles.py:690` | """Every assumed control (and profile-level assumption), for the report.""" |
| `compliance_profiles.py:696` | if c.get("assumed"): |
| `compliance_profiles.py:756` | "assumed": sum(1 for r in rows if any(c.get("assumed") for c in r["controls"]))}} |
| `compliance_profiles.py:828` | c = cat.get(cid, {"id": cid, "title": "", "assumed": False, "assumed_why": ""}) |
| `compliance_profiles.py:829` | rows.append({"control": cid, "title": c.get("title", ""), "status": status, "assumed": bool(c.get("assumed")), |
| `compliance_profiles.py:843` | "map_pack_rule", "applies", "controls", "assumed", "assessment_view", "get", "key_of", "ProfileError", "FEDERAL_KEYS"] |
| `config_backup.py:58` | one exists). Assumed, not verifiable without a tenant: that the SDK's add_ / |
| `config_backup.py:154` | operands carry the profile's UDID and the network's network id (assumed from the portal's payloads). |
| `config_backup.py:301` | """A bandwidth class the customer made (assumed: Zscaler's own classes are |
| `config_backup.py:347` | """A PAC file the customer made (assumed: Zscaler's own PAC files answer |
| `config_backup.py:523` | assumed: ZIA fills in its own linked ZPA tenant when zpa_tenant_id is left out of a create. |
| `config_backup.py:548` | assumed: ZIA picks the target's own primary and secondary VIPs and an internal IP range when a create leaves them out. |
| `config_backup.py:564` | assumed: a sub-location's name is unique within its parent, so it is matched by "<parent> / <name>". |
| `config_backup.py:605` | "path /rootCertificates (assumed); never updated", uses=()), |
| `config_backup.py:726` | why="its passwords and policy token are never read back or sent (an update leaves them as they are: assumed); a missing " |
| `config_backup.py:732` | why="the SDK's entitlement update sends no body: restored with a PUT of the entitlement (assumed body, as Bulk changes does)", |
| `config_backup.py:737` | why="the SDK's entitlement update sends no body: restored with a PUT of the entitlement (assumed body, as Bulk changes does)", |
| `config_backup.py:740` | assumed: GET /application-profiles answers {"policies": [...]}, the shape the SDK reads (zscaler/zcc/application_profiles.py). |
| `config_backup.py:1145` | Keys go in camel case as the GET answers them (assumed).""" |
| `config_backup.py:1351` | when missing; INSPECT for inspection: assumed).""" |
| `data_flow.py:950` | enters the tunnel. A host name is not resolved: it is assumed to |
| `data_flow.py:964` | "it is not resolved and is assumed to resolve outside them") |
| `data_flow.py:1021` | nis["zcc"] + " How the device forwards this traffic is not assessed; a tunnel to ZIA is assumed.", None, why="not in scope")) |
| `data_flow.py:1027` | + (f" (the tenant has {fps_n} forwarding profiles, so none can be assumed)" if fps_n > 1 else (" and the forwarding profile list could no… |
| `data_flow.py:1329` | f"SSL rule '{decided['name']}' has unrecognized action '{decided['action']}'. Its decryption or blocking behavior is unknown; it is not a… |
| `detection_health.py:1017` | assumed from one: |
| `device_posture.py:25` | Assumed, not verifiable from the SDK (stated on the page and in exports): |
| `device_posture.py:175` | "Client Connector trusted networks are matched to ZPA trusted networks by the ZPA network ID, assumed to be the " |
| `dlp_api_server.py:3888` | "assumed": list(ai_guard.DEPTH_ASSUMED)} |
| `dlp_api_server.py:9501` | w.writerow(["Control", "Title", "Status", "Assumed", "Passing", "Failing", "Review", "Checks"]) |
| `dlp_api_server.py:9503` | w.writerow([c["control"], c["title"], c["status"], "yes" if c["assumed"] else "", c["passing"], c["failing"], c["review"], |
| `dlp_api_server.py:9636` | """One profile: what it does and its control catalogue (sources and the assumed flag).""" |
| `dlp_assessment_full_auto.py:200` | times of a provider credential are assumed (not named by the SDK model). |
| `dns_forward_zones.py:50` | * Assumed (not in the SDK or Zscaler's API reference): that the resolver |
| `editions.py:12` | tenants, and are ASSUMED (not in the SDK). The ZDX edition is not exposed by |
| `editions.py:17` | brings the standard firewall; assumed) |
| `editions.py:19` | standard  ZSEC_WEB_ABA, or ZIA_ATP (assumed, as above) |
| `editions.py:26` | descriptions, ASSUMED: not verified against a tenant) |
| `editions.py:59` | SKU_NOTE = "Subscription ids are assumed (as seen on tenants; the SDK documents the licence list, not its ids)." |
| `editions.py:143` | out.append(SKU_NOTE + " What each edition allows is this app's reading of Zscaler's edition descriptions (assumed).") |
| `insights.py:670` | ASSUMED: Shadow IT's sanctioned_state spells the two states as |
| `mcp_tools.py:1187` | ZDX_BANDS = (("poor", 0, 33), ("okay", 34, 65), ("good", 66, 100))   # assumed: the ZDX portal's score bands (not in the SDK) |
| `offline_tenant.py:506` | Switches one app profile's state (zscaler/zcc/web_policy.py activate_web_policy; the toggle is assumed, see ops_zcc_live). |
| `offline_tenant.py:1361` | inspection catalogue, the ZDX configuration (assumed API, ops_zdx) and AI Guard's lists. |
| `ops_aiguard.py:33` | readiness check; what is verified against the SDK and what is assumed is |
| `ops_aiguard.py:622` | _SSL_STOPPERS = {"DO_NOT_DECRYPT", "BLOCK"}   # SSL inspection action types (BLOCK: assumed, not enumerated in the SDK model) |
| `ops_config_restore.py:79` | assumed: a rule created without it is active at once (the API's default). |
| `ops_config_restore.py:347` | assumed: POST /staticIP/validate only checks the address and never changes the tenant, so the |
| `ops_config_restore.py:360` | assumed: a 409, or an answer saying the address exists, is a duplicate or is already used, means |
| `ops_config_restore.py:481` | assumed: an entitlement's group list and an app profile's groups name the same user groups by the same ids. |
| `ops_config_restore.py:741` | assumed: the ZPA tenant read for the target (the profile's ZPA) is the one the target ZIA is linked to, so a |
| `ops_config_restore.py:754` | assumed: ZPA answers ip_anchored on a server group; only an explicit false refuses it. |
| `ops_config_restore.py:1462` | assumed: deleting in the reverse of the create order (a location, then its GRE tunnel, then its static |
| `ops_config_restore.py:1652` | or not sent (PRA and inspection: ZPA keeps them unless they are listed for deletion, assumed). |
| `ops_dlp_objects.py:57` | ASSUMED: that ZIA itself refuses deleting an object something outside the |
| `ops_dlp_objects.py:82` | NOT_CHECKED = "Anything outside the DLP rules and engines read here that uses it makes ZIA refuse the delete (assumed)." |
| `ops_fw_import.py:31` | firewall channel). Assumed: that the API accepts an IPv4 range a-b in an IP |
| `ops_ip_groups.py:59` | ASSUMED: the limits below (ops_list_fix's, from ZIA's Ranges & Limitations |
| `ops_ip_groups.py:93` | "(assumed).") |
| `ops_ip_groups.py:605` | f"default organisation limit is {lf.ORG_IP_ENTRIES:,} (assumed): writes past it are refused.") |
| `ops_list_fix.py:18` | assumed to take a host name too). Each is an existing |
| `ops_list_fix.py:92` | Assumed (marked where used): the per-group, organisation and list limits |
| `ops_list_fix.py:122` | CAT_NAME_MAX = 255          # assumed, as admin_ops._object_name |
| `ops_list_fix.py:128` | Limits. Assumed: Zscaler's ZIA "Ranges & Limitations" help page |
| `ops_list_fix.py:137` | Assumed: no published size for the security policy lists was found; the |
| `ops_list_fix.py:145` | GROUP_NAME_MAX = 128        # assumed: ZIA's own form caps names; refused by the tenant past its limit |
| `ops_list_fix.py:147` | NEW_RULE_RANK = 7           # assumed, as ops_zia_baseline |
| `ops_list_fix.py:795` | f"{ORG_IP_ENTRIES:,} per organisation across source and destination groups (assumed; Support can raise it). " |
| `ops_list_fix.py:846` | P.warnings.append(f"{len(entries):,} entries are more than one IP destination group holds ({MAX_GROUP_ADDRESSES:,}, assumed): " |
| `ops_list_fix.py:910` | reason=f"not changed: '{gname}' would hold more than {MAX_GROUP_ADDRESSES:,} entries (ZIA's per-group limit, assumed). " |
| `ops_list_fix.py:1002` | assumed: how ZIA returns such a rule when it is read back. The sample tenant gives request_methods |
| `ops_list_fix.py:1165` | reason=f"not changed: the list would hold more than {ATP_LIST_MAX:,} entries (assumed limit)") |
| `ops_list_fix.py:1372` | "(assumed); nothing was sent") |
| `ops_rule_csv.py:105` | ZIA_PAGE = 500     # page_size for the paged ZIA lists (the SDK documents page / page_size; the maximum is assumed) |
| `ops_rule_csv.py:876` | is added after the last rule that is not the Default rule (assumed: ZIA |
| `ops_rule_csv.py:930` | slots = list(range(1, len(sim) + 1))    # assumed: after an add or a delete ZIA numbers its rules 1..n again, top first |
| `ops_rule_csv.py:1213` | One write for the whole order (assumed: the list names every rule but the Default rule, top first). |
| `ops_sanction.py:25` | What is verified and what is assumed |
| `ops_sanction.py:39` | ASSUMED (not stated by the SDK, not checked against a live tenant): |
| `ops_sanction.py:69` | _RAW_STATE_KEYS = ("sanctionedState", "sanctioned_state", "sanctionState")   # ASSUMED field names on the list's raw rows |
| `ops_sanction.py:105` | carries one (ASSUMED field names), else None.""" |
| `ops_url_category_admin.py:38` | ASSUMED (not checkable without a tenant): that a full update sent as read |
| `ops_url_category_admin.py:63` | "delete if one of them still uses the category (assumed).") |
| `ops_zcc.py:47` | payload through unchanged (a test checks it). Assumed, not verifiable without |
| `ops_zcc.py:48` | a tenant (see ASSUMED): that POST /webForwardingProfile/edit with id "-1" |
| `ops_zcc.py:103` | ASSUMED = [ |
| `ops_zcc.py:832` | "assumed": list(ASSUMED), |
| `ops_zcc.py:1322` | "confirm_phrase": f"CREATE {app_name.upper()}", "assumed": list(ASSUMED)} |
| `ops_zcc.py:1663` | """ZCC's HTTP 200 with success "false" (assumed), as a refusal.""" |
| `ops_zcc_admin.py:63` | ASSUMED (not in the SDK, or not checkable without a tenant; see ASSUMED): |
| `ops_zcc_admin.py:109` | ASSUMED = [ |
| `ops_zcc_admin.py:111` | "/custom-ip-based-apps/{id} through the SDK's request executor; assumed.", |
| `ops_zcc_admin.py:113` | "changed, to /updateZpaGroupEntitlement or /updateZdxGroupEntitlement; assumed.", |
| `ops_zcc_admin.py:114` | "An app profile bypasses a custom IP-based app by listing its id in bypassCustomAppIds; assumed (the field is in the SDK's model).", |
| `ops_zcc_admin.py:115` | "Remove marks a device Removal Pending until Client Connector checks in; Force remove drops it at once; the state words; assumed.", |
| `ops_zcc_admin.py:259` | The portal's username filter is assumed to match exactly; anything else it answers is not this user's. |
| `ops_zcc_admin.py:339` | "errors": errors, "assumed": list(ASSUMED), "limits": {"devices": MAX_DEVICES, "entries": MAX_ENTRIES}} |
| `ops_zcc_admin.py:466` | notes=["You type the confirmation whatever the count: a removal always asks for it.", ASSUMED[3]]) |
| `ops_zcc_admin.py:470` | """ZCC's answer to a removal: errorMsg, or devicesRemoved 0, is a refusal (assumed).""" |
| `ops_zcc_admin.py:824` | notes=["You type the confirmation naming the count whatever the count.", ASSUMED[3]]) |
| `ops_zcc_admin.py:1050` | reason="Creates it: POST /custom-ip-based-apps (assumed; not in the SDK).")) |
| `ops_zcc_admin.py:1076` | reason="Deletes it: DELETE /custom-ip-based-apps/{id} (assumed; not in the SDK).")) |
| `ops_zcc_admin.py:1092` | reason="Edits it: PUT /custom-ip-based-apps/{id} (assumed; not in the SDK).")) |
| `ops_zcc_admin.py:1104` | notes=[ASSUMED[0]] + ([ASSUMED[2]] if action == "delete" else []), **extra) |
| `ops_zcc_admin.py:1232` | reason="Updates it: PUT /" + SERVICES[service][4] + " (the entitlement as read, assumed body)." if want_all != cur["enable_for_all"] |
| `ops_zcc_admin.py:1267` | undo="Undo: puts 'on for every user' and the exact group list back as read, previewed first.", notes=[ASSUMED[1]], **extra) |
| `ops_zcc_live.py:36` | Assumed (ASSUMED): see the list below; every applied value is read back, |
| `ops_zcc_live.py:57` | ASSUMED = [ |
| `ops_zdx.py:49` | What is verified and what is assumed |
| `ops_zdx.py:64` | ASSUMED (not in the SDK, and not checked against a live tenant from here): |
| `ops_zdx.py:86` | "Custom Apps Collection" a new ZDX tenant lacks are assumed the same way. |
| `ops_zdx.py:102` | CONFIG = ZDX_BASE + "/config"      # ASSUMED: the /config part (no configuration service in the SDK) |
| `ops_zdx.py:105` | INTERVALS_MIN = (5, 10, 15, 30)    # ASSUMED: the probe intervals ZDX offers between 5 and 30 minutes |
| `ops_zdx.py:113` | NAME_MAX = 64                      # ASSUMED: ZDX app and probe names |
| `ops_zdx.py:166` | (assumed), and agencies add their own portals. |
| `ops_zdx.py:219` | "assumed from Zscaler's public descriptions, not verified against your tenant. Check the result in the ZDX portal.") |
| `ops_zdx.py:312` | """The ZDX configuration API (ASSUMED paths) on the signed-in client's |
| `ops_zdx.py:558` | "assumed": ASSUMED_NOTE}, |
| `ops_zdx.py:731` | Probe and app bodies (ASSUMED: the shape the ZDX portal stores) |
| `ops_zdx.py:842` | P.warnings.append("ZDX Lite has no configurable probes (assumed): nothing in this setup is created.") |
| `ops_zdx.py:866` | reason=f"left out: {why_ed} (assumed, from the licensed edition)") |
| `ops_zdx.py:922` | reason=f"left out: {why_ed} (assumed, from the licensed edition)") |
| `ops_zdx_trace.py:40` | users.list_users(query_params={"search": ...})         GET  /users (search sent as q: ASSUMED to filter) |
| `ops_zdx_trace.py:52` | ASSUMED: the status words of a trace (which mean running and which mean |
| `ops_zdx_trace.py:87` | ASSUMED = [ |
| `ops_zdx_trace.py:88` | "The trace's status words (running: in progress, started, pending; ended: completed, failed, expired, stopped) are assumed.", |
| `ops_zdx_trace.py:277` | body, err = _read(z.users.list_users, query_params={"search": term, "since": 24})   # ASSUMED: ZDX filters users by q |
| `ops_zdx_trace.py:282` | continue   # the filter is assumed; anything else the API answers is not shown |
| `ops_zdx_trace.py:388` | "assumed": list(ASSUMED), "errors": {"ZDX application scores": err} if err else {}} |
| `ops_zdx_trace.py:504` | undo="Undo: stops the trace (ZDX deletes what it collected), previewed first.", notes=list(ASSUMED)) |
| `ops_zia_activation.py:30` | ASSUMED (the SDK has no enumeration and this was not checked against a live |
| `ops_zia_activation.py:49` | assumed: ZIA's activation status values (the SDK's Activation model has no enumeration). |
| `ops_zia_activation.py:59` | "tool or this app): check with the other admins first (assumed: the SDK does not say whose changes it activates).") |
| `ops_zia_baseline.py:65` | read them; the others are assumed and the tenant refuses what it lacks. |
| `ops_zia_directory.py:42` | delete_department. ASSUMED (not checkable without a tenant): that ZIA |
| `ops_zia_objects.py:53` | NAME_MAX = 255           # assumed for these objects (the API refuses longer) |
| `ops_zia_pac.py:40` | pacFiles/{id}/version/{v}/action/DEPLOY), delete_pac_file. ASSUMED: that |
| `ops_zia_sandbox.py:21` | Assumed (not modelled by the SDK): the fileHashCount fields |
| `ops_zid.py:54` | [{service, scopes [{id, name}]}]). ASSUMED (not checkable without a tenant): |
| `ops_zid_groups.py:33` | Assumed (ASSUMED): the member list pages with offset / limit as the user |
| `ops_zid_groups.py:54` | ASSUMED = [ |
| `ops_zid_user.py:60` | from this build machine, so ASSUMED (not verified against a live tenant): |
| `ops_zid_user.py:105` | "ZIdentity API reference (Users → {what}); not verified against a live tenant from this build (assumed).") |
| `ops_zid_user.py:422` | assumed: POST /ziam/admin/api/v1/users/{id}:resetpassword (no body) and |
| `ops_zid_user.py:423` | assumed: POST /ziam/admin/api/v1/users/{id}:setskipmfa ({"timestamp": epoch seconds}), |
| `ops_zid_user.py:436` | """SkipMfaDto {timestamp} (ASSUMED: now, epoch seconds); no body for a reset.""" |
| `ops_zpa.py:58` | other. Assumed, not verifiable without a |
| `ops_zpa.py:166` | Host names and ports are templates to review with the agency (assumed: agencies name and port these systems their own way). |
| `ops_zpa.py:1191` | assumed: the SDK's add_access_rule (zscaler-sdk-python 1.11.3, zpa/policies.py) sends no "disabled" field, so the rule |
| `ops_zpa.py:1245` | plan.warnings.append("New rules are added at the end of each policy (assumed ZPA behaviour); a rule above them still decides first." |
| `ops_zpa.py:1253` | ACCESS_NAME_MAX = 64    # assumed: a name this short is accepted by ZPA (the builder's own names are of this size) |
| `ops_zpa.py:1294` | (it is always last and is not part of a reorder; assumed, as |
| `ops_zpa.py:1699` | One write for the whole order (assumed, as ops_rule_csv: the list names every rule but the Default rule, top first). |
| `ops_zpa_admin.py:87` | ASSUMED (not verifiable without a tenant; see ASSUMED below and every plan's |
| `ops_zpa_admin.py:138` | ASSUMED = [ |
| `ops_zpa_admin.py:139` | "Moving an App Connector sends PUT /connector/{id} with the target group's id (appConnectorGroupId); assumed, not in the SDK's docstring.… |
| `ops_zpa_admin.py:140` | "A group's PUT sends its members (connectors, Service Edges, trusted networks) back as read, so ZPA keeps them; assumed.", |
| `ops_zpa_admin.py:142` | "default is 66600, 18:30) is shown and put back as it is; assumed.", |
| `ops_zpa_admin.py:144` | "sends cert_blob; the SDK's example names pem); assumed.", |
| `ops_zpa_admin.py:145` | "Revoking a provisioning key stops new enrollments with it; what already enrolled keeps working; assumed.", |
| `ops_zpa_admin.py:433` | "errors": errors, "assumed": list(ASSUMED), "limits": {"targets": MAX_TARGETS, "delete": MAX_DELETE, "assign": MAX_ASSIGN}} |
| `ops_zpa_admin.py:609` | notes=[a for a in ASSUMED[:3]]) |
| `ops_zpa_admin.py:621` | body["app_connector_group_id"] = want["group_id"]   # ASSUMED: PUT /connector/{id} moves it |
| `ops_zpa_admin.py:643` | body["connectors"] = [{"id": i} for i in members]   # ASSUMED: sent back as read, so they stay |
| `ops_zpa_admin.py:759` | notes=["You type the confirmation whatever the count: a delete always asks for it."] + [ASSUMED[4]]) |
| `ops_zpa_admin.py:1133` | ASSUMED[3]]) |
| `ops_zpa_fields.py:34` | Assumed, not verifiable without a tenant (said in the preview's notes): |
| `ops_zpa_fields.py:75` | "icmp_access_type": ("ICMP access", ("NONE", "PING", "PING_TRACEROUTING")),   # values assumed (not in the SDK docstrings) |
| `ops_zpa_fields.py:84` | "they are listed for deletion: assumed). The read-back checks every one is still there.", |
| `ops_zpa_fields.py:85` | "Assumed ZPA rules, checked in the preview: a segment keeps at least one port range and one server group, the port of a " |
| `ops_zpa_fields.py:160` | Assumed: a segment shared from another microtenant is changed only there. |
| `ops_zpa_fields.py:343` | note = f"check first: ZPA may refuse double encryption on a {' / '.join(ref['kinds'])} segment (assumed)" |
| `ops_zpa_fields.py:367` | **({"status": "excluded", "reason": "a segment needs at least one server group, so the last one is not removed (assumed ZPA rule)"} |
| `ops_zpa_fields.py:397` | u.update(status="excluded", reason=f"the {uses[0]} needs this port in the segment's TCP ranges (assumed ZPA rule)") |
| `ops_zpa_fields.py:408` | "domain in two segments on overlapping ports (assumed ZPA rule)") |
| `ops_zpa_fields.py:419` | u.update(status="excluded", reason="a segment needs at least one port range, so the last one is not removed (assumed ZPA rule)") |
| `ops_zpa_fields.py:483` | run.mark(ok, "excluded", "a segment needs at least one server group (assumed ZPA rule)") |
| `ops_zpa_fields.py:486` | run.mark(ok, "excluded", "a segment needs at least one port range (assumed ZPA rule)") |
| `ops_zpa_fields.py:490` | Sent back as read (with their ids), so the replacing PUT cannot drop them (assumed safe; see the module docstring). |
| `ops_zwa.py:285` | "verified": list(zi.VERIFIED), "assumed": list(zi.ASSUMED)} |
| `other_products.py:9` | "assumed" where the recommendation is this app's own reading). |
| `other_products.py:65` | Assumed (not answerable from the SDK alone, marked in each finding): the |
| `other_products.py:87` | KEY_MAX_AGE_DAYS = 365   # assumed threshold: rotate ZTB API keys yearly |
| `other_products.py:88` | PROTECTED_MIN = 80.0     # assumed threshold: share of ZMS resources protected |
| `other_products.py:89` | IDLE_SIM_MAX = 20.0      # assumed threshold: share of inactive SIMs |
| `other_products.py:135` | "model of that row, and both its camelCase and snake_case spellings are read (assumed: the API sends one of them).", |
| `other_products.py:136` | "The Microsegmentation customer ID is assumed to be the ZPA customer ID when no other is given on this page.", |
| `other_products.py:137` | "ZTB site and alarm status words (for example 'online', 'acknowledged') are assumed from the SDK's field names; a status " |
| `other_products.py:562` | client), ZMS's as given, else the ZPA customer ID (assumed).""" |
| `other_products.py:832` | if n > 10:   # assumed: a 0-100 score |
| `other_products.py:865` | "Deploy the first site's gateway from the ZTB admin portal (Sites > Add site).", "Assumed: this app's reading of an empty site list.") |
| `other_products.py:871` | "Assumed: site status words from the SDK field site_status.") |
| `other_products.py:884` | "Assumed: configuration-baseline practice (CIS Control 4.1 secure configuration process).") |
| `other_products.py:895` | "Assumed: alarm severity and status words from the SDK fields severity and status.") |
| `other_products.py:898` | "Review and acknowledge the open alarms in the ZTB admin portal.", "Assumed: as above.") |
| `other_products.py:909` | f"NIST SP 800-57 Part 1 Rev. 5 (cryptoperiods); the {KEY_MAX_AGE_DAYS}-day threshold is assumed.") |
| `other_products.py:922` | "Assumed: state words from the SDK's RansomwareKillState.") |
| `other_products.py:924` | "", "Rehearse engaging the kill switch in the incident response plan.", "Assumed: incident-readiness practice (NIST SP 800-61r3).") |
| `other_products.py:930` | "Add the organization and its seed domains in the EASM admin portal.", "Assumed: this app's reading of an empty organization list.") |
| `other_products.py:958` | "CISA Known Exploited Vulnerabilities catalog; FIRST EPSS (likelihood 0.5 or more assumed as high).") |
| `other_products.py:979` | "SDK model CustomApp.signatures; the recommendation is assumed.") |
| `other_products.py:990` | "Assumed: this app's reading of an empty report schedule.") |
| `other_products.py:1001` | "Assumed: anomaly detection for cellular IoT (NIST IR 8259A device security capabilities).") |
| `other_products.py:1005` | "An alert with no recipient is never seen.", "Add the operations team as alert recipients.", "Assumed.") |
| `other_products.py:1020` | f"Assumed: asset-inventory practice (CIS Control 1); the {IDLE_SIM_MAX:.0f}% threshold is this app's.") |
| `other_products.py:1032` | "Assumed: from the SDK field CustomerDataHandling.zia.") |
| `other_products.py:1040` | "Install agents with a provisioning key on the servers to protect.", "Assumed.") |
| `other_products.py:1046` | "Assumed: connection status words from the SDK field connectionStatus.") |
| `other_products.py:1069` | "Assumed: patch management practice (CIS Control 7.4).") |
| `other_products.py:1080` | "Assumed: least-privilege enrolment (NIST SP 800-207 zero trust principle 6).") |
| `other_products.py:1103` | f"Assumed: {PROTECTED_MIN:.0f}% threshold is this app's.") |
| `pac_eval.py:730` | self.assumed: set = set() |
| `pac_eval.py:1091` | self.assumed.add(A_PUBLIC) |
| `pac_eval.py:1120` | CLIENT_CONNECTOR_LISTENER = ("127.0.0.1", "9000")   # Client Connector's local proxy (assumed, see module notes) |
| `pac_eval.py:1227` | "depends_on": depends, "assumptions": sorted(it.assumed), "trail": it.trail, "error": None, "steps": it.steps} |
| `pac_eval.py:1448` | + (" Assumed: " + "; ".join(ev["assumptions"]) + "." if ev["assumptions"] else "")} |
| `pack_channels.py:932` | READ_ONLY when the rule's rank is above the API client's (rank_inherit.caller, assumed). |
| `pack_deploy.py:759` | READ_ONLY when the rule's rank is above the API client's (rank_inherit.caller, assumed). |
| `pack_deploy.py:1531` | pl = {"rank": 0, "send": None, "order": asked, "asked_order": asked, "state": ri.state_of(setting), "assumed": False, "warning": "", |
| `pack_deploy.py:1716` | out["rank_plan"] = {k: rp.get(k) for k in ("rank", "order", "asked_order", "why", "warning", "assumed", "state")} |
| `pack_ops.py:958` | through the raw request (POST/DELETE /rootCertificates, an assumed path). |
| `panos_migrate.py:17` | carried as a silent drop: assumed closest match). |
| `panos_migrate.py:33` | where a mapping exists in APP_MAP (assumed enum names, checked against |
| `panos_migrate.py:82` | OBJECT_NAME_MAX = 63                 # assumed limit for IP group and network service names |
| `panos_migrate.py:89` | Assumed enum names (Zscaler's published network application list; the |
| `panos_migrate.py:106` | segment of a rule whose service is application-default (assumed: the |
| `path_analyzer.py:127` | assumed for traffic that is not web). A default port is left out.""" |
| `path_analyzer.py:383` | assumptions += path_manual.ASSUMED |
| `path_analyzer.py:401` | _IMPACT = ("bypass", "blocked", "blind", "warn", "assumed", "unknown") |
| `path_analyzer.py:459` | order = {"bypass": 0, "blocked": 1, "blind": 2, "warn": 3, "assumed": 4, "unknown": 5} |
| `path_device.py:24` | health values is assumed from their names (the SDK documents the fields, |
| `path_device.py:97` | number or text (assumed: 1/true/enabled is on).""" |
| `path_device.py:330` | f"the network it is on is not reported, so {net_label} (your choice) is assumed.") |
| `path_manual.py:37` | (zcc_bypass.ASSUMED). |
| `path_manual.py:73` | ASSUMED = [ |
| `path_manual.py:248` | "assumptions": list(ASSUMED), "given": counts(m), |
| `path_probe.py:226` | (...)" under organisation "Zscaler Inc." (assumed from Zscaler's help on |
| `permissions.py:52` | Governance and audit reads; the permission names are assumed (the SDK |
| `rank_inherit.py:31` | The API client's own admin rank (assumed: inferred, never read) |
| `rank_inherit.py:38` | is inferred from the rules read, and marked assumed: |
| `rank_inherit.py:41` | model of the SDK, e.g. models/ssl_inspection_rules.py) is assumed to be |
| `rank_inherit.py:59` | evaluates them by rank is assumed, not documented in a source here. |
| `rank_inherit.py:74` | "which rules ZIA lets it edit (assumed)") |
| `rank_inherit.py:103` | enableAdminRankAccess reads as false (the model's default; assumed).""" |
| `rank_inherit.py:190` | """What the rules say about the API client's own admin rank (assumed, |
| `rank_inherit.py:237` | {rank, order, asked_order, state, why, warning, assumed, neighbour}: |
| `rank_inherit.py:239` | rank is not known; `assumed` when the rank rests on an assumption.""" |
| `rank_inherit.py:242` | base = {"state": st, "asked_order": asked, "order": asked, "name": name, "warning": "", "assumed": False, "neighbour": None} |
| `rank_inherit.py:246` | return dict(base, rank=LEGACY_RANK, assumed=True, |
| `rank_inherit.py:264` | out.update(assumed=True, why=out["why"] + f" ({CALLER_NOT_READABLE}).", |
| `rank_inherit.py:265` | warning=f"'{name}': this API client's own admin rank could not be read, so rank {want} is assumed to be one it may " |
| `rank_inherit.py:273` | out.update(rank=got, order=send, assumed=True, |
| `rank_inherit.py:275` | f"assumed from what ZIA lets it edit), so it gets rank {got}.") |
| `rank_inherit.py:292` | """{rule id: {rank, before, why, warning, assumed}} for each moved rule |
| `rank_inherit.py:325` | out[rid] = {"rank": cur, "before": cur, "change": False, "assumed": True, |
| `rank_inherit.py:332` | out[rid] = {"rank": want, "before": cur, "change": True, "assumed": ok is None, |
| `rank_inherit.py:335` | "warning": (f"'{name_of(r)}': this API client's own admin rank could not be read, so rank {want} is assumed to be one it " |
| `rank_inherit.py:362` | "rules": [{k: p.get(k) for k in ("name", "policy", "rank", "order", "asked_order", "why", "warning", "assumed", "before")} |
| `readiness.py:43` | in zscaler-sdk-python 1.11.3. Assumed (not in the SDK): its row shape (the |
| `readiness.py:70` | SUBSCRIPTIONS_PATH = "/zia/api/v1/subscriptions"   # organization_information.get_subscriptions (SDK 1.11.3); the row shape is assumed |
| `readiness.py:74` | product codes the token's service-info claim uses for it (assumed). |
| `readiness.py:85` | The other products (other_products.py); token only, codes assumed like the rest. |
| `readiness.py:128` | ── Licences: subscription id -> (area, plain name). Ids as seen on tenants (assumed). ─ |
| `readiness.py:219` | ZPA object classes the ZPA builder creates (matched on the role's friendly names; assumed). |
| `readiness.py:240` | ZPA object classes this app reads or writes (matched on the role's friendly names; assumed). |
| `readiness.py:242` | Client Connector role fields this app reads (0 none, 1 view, 2 full; names assumed). |
| `remediation.py:364` | A free-text field with no max_length of its own is still capped (assumed: |
| `remediation.py:368` | GAMBLING or CUSTOM_01 (assumed: a little wider here, the tenant refuses the rest). |
| `remediation.py:546` | No PATCH: ZIA updates a rule with a PUT of the whole rule (assumed: |
| `rule_csv.py:35` | (assumed). |
| `rule_csv.py:50` | MAX_CELL = 10240             # characters in one cell (ZIA's description limit, assumed) |
| `rule_editor.py:34` | says, the value is marked assumed below and the tenant refuses what it |
| `rule_editor.py:52` | MAX_NAME = 31            # ZIA refuses rule names longer than 31 characters (ops_zia_baseline; assumed for forwarding and IPS) |
| `rule_editor.py:53` | MAX_NAME_DLP = 127       # Web DLP rules took longer names on a real tenant (pack_channels.RULE_NAME_MAX); 127 is assumed |
| `rule_editor.py:78` | "SSL_RULE", "FOHTTP_RULE", "WEBSOCKETSSL_RULE", "WEBSOCKET_RULE")                # assumed (Zscaler's protocol list) |
| `rule_editor.py:80` | FTC_PROTOCOLS = ("ANY_RULE", "FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE")             # assumed |
| `rule_editor.py:83` | DLP_PROTOCOLS = ("ANY_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE")                              # assumed |
| `rule_editor.py:84` | DNS_PROTOCOLS = ("ANY_RULE", "TCP_RULE", "UDP_RULE", "DOHTTPS_RULE")                             # assumed |
| `rule_editor.py:85` | SEVERITY = ("RULE_SEVERITY_HIGH", "RULE_SEVERITY_MEDIUM", "RULE_SEVERITY_LOW", "RULE_SEVERITY_INFO")  # assumed (the API's names) |
| `rule_editor.py:525` | out.append("ZIA shows a Caution page for downloads only: set Applies to Download, or pick Allow or Block.")   # assumed |
| `rule_editor.py:591` | body["type"] = "FORWARDING"   # forwarding_control_policy.ForwardingControlRule.type; FORWARDING is the rule kind ZIA lists (assumed) |
| `rule_fields.py:125` | timers) and metadata. restrictionType is taken as metadata (assumed: |
| `rule_migrator.py:1067` | ASSUMED (not verified against the SDK or Zscaler's documentation): the |
| `sample_tenant.py:366` | assumed: the API sends lastModifiedBy on every tunnel. The SDK model (zscaler/zia/models/gre_tunnels.py) |
| `sample_tenant.py:445` | WebPolicy model (assumed: the readers ask for it, and a device reports it). |
| `sample_tenant.py:487` | fetches; it starts "User","Device type"). The other column names are assumed from the Client Connector Portal's |
| `sample_tenant.py:719` | not in the SDK: its shapes are ops_zdx's (assumed there). |
| `sample_tenant.py:804` | SANDBOX_HASH_COUNT = {"blockedFileHashesCount": 2, "remainingFileHashes": 9998}   # field names assumed (not modelled by the SDK) |
| `sample_tenant.py:1048` | Each profile's App Connector version is in versionDetails (role ASSISTANT; assumed role name). |
| `sample_tenant.py:1403` | assumed: the newer API answers {"policies": [...], "totalCount": n}, the shape |
| `scope_permissions.py:100` | "Reports (System Audit Report; assumed name)", |
| `scope_permissions.py:101` | "Alerts (alert subscriptions; assumed name)", |
| `scope_permissions.py:103` | "Organization (subscriptions; assumed name)", |
| `scope_permissions.py:385` | "Remote Assistance (assumed name)", |
| `scope_permissions.py:451` | "/zia/api/v1/proxies", "/zia/api/v1/proxyGateways", "/zia/api/v1/rootCertificates (assumed path)", "/zia/api/v1/forwardingRules", |
| `scope_permissions.py:538` | "customer_id_note": "The Microsegmentation customer ID; the ZPA customer ID is used when none is given (assumed).", |
| `shadow_rules.py:185` | set (time windows: a window list is not assumed to be a union). |
| `shadow_rules.py:363` | assumed, so only the same engines count as the same content.""" |
| `shadow_rules.py:609` | one names (rules are assumed to be first match per application and |
| `shadow_rules.py:926` | "The Inline Web DLP evaluation mode could not be read, so rule order (the default) is assumed; if the tenant runs Evaluate All " |
| `siem_queries.py:17` | patterns are assumed placeholders the admin replaces. |
| `static/aiguard_page.js:75` | <div class="df-hint">LLM providers AI Guard knows: ${E((d.providers \|\| []).join(', ') \|\| 'none')}. The owners of the applications are cou… |
| `static/compliance_choice.js:67` | <div class="df-hint">${E(s.reuses)}${s.assumed_profile ? ` Assumed: ${E(s.assumed_profile)}` : ''}</div> |
| `static/compliance_choice.js:69` | ${(s.assumed_controls \|\| []).length ? `<div class="df-hint">Controls marked assumed (not verified against the source): ${E(s.assumed_cont… |
| `static/data_flow.js:17` | assumed: ['Assumed tunnel', 'dim'], na: ['Not evaluated', 'dim'], step: ['Step', 'ok'], |
| `static/explain.js:121` | get: 'Findings per policy type with a severity, the rule and the rule that hides it, the reason in one sentence and the fix, a count per … |
| `static/explain.js:145` | get: 'For each product: what it is in plain words, what the tenant has in tables, best-practice checks with why each matters, what to do … |
| `static/flow_anim.js:41` | none: 'no rule', unknown: 'unknown', out_of_scope: 'not in scope', assumed: 'assumed', skipped: 'skipped', |
| `static/flow_anim.js:49` | if (status === 'warn' \|\| status === 'blind' \|\| status === 'monitor' \|\| status === 'assumed' \|\| status === 'unknown') return 'warn'; |
| `static/flow_anim.js:200` | note: [zh && zh.detail, fh && fh.detail].filter(Boolean).join(' ') \|\| (vv === 'out_of_scope' ? 'Client Connector is not in scope on the S… |
| `static/help_catalog.js:4725` | "input": "Pick a group of type IP, or A new group. The count shows how full it is (at most 8,000 entries, assumed).", |
| `static/help_catalog.js:4805` | "input": "Pick one. The count shows how full it is (at most 8,000 entries, assumed).", |
| `static/ops_admin.js:38` | const assumed = res => (res.assumed \|\| []).length ? `<details class="pa-details"><summary>What is assumed</summary><ul>${res.assumed.map(… |
| `static/ops_admin.js:79` | ${assumed(res)}`; |
| `static/ops_aiguard.js:41` | return `<details class="pa-details"><summary>What the app assumes (${(cat.assumed \|\| []).length})</summary><ul>${(cat.assumed \|\| []).map(… |
| `static/ops_aiguard.js:55` | const st = F.aiguard_routing, cat = res.catalog \|\| { apps: [], assumed: [] }, rd = res.readiness \|\| {}; |
| `static/ops_aiguard.js:116` | const st = F.aiguard_detection_policy, cat = res.catalog \|\| { apps: [], profiles: [], assumed: [] }, rd = res.readiness \|\| {}; |
| `static/ops_list_fix.js:263` | <p>Add or remove entries on one IP destination group, or make a new one. A group holds IPv4 addresses, CIDR blocks and ranges (type IP) o… |
| `static/ops_zdx.js:44` | const note = (H, res) => `<div class="df-hint">${H.E(data(res).assumed \|\| '')}</div>`; |
| `static/ops_zia_baseline.js:171` | <div class="df-hint">${E(cps.reuses)}${cps.assumed_profile ? ` Assumed: ${E(cps.assumed_profile)}` : ''}</div> |
| `static/ops_zia_baseline.js:173` | ${(cps.assumed_controls \|\| []).length ? `<div class="df-hint">Controls marked assumed (not verified against the source): ${E(cps.assumed_… |
| `static/path_motion.js:261` | extra.assumed = ['r_web>evid']; |
| `static/path_motion.js:396` | <div class="pm-legend" aria-hidden="true"><span><i class="lane-main"></i>content and verdict</span><span><i class="lane-ev"></i>evidence … |
| `static/path_motion.js:430` | el.setAttribute('class', `pm-bit lane-${r.lane}${r.tone === 'assumed' ? ' assumed' : ''}`); |
| `static/path_motion.js:454` | if (b.lane !== lane) { b.lane = lane; b.el.setAttribute('class', `pm-bit lane-${lane}${r.tone === 'assumed' ? ' assumed' : ''}`); } |
| `static/path_motion.js:480` | p.classList.toggle('is-assumed', !!(m.extra.assumed \|\| []).includes(k)); |
| `tenant_health.py:43` | Assumed (not stated by the SDK): the activation status words (ACTIVE, |
| `tenant_health.py:198` | activation status (GET /status). The words are assumed: ACTIVE, |
| `tenant_health.py:368` | object with a name, the SDK's service edge shape, or the name itself: assumed).""" |
| `tenant_terraform.py:98` | Assumed, not verifiable without a tenant: |
| `tenant_terraform.py:104` | posture profile's platform as 1..5). The posture list is NOT assumed |
| `tenant_terraform.py:463` | descriptions). assumed: answered in one GET (no paging), as a JSON array or |
| `tenant_terraform.py:464` | an envelope holding one. Not assumed complete for ZIA posture profiles: see |
| `tenant_terraform.py:1199` | address), any other into `entry_values` {lhs, rhs} (assumed mapping, |
| `traffic_logs.py:18` | in the default order (assumed, see DEFAULT_ORDERS). |
| `traffic_logs.py:91` | Zscaler's LSS documentation; the ones marked are assumed from field |
| `traffic_logs.py:98` | "zpn_client_type_browser_isolation": "Cloud Browser Isolation",   # assumed |
| `traffic_logs.py:103` | "zpn_client_type_vdi": "VDI",   # assumed |
| `traffic_logs.py:112` | published list of ZPA connection status and internal reasons (assumed: the |
| `traffic_logs.py:411` | Assumed: these orders are from Zscaler's NSS feed output format pages as |
| `tui.py:425` | out.append(clean(f"Assumed: {a}")) |
| `tui.py:481` | out.append(clean(f"Assumed: {a}")) |
| `ucaas_oneclick.py:18` | The predefined rules (as ZIA shows them; names and fields assumed from |
| `ucaas_oneclick.py:27` | provider it names, ZIA does not apply it (assumed: the switch turns the |
| `ucaas_oneclick.py:48` | predefined one-click rule uses for it: names assumed, compared without |
| `ucaas_oneclick.py:136` | "detail": f"The one-click configuration is off for {', '.join(LABEL[k] for k in keys)}, so ZIA does not apply this predefined rule (assum… |
| `url_tools.py:37` | 200 requests, under the assumed 400 an hour) with a visible note. |
| `url_tools.py:82` | HOURLY_REQUESTS = 400       # assumed: ZIA's documented POST limit (1/s, 400/h; zia_rate) applies to /urlLookup |
| `url_tools.py:546` | xn--bcher-kva.de (how the lookup spells it is assumed, not documented).""" |
| `vendor_endpoints.py:13` | The providers (PROVIDERS; the group names are ASSUMED: they are the names |
| `vendor_endpoints.py:17` | per line. Fetchable (FETCH_URL, ASSUMED: the address named in |
| `vendor_endpoints.py:23` | as a machine-readable file (ASSUMED from the article as last |
| `vendor_endpoints.py:26` | goto         machine-readable list known, ASSUMED), GoTo's (a support web |
| `workload_path.py:29` | Assumed, not documented in the SDK (said on the page): |
| `workload_path.py:89` | know (INVALID, or a newer value) is "unknown", never assumed to be ZIA.""" |
| `workload_path.py:434` | groups (assumed from the field's name; the SDK documents no more). |
| `workload_path.py:476` | application, which an earlier ZPA rule forwards (assumed). |
| `workload_path.py:593` | note = "No forwarding rule matches, so the connector forwards the traffic to ZIA (assumed default)." |
| `zcc_bypass.py:46` | ASSUMED lists what the SDK does not say. |
| `zcc_bypass.py:58` | ASSUMED = [ |
| `zcc_bypass.py:80` | Which definitions an id list names first (ASSUMED above). |
| `zcc_bypass.py:339` | note = f" {len(named)} gateway(s) are host names ({_zpm._short(named, 3)}); the address is assumed not to be theirs." |
| `zcc_bypass.py:378` | "not resolved and is assumed to resolve outside them.") |
| `zcc_bypass.py:385` | notes.append(why + "; they are assumed not to name this host.") |
| `zcc_bypass.py:455` | "Only private ranges are excluded; a public host is assumed to resolve outside them." if ex else "None configured."))) |
| `zcc_devices.py:29` | Assumed: the CSV's columns are named as Client Connector's export names them |
| `zcc_devices.py:40` | ASSUMED = [ |
| `zcc_fleet.py:332` | Version, Last Seen Connected to ZIA, Tunnel Version) are assumed from |
| `zcc_fleet.py:376` | (assumed from the portal's Service Status export, which has |
| `zcc_fleet.py:590` | ("Last Seen Connected to ZIA", assumed from the portal's export) for the same device. |
| `zcc_fleet.py:597` | A "<service> Enabled" column saying no: the service is not turned on for this device (assumed portal |
| `zcc_fleet_import.py:27` | the names this reads are assumed from the portal's exports and matched |
| `zdx_insights.py:22` | published; these are assumed safe). `analysis_status` reads it back and |
| `zdx_insights.py:36` | Assumed (see ASSUMED): the start answer carries the analysis id as `id` |
| `zdx_insights.py:48` | ASSUMED = [ |
| `zia_forwarding.py:42` | 1.11.3. Assumed (not in the SDK): the forwarding rule `type` values that |
| `zia_forwarding.py:63` | ZIA_TYPE = "FORWARDING"            # a ZIA forwarding rule; other types are connector rules (assumed) |
| `zia_forwarding.py:130` | type is a Cloud or Branch Connector rule (assumed type values).""" |
| `zia_forwarding.py:240` | return t / 1000.0 if t > 1e12 else t   # milliseconds accepted (assumed: seconds) |
| `zia_path_modules.py:327` | Returns {protocol, port, service, label, web, encrypted, assumed, |
| `zia_path_modules.py:340` | assumed = False |
| `zia_path_modules.py:350` | n, assumed = 443, True |
| `zia_path_modules.py:351` | notes.append("No port was given, so port 443 is assumed; choose a port to trace other traffic." if given_protocol else |
| `zia_path_modules.py:352` | "No protocol or port was given, so HTTPS (TCP/443) is assumed; choose a protocol and port to trace other traffic.") |
| `zia_path_modules.py:361` | "label": label, "web": web, "encrypted": n in (443, 8443) if web else None, "assumed": assumed, "notes": notes} |
| `zia_path_modules.py:634` | which of them ZIA records for HTTPS it does not decrypt is assumed).""" |
| `zia_path_modules.py:1063` | acts on is this tool's mapping (assumed, see the report). |
| `zia_path_modules.py:1157` | Allow lists first, then deny lists and toggles (assumed precedence). |
| `zia_path_modules.py:1257` | out.append(_crit("DNS protocol", "match", "A lookup over UDP is assumed (the standard resolver path).") if {"UDP", "UDP_RULE"} & set(p) e… |
| `zia_path_modules.py:1262` | f"An address lookup (A or AAAA) is assumed; the rule applies to {_short(types, 5)}.")) |
| `zpa_analysis.py:16` | ZPA semantics assumed (stated here and in every diagnosis): |
| `zpa_analysis.py:1030` | or a domain says what it holds (assumed vocabulary, English names). |
| `zpa_analysis.py:1456` | "An inspection profile whose every control action is PASS only monitors (it logs and lets the request through); global actions are read a… |
| `zpa_analysis.py:1457` | "A segment is treated as sensitive when it is a Privileged Remote Access segment, serves directory, database or remote admin ports, or it… |
| `zpa_analysis.py:1656` | not met (assumed from ZPA's per-IdP identity model: the SDK models carry |
| `zpa_analysis.py:1856` | assumptions.insert(0, f"No port was given, so port {d['port']} was assumed.") |
| `zpa_identity.py:62` | user filter was not applied (assumed: a real user name never has this |
| `zpa_path.py:65` | "When no Client Forwarding Policy rule matches, Client Connector intercepts the traffic for ZPA (assumed: the SDK does not document the d… |
| `zpa_path.py:130` | are Client Connector facts it never presents (assumed). |
| `zpa_path.py:275` | seg_notes.append(f"No port was given, so port {d['port']} was assumed.") |
| `zpa_path.py:337` | fv, fnote = "unknown", "The Client Forwarding Policy could not be read; intercept is assumed." |
| `zpa_path.py:341` | else "No rule matches, so Client Connector intercepts it for ZPA (the assumed default).") |
| `zpa_reader.py:460` | assumed from the values ZPA shows, the SDK types them only as strings). |
| `zpa_reader.py:621` | A ZPA provisioning key's shape: "<n>\|<cloud host>\|<key>" (assumed from the |
| `zscaler_full_checks.py:73` | Firewall filtering actions: ALLOW, BLOCK_DROP, BLOCK_RESET, BLOCK_ICMP, EVAL_NWAPP (ZIA API reference; assumed, the SDK does not list the… |
| `zscaler_full_checks.py:452` | _LOG_SKUS = ("Z_LOGFEED", "Z_CLOUD_NSS_WEB")   # SKU ids as readiness.SKU_INFO names them (assumed: the SDK lists no SKU names) |
| `zscaler_full_checks.py:470` | the body is assumed to be a list of {id, status, subscribed, ...} (the |
| `zscaler_full_checks.py:496` | Grades are assumed to be letters (A best … F worst) or words (GOOD, POOR): |
| `zscaler_full_checks.py:515` | """'good', 'bad' or None (not graded / not understood) for one audit grade (assumed scale).""" |
| `zscaler_full_checks.py:519` | return "good" if v >= 80 else "bad"   # assumed: a 0-100 score |
| `zscaler_full_checks.py:649` | or IN_TRIAL (nss_servers.add_nss_server docstring); state is assumed to be |
| `zscaler_full_checks.py:1803` | not model is marked "assumed". A 404 answer means the feature is not |
| `zscaler_full_checks.py:1856` | not modelled by the SDK (assumed: blockedFileHashesCount, remainingFileHashes). |
| `zscaler_full_checks.py:1953` | field names follow the attributes its update docstring lists (assumed). |
| `zscaler_full_checks.py:1976` | alertDefinitions (status; its values are not enumerated: "ENABLED" assumed). |
| `zscaler_full_checks.py:2118` | is listed by the SDK's update docstring but not modelled (assumed). |
| `zscaler_full_checks.py:2170` | Only OFLCASB_AVP_REPORT_MALWARE is named by the SDK; any action with QUARANTINE in it is assumed to quarantine. |
| `zscaler_full_checks.py:2289` | _INS_APP_LIMIT = 500           # applications asked per check (assumed accepted by Z-Insights; the SDK states no maximum) |
| `zscaler_full_checks.py:2290` | _INS_HIGH_RISK = 4             # risk index 1 (low) to 5 (high): 4 and 5 are high (SDK zia/shadow_it_report.py lists 1-5; the direction i… |
| `zscaler_full_checks.py:2293` | _CASB_SKUS = ("Z_CASB", "Z_CASB_BASIC")   # readiness.SKU_INFO (subscription ids assumed as seen on tenants) |
| `zscaler_full_checks.py:2295` | values a tenant of that app carries. ASSUMED: the SDK lists neither side's values. |
| `zscaler_full_checks.py:3165` | GET /config/isZiaCloudConfigAvailable. Assumed: that this availability |
| `zscaler_full_checks.py:3228` | GET /visible/versionProfiles). Assumed: "Previous Default" is the profile that holds |
| `zscaler_full_checks.py:3236` | profile itself has no version field). Assumed: App Connectors carry a role |
| `zscaler_full_checks.py:3311` | as metadata only). Assumed: the API states no expiry, so "expired" is |
| `zscaler_full_checks.py:3335` | Traffic capture actions that capture nothing (assumed: the SDK names no values; |
| `zscaler_full_checks.py:3408` | aup, enabled; SDK model). Assumed: the AUP is tenant-wide (the model |
| `zscaler_full_checks.py:3480` | (DnsApplicationGroups: name, dnsApplications). Assumed: a DNS Control |
| `zscaler_full_checks.py:3521` | do not do what their names say. Assumed: an empty expression selects no |
| `zscaler_full_checks.py:3557` | no criteria or no header inserts nothing. Assumed: profileReadyForUse |
| `zscaler_full_checks.py:3591` | C2C_FULL = 0.9   # assumed: a client-to-client range 90 % used asks for review |
| `zscaler_full_checks.py:3599` | totalIps, usedIps, availableIps). Assumed: a range with no address left |
| `zscaler_full_checks.py:3630` | CERT_SOON_DAYS = 30            # assumed review window before an isolation certificate expires |
| `zscaler_full_checks.py:3666` | a result. Assumed: isolation uses the certificate to trust the sites it |
| `zscaler_genai_checks.py:624` | Provider credential age (assumed thresholds: a key older than a year with no |
| `zscaler_ip_ranges.py:45` | the field names are ASSUMED: not reachable from here to |
| `zscaler_ip_ranges.py:50` | JSON paths and key ASSUMED); |
| `zscaler_ip_ranges.py:52` | centres not yet live (ASSUMED); |
| `zscaler_ip_ranges.py:54` | tunnel (Tunnel 2.0) addresses (ASSUMED); |
| `zscaler_ip_ranges.py:57` | zpatwo.net or zpabeta.net (ASSUMED: also an optional |
| `zscaler_ip_ranges.py:826` | Dynamic List": ASSUMED, not verifiable here). |
| `zscaler_rbac_checks.py:141` | "until" values are epoch times (seconds, or milliseconds; assumed).""" |
| `zscaler_rbac_checks.py:374` | classes when listed; else from its name (assumed: Zscaler's built-in |
| `zscaler_rbac_checks.py:395` | the API sends it (assumed: {"id", "name"}) and an API key's `roleId`.""" |
| `zscaler_rbac_checks.py:450` | The SDK documents the key as "ssologinonly"; other spellings are read too (assumed). |
| `zscaler_rbac_checks.py:531` | userStatus values are not enumerated by the SDK (assumed: ACTIVE when usable). |
| `zscaler_rbac_checks.py:558` | API filtered them itself (assumed: each admin row carries microtenantId). |
| `zscaler_rbac_checks.py:616` | lastCredentialResetTime (models/pra_credential.py), assumed epoch seconds. |
| `zscaler_zdx_checks.py:165` | AVAILABILITY_MIN = 99.0    # assumed target: an app available less than 99% of the week needs a look |
| `zscaler_zdx_checks.py:166` | PFT_MAX_MS = 5000.0        # assumed target: a page fetch time above 5 s is slow for users |
| `zscaler_zdx_checks.py:192` | ZDX marks an hour with no data as -1 (assumed); it is not a score. |
| `zscaler_zidentity_checks.py:91` | no last sign-in time; the time fields read below are assumed and used only |
| `zscaler_zidentity_checks.py:98` | _LAST_SIGN_IN = ("lastLoginTime", "lastLogin", "lastSignInTime", "last_login_time")   # assumed field names |
| `ztw_overview.py:42` | Assumed, not documented in the SDK (said on the page): |
| `ztw_overview.py:357` | """('pending' \| 'done' \| 'unknown', words) from the activation status (assumed values).""" |
| `zwa_incidents.py:22` | assumed is listed in VERIFIED and ASSUMED; the page shows the assumptions. |
| `zwa_incidents.py:45` | ASSUMED = ( |
| `zwa_incidents.py:284` | "withheld": list(WITHHELD), "verified": list(VERIFIED), "assumed": list(ASSUMED)} |
| `zwa_incidents.py:368` | "verified": list(VERIFIED), "assumed": list(ASSUMED)} |
