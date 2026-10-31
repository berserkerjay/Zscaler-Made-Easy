"""The provider attributes a whole-tenant Terraform export writes, per
resource type, in a compact form tenant_terraform.parse_schema reads.

Each entry is the provider's resource name and its configurable arguments
(computed-only attributes left out), written as `name:kind` tokens:

  s / n / f / b      a string, whole number, decimal number or true/false
  ls / ln            a list (or set) of strings / of whole numbers
  ids                a block holding the referenced objects' numeric ids:
                     `locations { id = [1, 2] }` (ZIA, Cloud & Branch Connector)
  sids               the same with string ids: `server_groups { id = ["1"] }` (ZPA)
  idb / sidb         one block per referenced object: `auditor { id = 1 }`
  extid              one block per ZPA segment: `{ external_id = "..", name = ".." }`
  secret             a value the export never writes: it becomes a sensitive variable
  blk(...)           nested blocks (one per element), with their own tokens

A trailing `!` marks an argument the provider requires.

Source: the configurable arguments of the official providers' published
resource schemas, zscaler/zia 4.8.17 (2026-10-30), zscaler/zpa 4.4.16
(2026-10-26), zscaler/ztc 0.2.0 (2026-06-29) and zscaler/zcc 0.1.2
(2026-08-13), read from each provider's Go schema definitions. Some arguments were left out on purpose:
  - Client Connector forwarding profiles: `trusted_networks` (names) and
    `trusted_network_ids_selected`: the profile names its trusted networks by
    id (`trusted_network_ids`), and the provider keeps the names in step;
  - ZPA application segments: `tcp_port_range` / `udp_port_range` blocks
    (the export writes the equivalent `tcp_port_ranges` / `udp_port_ranges`
    lists; the provider accepts one form at a time);
  - ZPA segment and server groups: `applications` (the segment names its
    groups; writing both directions would make a dependency cycle);
  - ZPA provisioning keys: the key itself (computed by ZPA, a secret);
  - ZIA locations: the VPN credentials' pre-shared keys (a location names its
    credentials by id), `parent_id` (sub-locations are not exported) and
    `dynamic_location_groups` (membership the tenant computes from criteria).
Terraform validates the workspace against the provider it installs, so a
drift between these tokens and a newer provider shows at `terraform
validate`, never as a silent change.
"""
from __future__ import annotations

from typing import Dict

SCHEMAS: Dict[str, str] = {
    "zia_advanced_settings": (
        "auth_bypass_apps:ls auth_bypass_urls:ls basic_bypass_apps:ls digest_auth_bypass_apps:ls "
        "dns_resolution_on_transparent_proxy_exempt_apps:ls dns_resolution_on_transparent_proxy_ipv6_exempt_apps:ls "
        "dns_resolution_on_transparent_proxy_apps:ls dns_resolution_on_transparent_proxy_ipv6_apps:ls "
        "block_domain_fronting_apps:ls prefer_sni_over_conn_host_apps:ls "
        "dns_resolution_on_transparent_proxy_exempt_url_categories:ls "
        "dns_resolution_on_transparent_proxy_ipv6_exempt_url_categories:ls "
        "dns_resolution_on_transparent_proxy_url_categories:ls "
        "dns_resolution_on_transparent_proxy_ipv6_url_categories:ls auth_bypass_url_categories:ls "
        "domain_fronting_bypass_url_categories:ls kerberos_bypass_url_categories:ls basic_bypass_url_categories:ls "
        "http_range_header_remove_url_categories:ls digest_auth_bypass_url_categories:ls "
        "sni_dns_optimization_bypass_url_categories:ls kerberos_bypass_urls:ls kerberos_bypass_apps:ls "
        "digest_auth_bypass_urls:ls dns_resolution_on_transparent_proxy_exempt_urls:ls "
        "dns_resolution_on_transparent_proxy_urls:ls enable_dns_resolution_on_transparent_proxy:b "
        "enable_ipv6_dns_resolution_on_transparent_proxy:b enable_ipv6_dns_optimization_on_all_transparent_proxy:b "
        "enable_evaluate_policy_on_global_ssl_bypass:b enable_office365:b log_internal_ip:b "
        "enforce_surrogate_ip_for_windows_app:b track_http_tunnel_on_http_ports:b block_http_tunnel_on_non_http_ports:b "
        "block_domain_fronting_on_host_header:b zscaler_client_connector_1_and_pac_road_warrior_in_firewall:b "
        "cascade_url_filtering:b enable_policy_for_unauthenticated_traffic:b "
        "block_non_compliant_http_request_on_http_ports:b enable_admin_rank_access:b http2_nonbrowser_traffic_enabled:b "
        "ecs_for_all_enabled:b dynamic_user_risk_enabled:b block_connect_host_sni_mismatch:b "
        "prefer_sni_over_conn_host:b sipa_xff_header_enabled:b block_non_http_on_http_port_enabled:b "
        "ui_session_timeout:n api_session_timeout:n ecs_object:blk(id:s name:s external_id:s)"
    ),
    "zia_advanced_threat_settings": (
        "risk_tolerance:n risk_tolerance_capture:b cmd_ctl_server_blocked:b cmd_ctl_server_capture:b "
        "cmd_ctl_traffic_blocked:b cmd_ctl_traffic_capture:b malware_sites_blocked:b malware_sites_capture:b "
        "activex_blocked:b activex_capture:b browser_exploits_blocked:b browser_exploits_capture:b "
        "file_format_vunerabilites_blocked:b file_format_vunerabilites_capture:b known_phishing_sites_blocked:b "
        "known_phishing_sites_capture:b suspected_phishing_sites_blocked:b suspected_phishing_sites_capture:b "
        "suspect_adware_spyware_sites_blocked:b suspect_adware_spyware_sites_capture:b web_spam_blocked:b "
        "web_spam_capture:b irc_tunnelling_blocked:b irc_tunnelling_capture:b anonymizer_blocked:b anonymizer_capture:b "
        "cookie_stealing_blocked:b cookie_stealing_pcap_enabled:b potential_malicious_requests_blocked:b "
        "potential_malicious_requests_capture:b blocked_countries:ls block_countries_capture:b bit_torrent_blocked:b "
        "bit_torrent_capture:b tor_blocked:b tor_capture:b google_talk_blocked:b google_talk_capture:b "
        "ssh_tunnelling_blocked:b ssh_tunnelling_capture:b crypto_mining_blocked:b crypto_mining_capture:b "
        "ad_spyware_sites_blocked:b ad_spyware_sites_capture:b dga_domains_blocked:b "
        "alert_for_unknown_suspicious_c2_traffic:b dga_domains_capture:b malicious_urls_capture:b"
    ),
    "zia_atp_malicious_urls": "malicious_urls:ls",
    "zia_atp_malware_inspection": "inspect_inbound:b inspect_outbound:b",
    "zia_atp_malware_policy": "block_unscannable_files:b block_password_protected_archive_files:b",
    "zia_atp_malware_protocols": "inspect_http:b inspect_ftp_over_http:b inspect_ftp:b",
    "zia_atp_malware_settings": (
        "virus_blocked:b virus_capture:b unwanted_applications_blocked:b unwanted_applications_capture:b "
        "trojan_blocked:b trojan_capture:b worm_blocked:b worm_capture:b adware_blocked:b adware_capture:b "
        "spyware_blocked:b spyware_capture:b ransomware_blocked:b ransomware_capture:b remote_access_tool_blocked:b "
        "remote_access_tool_capture:b"
    ),
    "zia_atp_security_exceptions": "bypass_urls:ls",
    "zia_auth_settings_urls": "urls:ls",
    "zia_cloud_app_control_rule": (
        "name:s description:s order:n! state:s rank:n actions:ls applications:ls time_quota:n size_quota:n "
        "enforce_time_validity:b validity_start_time:s validity_end_time:s validity_time_zone_id:s cascading_enabled:b "
        "eun_enabled:b prompt_capture_enabled:b eun_template_id:n browser_eun_template_id:n cbi_profile:blk(id:s name:s "
        "url:s) device_groups:ids devices:ids time_windows:ids labels:ids locations:ids location_groups:ids groups:ids "
        "departments:ids users:ids tenancy_profile_ids:ids cloud_app_instances:ids cloud_app_risk_profile:idb "
        "device_trust_levels:ls user_risk_score_levels:ls user_agent_types:ls type:s"
    ),
    "zia_dlp_dictionaries": (
        "name:s description:s custom:b confidence_level_for_predefined_dict:s confidence_threshold:s "
        "phrases:blk(action:s phrase:s) custom_phrase_match_type:s patterns:blk(action:s pattern:s) dictionary_type:s "
        "hierarchical_identifiers:ls exact_data_match_details:blk(dictionary_edm_mapping_id:n schema_id:n "
        "primary_fields:ln secondary_fields:ln secondary_field_match_on:s) "
        "idm_profile_match_accuracy:blk(adp_idm_profile:blk(id:n) match_accuracy:s) proximity:n "
        "proximity_enabled_for_custom_dictionary:b ignore_exact_match_idm_dict:b include_bin_numbers:b bin_numbers:ln "
        "dict_template_id:n"
    ),
    "zia_dlp_engines": "name:s! description:s engine_expression:s custom_dlp_engine:b",
    "zia_dlp_notification_templates": "name:s! subject:s! attach_content:b plain_text_message:s! html_message:s! tls_enabled:b",
    "zia_dlp_web_rules": (
        "name:s! description:s protocols:ls rank:n order:n! severity:s parent_rule:n sub_rules:ls "
        "user_risk_score_levels:ls cloud_applications:ls file_types:ls min_size:n action:s state:s "
        "external_auditor_email:s match_only:b inspect_http_get_enabled:b without_content_inspection:b "
        "dlp_download_scan_enabled:b zcc_notifications_enabled:b eun_template_id:n zscaler_incident_receiver:b "
        "locations:ids location_groups:ids users:ids groups:ids departments:ids excluded_departments:ids "
        "excluded_users:ids excluded_groups:ids included_domain_profiles:ids excluded_domain_profiles:ids "
        "workload_groups:idb dlp_engines:ids time_windows:ids labels:ids source_ip_groups:ids url_categories:ids "
        "auditor:idb notification_template:idb icap_server:idb receiver:blk(id:s! name:s type:s tenant:blk(id:s "
        "name:s))"
    ),
    "zia_end_user_notification": (
        "aup_frequency:s aup_custom_frequency:n aup_day_offset:n aup_message:s notification_type:s display_reason:b "
        "display_company_name:b display_company_logo:b custom_text:s url_cat_review_enabled:b "
        "url_cat_review_submit_to_security_cloud:b url_cat_review_custom_location:s url_cat_review_text:s "
        "security_review_enabled:b security_review_submit_to_security_cloud:b security_review_custom_location:s "
        "security_review_text:s web_dlp_review_enabled:b web_dlp_review_submit_to_security_cloud:b "
        "web_dlp_review_custom_location:s web_dlp_review_text:s redirect_url:s support_email:s support_phone:s "
        "org_policy_link:s caution_again_after:n caution_per_domain:b caution_custom_text:s "
        "idp_proxy_notification_text:s quarantine_custom_notification_text:s"
    ),
    "zia_file_type_control_rules": (
        "name:s! description:s state:s rank:n order:n! filtering_action:s operation:s min_size:n max_size:n "
        "capture_pcap:b active_content:b unscannable:b browser_eun_template_id:n cloud_applications:ls "
        "url_categories:ls file_types:ls device_groups:ids devices:ids locations:ids location_groups:ids "
        "departments:ids groups:ids users:ids time_windows:ids labels:ids zpa_app_segments:extid device_trust_levels:ls "
        "protocols:ls!"
    ),
    "zia_firewall_dns_rule": (
        "name:s! description:s order:n! rank:n action:s state:s redirect_ip:s block_response_code:s res_categories:ls "
        "src_ips:ls dest_addresses:ls dest_ip_categories:ls capture_pcap:b is_web_eun_enabled:b is_eun_enabled:b "
        "eun_template_id:n exclude_context_shield_end_point:b applications:ls locations:ids location_groups:ids "
        "users:ids groups:ids departments:ids time_windows:ids labels:ids device_groups:ids devices:ids "
        "src_ip_groups:ids src_ipv6_groups:ids dest_ip_groups:ids dest_ipv6_groups:ids application_groups:ids "
        "dns_gateway:idb zpa_ip_group:idb edns_ecs_object:idb dest_countries:ls source_countries:ls "
        "dns_rule_request_types:ls protocols:ls"
    ),
    "zia_firewall_filtering_destination_groups": "name:s! description:s type:s addresses:ls ip_categories:ls countries:ls",
    "zia_firewall_filtering_ip_source_groups": "name:s! description:s ip_addresses:ls!",
    "zia_firewall_filtering_network_application_groups": "name:s! description:s network_applications:ls",
    "zia_firewall_filtering_network_service": (
        "name:s! description:s tag:s src_tcp_ports:blk(start:n end:n) dest_tcp_ports:blk(start:n end:n) "
        "src_udp_ports:blk(start:n end:n) dest_udp_ports:blk(start:n end:n) type:s is_name_l10n_tag:b"
    ),
    "zia_firewall_filtering_network_service_groups": "name:s! description:s services:ids",
    "zia_firewall_filtering_rule": (
        "name:s! description:s order:n! rank:n enable_full_logging:b action:s state:s src_ips:ls dest_addresses:ls "
        "dest_ip_categories:ls nw_applications:ls exclude_src_countries:b is_eun_enabled:b eun_template_id:n "
        "exclude_context_shield_end_point:b locations:ids location_groups:ids users:ids groups:ids departments:ids "
        "time_windows:ids labels:ids device_groups:ids devices:ids src_ip_groups:ids dest_ip_groups:ids "
        "app_service_groups:ids app_services:ids nw_application_groups:ids nw_service_groups:ids workload_groups:idb "
        "nw_services:ids zpa_app_segments:extid dest_countries:ls source_countries:ls device_trust_levels:ls"
    ),
    "zia_firewall_ips_rule": (
        "name:s! description:s order:n! rank:n enable_full_logging:b capture_pcap:b action:s state:s res_categories:ls "
        "src_ips:ls dest_addresses:ls dest_ip_categories:ls is_eun_enabled:b eun_template_id:n locations:ids "
        "location_groups:ids users:ids groups:ids departments:ids time_windows:ids labels:ids device_groups:ids "
        "devices:ids src_ip_groups:ids src_ipv6_groups:ids dest_ip_groups:ids dest_ipv6_groups:ids nw_services:ids "
        "nw_service_groups:ids threat_categories:ids zpa_app_segments:extid dest_countries:ls source_countries:ls"
    ),
    "zia_forwarding_control_proxies": "name:s description:s type:s address:s port:n insert_xau_header:b base64_encode_xau_header:b cert:idb",
    "zia_forwarding_control_rule": (
        "name:s description:s type:s forward_method:s! order:n! rank:n state:s src_ips:ls dest_addresses:ls "
        "dest_ip_categories:ls res_categories:ls locations:ids location_groups:ids ec_groups:ids departments:ids "
        "groups:ids users:ids device_groups:ids src_ip_groups:ids src_ipv6_groups:ids dest_ip_groups:ids "
        "dest_ipv6_groups:ids nw_services:ids nw_service_groups:ids labels:ids nw_application_groups:ids "
        "app_service_groups:ids proxy_gateway:idb dedicated_ip_gateway:idb zpa_gateway:idb zpa_app_segments:extid "
        "zpa_application_segments:ids zpa_application_segment_groups:ids dest_countries:ls"
    ),
    "zia_forwarding_control_zpa_gateway": (
        "name:s! description:s type:s zpa_server_group:blk(external_id:s! name:s!)! zpa_app_segments:blk(name:s! "
        "external_id:s!)"
    ),
    "zia_ftp_control_policy": "ftp_over_http_enabled:b ftp_enabled:b urls:ls url_categories:ls",
    "zia_http_header_action_profile": "name:s! description:s http_header_action_profile_keys:blk(key:s! value:s!)",
    "zia_http_header_profile": (
        "name:s! description:s http_header_profile_criteria:blk(header:s operator:s user_agent:s user_agent_bitmap:s "
        "user_agent_version:s category_bitmap:ls cloud_app_bitmap:ls)"
    ),
    "zia_location_management": (
        "name:s! description:s up_bandwidth:n dn_bandwidth:n country:s tz:s state:s ip_addresses:ls ports:ln "
        "vpn_credentials:blk(id:n type:s) ssl_scan_enabled:b zapp_ssl_scan_enabled:b xff_forward_enabled:b "
        "other_sub_location:b other6_sub_location:b sub_loc_scope:s sub_loc_scope_values:ls sub_loc_acc_ids:ls "
        "surrogate_ip:b basic_auth_enabled:b digest_auth_enabled:b kerberos_auth:b iot_discovery_enabled:b "
        "iot_enforce_policy_set:b auth_required:b cookies_and_proxy:b default_extranet_ts_pool:b default_extranet_dns:b "
        "idle_time_in_minutes:n display_time_unit:s surrogate_ip_enforced_for_known_browsers:b "
        "surrogate_refresh_time_in_minutes:n surrogate_refresh_time_unit:s ofw_enabled:b ips_control:b aup_enabled:b "
        "caution_enabled:b aup_block_internet_until_accepted:b aup_force_ssl_inspection:b ipv6_enabled:b "
        "ipv6_dns_64prefix:b aup_timeout_in_days:n profile:s exclude_from_dynamic_groups:b exclude_from_manual_groups:b "
        "static_location_groups:ids extranet:idb extranet_ip_pool:idb extranet_dns:idb "
        "virtual_zen_clusters:ids virtual_zens:ids"
    ),
    "zia_mobile_malware_protection_policy": (
        "block_apps_with_malicious_activity:b block_apps_with_known_vulnerabilities:b "
        "block_apps_sending_unencrypted_user_credentials:b block_apps_sending_location_info:b "
        "block_apps_sending_personally_identifiable_info:b block_apps_sending_device_identifier:b "
        "block_apps_communicating_with_ad_websites:b block_apps_communicating_with_remote_unknown_servers:b"
    ),
    "zia_nat_control_rules": (
        "name:s! description:s order:n! rank:n enable_full_logging:b state:s redirect_fqdn:s redirect_ip:s "
        "redirect_port:n src_ips:ls dest_addresses:ls dest_ip_categories:ls res_categories:ls locations:ids "
        "location_groups:ids users:ids groups:ids departments:ids time_windows:ids labels:ids device_groups:ids "
        "devices:ids src_ip_groups:ids src_ipv6_groups:ids dest_ip_groups:ids dest_ipv6_groups:ids "
        "nw_service_groups:ids nw_services:ids dest_countries:ls"
    ),
    "zia_risk_profiles": (
        "profile_name:s! profile_type:s status:s exclude_certificates:n poor_items_of_service:s admin_audit_logs:s "
        "data_breach:s source_ip_restrictions:s mfa_support:s ssl_pinned:s http_security_headers:s evasive:s "
        "dns_caa_policy:s weak_cipher_support:s password_strength:s ssl_cert_validity:s vulnerability:s "
        "malware_scanning_for_content:s file_sharing:s ssl_cert_key_size:s vulnerable_to_heart_bleed:s "
        "vulnerable_to_log_jam:s vulnerable_to_poodle:s vulnerability_disclosure:s support_for_waf:s "
        "remote_screen_sharing:s sender_policy_framework:s domain_keys_identified_mail:s domain_based_message_auth:s "
        "custom_tags:ids data_encryption_in_transit:ls risk_index:ln certifications:ls"
    ),
    "zia_rule_labels": "name:s description:s",
    "zia_sandbox_behavioral_analysis": "file_hashes_to_be_blocked:ls",
    "zia_sandbox_rules": (
        "name:s! description:s state:s rank:n order:n! ba_rule_action:s first_time_enable:b first_time_operation:s "
        "ml_action_enabled:b by_threat_score:n url_categories:ls file_types:ls locations:ids location_groups:ids "
        "departments:ids groups:ids users:ids labels:ids zpa_app_segments:extid ba_policy_categories:ls protocols:ls!"
    ),
    "zia_security_settings": "whitelist_urls:ls blacklist_urls:ls",
    "zia_ssl_inspection_rules": (
        "name:s! description:s state:s rank:n order:n! road_warrior_for_kerberos:b cloud_applications:ls "
        "url_categories:ls action:blk(type:s show_eun:b show_eunatp:b override_default_certificate:b "
        "ssl_interception_cert:idb decrypt_sub_actions:blk(server_certificates:s ocsp_check:b "
        "block_ssl_traffic_with_no_sni_enabled:b min_client_tls_version:s min_server_tls_version:s block_undecrypt:b "
        "http2_enabled:b) do_not_decrypt_sub_actions:blk(bypass_other_policies:b server_certificates:s ocsp_check:b "
        "block_ssl_traffic_with_no_sni_enabled:b min_tls_version:s)) locations:ids location_groups:ids users:ids "
        "groups:ids departments:ids time_windows:ids labels:ids device_groups:ids devices:ids source_ip_groups:ids "
        "dest_ip_groups:ids workload_groups:idb proxy_gateways:ids zpa_app_segments:extid user_agent_types:ls "
        "device_trust_levels:ls platforms:ls"
    ),
    "zia_subscription_alert": (
        "email:s description:s pt0_severities:ls secure_severities:ls manage_severities:ls comply_severities:ls "
        "system_severities:ls"
    ),
    "zia_traffic_forwarding_gre_tunnel": (
        "source_ip:s! within_country:b primary_dest_vip:blk(id:n virtual_ip:s datacenter:s) secondary_dest_vip:blk(id:n "
        "virtual_ip:s datacenter:s) internal_ip_range:s country_code:s comment:s ip_unnumbered:b"
    ),
    "zia_traffic_forwarding_static_ip": "ip_address:s! geo_override:b latitude:f longitude:f routable_ip:b comment:s",
    "zia_traffic_forwarding_vpn_credentials": "type:s fqdn:s ip_address:s pre_shared_key:secret comments:s",
    "zia_url_categories": (
        "configured_name:s description:s urls:ls keywords:ls keywords_retaining_parent_category:ls "
        "db_categorized_urls:ls custom_category:b scopes:blk(type:s) type:s url_type:s ip_ranges:ls "
        "ip_ranges_retaining_parent_category:ls super_category:s regex_patterns:ls "
        "regex_patterns_retaining_parent_category:ls"
    ),
    "zia_url_filtering_and_cloud_app_settings": (
        "enable_dynamic_content_cat:b consider_embedded_sites:b enforce_safe_search:b safe_search_apps:ls "
        "enable_office365:b enable_msft_o365:b enable_ucaas_zoom:b enable_ucaas_logmein:b enable_ucaas_ring_central:b "
        "enable_ucaas_webex:b enable_ucaas_talkdesk:b enable_chatgpt_prompt:b enable_microsoft_copilot_prompt:b "
        "enable_gemini_prompt:b enable_poe_prompt:b enable_meta_prompt:b enable_per_plexity_prompt:b "
        "enable_deep_seek_prompt:b enable_writer_prompt:b enable_grok_prompt:b enable_mistral_ai_prompt:b "
        "enable_claude_prompt:b enable_grammarly_prompt:b enable_newly_registered_domains:b "
        "enable_block_override_for_non_auth_user:b enable_cipa_compliance:b zvelo_db_lookup_disabled:b "
        "enable_google_ai_prompt:b enable_quillbot_ai_prompt:b"
    ),
    "zia_url_filtering_rules": (
        "name:s! description:s order:n! state:s rank:n end_user_notification_url:s block_override:b time_quota:n "
        "size_quota:n enforce_time_validity:b validity_start_time:s validity_end_time:s validity_time_zone_id:s "
        "action:s ciparule:b browser_eun_template_id:n cbi_profile:blk(profile_seq:n id:s name:s url:s) "
        "url_categories:ls! locations:ids groups:ids departments:ids users:ids time_windows:ids override_users:ids "
        "override_groups:ids device_groups:ids devices:ids location_groups:ids labels:ids source_ip_groups:ids "
        "workload_groups:idb http_header_profiles:ids http_header_action_profiles:ids device_trust_levels:ls "
        "user_risk_score_levels:ls request_methods:ls protocols:ls! user_agent_types:ls source_countries:ls"
    ),
    "zia_virtual_service_edge_cluster": "name:s status:s ip_sec_enabled:b ip_address:s subnet_mask:s default_gateway:s type:s virtual_zen_nodes:ids",
    "zia_virtual_service_edge_node": (
        "name:s status:s type:s ip_sec_enabled:b ip_address:s subnet_mask:s default_gateway:s in_production:b "
        "on_demand_support_tunnel_enabled:b establish_support_tunnel_enabled:b load_balancer_ip_address:s "
        "deployment_mode:s cluster_name:s vzen_sku_type:s"
    ),
    "zia_workload_groups": (
        "name:s description:s expression_json:blk(expression_containers:blk(tag_type:s operator:s "
        "tag_container:blk(tags:blk(key:s value:s) operator:s)))"
    ),
    "zia_endpoint_dlp_rules": (
        "name:s! description:s rank:n order:n! severity:s user_risk_score_levels:ls device_trust_levels:ls "
        "file_types:ls data_transfer_method:s network_type:s min_size:n action:s state:s external_auditor_email:s "
        "without_content_inspection:b eun_enabled:b eun_template_id:n uc_template_id:n device_groups:ids devices:ids "
        "users:ids groups:ids departments:ids resources:ids resource_groups:ids dlp_engines:ids labels:ids auditor:idb "
        "notification_template:idb receiver:sidb"
    ),
    "zia_casb_dlp_rules": (
        "name:s description:s type:s order:n! rank:n state:s action:s severity:s bucket_owner:s "
        "external_auditor_email:s content_location:s recipient:s quarantine_location:s watermark_delete_old_version:b "
        "include_criteria_domain_profile:b include_email_recipient_profile:b without_content_inspection:b "
        "include_entity_groups:b domains:ls cloud_app_tenants:ids entity_groups:ids included_domain_profiles:ids "
        "excluded_domain_profiles:ids criteria_domain_profiles:ids email_recipient_profiles:ids object_types:ids "
        "labels:ids dlp_engines:ids buckets:ids groups:ids departments:ids users:ids zscaler_incident_receiver:idb "
        "auditor_notification:idb tag:idb watermark_profile:idb redaction_profile:idb casb_email_label:idb "
        "casb_tombstone_template:idb collaboration_scope:ls file_types:ls components:ls receiver:blk(id:s! name:s "
        "type:s tenant:blk(id:s name:s))"
    ),
    "zia_outbound_email_dlp": (
        "name:s! description:s order:n! state:s action:s severity:s file_types:ls content_locations:ls min_size:n "
        "without_content_inspection:b external_auditor_email:s custom_header:s parent_rule:n sub_rules:ls "
        "user_risk_score_levels:ls groups:ids departments:ids users:ids excluded_groups:ids excluded_departments:ids "
        "excluded_users:ids time_windows:ids dlp_engines:ids labels:ids included_domain_profiles:ids email_tenants:ids "
        "email_recipient_profiles:ids auditor:idb notification_template:idb receiver:sidb"
    ),
    "zia_bandwidth_classes": "name:s urls:ls url_categories:ls web_applications:ls",
    "zia_bandwidth_control_rule": (
        "name:s description:s state:s order:n! rank:n min_bandwidth:n max_bandwidth:n bandwidth_classes:ids "
        "locations:ids location_groups:ids labels:ids time_windows:ids protocols:ls!"
    ),
    "zia_browser_control_policy": (
        "plugin_check_frequency:s bypass_plugins:ls bypass_applications:ls blocked_internet_explorer_versions:ls "
        "blocked_chrome_versions:ls blocked_firefox_versions:ls blocked_safari_versions:ls blocked_opera_versions:ls "
        "bypass_all_browsers:b allow_all_browsers:b enable_warnings:b enable_smart_browser_isolation:b "
        "smart_isolation_profile:blk(id:s name:s url:s) smart_isolation_groups:ids smart_isolation_users:ids"
    ),
    "zia_tenant_restriction_profile": (
        "name:s! description:s app_type:s item_type_primary:s item_type_secondary:s restrict_personal_o365_domains:b "
        "allow_google_consumers:b ms_login_services_tr_v2:b allow_google_visitors:b allow_gcp_cloud_storage_read:b "
        "item_data_primary:ls item_data_secondary:ls item_value:ls"
    ),
    "zia_cloud_application_instance": (
        "name:s instance_type:s instance_identifiers:blk(instance_identifier:s instance_identifier_name:s "
        "identifier_type:s)"
    ),
    "zia_dns_application_groups": "name:s! description:s dns_applications:ls!",
    "zpa_app_connector_group": (
        "name:s! city_country:s country_code:s description:s dns_query_type:s enabled:b latitude:s! location:s! "
        "longitude:s! lss_app_connector_group:b tcp_quick_ack_app:b tcp_quick_ack_assistant:b "
        "tcp_quick_ack_read_assistant:b use_in_dr_mode:b pra_enabled:b waf_disabled:b microtenant_id:s upgrade_day:s "
        "upgrade_time_in_secs:s override_version_profile:b version_profile_name:s version_profile_id:s "
        "dc_hosting_info:s enrollment_cert_id:s user_codes:ls"
    ),
    "zpa_application_segment": (
        "segment_group_id:s bypass_on_reauth:b bypass_type:s tcp_port_ranges:ls udp_port_ranges:ls description:s "
        "domain_names:ls! double_encrypt:b share_to_microtenants:ls enabled:b inspect_traffic_with_zia:b "
        "health_check_type:s match_style:s health_reporting:s icmp_access_type:s ip_anchored:b fqdn_dns_check:b "
        "select_connector_close_to_app:b use_in_dr_mode:b is_cname_enabled:b name:s! passive_health_enabled:b "
        "tcp_keep_alive:s microtenant_id:s weighted_load_balancing:b policy_style:b api_protection_enabled:b "
        "server_groups:sids zpn_er_id:sids tags:blk(tag_key_id:s! tag_value_id:s!)"
    ),
    "zpa_application_segment_browser_access": (
        "microtenant_id:s segment_group_id:s! bypass_type:s tcp_port_ranges:ls udp_port_ranges:ls description:s "
        "domain_names:ls! double_encrypt:b health_check_type:s passive_health_enabled:b enabled:b policy_style:b "
        "health_reporting:s icmp_access_type:s tcp_keep_alive:s ip_anchored:b fqdn_dns_check:b "
        "select_connector_close_to_app:b use_in_dr_mode:b is_cname_enabled:b name:s! "
        "clientless_apps:blk(microtenant_id:s name:s! allow_options:b application_port:s! application_protocol:s! "
        "certificate_id:s description:s domain:s enabled:b trust_untrusted_cert:b ext_label:s ext_domain:s)! "
        "server_groups:sids zpn_er_id:sids"
    ),
    "zpa_application_segment_inspection": (
        "name:s! segment_group_id:s! adp_enabled:b auto_app_protect_enabled:b bypass_on_reauth:b bypass_type:s "
        "tcp_port_ranges:ls tcp_protocols:ls udp_protocols:ls udp_port_ranges:ls description:s domain_names:ls! "
        "double_encrypt:b health_check_type:s health_reporting:s passive_health_enabled:b enabled:b policy_style:b "
        "icmp_access_type:s ip_anchored:b fqdn_dns_check:b select_connector_close_to_app:b use_in_dr_mode:b "
        "is_cname_enabled:b tcp_keep_alive:s common_apps_dto:blk(apps_config:blk(name:s app_types:ls application_port:s "
        "application_protocol:s certificate_id:s domain:s trust_untrusted_cert:b)) server_groups:sids"
    ),
    "zpa_application_segment_pra": (
        "name:s! microtenant_id:s segment_group_id:s! bypass_on_reauth:b bypass_type:s tcp_port_ranges:ls "
        "udp_port_ranges:ls description:s domain_names:ls! double_encrypt:b health_check_type:s health_reporting:s "
        "passive_health_enabled:b enabled:b policy_style:b icmp_access_type:s ip_anchored:b fqdn_dns_check:b "
        "select_connector_close_to_app:b use_in_dr_mode:b is_cname_enabled:b tcp_keep_alive:s "
        "common_apps_dto:blk(apps_config:blk(name:s app_types:ls application_port:s application_protocol:s "
        "connection_security:s domain:s)) server_groups:sids zpn_er_id:sids"
    ),
    "zpa_application_server": "name:s! description:s address:s! enabled:b app_server_group_ids:ls microtenant_id:s",
    "zpa_segment_group": "description:s enabled:b name:s! microtenant_id:s",
    "zpa_server_group": (
        "description:s enabled:b ip_anchored:b dynamic_discovery:b name:s! microtenant_id:s servers:sids "
        "app_connector_groups:sids extranet_enabled:b extranet_dto:blk(zpn_er_id:s location_dto:sidb "
        "location_group_dto:sidb)"
    ),
    "zpa_service_edge_group": (
        "name:s! city_country:s city:s country_code:s description:s enabled:b is_public:b latitude:s! location:s! "
        "longitude:s! override_version_profile:b use_in_dr_mode:b service_edges:sids trusted_networks:sids "
        "exclusive_for_business_continuity:b upgrade_day:s upgrade_time_in_secs:s version_profile_id:s "
        "version_profile_name:s version_profile_visibility_scope:s microtenant_id:s grace_distance_enabled:b "
        "grace_distance_value:s grace_distance_value_unit:s enrollment_cert_id:s user_codes:ls"
    ),
    "zpa_provisioning_key": (
        "app_connector_group_id:s enabled:b max_usage:s! name:s! enrollment_cert_id:s! ui_config:s zcomponent_id:s! "
        "association_type:s! ip_acl:ls microtenant_id:s"
    ),
    "zpa_policy_access_rule_v2": (
        "name:s! description:s action:s operator:s custom_msg:s device_posture_failure_notification_enabled:b "
        "conditions:blk(operator:s operands:blk(values:ls object_type:s entry_values:blk(rhs:s lhs:s))) "
        "app_server_groups:sids app_connector_groups:sids extranet_enabled:b extranet_dto:blk(zpn_er_id:s "
        "location_dto:sidb location_group_dto:sidb)"
    ),
    "zpa_policy_timeout_rule_v2": (
        "name:s! description:s action:s custom_msg:s reauth_idle_timeout:s reauth_timeout:s conditions:blk(operator:s "
        "operands:blk(values:ls object_type:s entry_values:blk(rhs:s lhs:s))) microtenant_id:s"
    ),
    "zpa_policy_forwarding_rule_v2": (
        "name:s! description:s action:s conditions:blk(operator:s operands:blk(values:ls object_type:s "
        "entry_values:blk(rhs:s lhs:s))) microtenant_id:s"
    ),
    "zpa_policy_inspection_rule_v2": (
        "name:s! description:s action:s zpn_inspection_profile_id:s conditions:blk(operator:s operands:blk(values:ls "
        "object_type:s entry_values:blk(rhs:s lhs:s))) microtenant_id:s"
    ),
    "zpa_policy_isolation_rule_v2": (
        "name:s! description:s action:s zpn_isolation_profile_id:s conditions:blk(operator:s operands:blk(values:ls "
        "object_type:s entry_values:blk(rhs:s lhs:s))) microtenant_id:s"
    ),
    "zpa_pra_portal_controller": (
        "name:s description:s enabled:b domain:s certificate_id:s user_notification:s user_notification_enabled:b "
        "ext_label:s ext_domain:s ext_domain_name:s ext_domain_translation:s microtenant_id:s user_portal_gid:s "
        "approval_reviewers:ls"
    ),
    "zpa_pra_console_controller": "name:s description:s enabled:b icon_text:s pra_portals:sids! pra_application:sidb! microtenant_id:s",
    "zpa_pra_credential_controller": (
        "name:s description:s credential_type:s passphrase:secret password:secret private_key:secret user_domain:s "
        "username:s microtenant_id:s"
    ),
    "zpa_pra_approval_controller": (
        "email_ids:ls start_time:s end_time:s status:s working_hours:blk(days:ls start_time:s start_time_cron:s "
        "end_time:s end_time_cron:s timezone:s) applications:sids! microtenant_id:s"
    ),
    "zpa_pra_credential_pool": "name:s credential_type:s credentials:sids microtenant_id:s",
    "zpa_lss_config_controller": (
        "connector_groups:sids config:blk(audit_message:s description:s enabled:b filter:ls format:s! name:s! "
        "lss_host:s! lss_port:s! source_log_type:s! use_tls:b)"
    ),
    "zpa_microtenant_controller": (
        "name:s! description:s enabled:b criteria_attribute:s criteria_attribute_values:ls "
        "privileged_approvals_enabled:b"
    ),
    "zpa_user_portal_controller": (
        "name:s! certificate_id:s description:s domain:s enabled:b ext_domain:s ext_domain_name:s "
        "ext_domain_translation:s ext_label:s microtenant_id:s user_notification:s user_notification_enabled:b"
    ),
    "zpa_user_portal_link": (
        "name:s! description:s enabled:b icon_text:s link:s link_path:s protocol:s microtenant_id:s application_id:s "
        "user_portals:sids"
    ),
    "zpa_inspection_custom_controls": (
        "name:s! description:s action:s action_value:s control_number:s control_rule_json:s control_type:s "
        "default_action:s default_action_value:s paranoia_level:s protocol_type:s rules:blk(names:ls type:s "
        "conditions:blk(lhs:s op:s rhs:s)) severity:s! type:s! version:s"
    ),
    "zpa_inspection_profile": (
        "name:s description:s api_profile:b override_action:s associate_all_controls:b "
        "controls_info:blk(control_type:s) custom_controls:blk(id:s! action:s action_value:s) global_control_actions:ls "
        "paranoia_level:s predefined_controls:blk(id:s action:s action_value:s) predefined_api_controls:blk(id:s "
        "action:s action_value:s) threat_labz_controls:blk(id:s action:s action_value:s) websocket_controls:blk(id:s "
        "action:s action_value:s) predefined_controls_version:s zs_defined_control_choice:s"
    ),
    "zpa_cloud_browser_isolation_banner": "name:s primary_color:s text_color:s notification_title:s notification_text:s logo:s banner:b persist:b",
    "zpa_cloud_browser_isolation_external_profile": (
        "name:s! description:s banner_id:s! region_ids:ls certificate_ids:ls user_experience:blk(zgpu:b "
        "forward_to_zia:blk(enabled:b organization_id:s cloud_name:s pac_file_url:s) browser_in_browser:b "
        "persist_isolation_bar:b translate:b session_persistence:b) debug_mode:blk(allowed:b file_password:secret) "
        "security_controls:blk(copy_paste:s upload_download:s document_viewer:b local_render:b allow_printing:b "
        "restrict_keystrokes:b deep_link:blk(enabled:b applications:ls) flattened_pdf:b watermark:blk(enabled:b "
        "show_user_id:b show_timestamp:b show_message:b message:s))"
    ),
    "zpa_cloud_browser_isolation_certificate": "name:s pem:s",
    "zpa_c2c_ip_ranges": (
        "name:s! description:s enabled:b ip_range_begin:s ip_range_end:s location:s location_hint:s sccm_flag:b "
        "subnet_cidr:s country_code:s latitude_in_db:s longitude_in_db:s"
    ),
    "zpa_private_cloud_group": (
        "name:s! city_country:s country_code:s description:s enabled:b is_public:s latitude:s location:s longitude:s "
        "override_version_profile:b microtenant_id:s site_id:s upgrade_day:s upgrade_time_in_secs:s "
        "version_profile_id:s version_profile_name:s enrollment_cert_id:s user_codes:ls"
    ),
    "ztc_forwarding_gateway": (
        "name:s description:s type:s fail_closed:b manual_primary:s manual_secondary:s primary_type:s! "
        "secondary_type:s! subcloud_primary:idb subcloud_secondary:idb"
    ),
    "ztc_ip_destination_groups": "name:s! description:s type:s addresses:ls ip_categories:ls countries:ls",
    "ztc_ip_pool_groups": "name:s! description:s ip_addresses:ls!",
    "ztc_ip_source_groups": "name:s! description:s ip_addresses:ls!",
    "ztc_location_template": (
        "name:s desc:s template:blk(template_prefix:s xff_forward_enabled:b auth_required:b aup_enabled:b "
        "caution_enabled:b aup_timeout_in_days:n ofw_enabled:b ips_control:b enforce_bandwidth_control:b up_bandwidth:n "
        "dn_bandwidth:n)"
    ),
    "ztc_network_service_groups": "name:s! description:s services:ids",
    "ztc_network_services": (
        "name:s! description:s tag:s src_tcp_ports:blk(start:n end:n) dest_tcp_ports:blk(start:n end:n) "
        "src_udp_ports:blk(start:n end:n) dest_udp_ports:blk(start:n end:n) type:s is_name_l10n_tag:b"
    ),
    "ztc_provisioning_url": (
        "name:s! desc:s prov_url_type:s prov_url_data:blk(location_template:idb! form_factor:s cloud_provider_type:s "
        "release_channel:s auto_scale_details:blk(auto_scale:b) cell_edge_deploy:b)"
    ),
    "ztc_public_cloud_info": (
        "name:s cloud_type:s account_details:blk(aws_account_id:s aws_role_name:s cloud_watch_group_arn:s "
        "event_bus_name:s log_info_type:s trouble_shooting_logging:b trusted_account_id:s trusted_role:s) "
        "supported_regions:ids"
    ),
    "ztc_traffic_forwarding_rule": (
        "name:s description:s type:s forward_method:s! order:n! rank:n state:s src_ips:ls source_ip_group_exclusion:b "
        "dest_addresses:ls dest_ip_categories:ls res_categories:ls wan_selection:s locations:ids location_groups:ids "
        "ec_groups:ids src_ip_groups:ids dest_ip_groups:ids nw_services:ids nw_service_groups:ids "
        "app_service_groups:ids proxy_gateway:idb zpa_application_segments:ids zpa_application_segment_groups:ids "
        "dest_countries:ls src_workload_groups:ids"
    ),
    "zcc_trusted_network": (
        "active:b! condition_type:s! name:s hostname:s ssid:s dns_search_domains:ls dns_server_ips:ls "
        "resolved_ips_for_hostname:ls trusted_dhcp_servers_ips:ls trusted_egress_ips:ls trusted_gateway_ips:ls "
        "trusted_subnet_ips:ls"
    ),
    # zcc 0.1.2 docs/resources: every argument optional; the switches are booleans the API writes as 0 / 1.
    "zcc_failopen_policy": (
        "active:b enable_fail_open:b enable_strict_enforcement_prompt:b strict_enforcement_prompt_message:s "
        "strict_enforcement_prompt_delay_minutes:n enable_web_sec_on_proxy_unreachable:b enable_web_sec_on_tunnel_failure:b "
        "tunnel_failure_retry_count:n enable_captive_portal_detection:b captive_portal_web_sec_disable_minutes:n"
    ),
    "zcc_device_cleanup": (
        "active:b force_remove_type:s device_exceed_limit:n auto_removal_days:n auto_purge_days:n"
    ),
    "zcc_web_privacy": (
        "active:b collect_user_info:b collect_machine_hostname:b collect_zdx_location:b enable_packet_capture:b "
        "disable_crashlytics:b override_t2_protocol_setting:b restrict_remote_packet_capture:b "
        "grant_access_to_zscaler_log_folder:b export_logs_for_non_admin:b enable_auto_log_snippet:b enforce_secure_pac_urls:b "
        "enable_fqdn_match_for_vpn_bypasses:b"
    ),
    "zcc_forwarding_profile": (
        "name:s! active:b condition_type:n dns_servers:s dns_search_domains:s enable_lwf_driver:b hostname:s "
        "resolved_ips_for_hostname:s trusted_subnets:s trusted_gateways:s trusted_dhcp_servers:s trusted_egress_ips:s "
        "predefined_trusted_networks:b predefined_tn_all:b enable_split_vpn_tn:b enable_unified_tunnel:b "
        "evaluate_trusted_network:b skip_trusted_criteria_match:b enable_all_default_adapters_tn:b "
        "trusted_network_ids:ln "
        "forwarding_profile_actions:blk(network_type:n action_type:n primary_transport:n dtls_timeout:n udp_timeout:n "
        "tls_timeout:n mtu_for_zadapter:n tunnel2_fallback_type:n zen_probe_interval:n zen_probe_sample_size:n "
        "zen_threshold_limit:n lbs_probe_interval:n lbs_probe_sample_size:n lbs_threshold_limit:n custom_pac:s "
        "system_proxy:b enable_packet_tunnel:b block_unreachable_domains_traffic:b allow_tls_fallback:b "
        "send_all_dns_to_trusted_server:b drop_ipv6_traffic:b redirect_web_traffic:b drop_ipv6_include_traffic_in_t2:b "
        "use_tunnel2_for_proxied_web_traffic:b use_tunnel2_for_unencrypted_web_traffic:b path_mtu_discovery:b "
        "latency_based_zen_enablement:b latency_based_server_enablement:b latency_based_server_mt_enablement:b "
        "drop_ipv6_traffic_in_ipv6_network:b optimise_for_unstable_connections:b is_same_as_on_trusted_network:b "
        "system_proxy_data:blk(proxy_action:n enable_auto_detect:b enable_pac:b pac_url:s enable_proxy_server:b "
        "proxy_server_address:s proxy_server_port:s bypass_proxy_for_private_ip:b perform_gp_update:b pac_data_path:s)) "
        "forwarding_profile_zpa_actions:blk(network_type:n action_type:n primary_transport:n dtls_timeout:n "
        "tls_timeout:n mtu_for_zadapter:n lbs_probe_interval:n lbs_probe_sample_size:n lbs_threshold_limit:n "
        "send_trusted_network_result_to_zpa:b latency_based_server_enablement:b latency_based_server_mt_enablement:b "
        "is_same_as_on_trusted_network:b partner_info:blk(primary_transport:n mtu_for_zadapter:n allow_tls_fallback:b)) "
        "unified_tunnel:blk(network_type:n action_type_zia:n action_type_zpa:n primary_transport:n dtls_timeout:n "
        "tls_timeout:n mtu_for_zadapter:n tunnel2_fallback_type:n allow_tls_fallback:b path_mtu_discovery:b "
        "optimise_for_unstable_connections:b redirect_web_traffic:b drop_ipv6_traffic:b "
        "drop_ipv6_traffic_in_ipv6_network:b block_unreachable_domains_traffic:b drop_ipv6_include_traffic_in_t2:b "
        "send_all_dns_to_trusted_server:b same_as_on_trusted:b system_proxy_data:blk(proxy_action:n "
        "enable_auto_detect:b enable_pac:b pac_url:s enable_proxy_server:b proxy_server_address:s proxy_server_port:s "
        "bypass_proxy_for_private_ip:b perform_gp_update:b pac_data_path:s))"
    ),
}
