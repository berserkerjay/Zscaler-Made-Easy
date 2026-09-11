# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "z_atomic_energy_act_monitor" {
  name                         = "Z-Atomic Energy Act Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_financial_information_monitor" {
  name                         = "Z-Financial Information-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
}

resource "zia_dlp_web_rules" "z_for_official_use_only_markings_monitor" {
  name                         = "Z-For Official Use Only Markings-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_itar_international_traffic_in_arms_regulations_monitor" {
  name                         = "Z-ITAR International Traffic in Arms Regulations-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
}

resource "zia_dlp_web_rules" "z_standard_forms_monitor" {
  name                         = "Z-Standard Forms-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
}

resource "zia_dlp_web_rules" "z_traffic_light_protocol_monitor" {
  name                         = "Z-Traffic Light Protocol-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id, zia_dlp_engines.tlp_amber_strict.id, zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_dlp_web_rules" "z_us_pii_monitor" {
  name                         = "Z-US PII-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
}

resource "zia_dlp_web_rules" "z_us_phi_monitor" {
  name                         = "Z-US PHI-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id, zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_private_keys_monitor" {
  name                         = "Z-Private Keys-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
}

resource "zia_dlp_web_rules" "cui_block_marked_documents" {
  name                         = "CUI-Block-Marked-Documents"
  description                  = "Inline Web DLP: block uploads carrying high-precision CUI markings (banners, category tokens, legacy FOUO/LES/SBU, distribution statements) via CUI-Detect-Block-Grade. Ships DISABLED at INFO; enable after reviewing monitor incidents from CUI-Monitor-All. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
}

resource "zia_dlp_web_rules" "cui_caution_weak_markings" {
  name                         = "CUI-Caution-Weak-Markings"
  description                  = "Inline Web DLP: caution (user must confirm) on lower-precision CUI signals: bare CUI, standalone LDCs, malformed markings, designation blocks, via CUI-Detect-Caution-Grade. Never BLOCK on these. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "CONFIRM"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
}

resource "zia_dlp_web_rules" "cui_monitor_all" {
  name                         = "CUI-Monitor-All"
  description                  = "Inline Web DLP: monitor-only rule over the full CUI-Detect-All surface plus the content-based CUI-Detect-Contextual signal. Enable this first to size incident volume and tune before enabling the block and caution rules above it. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id, zia_dlp_engines.cui_detect_contextual.id]
  }
}

resource "zia_endpoint_dlp_rules" "z_atomic_energy_act_endpoint" {
  name                         = "Z-Atomic Energy Act [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_atomic_energy_act_saas" {
  name                         = "Z-Atomic Energy Act [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_atomic_energy_act_saas
  }
}

resource "zia_outbound_email_dlp" "z_atomic_energy_act_email" {
  name                         = "Z-Atomic Energy Act [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_atomic_energy_act_email
  }
}

resource "zia_endpoint_dlp_rules" "z_financial_information_endpoint" {
  name                         = "Z-Financial Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
}

resource "zia_casb_dlp_rules" "z_financial_information_saas" {
  name                         = "Z-Financial Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_financial_information_saas
  }
}

resource "zia_outbound_email_dlp" "z_financial_information_email" {
  name                         = "Z-Financial Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_financial_information_email
  }
}

resource "zia_endpoint_dlp_rules" "z_for_official_use_only_markings_endpoint" {
  name                         = "Z-For Official Use Only Markings [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_for_official_use_only_markings_saas" {
  name                         = "Z-For Official Use Only Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_for_official_use_only_markings_saas
  }
}

resource "zia_outbound_email_dlp" "z_for_official_use_only_markings_email" {
  name                         = "Z-For Official Use Only Markings [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_for_official_use_only_markings_email
  }
}

resource "zia_endpoint_dlp_rules" "z_itar_international_traffic_in_arms_regulations_endpoint" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
}

resource "zia_casb_dlp_rules" "z_itar_international_traffic_in_arms_regulations_saas" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_itar_international_traffic_in_arms_regulations_saas
  }
}

resource "zia_outbound_email_dlp" "z_itar_international_traffic_in_arms_regulations_email" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_itar_international_traffic_in_arms_regulations_email
  }
}

resource "zia_endpoint_dlp_rules" "z_standard_forms_endpoint" {
  name                         = "Z-Standard Forms [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
}

resource "zia_casb_dlp_rules" "z_standard_forms_saas" {
  name                         = "Z-Standard Forms [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_standard_forms_saas
  }
}

resource "zia_outbound_email_dlp" "z_standard_forms_email" {
  name                         = "Z-Standard Forms [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_standard_forms_email
  }
}

resource "zia_endpoint_dlp_rules" "z_traffic_light_protocol_endpoint" {
  name                         = "Z-Traffic Light Protocol [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id, zia_dlp_engines.tlp_amber_strict.id, zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_casb_dlp_rules" "z_traffic_light_protocol_saas" {
  name                         = "Z-Traffic Light Protocol [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id, zia_dlp_engines.tlp_amber_strict.id, zia_dlp_engines.tlp_amber.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_traffic_light_protocol_saas
  }
}

resource "zia_outbound_email_dlp" "z_traffic_light_protocol_email" {
  name                         = "Z-Traffic Light Protocol [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id, zia_dlp_engines.tlp_amber_strict.id, zia_dlp_engines.tlp_amber.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_traffic_light_protocol_email
  }
}

resource "zia_endpoint_dlp_rules" "z_us_pii_endpoint" {
  name                         = "Z-US PII [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_pii_saas" {
  name                         = "Z-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_us_pii_saas
  }
}

resource "zia_outbound_email_dlp" "z_us_pii_email" {
  name                         = "Z-US PII [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_us_pii_email
  }
}

resource "zia_endpoint_dlp_rules" "z_us_phi_endpoint" {
  name                         = "Z-US PHI [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id, zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_phi_saas" {
  name                         = "Z-US PHI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id, zia_dlp_engines.us_phi_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_us_phi_saas
  }
}

resource "zia_outbound_email_dlp" "z_us_phi_email" {
  name                         = "Z-US PHI [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id, zia_dlp_engines.us_phi_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_us_phi_email
  }
}

resource "zia_endpoint_dlp_rules" "z_private_keys_endpoint" {
  name                         = "Z-Private Keys [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
}

resource "zia_casb_dlp_rules" "z_private_keys_saas" {
  name                         = "Z-Private Keys [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_private_keys_saas
  }
}

resource "zia_outbound_email_dlp" "z_private_keys_email" {
  name                         = "Z-Private Keys [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_private_keys_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_block_marked_documents_endpoint" {
  name                         = "CUI-Block-Marked-Documents [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
}

resource "zia_casb_dlp_rules" "cui_block_marked_documents_saas" {
  name                         = "CUI-Block-Marked-Documents [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_block_marked_documents_saas
  }
}

resource "zia_outbound_email_dlp" "cui_block_marked_documents_email" {
  name                         = "CUI-Block-Marked-Documents [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Block-Marked-Documents\" (CUI-Detect-Block-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_block_marked_documents_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_caution_weak_markings_endpoint" {
  name                         = "CUI-Caution-Weak-Markings [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
}

resource "zia_casb_dlp_rules" "cui_caution_weak_markings_saas" {
  name                         = "CUI-Caution-Weak-Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_caution_weak_markings_saas
  }
}

resource "zia_outbound_email_dlp" "cui_caution_weak_markings_email" {
  name                         = "CUI-Caution-Weak-Markings [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Caution-Weak-Markings\" (CUI-Detect-Caution-Grade). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_caution_weak_markings_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_monitor_all_endpoint" {
  name                         = "CUI-Monitor-All [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All, CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id, zia_dlp_engines.cui_detect_contextual.id]
  }
}

resource "zia_casb_dlp_rules" "cui_monitor_all_saas" {
  name                         = "CUI-Monitor-All [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All, CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id, zia_dlp_engines.cui_detect_contextual.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_saas
  }
}

resource "zia_outbound_email_dlp" "cui_monitor_all_email" {
  name                         = "CUI-Monitor-All [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All, CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id, zia_dlp_engines.cui_detect_contextual.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_email
  }
}

resource "zia_endpoint_dlp_rules" "aea_high_confidence_endpoint_removable_media" {
  name                         = "AEA High Confidence [Endpoint Removable Media]"
  description                  = "Endpoint DLP: AEA High Confidence on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
}

resource "zia_endpoint_dlp_rules" "financial_information_endpoint_removable_media" {
  name                         = "Financial Information [Endpoint Removable Media]"
  description                  = "Endpoint DLP: Financial Information on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 13
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
}

resource "zia_endpoint_dlp_rules" "fouo_markings_high_confidence_endpoint_removable_media" {
  name                         = "FOUO Markings High Confidence [Endpoint Removable Media]"
  description                  = "Endpoint DLP: FOUO Markings High Confidence on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 14
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id]
  }
}

resource "zia_endpoint_dlp_rules" "fouo_markings_medium_confidence_endpoint_removable_media" {
  name                         = "FOUO Markings Medium Confidence [Endpoint Removable Media]"
  description                  = "Endpoint DLP: FOUO Markings Medium Confidence on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 15
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_endpoint_dlp_rules" "itar_phrases_endpoint_removable_media" {
  name                         = "ITAR Phrases [Endpoint Removable Media]"
  description                  = "Endpoint DLP: ITAR Phrases on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 16
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
}

resource "zia_endpoint_dlp_rules" "standard_forms_endpoint_removable_media" {
  name                         = "Standard Forms [Endpoint Removable Media]"
  description                  = "Endpoint DLP: Standard Forms on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 17
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
}

resource "zia_endpoint_dlp_rules" "tlp_red_endpoint_removable_media" {
  name                         = "TLP Red [Endpoint Removable Media]"
  description                  = "Endpoint DLP: TLP Red on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 18
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id]
  }
}

resource "zia_endpoint_dlp_rules" "tlp_amber_strict_endpoint_removable_media" {
  name                         = "TLP Amber Strict [Endpoint Removable Media]"
  description                  = "Endpoint DLP: TLP Amber Strict on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 19
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber_strict.id]
  }
}

resource "zia_endpoint_dlp_rules" "tlp_amber_endpoint_removable_media" {
  name                         = "TLP Amber [Endpoint Removable Media]"
  description                  = "Endpoint DLP: TLP Amber on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 20
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_endpoint_dlp_rules" "us_pii_endpoint_removable_media" {
  name                         = "US PII [Endpoint Removable Media]"
  description                  = "Endpoint DLP: US PII on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 21
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
}

resource "zia_endpoint_dlp_rules" "us_phi_medium_confidence_endpoint_removable_media" {
  name                         = "US PHI - Medium Confidence [Endpoint Removable Media]"
  description                  = "Endpoint DLP: US PHI - Medium Confidence on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 22
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id]
  }
}

resource "zia_endpoint_dlp_rules" "us_phi_high_confidence_endpoint_removable_media" {
  name                         = "US PHI - High Confidence [Endpoint Removable Media]"
  description                  = "Endpoint DLP: US PHI - High Confidence on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 23
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_endpoint_dlp_rules" "private_keys_endpoint_removable_media" {
  name                         = "Private Keys [Endpoint Removable Media]"
  description                  = "Endpoint DLP: Private Keys on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 24
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
}

resource "zia_endpoint_dlp_rules" "cui_detect_block_grade_endpoint_removable_media" {
  name                         = "CUI-Detect-Block-Grade [Endpoint Removable Media]"
  description                  = "Endpoint DLP: CUI-Detect-Block-Grade on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 25
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_block_grade.id]
  }
}

resource "zia_endpoint_dlp_rules" "cui_detect_caution_grade_endpoint_removable_media" {
  name                         = "CUI-Detect-Caution-Grade [Endpoint Removable Media]"
  description                  = "Endpoint DLP: CUI-Detect-Caution-Grade on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 26
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_caution_grade.id]
  }
}

resource "zia_endpoint_dlp_rules" "cui_detect_all_endpoint_removable_media" {
  name                         = "CUI-Detect-All [Endpoint Removable Media]"
  description                  = "Endpoint DLP: CUI-Detect-All on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 27
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
}

resource "zia_endpoint_dlp_rules" "cui_detect_contextual_endpoint_removable_media" {
  name                         = "CUI-Detect-Contextual [Endpoint Removable Media]"
  description                  = "Endpoint DLP: CUI-Detect-Contextual on removable media (USB and other removable drives). One rule per engine so incidents name the engine. Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 28
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_contextual.id]
  }
}

