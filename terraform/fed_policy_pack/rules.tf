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

resource "zia_dlp_web_rules" "z_fouo_markings_high_confidence_monitor" {
  name                         = "Z-FOUO Markings High Confidence-Monitor"
  description                  = "One rule per engine: this rule carries FOUO Markings High Confidence only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_fouo_markings_medium_confidence_monitor" {
  name                         = "Z-FOUO Markings Medium Confidence-Monitor"
  description                  = "One rule per engine: this rule carries FOUO Markings Medium Confidence only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_itar_international_traffic_in_arms_regulations_monitor" {
  name                         = "Z-ITAR International Traffic in Arms Regulations-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
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
  order                        = var.rule_starting_order + 5
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

resource "zia_dlp_web_rules" "z_tlp_red_monitor" {
  name                         = "Z-TLP Red-Monitor"
  description                  = "One rule per engine: this rule carries TLP Red only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id]
  }
}

resource "zia_dlp_web_rules" "z_tlp_amber_strict_monitor" {
  name                         = "Z-TLP Amber Strict-Monitor"
  description                  = "One rule per engine: this rule carries TLP Amber Strict only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber_strict.id]
  }
}

resource "zia_dlp_web_rules" "z_tlp_amber_monitor" {
  name                         = "Z-TLP Amber-Monitor"
  description                  = "One rule per engine: this rule carries TLP Amber only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_dlp_web_rules" "z_us_pii_monitor" {
  name                         = "Z-US PII-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
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

resource "zia_dlp_web_rules" "z_us_phi_medium_confidence_monitor" {
  name                         = "Z-US PHI - Medium Confidence-Monitor"
  description                  = "One rule per engine: this rule carries US PHI - Medium Confidence only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_us_phi_high_confidence_monitor" {
  name                         = "Z-US PHI - High Confidence-Monitor"
  description                  = "One rule per engine: this rule carries US PHI - High Confidence only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_private_keys_monitor" {
  name                         = "Z-Private Keys-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
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
  order                        = var.rule_starting_order + 13
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  # Ships monitor-only; the designed action once incidents are tuned is BLOCK.
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
  order                        = var.rule_starting_order + 14
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  # Ships monitor-only; the designed action once incidents are tuned is CONFIRM.
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
  description                  = "Inline Web DLP: monitor-only rule over the full CUI-Detect-All surface plus the content-based CUI-Detect-Contextual signal. Enable this first to size incident volume and tune before enabling the block and caution rules above it. One rule per engine: this rule carries CUI-Detect-All only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 15
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
}

resource "zia_dlp_web_rules" "cui_monitor_contextual" {
  name                         = "CUI-Monitor-Contextual"
  description                  = "Inline Web DLP: monitor-only rule over the full CUI-Detect-All surface plus the content-based CUI-Detect-Contextual signal. Enable this first to size incident volume and tune before enabling the block and caution rules above it. One rule per engine: this rule carries CUI-Detect-Contextual only. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 16
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_contextual.id]
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

resource "zia_endpoint_dlp_rules" "z_fouo_markings_high_confidence_endpoint" {
  name                         = "Z-FOUO Markings High Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-FOUO Markings High Confidence-Monitor\" (FOUO Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.fouo_markings_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_fouo_markings_high_confidence_saas" {
  name                         = "Z-FOUO Markings High Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-FOUO Markings High Confidence-Monitor\" (FOUO Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_fouo_markings_high_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "z_fouo_markings_high_confidence_email" {
  name                         = "Z-FOUO Markings High Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-FOUO Markings High Confidence-Monitor\" (FOUO Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_fouo_markings_high_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "z_fouo_markings_medium_confidence_endpoint" {
  name                         = "Z-FOUO Markings Medium Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-FOUO Markings Medium Confidence-Monitor\" (FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_fouo_markings_medium_confidence_saas" {
  name                         = "Z-FOUO Markings Medium Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-FOUO Markings Medium Confidence-Monitor\" (FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_fouo_markings_medium_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "z_fouo_markings_medium_confidence_email" {
  name                         = "Z-FOUO Markings Medium Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-FOUO Markings Medium Confidence-Monitor\" (FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_fouo_markings_medium_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "z_itar_international_traffic_in_arms_regulations_endpoint" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.itar_phrases.id]
  }
}

resource "zia_casb_dlp_rules" "z_itar_international_traffic_in_arms_regulations_saas" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
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
  order                        = var.rule_starting_order + 4
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
    id = [zia_dlp_engines.standard_forms.id]
  }
}

resource "zia_casb_dlp_rules" "z_standard_forms_saas" {
  name                         = "Z-Standard Forms [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
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
  order                        = var.rule_starting_order + 5
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

resource "zia_endpoint_dlp_rules" "z_tlp_red_endpoint" {
  name                         = "Z-TLP Red [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-TLP Red-Monitor\" (TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.tlp_red.id]
  }
}

resource "zia_casb_dlp_rules" "z_tlp_red_saas" {
  name                         = "Z-TLP Red [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-TLP Red-Monitor\" (TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_tlp_red_saas
  }
}

resource "zia_outbound_email_dlp" "z_tlp_red_email" {
  name                         = "Z-TLP Red [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-TLP Red-Monitor\" (TLP Red). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_tlp_red_email
  }
}

resource "zia_endpoint_dlp_rules" "z_tlp_amber_strict_endpoint" {
  name                         = "Z-TLP Amber Strict [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-TLP Amber Strict-Monitor\" (TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.tlp_amber_strict.id]
  }
}

resource "zia_casb_dlp_rules" "z_tlp_amber_strict_saas" {
  name                         = "Z-TLP Amber Strict [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-TLP Amber Strict-Monitor\" (TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber_strict.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_tlp_amber_strict_saas
  }
}

resource "zia_outbound_email_dlp" "z_tlp_amber_strict_email" {
  name                         = "Z-TLP Amber Strict [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-TLP Amber Strict-Monitor\" (TLP Amber Strict). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber_strict.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_tlp_amber_strict_email
  }
}

resource "zia_endpoint_dlp_rules" "z_tlp_amber_endpoint" {
  name                         = "Z-TLP Amber [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-TLP Amber-Monitor\" (TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_casb_dlp_rules" "z_tlp_amber_saas" {
  name                         = "Z-TLP Amber [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-TLP Amber-Monitor\" (TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_tlp_amber_saas
  }
}

resource "zia_outbound_email_dlp" "z_tlp_amber_email" {
  name                         = "Z-TLP Amber [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-TLP Amber-Monitor\" (TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_amber.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_tlp_amber_email
  }
}

resource "zia_endpoint_dlp_rules" "z_us_pii_endpoint" {
  name                         = "Z-US PII [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_pii_saas" {
  name                         = "Z-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
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
  order                        = var.rule_starting_order + 9
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

resource "zia_endpoint_dlp_rules" "z_us_phi_medium_confidence_endpoint" {
  name                         = "Z-US PHI - Medium Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PHI - Medium Confidence-Monitor\" (US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.us_phi_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_phi_medium_confidence_saas" {
  name                         = "Z-US PHI - Medium Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PHI - Medium Confidence-Monitor\" (US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_us_phi_medium_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "z_us_phi_medium_confidence_email" {
  name                         = "Z-US PHI - Medium Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PHI - Medium Confidence-Monitor\" (US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_us_phi_medium_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "z_us_phi_high_confidence_endpoint" {
  name                         = "Z-US PHI - High Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PHI - High Confidence-Monitor\" (US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
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
    id = [zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_phi_high_confidence_saas" {
  name                         = "Z-US PHI - High Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PHI - High Confidence-Monitor\" (US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.us_phi_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_us_phi_high_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "z_us_phi_high_confidence_email" {
  name                         = "Z-US PHI - High Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PHI - High Confidence-Monitor\" (US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_us_phi_high_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "z_private_keys_endpoint" {
  name                         = "Z-Private Keys [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
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
  order                        = var.rule_starting_order + 12
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
  order                        = var.rule_starting_order + 12
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
  order                        = var.rule_starting_order + 13
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
  order                        = var.rule_starting_order + 13
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
  order                        = var.rule_starting_order + 13
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
  order                        = var.rule_starting_order + 14
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
  order                        = var.rule_starting_order + 14
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
  order                        = var.rule_starting_order + 14
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 15
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
}

resource "zia_casb_dlp_rules" "cui_monitor_all_saas" {
  name                         = "CUI-Monitor-All [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 15
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_saas
  }
}

resource "zia_outbound_email_dlp" "cui_monitor_all_email" {
  name                         = "CUI-Monitor-All [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Monitor-All\" (CUI-Detect-All). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 15
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_all.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_monitor_all_email
  }
}

resource "zia_endpoint_dlp_rules" "cui_monitor_contextual_endpoint" {
  name                         = "CUI-Monitor-Contextual [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"CUI-Monitor-Contextual\" (CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 16
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_contextual.id]
  }
}

resource "zia_casb_dlp_rules" "cui_monitor_contextual_saas" {
  name                         = "CUI-Monitor-Contextual [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"CUI-Monitor-Contextual\" (CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 16
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_contextual.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_cui_monitor_contextual_saas
  }
}

resource "zia_outbound_email_dlp" "cui_monitor_contextual_email" {
  name                         = "CUI-Monitor-Contextual [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"CUI-Monitor-Contextual\" (CUI-Detect-Contextual). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v2.0] Terraform-managed."
  order                        = var.rule_starting_order + 16
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_detect_contextual.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_cui_monitor_contextual_email
  }
}

