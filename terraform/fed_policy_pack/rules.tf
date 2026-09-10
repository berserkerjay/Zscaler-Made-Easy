# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "z_atomic_energy_act_monitor" {
  name                         = "Z-Atomic Energy Act Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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

resource "zia_dlp_web_rules" "z_controlled_unclassified_information_monitor" {
  name                         = "Z-Controlled Unclassified Information-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["WEBSOCKETSSL_RULE", "WEBSOCKET_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.cui_engine_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_private_keys_monitor" {
  name                         = "Z-Private Keys-Monitor"
  description                  = "[DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 9
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

resource "zia_endpoint_dlp_rules" "z_atomic_energy_act_endpoint" {
  name                         = "Z-Atomic Energy Act [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.aea_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_atomic_energy_act_saas" {
  name                         = "Z-Atomic Energy Act [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-Atomic Energy Act Monitor\" (AEA High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.financial_information.id]
  }
}

resource "zia_casb_dlp_rules" "z_financial_information_saas" {
  name                         = "Z-Financial Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-Financial Information-Monitor\" (Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.fouo_markings_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_for_official_use_only_markings_saas" {
  name                         = "Z-For Official Use Only Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-For Official Use Only Markings-Monitor\" (FOUO Markings High Confidence, FOUO Markings Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.itar_phrases.id]
  }
}

resource "zia_casb_dlp_rules" "z_itar_international_traffic_in_arms_regulations_saas" {
  name                         = "Z-ITAR International Traffic in Arms Regulations [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-ITAR International Traffic in Arms Regulations-Monitor\" (ITAR Phrases). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.standard_forms.id]
  }
}

resource "zia_casb_dlp_rules" "z_standard_forms_saas" {
  name                         = "Z-Standard Forms [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-Standard Forms-Monitor\" (Standard Forms). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.tlp_red.id, zia_dlp_engines.tlp_amber_strict.id, zia_dlp_engines.tlp_amber.id]
  }
}

resource "zia_casb_dlp_rules" "z_traffic_light_protocol_saas" {
  name                         = "Z-Traffic Light Protocol [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-Traffic Light Protocol-Monitor\" (TLP Red, TLP Amber Strict, TLP Amber). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_pii_saas" {
  name                         = "Z-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PII-Monitor\" (US PII). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.us_phi_medium_confidence.id, zia_dlp_engines.us_phi_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_us_phi_saas" {
  name                         = "Z-US PHI [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-US PHI-Monitor\" (US PHI - Medium Confidence, US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
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

resource "zia_endpoint_dlp_rules" "z_controlled_unclassified_information_endpoint" {
  name                         = "Z-Controlled Unclassified Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Controlled Unclassified Information-Monitor\" (CUI Engine (High Confidence), CUI Engine (Medium Confidence)). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.cui_engine_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_controlled_unclassified_information_saas" {
  name                         = "Z-Controlled Unclassified Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Controlled Unclassified Information-Monitor\" (CUI Engine (High Confidence), CUI Engine (Medium Confidence)). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.cui_engine_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_controlled_unclassified_information_saas
  }
}

resource "zia_outbound_email_dlp" "z_controlled_unclassified_information_email" {
  name                         = "Z-Controlled Unclassified Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-Controlled Unclassified Information-Monitor\" (CUI Engine (High Confidence), CUI Engine (Medium Confidence)). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.cui_engine_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_controlled_unclassified_information_email
  }
}

resource "zia_endpoint_dlp_rules" "z_private_keys_endpoint" {
  name                         = "Z-Private Keys [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "ANY"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.private_keys.id]
  }
}

resource "zia_casb_dlp_rules" "z_private_keys_saas" {
  name                         = "Z-Private Keys [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 9
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
  description                  = "Email DLP: the same detection as the inline rule \"Z-Private Keys-Monitor\" (Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check pack fed_policy_pack v1.1] Terraform-managed."
  order                        = var.rule_starting_order + 9
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

