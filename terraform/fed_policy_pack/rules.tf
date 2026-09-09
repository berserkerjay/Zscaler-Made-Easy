# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "z_atomic_energy_act_monitor" {
  name                         = "Z-Atomic Energy Act Monitor"
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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
  description                  = "[DLP-Check pack fed_policy_pack] Terraform-managed."
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

resource "zia_endpoint_dlp_rules" "z_fed_endpoint_monitor" {
  name                         = "Z-Fed Endpoint-Monitor"
  description                  = "Endpoint DLP: monitor CUI, FOUO-marked and US PII content leaving managed devices via removable media, printing, network shares and application file access. Monitor-only. [DLP-Check pack fed_policy_pack] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "z_fed_saas_file_monitor" {
  name                         = "Z-Fed SaaS File-Monitor"
  description                  = "SaaS Security API: scan files at rest in onboarded file-storage tenants for CUI, FOUO markings and US PII; report incidents. Applies to every matching onboarded tenant. [DLP-Check pack fed_policy_pack] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.us_pii.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_fed_saas_file_monitor
  }
}

resource "zia_outbound_email_dlp" "z_fed_email_monitor" {
  name                         = "Z-Fed Email-Monitor"
  description                  = "Outbound Email DLP: monitor mail leaving onboarded Microsoft 365 / Gmail tenants for CUI, FOUO markings and US PII. Monitor-only. [DLP-Check pack fed_policy_pack] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cui_engine_high_confidence.id, zia_dlp_engines.fouo_markings_high_confidence.id, zia_dlp_engines.us_pii.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_fed_email_monitor
  }
}

