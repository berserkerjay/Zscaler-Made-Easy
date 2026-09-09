# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "zbp_financial_information_monitor" {
  name                         = "ZBP-Financial Information-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_dlp_web_rules" "zbp_itar_international_traffic_in_arms_regulations_monitor" {
  name                         = "ZBP-ITAR International Traffic in Arms Regulations-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_itar_phrases.id]
  }
}

resource "zia_dlp_web_rules" "zbp_traffic_light_protocol_monitor" {
  name                         = "ZBP-Traffic Light Protocol-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_tlp_red.id, zia_dlp_engines.zbp_tlp_amber_strict.id, zia_dlp_engines.zbp_tlp_amber.id]
  }
}

resource "zia_dlp_web_rules" "zbp_us_pii_monitor" {
  name                         = "ZBP-US PII-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_dlp_web_rules" "zbp_us_phi_monitor" {
  name                         = "ZBP-US PHI-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_phi_medium_confidence.id, zia_dlp_engines.zbp_us_phi_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "zbp_private_keys_monitor" {
  name                         = "ZBP-Private Keys-Monitor"
  description                  = "[DLP-Check baseline zbp_enterprise_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["ANY_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
}

