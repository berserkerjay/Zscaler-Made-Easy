# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_eun_user_confirmation_template_product" "endpoint_dlp" {
  product = "ENDPOINT_DLP"
  name    = var.endpoint_dlp_user_confirmation_template_name
}

resource "zia_endpoint_dlp_application_group" "zbp_genai_applications" {
  name                         = "zbp-GenAI Applications"
  description                  = "ZBP managed Endpoint Application Group generated from Endpoint DLP golden config. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  resources                    = ["500000603", "500000601", "500000605", "600000601", "600000605", "600000603"]
}

resource "zia_endpoint_dlp_rules" "zbp_sensitive_data_to_usb" {
  name                         = "zbp-Sensitive Data to USB"
  description                  = "Endpoint DLP: sensitive data (PCI engines) copied to removable drives. Parent rule; the sub-rules below grade the response by engine confidence. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.pci_high.id, zia_dlp_engines.pci_medium.id, zia_dlp_engines.pci_low.id]
  }
}

resource "zia_endpoint_dlp_sub_rules" "zbp_pci_high_usb_block" {
  name                         = "zbp-PCI High USB Block"
  description                  = "Sub-rule: high-confidence PCI to USB is blocked. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  parent_rule                  = zia_endpoint_dlp_rules.zbp_sensitive_data_to_usb.rule_id
  order                        = 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.pci_high.id]
  }
}

resource "zia_endpoint_dlp_sub_rules" "zbp_pci_medium_usb" {
  name                         = "zbp-PCI Medium USB"
  description                  = "Sub-rule: medium-confidence PCI to USB asks the user to confirm (needs the tenant's Endpoint DLP user confirmation template). [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  parent_rule                  = zia_endpoint_dlp_rules.zbp_sensitive_data_to_usb.rule_id
  order                        = 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "CONFIRM"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  uc_template_id               = data.zia_eun_user_confirmation_template_product.endpoint_dlp.id
  dlp_engines {
    id = [zia_dlp_engines.pci_medium.id]
  }
}

resource "zia_endpoint_dlp_sub_rules" "zbp_pci_low_usb" {
  name                         = "zbp-PCI Low USB"
  description                  = "Sub-rule: low-confidence PCI to USB is allowed and logged. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  parent_rule                  = zia_endpoint_dlp_rules.zbp_sensitive_data_to_usb.rule_id
  order                        = 3
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
    id = [zia_dlp_engines.pci_low.id]
  }
}

resource "zia_endpoint_dlp_rules" "zbp_unapproved_genai_applications" {
  name                         = "zbp-Unapproved GenAI Applications"
  description                  = "Endpoint DLP: sensitive data opened by unapproved desktop GenAI applications (the zbp-GenAI Applications group: ChatGPT and Claude desktop apps on Windows and macOS). [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "APPLICATION_FILE_ACCESS"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  end_point_application_groups {
    group_id = [tostring(zia_endpoint_dlp_application_group.zbp_genai_applications.group_id)]
  }
  lifecycle {
    ignore_changes = [end_point_application_groups]
  }
  dlp_engines {
    id = [zia_dlp_engines.pci_high.id, zia_dlp_engines.pci_medium.id, zia_dlp_engines.pci_low.id]
  }
}

resource "zia_endpoint_dlp_sub_rules" "zbp_genai_application_block" {
  name                         = "zbp-GenAI Application Block"
  description                  = "Sub-rule: high/medium-confidence PCI opened by a GenAI desktop app is blocked. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  parent_rule                  = zia_endpoint_dlp_rules.zbp_unapproved_genai_applications.rule_id
  order                        = 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "APPLICATION_FILE_ACCESS"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  end_point_application_groups {
    group_id = [tostring(zia_endpoint_dlp_application_group.zbp_genai_applications.group_id)]
  }
  lifecycle {
    ignore_changes = [end_point_application_groups]
  }
  dlp_engines {
    id = [zia_dlp_engines.pci_high.id, zia_dlp_engines.pci_medium.id]
  }
}

resource "zia_endpoint_dlp_sub_rules" "zbp_genai_application_monitor" {
  name                         = "zbp-GenAI Application Monitor"
  description                  = "Sub-rule: low-confidence PCI opened by a GenAI desktop app is allowed and logged. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  parent_rule                  = zia_endpoint_dlp_rules.zbp_unapproved_genai_applications.rule_id
  order                        = 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "APPLICATION_FILE_ACCESS"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  end_point_application_groups {
    group_id = [tostring(zia_endpoint_dlp_application_group.zbp_genai_applications.group_id)]
  }
  lifecycle {
    ignore_changes = [end_point_application_groups]
  }
  dlp_engines {
    id = [zia_dlp_engines.pci_low.id]
  }
}

resource "zia_endpoint_dlp_rules" "zbp_sensitive_data_private_share" {
  name                         = "zbp-Sensitive Data Private Share"
  description                  = "Endpoint DLP: sensitive data (PCI engines) copied to network drives / private shares. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "NETWORK_DRIVE_TRANSFER"
  user_risk_score_levels       = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
  eun_enabled                  = false
  dlp_engines {
    id = [zia_dlp_engines.pci_high.id, zia_dlp_engines.pci_medium.id, zia_dlp_engines.pci_low.id]
  }
}

