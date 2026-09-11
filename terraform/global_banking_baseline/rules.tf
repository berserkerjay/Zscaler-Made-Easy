# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "bank_payment_card_data_monitor" {
  name                         = "Bank-Payment Card Data-Monitor"
  description                  = "Inline Web DLP: payment card data (PAN with CVV/PIN/expiry, several card numbers, magnetic tracks). Monitor-only to start; OCR on so photographed cards and scanned forms are inspected. Move to BLOCK after tuning. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id]
  }
}

resource "zia_dlp_web_rules" "bank_payment_card_data_bulk_monitor" {
  name                         = "Bank-Payment Card Data-Bulk-Monitor"
  description                  = "Inline Web DLP: block bulk card-number exports (25+ distinct PANs or 5+ track records). Enforcing by design; ships disabled so you choose when. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data_bulk.id]
  }
}

resource "zia_dlp_web_rules" "bank_payment_instructions_monitor" {
  name                         = "Bank-Payment Instructions-Monitor"
  description                  = "Inline Web DLP: bank account identifiers (ABA, EU IBAN, global IBAN, SWIFT/BIC) in payment context. Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_account_and_payment_instructions.id]
  }
}

resource "zia_dlp_web_rules" "bank_customer_pii_global_monitor" {
  name                         = "Bank-Customer PII (Global)-Monitor"
  description                  = "Inline Web DLP: customer personal data across jurisdictions (US SSN/ITIN, UK/CA/AU/ZA and IN/SG/HK national IDs, EU/APAC passports, DOB with US licence) plus Zscaler's US PII engine. Monitor-only. One rule per engine: this rule carries Bank-Customer PII (Global) only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_global.id]
  }
}

resource "zia_dlp_web_rules" "bank_us_pii_monitor" {
  name                         = "Bank-US PII-Monitor"
  description                  = "Inline Web DLP: customer personal data across jurisdictions (US SSN/ITIN, UK/CA/AU/ZA and IN/SG/HK national IDs, EU/APAC passports, DOB with US licence) plus Zscaler's US PII engine. Monitor-only. One rule per engine: this rule carries ZBP-US PII only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_dlp_web_rules" "bank_customer_pii_bulk_monitor" {
  name                         = "Bank-Customer PII-Bulk-Monitor"
  description                  = "Inline Web DLP: block bulk customer-data exports (25+ distinct identifiers or 50+ dates of birth). Enforcing by design; ships disabled. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_bulk.id]
  }
}

resource "zia_dlp_web_rules" "bank_customer_financial_records_monitor" {
  name                         = "Bank-Customer Financial Records-Monitor"
  description                  = "Inline Web DLP: account statements, KYC/AML case files and loan applications that carry an identifier. Monitor-only. One rule per engine: this rule carries Bank-Customer Financial Records only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_financial_records.id]
  }
}

resource "zia_dlp_web_rules" "bank_kyc_and_aml_files_monitor" {
  name                         = "Bank-KYC and AML Files-Monitor"
  description                  = "Inline Web DLP: account statements, KYC/AML case files and loan applications that carry an identifier. Monitor-only. One rule per engine: this rule carries Bank-KYC and AML Files only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_kyc_and_aml_files.id]
  }
}

resource "zia_dlp_web_rules" "bank_credit_and_loan_applications_monitor" {
  name                         = "Bank-Credit and Loan Applications-Monitor"
  description                  = "Inline Web DLP: account statements, KYC/AML case files and loan applications that carry an identifier. Monitor-only. One rule per engine: this rule carries Bank-Credit and Loan Applications only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_credit_and_loan_applications.id]
  }
}

resource "zia_dlp_web_rules" "bank_mnpi_and_deal_information_monitor" {
  name                         = "Bank-MNPI and Deal Information-Monitor"
  description                  = "Inline Web DLP: material non-public information, deal documents and tax forms (Zscaler's Financial Information engine). Monitor-only. One rule per engine: this rule carries Bank-MNPI and Deal Information only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_mnpi_and_deal_information.id]
  }
}

resource "zia_dlp_web_rules" "bank_financial_information_monitor" {
  name                         = "Bank-Financial Information-Monitor"
  description                  = "Inline Web DLP: material non-public information, deal documents and tax forms (Zscaler's Financial Information engine). Monitor-only. One rule per engine: this rule carries ZBP-Financial Information only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_dlp_web_rules" "bank_confidential_markings_monitor" {
  name                         = "Bank-Confidential Markings-Monitor"
  description                  = "Inline Web DLP: any document stamped with a bank confidentiality marking. Monitor-only; a good first rule to enable because it has almost no false positives. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_confidential_markings.id]
  }
}

resource "zia_dlp_web_rules" "bank_credentials_monitor" {
  name                         = "Bank-Credentials-Monitor"
  description                  = "Inline Web DLP: private keys and secrets (Zscaler's Private Keys engine). Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
}

resource "zia_endpoint_dlp_rules" "bank_payment_card_data_endpoint" {
  name                         = "Bank-Payment Card Data [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Payment Card Data-Monitor\" (Bank-Payment Card Data). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_payment_card_data.id]
  }
}

resource "zia_casb_dlp_rules" "bank_payment_card_data_saas" {
  name                         = "Bank-Payment Card Data [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Payment Card Data-Monitor\" (Bank-Payment Card Data). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_payment_card_data_saas
  }
}

resource "zia_outbound_email_dlp" "bank_payment_card_data_email" {
  name                         = "Bank-Payment Card Data [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Payment Card Data-Monitor\" (Bank-Payment Card Data). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_payment_card_data_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_payment_card_data_bulk_endpoint" {
  name                         = "Bank-Payment Card Data-Bulk [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Payment Card Data-Bulk-Monitor\" (Bank-Payment Card Data - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_payment_card_data_bulk.id]
  }
}

resource "zia_casb_dlp_rules" "bank_payment_card_data_bulk_saas" {
  name                         = "Bank-Payment Card Data-Bulk [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Payment Card Data-Bulk-Monitor\" (Bank-Payment Card Data - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data_bulk.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_payment_card_data_bulk_saas
  }
}

resource "zia_outbound_email_dlp" "bank_payment_card_data_bulk_email" {
  name                         = "Bank-Payment Card Data-Bulk [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Payment Card Data-Bulk-Monitor\" (Bank-Payment Card Data - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data_bulk.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_payment_card_data_bulk_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_payment_instructions_endpoint" {
  name                         = "Bank-Payment Instructions [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Payment Instructions-Monitor\" (Bank-Account and Payment Instructions). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_account_and_payment_instructions.id]
  }
}

resource "zia_casb_dlp_rules" "bank_payment_instructions_saas" {
  name                         = "Bank-Payment Instructions [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Payment Instructions-Monitor\" (Bank-Account and Payment Instructions). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_account_and_payment_instructions.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_payment_instructions_saas
  }
}

resource "zia_outbound_email_dlp" "bank_payment_instructions_email" {
  name                         = "Bank-Payment Instructions [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Payment Instructions-Monitor\" (Bank-Account and Payment Instructions). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_account_and_payment_instructions.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_payment_instructions_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_customer_pii_global_endpoint" {
  name                         = "Bank-Customer PII (Global) [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Customer PII (Global)-Monitor\" (Bank-Customer PII (Global)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_customer_pii_global.id]
  }
}

resource "zia_casb_dlp_rules" "bank_customer_pii_global_saas" {
  name                         = "Bank-Customer PII (Global) [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Customer PII (Global)-Monitor\" (Bank-Customer PII (Global)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_global.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_customer_pii_global_saas
  }
}

resource "zia_outbound_email_dlp" "bank_customer_pii_global_email" {
  name                         = "Bank-Customer PII (Global) [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Customer PII (Global)-Monitor\" (Bank-Customer PII (Global)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_global.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_customer_pii_global_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_us_pii_endpoint" {
  name                         = "Bank-US PII [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "bank_us_pii_saas" {
  name                         = "Bank-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_us_pii_saas
  }
}

resource "zia_outbound_email_dlp" "bank_us_pii_email" {
  name                         = "Bank-US PII [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-US PII-Monitor\" (ZBP-US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_us_pii.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_us_pii_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_customer_pii_bulk_endpoint" {
  name                         = "Bank-Customer PII-Bulk [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Customer PII-Bulk-Monitor\" (Bank-Customer PII - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_customer_pii_bulk.id]
  }
}

resource "zia_casb_dlp_rules" "bank_customer_pii_bulk_saas" {
  name                         = "Bank-Customer PII-Bulk [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Customer PII-Bulk-Monitor\" (Bank-Customer PII - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_bulk.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_customer_pii_bulk_saas
  }
}

resource "zia_outbound_email_dlp" "bank_customer_pii_bulk_email" {
  name                         = "Bank-Customer PII-Bulk [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Customer PII-Bulk-Monitor\" (Bank-Customer PII - Bulk). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_bulk.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_customer_pii_bulk_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_customer_financial_records_endpoint" {
  name                         = "Bank-Customer Financial Records [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Customer Financial Records-Monitor\" (Bank-Customer Financial Records). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_customer_financial_records.id]
  }
}

resource "zia_casb_dlp_rules" "bank_customer_financial_records_saas" {
  name                         = "Bank-Customer Financial Records [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Customer Financial Records-Monitor\" (Bank-Customer Financial Records). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_financial_records.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_customer_financial_records_saas
  }
}

resource "zia_outbound_email_dlp" "bank_customer_financial_records_email" {
  name                         = "Bank-Customer Financial Records [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Customer Financial Records-Monitor\" (Bank-Customer Financial Records). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_financial_records.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_customer_financial_records_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_kyc_and_aml_files_endpoint" {
  name                         = "Bank-KYC and AML Files [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-KYC and AML Files-Monitor\" (Bank-KYC and AML Files). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_kyc_and_aml_files.id]
  }
}

resource "zia_casb_dlp_rules" "bank_kyc_and_aml_files_saas" {
  name                         = "Bank-KYC and AML Files [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-KYC and AML Files-Monitor\" (Bank-KYC and AML Files). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_kyc_and_aml_files.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_kyc_and_aml_files_saas
  }
}

resource "zia_outbound_email_dlp" "bank_kyc_and_aml_files_email" {
  name                         = "Bank-KYC and AML Files [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-KYC and AML Files-Monitor\" (Bank-KYC and AML Files). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_kyc_and_aml_files.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_kyc_and_aml_files_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_credit_and_loan_applications_endpoint" {
  name                         = "Bank-Credit and Loan Applications [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Credit and Loan Applications-Monitor\" (Bank-Credit and Loan Applications). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_credit_and_loan_applications.id]
  }
}

resource "zia_casb_dlp_rules" "bank_credit_and_loan_applications_saas" {
  name                         = "Bank-Credit and Loan Applications [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Credit and Loan Applications-Monitor\" (Bank-Credit and Loan Applications). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_credit_and_loan_applications.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_credit_and_loan_applications_saas
  }
}

resource "zia_outbound_email_dlp" "bank_credit_and_loan_applications_email" {
  name                         = "Bank-Credit and Loan Applications [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Credit and Loan Applications-Monitor\" (Bank-Credit and Loan Applications). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_credit_and_loan_applications.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_credit_and_loan_applications_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_mnpi_and_deal_information_endpoint" {
  name                         = "Bank-MNPI and Deal Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-MNPI and Deal Information-Monitor\" (Bank-MNPI and Deal Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_mnpi_and_deal_information.id]
  }
}

resource "zia_casb_dlp_rules" "bank_mnpi_and_deal_information_saas" {
  name                         = "Bank-MNPI and Deal Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-MNPI and Deal Information-Monitor\" (Bank-MNPI and Deal Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_mnpi_and_deal_information.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_mnpi_and_deal_information_saas
  }
}

resource "zia_outbound_email_dlp" "bank_mnpi_and_deal_information_email" {
  name                         = "Bank-MNPI and Deal Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-MNPI and Deal Information-Monitor\" (Bank-MNPI and Deal Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 9
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_mnpi_and_deal_information.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_mnpi_and_deal_information_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_financial_information_endpoint" {
  name                         = "Bank-Financial Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_casb_dlp_rules" "bank_financial_information_saas" {
  name                         = "Bank-Financial Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_financial_information_saas
  }
}

resource "zia_outbound_email_dlp" "bank_financial_information_email" {
  name                         = "Bank-Financial Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Financial Information-Monitor\" (ZBP-Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 10
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_financial_information.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_financial_information_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_confidential_markings_endpoint" {
  name                         = "Bank-Confidential Markings [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Confidential Markings-Monitor\" (Bank-Confidential Markings). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.bank_confidential_markings.id]
  }
}

resource "zia_casb_dlp_rules" "bank_confidential_markings_saas" {
  name                         = "Bank-Confidential Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Confidential Markings-Monitor\" (Bank-Confidential Markings). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_confidential_markings.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_confidential_markings_saas
  }
}

resource "zia_outbound_email_dlp" "bank_confidential_markings_email" {
  name                         = "Bank-Confidential Markings [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Confidential Markings-Monitor\" (Bank-Confidential Markings). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 11
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_confidential_markings.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_confidential_markings_email
  }
}

resource "zia_endpoint_dlp_rules" "bank_credentials_endpoint" {
  name                         = "Bank-Credentials [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Bank-Credentials-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
}

resource "zia_casb_dlp_rules" "bank_credentials_saas" {
  name                         = "Bank-Credentials [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Bank-Credentials-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_credentials_saas
  }
}

resource "zia_outbound_email_dlp" "bank_credentials_email" {
  name                         = "Bank-Credentials [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Bank-Credentials-Monitor\" (ZBP-Private Keys). Monitor-only; enable after reviewing incidents. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 12
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.zbp_private_keys.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_credentials_email
  }
}

