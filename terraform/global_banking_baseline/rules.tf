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

resource "zia_dlp_web_rules" "bank_payment_card_data_bulk_block" {
  name                         = "Bank-Payment Card Data-Bulk-Block"
  description                  = "Inline Web DLP: block bulk card-number exports (25+ distinct PANs or 5+ track records). Enforcing by design; ships disabled so you choose when. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
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

resource "zia_dlp_web_rules" "bank_customer_pii_monitor" {
  name                         = "Bank-Customer PII-Monitor"
  description                  = "Inline Web DLP: customer personal data across jurisdictions (US SSN/ITIN, UK/CA/AU/ZA and IN/SG/HK national IDs, EU/APAC passports, DOB with US licence) plus Zscaler's US PII engine. Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_global.id, zia_dlp_engines.zbp_us_pii.id]
  }
}

resource "zia_dlp_web_rules" "bank_customer_pii_bulk_block" {
  name                         = "Bank-Customer PII-Bulk-Block"
  description                  = "Inline Web DLP: block bulk customer-data exports (25+ distinct identifiers or 50+ dates of birth). Enforcing by design; ships disabled. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_pii_bulk.id]
  }
}

resource "zia_dlp_web_rules" "bank_customer_records_monitor" {
  name                         = "Bank-Customer Records-Monitor"
  description                  = "Inline Web DLP: account statements, KYC/AML case files and loan applications that carry an identifier. Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_customer_financial_records.id, zia_dlp_engines.bank_kyc_and_aml_files.id, zia_dlp_engines.bank_credit_and_loan_applications.id]
  }
}

resource "zia_dlp_web_rules" "bank_mnpi_monitor" {
  name                         = "Bank-MNPI-Monitor"
  description                  = "Inline Web DLP: material non-public information, deal documents and tax forms (Zscaler's Financial Information engine). Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.bank_mnpi_and_deal_information.id, zia_dlp_engines.zbp_financial_information.id]
  }
}

resource "zia_dlp_web_rules" "bank_confidential_markings_monitor" {
  name                         = "Bank-Confidential Markings-Monitor"
  description                  = "Inline Web DLP: any document stamped with a bank confidentiality marking. Monitor-only; a good first rule to enable because it has almost no false positives. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
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
  order                        = var.rule_starting_order + 8
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

resource "zia_endpoint_dlp_rules" "bank_endpoint_monitor" {
  name                         = "Bank-Endpoint-Monitor"
  description                  = "Endpoint DLP: card data, payment instructions, customer PII and customer records leaving managed devices via removable media, printing, network shares and application file access. Monitor-only. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id, zia_dlp_engines.bank_account_and_payment_instructions.id, zia_dlp_engines.bank_customer_pii_global.id, zia_dlp_engines.bank_customer_financial_records.id]
  }
}

resource "zia_endpoint_dlp_rules" "bank_endpoint_bulk_block_usb" {
  name                         = "Bank-Endpoint-Bulk-Block-USB"
  description                  = "Endpoint DLP: block bulk card-number or customer-data exports copied to removable drives. Enforcing by design; ships disabled. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  data_transfer_method         = "REMOVABLE_DRIVE_TRANSFER"
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data_bulk.id, zia_dlp_engines.bank_customer_pii_bulk.id]
  }
}

resource "zia_casb_dlp_rules" "bank_saas_file_monitor" {
  name                         = "Bank-SaaS File-Monitor"
  description                  = "SaaS Security API: scan files at rest in onboarded file-storage tenants (OneDrive, SharePoint, Box, Google Drive) for card data, payment instructions, customer PII and customer records; report incidents. Applies to every matching onboarded tenant. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id, zia_dlp_engines.bank_account_and_payment_instructions.id, zia_dlp_engines.bank_customer_pii_global.id, zia_dlp_engines.bank_customer_financial_records.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_bank_saas_file_monitor
  }
}

resource "zia_outbound_email_dlp" "bank_email_monitor" {
  name                         = "Bank-Email-Monitor"
  description                  = "Outbound Email DLP: monitor mail leaving onboarded Microsoft 365 / Gmail tenants for card data, payment instructions, customer PII, customer records and KYC files. Monitor-only; needs an email tenant under Administration > SaaS Application Tenants. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.bank_payment_card_data.id, zia_dlp_engines.bank_account_and_payment_instructions.id, zia_dlp_engines.bank_customer_pii_global.id, zia_dlp_engines.bank_customer_financial_records.id, zia_dlp_engines.bank_kyc_and_aml_files.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_bank_email_monitor
  }
}

