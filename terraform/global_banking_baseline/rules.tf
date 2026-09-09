# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

data "zia_cloud_applications" "apps_ssl_file_share" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["FILE_SHARE"]
}

data "zia_cloud_applications" "apps_ssl_webmail" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["WEBMAIL"]
}

data "zia_cloud_applications" "apps_ssl_ai_ml" {
  policy_type = "cloud_application_ssl_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_applications" "apps_file_share" {
  policy_type = "cloud_application_policy"
  app_class   = ["FILE_SHARE"]
}

data "zia_cloud_app_control_rule_actions" "bank_cac_file_share_no_upload_actions" {
  type       = "FILE_SHARE"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
}

data "zia_cloud_applications" "apps_webmail" {
  policy_type = "cloud_application_policy"
  app_class   = ["WEBMAIL"]
}

data "zia_cloud_app_control_rule_actions" "bank_cac_webmail_no_send_actions" {
  type       = "WEBMAIL"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_webmail.applications : a.app])))
}

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_app_control_rule_actions" "bank_cac_ai_no_upload_actions" {
  type       = "AI_ML"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
}

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

resource "zia_ssl_inspection_rules" "bank_ssl_decrypt_file_share_webmail_ai" {
  name                         = "Bank-SSL-Decrypt-File-Share-Webmail-AI"
  description                  = "SSL Inspection: decrypt traffic to file-sharing, webmail and AI/ML applications so the DLP rules can inspect HTTPS uploads. Without this, content inspection never sees the payload. Applications are resolved from the tenant catalogue at deploy time. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  platforms                    = ["SCAN_WINDOWS", "SCAN_MACOS", "SCAN_LINUX", "SCAN_IOS", "SCAN_ANDROID", "NO_CLIENT_CONNECTOR"]
  road_warrior_for_kerberos    = true
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ssl_file_share.applications : a.app], [for a in data.zia_cloud_applications.apps_ssl_webmail.applications : a.app], [for a in data.zia_cloud_applications.apps_ssl_ai_ml.applications : a.app])))
  # not in the zscaler/zia provider schema (set in the Admin Portal if needed): action.ssl_interception_cert.default_certificate = true
  action {
    type                   = "DECRYPT"
    override_default_certificate = false
    ssl_interception_cert {
      id                     = 1
    }
    decrypt_sub_actions {
      server_certificates    = "ALLOW"
      ocsp_check             = true
      block_ssl_traffic_with_no_sni_enabled = false
      min_client_tls_version = "CLIENT_TLS_1_2"
      min_server_tls_version = "SERVER_TLS_1_2"
      block_undecrypt        = false
      http2_enabled          = true
    }
  }
}

resource "zia_cloud_app_control_rule" "bank_cac_file_share_no_upload" {
  name                         = "Bank-CAC-File-Share-No-Upload"
  description                  = "Cloud App Control: on personal file-sharing applications, allow viewing and downloading but block upload and share. Stops bulk exports of customer data to personal cloud storage before content inspection is needed. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "FILE_SHARE"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.bank_cac_file_share_no_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD", "_SHARE"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_cloud_app_control_rule" "bank_cac_webmail_no_send" {
  name                         = "Bank-CAC-Webmail-No-Send"
  description                  = "Cloud App Control: on personal webmail (Gmail, Yahoo, ...), allow reading but block sending and attachments. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "WEBMAIL"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_webmail.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.bank_cac_webmail_no_send_actions.available_actions_without_isolate : a if (anytrue([for v in ["_SEND", "_ATTACHMENT_SEND"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_cloud_app_control_rule" "bank_cac_ai_no_upload" {
  name                         = "Bank-CAC-AI-No-Upload"
  description                  = "Cloud App Control: on AI & ML applications (ChatGPT and similar), allow browsing but block upload and file submission. Customer data and MNPI must not be pasted into public models. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "AI_ML"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.bank_cac_ai_no_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_file_type_control_rules" "bank_ftc_block_bulk_export_upload" {
  name                         = "Bank-FTC-Block-Bulk-Export-Upload"
  description                  = "File Type Control: block upload of spreadsheets, databases and archives to file-sharing applications. These are the bulk-export formats where DLP byte proximity is least reliable. Adjust file_types to the category names your tenant shows under Administration > File Type Control. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  filtering_action             = "BLOCK"
  operation                    = "UPLOAD"
  file_types                   = ["FTCATEGORY_MS_EXCEL", "FTCATEGORY_ZIP", "FTCATEGORY_RAR", "FTCATEGORY_TAR", "FTCATEGORY_GZIP", "FTCATEGORY_ACCDB", "FTCATEGORY_SQL"]
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE"]
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_url_filtering_rules" "bank_url_block_post_to_unknown" {
  name                         = "Bank-URL-Block-Post-To-Unknown"
  description                  = "URL Filtering: block POST/PUT (uploads and form submissions) to uncategorised and gambling sites. Closes the unknown-destination channel; adjust url_categories to your tenant's category names. [DLP-Check baseline global_banking_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  protocols                    = ["HTTP_RULE", "HTTPS_RULE"]
  url_categories               = ["OTHER_MISCELLANEOUS", "GAMBLING"]
  request_methods              = ["POST", "PUT"]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

