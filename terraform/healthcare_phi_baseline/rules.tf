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

data "zia_cloud_app_control_rule_actions" "r_phi_cac_file_share_no_upload_actions" {
  type       = "FILE_SHARE"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
}

data "zia_cloud_applications" "apps_webmail" {
  policy_type = "cloud_application_policy"
  app_class   = ["WEBMAIL"]
}

data "zia_cloud_app_control_rule_actions" "r_phi_cac_webmail_no_send_actions" {
  type       = "WEBMAIL"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_webmail.applications : a.app])))
}

data "zia_cloud_applications" "apps_ai_ml" {
  policy_type = "cloud_application_policy"
  app_class   = ["AI_ML"]
}

data "zia_cloud_app_control_rule_actions" "r_phi_cac_ai_no_upload_actions" {
  type       = "AI_ML"
  cloud_apps = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
}

resource "zia_dlp_web_rules" "r_healthcare_phi_mrn_acct_dob" {
  name                         = "R_HEALTHCARE_PHI_MRN_ACCT_DOB"
  description                  = "Inline Web DLP: PHI presence (E_HEALTHCARE_PHI) or bulk export (E_PHI_BULK_EXPORT). Monitor-only to start; OCR on so screenshots and scanned PDFs are inspected; 10 KB floor suppresses small-telemetry false positives. Move to BLOCK after tuning. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  min_size                     = 10
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
}

resource "zia_ssl_inspection_rules" "r_phi_ssl_decrypt_file_share_webmail_ai" {
  name                         = "R_PHI_SSL_DECRYPT_FILE_SHARE_WEBMAIL_AI"
  description                  = "SSL Inspection: decrypt traffic to file-sharing, webmail and AI/ML applications so the DLP rule can inspect HTTPS uploads. Without this, content inspection never sees the payload. Applications are resolved from the tenant catalogue at deploy time. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
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

resource "zia_cloud_app_control_rule" "r_phi_cac_file_share_no_upload" {
  name                         = "R_PHI_CAC_FILE_SHARE_NO_UPLOAD"
  description                  = "Cloud App Control: on file-sharing applications, allow viewing and downloading but block upload and share. Stops bulk exports to personal cloud storage before content inspection is needed. Actions are chosen from the tenant's available actions for each application. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "FILE_SHARE"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.r_phi_cac_file_share_no_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD", "_SHARE"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_cloud_app_control_rule" "r_phi_cac_webmail_no_send" {
  name                         = "R_PHI_CAC_WEBMAIL_NO_SEND"
  description                  = "Cloud App Control: on personal webmail (Gmail, Yahoo, ...), allow reading but block sending and attachments. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "WEBMAIL"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_webmail.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.r_phi_cac_webmail_no_send_actions.available_actions_without_isolate : a if (anytrue([for v in ["_SEND", "_ATTACHMENT_SEND"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_cloud_app_control_rule" "r_phi_cac_ai_no_upload" {
  name                         = "R_PHI_CAC_AI_NO_UPLOAD"
  description                  = "Cloud App Control: on AI & ML applications (ChatGPT and similar), allow browsing but block upload and file submission. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  type                         = "AI_ML"
  applications                 = sort(distinct(concat([for a in data.zia_cloud_applications.apps_ai_ml.applications : a.app])))
  actions                      = [for a in data.zia_cloud_app_control_rule_actions.r_phi_cac_ai_no_upload_actions.available_actions_without_isolate : a if (anytrue([for v in ["_UPLOAD"] : endswith(a, v)]) ? startswith(a, "BLOCK_") : (anytrue([for v in [] : endswith(a, v)]) ? startswith(a, "ALLOW_") : startswith(a, "ALLOW_")))]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_file_type_control_rules" "r_phi_ftc_block_bulk_export_upload" {
  name                         = "R_PHI_FTC_BLOCK_BULK_EXPORT_UPLOAD"
  description                  = "File Type Control: block upload of spreadsheets, databases and archives to file-sharing applications. These are the bulk-export formats where DLP byte proximity is least reliable. Adjust file_types to the category names your tenant shows under Administration > File Type Control. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
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

resource "zia_file_type_control_rules" "r_phi_ftc_caution_image_upload" {
  name                         = "R_PHI_FTC_CAUTION_IMAGE_UPLOAD"
  description                  = "File Type Control: caution on image uploads (screenshots, photographed records) to file-sharing applications. Images bypass text-based dictionaries; the DLP rule's OCR covers what you allow through. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  filtering_action             = "CAUTION"
  operation                    = "UPLOAD"
  file_types                   = ["FTCATEGORY_BITMAP", "FTCATEGORY_JPEG", "FTCATEGORY_PNG", "FTCATEGORY_TIFF"]
  protocols                    = ["HTTP_RULE", "HTTPS_RULE"]
  cloud_applications           = sort(distinct(concat([for a in data.zia_cloud_applications.apps_file_share.applications : a.app])))
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_url_filtering_rules" "r_phi_url_block_post_to_unknown" {
  name                         = "R_PHI_URL_BLOCK_POST_TO_UNKNOWN"
  description                  = "URL Filtering: block POST/PUT (uploads and form submissions) to uncategorised and gambling sites. Closes the unknown-destination channel; adjust url_categories to your tenant's category names. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "BLOCK"
  protocols                    = ["HTTP_RULE", "HTTPS_RULE"]
  url_categories               = ["OTHER_MISCELLANEOUS", "GAMBLING"]
  request_methods              = ["POST", "PUT"]
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
}

resource "zia_outbound_email_dlp" "r_phi_email_monitor" {
  name                         = "R_PHI_EMAIL_MONITOR"
  description                  = "Outbound Email DLP: monitor mail leaving onboarded Microsoft 365 / Gmail tenants for PHI (E_HEALTHCARE_PHI) and bulk exports (E_PHI_BULK_EXPORT). Monitor-only; needs an email tenant under Administration > SaaS Application Tenants. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_r_phi_email_monitor
  }
}

