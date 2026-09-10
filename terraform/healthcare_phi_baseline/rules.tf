# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

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

resource "zia_endpoint_dlp_rules" "r_healthcare_phi_mrn_acct_dob_endpoint" {
  name                         = "R_HEALTHCARE_PHI_MRN_ACCT_DOB [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"R_HEALTHCARE_PHI_MRN_ACCT_DOB\" (E_HEALTHCARE_PHI, E_PHI_BULK_EXPORT). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
}

resource "zia_casb_dlp_rules" "r_healthcare_phi_mrn_acct_dob_saas" {
  name                         = "R_HEALTHCARE_PHI_MRN_ACCT_DOB [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"R_HEALTHCARE_PHI_MRN_ACCT_DOB\" (E_HEALTHCARE_PHI, E_PHI_BULK_EXPORT). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_r_healthcare_phi_mrn_acct_dob_saas
  }
}

resource "zia_outbound_email_dlp" "r_healthcare_phi_mrn_acct_dob_email" {
  name                         = "R_HEALTHCARE_PHI_MRN_ACCT_DOB [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"R_HEALTHCARE_PHI_MRN_ACCT_DOB\" (E_HEALTHCARE_PHI, E_PHI_BULK_EXPORT). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_r_healthcare_phi_mrn_acct_dob_email
  }
}

