# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "r_healthcare_phi_mrn_acct_dob" {
  name                         = "R_HEALTHCARE_PHI_MRN_ACCT_DOB"
  description                  = "Inline Web DLP: PHI presence (E_HEALTHCARE_PHI) or bulk export (E_PHI_BULK_EXPORT). Monitor-only to start; OCR on so screenshots and scanned PDFs are inspected; 10 KB floor suppresses small-telemetry false positives. Move to BLOCK after tuning. [DLP-Check baseline healthcare_phi_baseline v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  min_size                     = 10
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.e_healthcare_phi.id, zia_dlp_engines.e_phi_bulk_export.id]
  }
}

