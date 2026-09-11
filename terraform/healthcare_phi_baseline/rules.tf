# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "hc_hipaa_critical_monitor" {
  name                         = "HC-HIPAA Critical-Monitor"
  description                  = "Inline Web DLP, Engine 1: strong PHI signature with an identity anchor. Single record reportable: immediate investigation. Block-grade; ships DISABLED at INFO, raise to HIGH when enabled. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_critical_strong_signature_and_clinical_document.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_narrative_low_volume_monitor" {
  name                         = "HC-HIPAA Narrative Low Volume-Monitor"
  description                  = "Inline Web DLP, Engine 2: short-form clinical content with a name and a second identifier. Single record reportable; monitor first because referral and prior-authorization traffic to payers is legitimate. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_narrative_low_volume.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_identity_trifecta_monitor" {
  name                         = "HC-HIPAA Identity Trifecta-Monitor"
  description                  = "Inline Web DLP, Engine 3: name + DOB + SSN (or licence / TIN). Reportable under state breach law regardless of healthcare context. Block-grade. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_identity_trifecta.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_sensitive_subcategory_monitor" {
  name                         = "HC-HIPAA Sensitive Subcategory-Monitor"
  description                  = "Inline Web DLP, Engine 4: SUD, mental health, HIV, genetic and reproductive PHI beside an identifier. 42 CFR Part 2 and GINA: route to the restricted reviewer queue (attach a dedicated notification template and auditor). Block-grade. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_sensitive_subcategory.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_pharmacy_claims_billing_monitor" {
  name                         = "HC-HIPAA Pharmacy Claims Billing-Monitor"
  description                  = "Inline Web DLP, Engine 5: e-prescribing, pharmacy fills, claims, EOBs, prior authorizations and EDI. Monitor first: watch the false-positive rate of the merged pharmacy and claims pathways (Insurance Document and Credit Cards especially), and exclude the clearing house. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_pharmacy_claims_billing.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_bulk_phi_major_monitor" {
  name                         = "HC-HIPAA Bulk PHI Major-Monitor"
  description                  = "Inline Web DLP, Engine 6 MAJOR tier (> 500 identifiers): a potential 500+ individual breach. Bypass tier-2 review: Privacy Officer, legal counsel, executive incident response and forensics; breach risk assessment within 1 hour. Block-grade. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_major.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_bulk_phi_significant_monitor" {
  name                         = "HC-HIPAA Bulk PHI Significant-Monitor"
  description                  = "Inline Web DLP, Engine 6 significant tier (> 50 identifiers): executive escalation and immediate forensic investigation; still under the 500-individual notification threshold. Block-grade. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_significant.id]
  }
}

resource "zia_dlp_web_rules" "hc_hipaa_bulk_phi_small_monitor" {
  name                         = "HC-HIPAA Bulk PHI Small-Monitor"
  description                  = "Inline Web DLP, Engine 6 small tier (> 1 identifiers): any multi-record exposure. Standard tier-2 review; investigate and document for the annual HHS log. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_small.id]
  }
}

resource "zia_dlp_web_rules" "hc_us_pii_monitor" {
  name                         = "HC-US PII-Monitor"
  description                  = "Inline Web DLP, Engine 7: US PII (SSN, TIN, driver's licence, alien registration, passport, date of birth) from the Fed pack. Reportable under state breach law regardless of healthcare context. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_pii.id]
  }
}

resource "zia_dlp_web_rules" "hc_us_phi_medium_confidence_monitor" {
  name                         = "HC-US PHI Medium Confidence-Monitor"
  description                  = "Inline Web DLP, Engine 8: medical content plus one identifier (Fed pack US PHI - Medium Confidence). Second PHI opinion beside Engine 1. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_medium_confidence.id]
  }
}

resource "zia_dlp_web_rules" "hc_us_phi_high_confidence_monitor" {
  name                         = "HC-US PHI High Confidence-Monitor"
  description                  = "Inline Web DLP, Engine 9: dense medical content plus five identifiers, or an identifier beside its label (Fed pack US PHI - High Confidence). Block-grade. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "hc_financial_information_monitor" {
  name                         = "HC-Financial Information-Monitor"
  description                  = "Inline Web DLP, Engine 10: payment card, routing-number and tax-form data (Fed pack Financial Information). PCI DSS scope beside HIPAA. Monitor-only. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)
  dlp_engines {
    id = [zia_dlp_engines.hipaa_financial_information.id]
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_critical_endpoint" {
  name                         = "HC-HIPAA Critical [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Critical-Monitor\" (HIPAA Critical (Strong Signature and Clinical Document)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_critical_strong_signature_and_clinical_document.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_critical_saas" {
  name                         = "HC-HIPAA Critical [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Critical-Monitor\" (HIPAA Critical (Strong Signature and Clinical Document)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_critical_strong_signature_and_clinical_document.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_critical_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_critical_email" {
  name                         = "HC-HIPAA Critical [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Critical-Monitor\" (HIPAA Critical (Strong Signature and Clinical Document)). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_critical_strong_signature_and_clinical_document.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_critical_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_narrative_low_volume_endpoint" {
  name                         = "HC-HIPAA Narrative Low Volume [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Narrative Low Volume-Monitor\" (HIPAA Narrative - Low Volume). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_narrative_low_volume.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_narrative_low_volume_saas" {
  name                         = "HC-HIPAA Narrative Low Volume [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Narrative Low Volume-Monitor\" (HIPAA Narrative - Low Volume). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_narrative_low_volume.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_narrative_low_volume_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_narrative_low_volume_email" {
  name                         = "HC-HIPAA Narrative Low Volume [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Narrative Low Volume-Monitor\" (HIPAA Narrative - Low Volume). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_narrative_low_volume.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_narrative_low_volume_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_identity_trifecta_endpoint" {
  name                         = "HC-HIPAA Identity Trifecta [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Identity Trifecta-Monitor\" (HIPAA Identity Trifecta). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_identity_trifecta.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_identity_trifecta_saas" {
  name                         = "HC-HIPAA Identity Trifecta [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Identity Trifecta-Monitor\" (HIPAA Identity Trifecta). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_identity_trifecta.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_identity_trifecta_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_identity_trifecta_email" {
  name                         = "HC-HIPAA Identity Trifecta [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Identity Trifecta-Monitor\" (HIPAA Identity Trifecta). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_identity_trifecta.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_identity_trifecta_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_sensitive_subcategory_endpoint" {
  name                         = "HC-HIPAA Sensitive Subcategory [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Sensitive Subcategory-Monitor\" (HIPAA Sensitive Subcategory). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_sensitive_subcategory.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_sensitive_subcategory_saas" {
  name                         = "HC-HIPAA Sensitive Subcategory [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Sensitive Subcategory-Monitor\" (HIPAA Sensitive Subcategory). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_sensitive_subcategory.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_sensitive_subcategory_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_sensitive_subcategory_email" {
  name                         = "HC-HIPAA Sensitive Subcategory [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Sensitive Subcategory-Monitor\" (HIPAA Sensitive Subcategory). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_sensitive_subcategory.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_sensitive_subcategory_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_pharmacy_claims_billing_endpoint" {
  name                         = "HC-HIPAA Pharmacy Claims Billing [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Pharmacy Claims Billing-Monitor\" (HIPAA Pharmacy - Claims - Billing). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_pharmacy_claims_billing.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_pharmacy_claims_billing_saas" {
  name                         = "HC-HIPAA Pharmacy Claims Billing [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Pharmacy Claims Billing-Monitor\" (HIPAA Pharmacy - Claims - Billing). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_pharmacy_claims_billing.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_pharmacy_claims_billing_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_pharmacy_claims_billing_email" {
  name                         = "HC-HIPAA Pharmacy Claims Billing [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Pharmacy Claims Billing-Monitor\" (HIPAA Pharmacy - Claims - Billing). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_pharmacy_claims_billing.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_pharmacy_claims_billing_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_bulk_phi_major_endpoint" {
  name                         = "HC-HIPAA Bulk PHI Major [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Major-Monitor\" (HIPAA Bulk PHI - Major). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_bulk_phi_major.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_bulk_phi_major_saas" {
  name                         = "HC-HIPAA Bulk PHI Major [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Bulk PHI Major-Monitor\" (HIPAA Bulk PHI - Major). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_major.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_major_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_bulk_phi_major_email" {
  name                         = "HC-HIPAA Bulk PHI Major [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Major-Monitor\" (HIPAA Bulk PHI - Major). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_major.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_major_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_bulk_phi_significant_endpoint" {
  name                         = "HC-HIPAA Bulk PHI Significant [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Significant-Monitor\" (HIPAA Bulk PHI - Significant). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_bulk_phi_significant.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_bulk_phi_significant_saas" {
  name                         = "HC-HIPAA Bulk PHI Significant [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Bulk PHI Significant-Monitor\" (HIPAA Bulk PHI - Significant). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_significant.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_significant_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_bulk_phi_significant_email" {
  name                         = "HC-HIPAA Bulk PHI Significant [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Significant-Monitor\" (HIPAA Bulk PHI - Significant). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_significant.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_significant_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_hipaa_bulk_phi_small_endpoint" {
  name                         = "HC-HIPAA Bulk PHI Small [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Small-Monitor\" (HIPAA Bulk PHI - Small). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_bulk_phi_small.id]
  }
}

resource "zia_casb_dlp_rules" "hc_hipaa_bulk_phi_small_saas" {
  name                         = "HC-HIPAA Bulk PHI Small [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-HIPAA Bulk PHI Small-Monitor\" (HIPAA Bulk PHI - Small). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_small.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_small_saas
  }
}

resource "zia_outbound_email_dlp" "hc_hipaa_bulk_phi_small_email" {
  name                         = "HC-HIPAA Bulk PHI Small [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-HIPAA Bulk PHI Small-Monitor\" (HIPAA Bulk PHI - Small). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_bulk_phi_small.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_hipaa_bulk_phi_small_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_us_pii_endpoint" {
  name                         = "HC-US PII [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-US PII-Monitor\" (HIPAA US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_us_pii.id]
  }
}

resource "zia_casb_dlp_rules" "hc_us_pii_saas" {
  name                         = "HC-US PII [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-US PII-Monitor\" (HIPAA US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_pii.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_us_pii_saas
  }
}

resource "zia_outbound_email_dlp" "hc_us_pii_email" {
  name                         = "HC-US PII [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-US PII-Monitor\" (HIPAA US PII). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_pii.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_us_pii_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_us_phi_medium_confidence_endpoint" {
  name                         = "HC-US PHI Medium Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-US PHI Medium Confidence-Monitor\" (HIPAA US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_us_phi_medium_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "hc_us_phi_medium_confidence_saas" {
  name                         = "HC-US PHI Medium Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-US PHI Medium Confidence-Monitor\" (HIPAA US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 9
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_medium_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_us_phi_medium_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "hc_us_phi_medium_confidence_email" {
  name                         = "HC-US PHI Medium Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-US PHI Medium Confidence-Monitor\" (HIPAA US PHI - Medium Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 9
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_medium_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_us_phi_medium_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_us_phi_high_confidence_endpoint" {
  name                         = "HC-US PHI High Confidence [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-US PHI High Confidence-Monitor\" (HIPAA US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_us_phi_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "hc_us_phi_high_confidence_saas" {
  name                         = "HC-US PHI High Confidence [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-US PHI High Confidence-Monitor\" (HIPAA US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 10
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_us_phi_high_confidence_saas
  }
}

resource "zia_outbound_email_dlp" "hc_us_phi_high_confidence_email" {
  name                         = "HC-US PHI High Confidence [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-US PHI High Confidence-Monitor\" (HIPAA US PHI - High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 10
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_us_phi_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_us_phi_high_confidence_email
  }
}

resource "zia_endpoint_dlp_rules" "hc_financial_information_endpoint" {
  name                         = "HC-Financial Information [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"HC-Financial Information-Monitor\" (HIPAA Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
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
    id = [zia_dlp_engines.hipaa_financial_information.id]
  }
}

resource "zia_casb_dlp_rules" "hc_financial_information_saas" {
  name                         = "HC-Financial Information [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"HC-Financial Information-Monitor\" (HIPAA Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 11
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.hipaa_financial_information.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_hc_financial_information_saas
  }
}

resource "zia_outbound_email_dlp" "hc_financial_information_email" {
  name                         = "HC-Financial Information [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"HC-Financial Information-Monitor\" (HIPAA Financial Information). Monitor-only; enable after reviewing incidents. [DLP-Check baseline healthcare_phi_baseline v3.2] Terraform-managed."
  order                        = var.rule_starting_order + 11
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.hipaa_financial_information.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_hc_financial_information_email
  }
}

