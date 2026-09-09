# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "z_cjis_markings_monitor" {
  name                         = "Z-CJIS Markings-Monitor"
  description                  = "Monitor outbound content with explicit CJIS / CHRI / LES markings. Covers banner and portion markings anywhere in the document. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_markings_high_confidence.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_identifier_monitor" {
  name                         = "Z-CJIS Identifier-Monitor"
  description                  = "Monitor structured CJIS identifiers — NCIC ORI, FBI UCN, SID, NCIC Purpose Code. Any such identifier leaving the tenant is logged for review. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_identifier_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_criminal_history_monitor" {
  name                         = "Z-CJIS Criminal History-Monitor"
  description                  = "Monitor transmission of criminal-history records (RAP sheets, booking reports, incident reports) when they co-occur with subject PII. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.criminal_history_rap_sheet_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_ncic_iii_data_monitor" {
  name                         = "Z-CJIS NCIC III Data-Monitor"
  description                  = "Monitor NCIC / III query results (wanted persons, stolen property, missing persons) correlated with subject PII. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.ncic_iii_data_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_warrants_monitor" {
  name                         = "Z-CJIS Warrants-Monitor"
  description                  = "Monitor wanted-person / warrant content near subject PII — flags accidental or intentional exfil of active-warrant data. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.warrant_wanted_person_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_biometric_monitor" {
  name                         = "Z-CJIS Biometric-Monitor"
  description                  = "Monitor biometric references (fingerprint, palm, AFIS/IAFIS/NGI, booking photo) that co-occur with CJIS markings or structured identifiers. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.biometric_cji_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_nics_firearms_monitor" {
  name                         = "Z-CJIS NICS Firearms-Monitor"
  description                  = "Monitor NICS / firearm background-check terminology — ATF Form 4473, NICS denials, prohibited-person content. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_MEDIUM"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.nics_firearms_background_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_info_sharing_monitor" {
  name                         = "Z-CJIS Info-Sharing-Monitor"
  description                  = "Monitor egress of content derived from LE info-sharing portals (N-DEx, LEEP, Nlets, RISS) when coupled with subject identifiers. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.info_sharing_portal_engine.id]
  }
}

resource "zia_dlp_web_rules" "z_cjis_any_signal_monitor" {
  name                         = "Z-CJIS Any-Signal-Monitor"
  description                  = "Broad catch-all — any high-signal CJIS marking or structured identifier. Useful as a safety net while tuning the narrower policies above. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_MEDIUM"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_endpoint_monitor" {
  name                         = "Z-CJIS Endpoint-Monitor"
  description                  = "Endpoint DLP: monitor CJI leaving managed devices via removable media, printing, network shares and application file access. Uses the broadest CJIS engine; monitor-only. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  device_trust_levels          = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_saas_file_monitor" {
  name                         = "Z-CJIS SaaS File-Monitor"
  description                  = "SaaS Security API: scan files at rest in onboarded file-storage tenants (Box, Google Drive, OneDrive, SharePoint) for CJI and report incidents. Applies to every matching onboarded tenant; pin with \"tenants\": [\"<name>\"] to narrow. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_saas_file_monitor
  }
}

resource "zia_casb_dlp_rules" "z_cjis_saas_collaboration_monitor" {
  name                         = "Z-CJIS SaaS Collaboration-Monitor"
  description                  = "SaaS Security API: scan messages and attachments in onboarded collaboration tenants (Slack, Teams, Webex) for CJI and report incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "ENABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_COLLAB"
  collaboration_scope          = ["ANY"]
  components                   = ["COMPONENT_COLLAB_MESSAGES", "COMPONENT_COLLAB_ATTACHMENTS"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_saas_collaboration_monitor
  }
}

resource "zia_outbound_email_dlp" "z_cjis_email_monitor" {
  name                         = "Z-CJIS Email-Monitor"
  description                  = "Outbound Email DLP: monitor mail leaving onboarded Microsoft 365 / Gmail tenants for CJI markings, NCIC/III references and criminal-justice PII. Monitor-only; switch to BLOCK after tuning. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "ENABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_HIGH"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_email_monitor
  }
}

