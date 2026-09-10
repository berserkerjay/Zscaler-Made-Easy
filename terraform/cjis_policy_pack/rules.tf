# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.

resource "zia_dlp_web_rules" "z_cjis_markings_monitor" {
  name                         = "Z-CJIS Markings-Monitor"
  description                  = "Monitor outbound content with explicit CJIS / CHRI / LES markings. Covers banner and portion markings anywhere in the document. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
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
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  protocols                    = ["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_markings_endpoint" {
  name                         = "Z-CJIS Markings [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Markings-Monitor\" (CJIS Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
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
    id = [zia_dlp_engines.cjis_markings_high_confidence.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_markings_saas" {
  name                         = "Z-CJIS Markings [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Markings-Monitor\" (CJIS Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_markings_high_confidence.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_markings_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_markings_email" {
  name                         = "Z-CJIS Markings [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Markings-Monitor\" (CJIS Markings High Confidence). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 0
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cjis_markings_high_confidence.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_markings_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_identifier_endpoint" {
  name                         = "Z-CJIS Identifier [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Identifier-Monitor\" (CJIS Identifier Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
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
    id = [zia_dlp_engines.cjis_identifier_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_identifier_saas" {
  name                         = "Z-CJIS Identifier [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Identifier-Monitor\" (CJIS Identifier Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_identifier_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_identifier_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_identifier_email" {
  name                         = "Z-CJIS Identifier [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Identifier-Monitor\" (CJIS Identifier Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 1
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cjis_identifier_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_identifier_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_criminal_history_endpoint" {
  name                         = "Z-CJIS Criminal History [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Criminal History-Monitor\" (Criminal History / RAP Sheet Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
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
    id = [zia_dlp_engines.criminal_history_rap_sheet_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_criminal_history_saas" {
  name                         = "Z-CJIS Criminal History [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Criminal History-Monitor\" (Criminal History / RAP Sheet Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.criminal_history_rap_sheet_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_criminal_history_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_criminal_history_email" {
  name                         = "Z-CJIS Criminal History [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Criminal History-Monitor\" (Criminal History / RAP Sheet Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 2
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.criminal_history_rap_sheet_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_criminal_history_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_ncic_iii_data_endpoint" {
  name                         = "Z-CJIS NCIC III Data [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS NCIC III Data-Monitor\" (NCIC / III Data Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
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
    id = [zia_dlp_engines.ncic_iii_data_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_ncic_iii_data_saas" {
  name                         = "Z-CJIS NCIC III Data [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS NCIC III Data-Monitor\" (NCIC / III Data Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.ncic_iii_data_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_ncic_iii_data_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_ncic_iii_data_email" {
  name                         = "Z-CJIS NCIC III Data [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS NCIC III Data-Monitor\" (NCIC / III Data Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 3
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.ncic_iii_data_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_ncic_iii_data_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_warrants_endpoint" {
  name                         = "Z-CJIS Warrants [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Warrants-Monitor\" (Warrant / Wanted-Person Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
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
    id = [zia_dlp_engines.warrant_wanted_person_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_warrants_saas" {
  name                         = "Z-CJIS Warrants [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Warrants-Monitor\" (Warrant / Wanted-Person Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.warrant_wanted_person_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_warrants_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_warrants_email" {
  name                         = "Z-CJIS Warrants [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Warrants-Monitor\" (Warrant / Wanted-Person Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 4
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.warrant_wanted_person_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_warrants_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_biometric_endpoint" {
  name                         = "Z-CJIS Biometric [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Biometric-Monitor\" (Biometric CJI Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
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
    id = [zia_dlp_engines.biometric_cji_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_biometric_saas" {
  name                         = "Z-CJIS Biometric [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Biometric-Monitor\" (Biometric CJI Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.biometric_cji_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_biometric_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_biometric_email" {
  name                         = "Z-CJIS Biometric [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Biometric-Monitor\" (Biometric CJI Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 5
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.biometric_cji_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_biometric_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_nics_firearms_endpoint" {
  name                         = "Z-CJIS NICS Firearms [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS NICS Firearms-Monitor\" (NICS Firearms Background Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
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
    id = [zia_dlp_engines.nics_firearms_background_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_nics_firearms_saas" {
  name                         = "Z-CJIS NICS Firearms [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS NICS Firearms-Monitor\" (NICS Firearms Background Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.nics_firearms_background_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_nics_firearms_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_nics_firearms_email" {
  name                         = "Z-CJIS NICS Firearms [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS NICS Firearms-Monitor\" (NICS Firearms Background Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 6
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.nics_firearms_background_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_nics_firearms_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_info_sharing_endpoint" {
  name                         = "Z-CJIS Info-Sharing [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Info-Sharing-Monitor\" (Info-Sharing Portal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
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
    id = [zia_dlp_engines.info_sharing_portal_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_info_sharing_saas" {
  name                         = "Z-CJIS Info-Sharing [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Info-Sharing-Monitor\" (Info-Sharing Portal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.info_sharing_portal_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_info_sharing_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_info_sharing_email" {
  name                         = "Z-CJIS Info-Sharing [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Info-Sharing-Monitor\" (Info-Sharing Portal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 7
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.info_sharing_portal_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_info_sharing_email
  }
}

resource "zia_endpoint_dlp_rules" "z_cjis_any_signal_endpoint" {
  name                         = "Z-CJIS Any-Signal [Endpoint]"
  description                  = "Endpoint DLP: the same detection as the inline rule \"Z-CJIS Any-Signal-Monitor\" (CJIS Any-Signal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
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
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
}

resource "zia_casb_dlp_rules" "z_cjis_any_signal_saas" {
  name                         = "Z-CJIS Any-Signal [SaaS]"
  description                  = "SaaS Security API: the same detection as the inline rule \"Z-CJIS Any-Signal-Monitor\" (CJIS Any-Signal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  rank                         = var.policy_rank
  state                        = "DISABLED"
  action                       = "OFLCASB_DLP_REPORT_INCIDENT"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  type                         = "OFLCASB_DLP_FILE"
  collaboration_scope          = ["ANY"]
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
  cloud_app_tenants {
    id = var.saas_tenant_ids_z_cjis_any_signal_saas
  }
}

resource "zia_outbound_email_dlp" "z_cjis_any_signal_email" {
  name                         = "Z-CJIS Any-Signal [Email]"
  description                  = "Email DLP: the same detection as the inline rule \"Z-CJIS Any-Signal-Monitor\" (CJIS Any-Signal Engine). Monitor-only; enable after reviewing incidents. [DLP-Check pack cjis_policy_pack v1.0] Terraform-managed."
  order                        = var.rule_starting_order + 8
  state                        = "DISABLED"
  action                       = "ALLOW"
  severity                     = "RULE_SEVERITY_INFO"
  without_content_inspection   = false
  dlp_engines {
    id = [zia_dlp_engines.cjis_any_signal_engine.id]
  }
  email_tenants {
    id = var.saas_tenant_ids_z_cjis_any_signal_email
  }
}

