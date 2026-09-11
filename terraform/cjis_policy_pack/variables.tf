variable "zscaler_client_id" {
  description = "OneAPI client ID. Leave null to use ZSCALER_CLIENT_ID."
  type        = string
  default     = null
  sensitive   = true
}

variable "zscaler_client_secret" {
  description = "OneAPI client secret. Leave null to use ZSCALER_CLIENT_SECRET."
  type        = string
  default     = null
  sensitive   = true
}

variable "zscaler_vanity_domain" {
  description = "ZIdentity vanity domain (acme for acme.zslogin.net). Leave null to use ZSCALER_VANITY_DOMAIN."
  type        = string
  default     = null
}

variable "zscaler_cloud" {
  description = "Leave null (or empty) for commercial production; beta, gov or govus otherwise. Env: ZSCALER_CLOUD."
  type        = string
  default     = null
}

variable "rule_starting_order" {
  description = "Order given to the first NEW rule of each channel; further new rules follow contiguously. Existing rules imported in gap mode keep their current order."
  type        = number
  default     = 1
}

variable "policy_rank" {
  description = "Admin rank for the rules (0-7). 0 takes precedence over rules made by lower-ranked admins."
  type        = number
  default     = 7
}

variable "activate" {
  description = "Activate pending ZIA changes after apply (zia_activation_status)."
  type        = bool
  default     = true
}

variable "saas_tenant_ids_z_cjis_markings_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Markings [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_markings_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Markings [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_identifier_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Identifier [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_identifier_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Identifier [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_criminal_history_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Criminal History [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_criminal_history_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Criminal History [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_ncic_iii_data_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS NCIC III Data [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_ncic_iii_data_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS NCIC III Data [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_warrants_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Warrants [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_warrants_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Warrants [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_biometric_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Biometric [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_biometric_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Biometric [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_nics_firearms_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS NICS Firearms [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_nics_firearms_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS NICS Firearms [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_info_sharing_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Info-Sharing [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_info_sharing_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Info-Sharing [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_any_signal_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Any-Signal [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_any_signal_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Any-Signal [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_markings_medium_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Markings Medium Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_cjis_markings_medium_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-CJIS Markings Medium Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

