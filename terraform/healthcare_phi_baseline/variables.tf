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

variable "saas_tenant_ids_hc_hipaa_critical_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Critical [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_critical_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Critical [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_narrative_low_volume_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Narrative Low Volume [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_narrative_low_volume_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Narrative Low Volume [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_identity_trifecta_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Identity Trifecta [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_identity_trifecta_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Identity Trifecta [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_sensitive_subcategory_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Sensitive Subcategory [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_sensitive_subcategory_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Sensitive Subcategory [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_pharmacy_claims_billing_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Pharmacy Claims Billing [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_pharmacy_claims_billing_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Pharmacy Claims Billing [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_major_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Major [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_major_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Major [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_significant_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Significant [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_significant_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Significant [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_small_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Small [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_hipaa_bulk_phi_small_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-HIPAA Bulk PHI Small [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_pii_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PII [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_pii_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PII [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_phi_medium_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PHI Medium Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_phi_medium_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PHI Medium Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_phi_high_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PHI High Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_hc_us_phi_high_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule HC-US PHI High Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

