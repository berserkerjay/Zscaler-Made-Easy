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

variable "saas_tenant_ids_z_atomic_energy_act_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Atomic Energy Act [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_atomic_energy_act_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Atomic Energy Act [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_financial_information_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Financial Information [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_financial_information_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Financial Information [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_fouo_markings_high_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-FOUO Markings High Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_fouo_markings_high_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-FOUO Markings High Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_fouo_markings_medium_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-FOUO Markings Medium Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_fouo_markings_medium_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-FOUO Markings Medium Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_itar_international_traffic_in_arms_regulations_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-ITAR International Traffic in Arms Regulations [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_itar_international_traffic_in_arms_regulations_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-ITAR International Traffic in Arms Regulations [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_standard_forms_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Standard Forms [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_standard_forms_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Standard Forms [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_red_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Red [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_red_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Red [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_amber_strict_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Amber Strict [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_amber_strict_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Amber Strict [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_amber_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Amber [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_tlp_amber_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-TLP Amber [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_pii_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PII [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_pii_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PII [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_phi_medium_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PHI - Medium Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_phi_medium_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PHI - Medium Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_phi_high_confidence_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PHI - High Confidence [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_us_phi_high_confidence_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-US PHI - High Confidence [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_private_keys_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Private Keys [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_z_private_keys_email" {
  description = "IDs of the onboarded SaaS application tenants rule Z-Private Keys [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_marked_documents_saas" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Marked-Documents [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_marked_documents_email" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Marked-Documents [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_weak_markings_saas" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Weak-Markings [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_weak_markings_email" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Weak-Markings [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_all_saas" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-All [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_all_email" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-All [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_contextual_saas" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Contextual [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_cui_monitor_contextual_email" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Monitor-Contextual [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

