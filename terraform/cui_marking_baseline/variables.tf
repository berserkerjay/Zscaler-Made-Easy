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

variable "saas_tenant_ids_cui_email_monitor" {
  description = "IDs of the onboarded SaaS application tenants rule CUI-Email-Monitor applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

