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

variable "saas_tenant_ids_src_csharp_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-CSharp Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_csharp_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-CSharp Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_cplusplus_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-CPlusPlus Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_cplusplus_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-CPlusPlus Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_go_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Go Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_go_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Go Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_html_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-HTML Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_html_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-HTML Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_java_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Java Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_java_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Java Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_javascript_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-JavaScript Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_javascript_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-JavaScript Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_kotlin_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Kotlin Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_kotlin_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Kotlin Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_python_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Python Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_python_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Python Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_rust_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Rust Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_rust_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Rust Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_sql_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-SQL Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_sql_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-SQL Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_swift_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Swift Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_swift_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Swift Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_typescript_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-TypeScript Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_typescript_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-TypeScript Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_vbnet_code_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-VBNet Code to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_vbnet_code_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-VBNet Code to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_private_keys_to_ai_saas" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Private Keys to AI [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_src_private_keys_to_ai_email" {
  description = "IDs of the onboarded SaaS application tenants rule SRC-Private Keys to AI [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

