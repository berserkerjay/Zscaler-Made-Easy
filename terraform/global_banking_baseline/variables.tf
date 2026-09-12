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

variable "saas_tenant_ids_bank_payment_card_data_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Card Data [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_payment_card_data_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Card Data [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_payment_card_2_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Card 2 [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_payment_card_data_bulk_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Card Data-Bulk [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_payment_instruction_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Instruction [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_payment_instructions_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Payment Instructions [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_pii_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer PII [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_pii_global_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer PII (Global) [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_us_pii_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-US PII [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_us_pii_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-US PII [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_pii_bulk_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer PII-Bulk [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_pii_bulk_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer PII-Bulk [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_financial_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer Financial [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_customer_financial_records_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Customer Financial Records [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_kyc_and_aml_files_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-KYC and AML Files [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_kyc_and_aml_files_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-KYC and AML Files [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_credit_and_loan_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Credit and Loan [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_credit_and_loan_applications_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Credit and Loan Applications [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_mnpi_and_deal_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-MNPI and Deal [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_mnpi_and_deal_information_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-MNPI and Deal Information [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_financial_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Financial [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_financial_information_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Financial Information [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_confidential_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Confidential [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_confidential_markings_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Confidential Markings [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_credentials_saas" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Credentials [SaaS] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

variable "saas_tenant_ids_bank_credentials_email" {
  description = "IDs of the onboarded SaaS application tenants rule Bank-Credentials [Email] applies to (Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."
  type        = list(number)
}

