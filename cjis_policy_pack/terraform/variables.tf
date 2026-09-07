# ── ZIA credentials ──────────────────────────────────────────
variable "zia_username" {
  type        = string
  sensitive   = true
  description = "ZIA admin username (email)"
}

variable "zia_password" {
  type        = string
  sensitive   = true
  description = "ZIA admin password"
}

variable "zia_api_key" {
  type        = string
  sensitive   = true
  description = "ZIA API key"
}

variable "zia_cloud" {
  type        = string
  default     = "zscalergov"
  description = "ZIA cloud (zscaler, zscalerone, zscalertwo, zscalerthree, zscloud, zscalergov, zscalerten)"
}

# ── AWS ─────────────────────────────────────────────────────
variable "aws_region" {
  type        = string
  default     = "us-gov-west-1"
  description = "AWS region for state backend (us-gov-west-1 for GovCloud)"
}

# ── Pack behavior ───────────────────────────────────────────
variable "policy_action" {
  type        = string
  default     = "ALLOW"
  description = "ALLOW = monitor only; BLOCK = enforce. Start with ALLOW."
  validation {
    condition     = contains(["ALLOW", "BLOCK"], var.policy_action)
    error_message = "Must be ALLOW or BLOCK."
  }
}

variable "policy_state" {
  type        = string
  default     = "ENABLED"
  description = "ENABLED or DISABLED"
}

variable "policy_rank" {
  type        = number
  default     = 7
  description = "Policy rank. 0 = highest priority (Admin Rank 0). 7 = default."
}
