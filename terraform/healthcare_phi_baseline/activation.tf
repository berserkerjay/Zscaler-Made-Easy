# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.r_healthcare_phi_mrn_acct_dob,
    zia_endpoint_dlp_rules.r_healthcare_phi_mrn_acct_dob_endpoint,
    zia_casb_dlp_rules.r_healthcare_phi_mrn_acct_dob_saas,
    zia_outbound_email_dlp.r_healthcare_phi_mrn_acct_dob_email,
  ]
}
