# Activate pending ZIA configuration once every rule is in place.

resource "zia_activation_status" "this" {
  count  = var.activate ? 1 : 0
  status = "ACTIVE"

  depends_on = [
    zia_dlp_web_rules.cui_block_marked_documents,
    zia_dlp_web_rules.cui_caution_weak_markings,
    zia_dlp_web_rules.cui_monitor_all,
    zia_outbound_email_dlp.cui_email_monitor,
  ]
}
