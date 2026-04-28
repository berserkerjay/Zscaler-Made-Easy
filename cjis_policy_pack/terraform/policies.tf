# ──────────────────────────────────────────────────────────────
# CJIS Policies — 9 DLP web rules (monitor-first by default)
# ──────────────────────────────────────────────────────────────
# action, state, and rank are driven by variables so you can
# flip from ALLOW (monitor) to BLOCK (enforce) in tfvars
# without touching the resource definitions.
# ──────────────────────────────────────────────────────────────

resource "zia_dlp_web_rules" "cjis_markings" {
  name      = "Z-CJIS Markings-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 1
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.markings_high.id]
  }
}

resource "zia_dlp_web_rules" "cjis_identifiers" {
  name      = "Z-CJIS Identifier-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 2
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.identifiers.id]
  }
}

resource "zia_dlp_web_rules" "criminal_history" {
  name      = "Z-CJIS Criminal History-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 3
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.criminal_history.id]
  }
}

resource "zia_dlp_web_rules" "ncic_iii" {
  name      = "Z-CJIS NCIC III Data-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 4
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.ncic_iii.id]
  }
}

resource "zia_dlp_web_rules" "warrants" {
  name      = "Z-CJIS Warrants-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 5
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.warrants.id]
  }
}

resource "zia_dlp_web_rules" "biometric" {
  name      = "Z-CJIS Biometric-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 6
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.biometric.id]
  }
}

resource "zia_dlp_web_rules" "nics" {
  name      = "Z-CJIS NICS Firearms-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 7
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_MEDIUM"

  dlp_engines {
    id = [zia_dlp_engines.nics.id]
  }
}

resource "zia_dlp_web_rules" "info_sharing" {
  name      = "Z-CJIS Info-Sharing-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 8
  rank      = var.policy_rank
  protocols = ["HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_HIGH"

  dlp_engines {
    id = [zia_dlp_engines.info_sharing.id]
  }
}

resource "zia_dlp_web_rules" "any_signal" {
  name      = "Z-CJIS Any-Signal-Monitor"
  action    = var.policy_action
  state     = var.policy_state
  order     = 9
  rank      = var.policy_rank
  protocols = ["FTP_RULE", "HTTPS_RULE", "HTTP_PROXY"]
  severity  = "RULE_SEVERITY_MEDIUM"

  dlp_engines {
    id = [zia_dlp_engines.any_signal.id]
  }
}
