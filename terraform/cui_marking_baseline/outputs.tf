output "dictionaries" {
  value = { for k, r in {
    cui_banner_structural = zia_dlp_dictionaries.cui_banner_structural
    cui_banner_ldc = zia_dlp_dictionaries.cui_banner_ldc
    cui_portionmark_structural = zia_dlp_dictionaries.cui_portionmark_structural
    cui_basic_bare = zia_dlp_dictionaries.cui_basic_bare
    cui_ldc_standalone = zia_dlp_dictionaries.cui_ldc_standalone
    cui_code_cti = zia_dlp_dictionaries.cui_code_cti
    cui_code_prvcy = zia_dlp_dictionaries.cui_code_prvcy
    cui_code_propin = zia_dlp_dictionaries.cui_code_propin
    cui_code_ssel = zia_dlp_dictionaries.cui_code_ssel
    cui_code_isvi = zia_dlp_dictionaries.cui_code_isvi
    cui_code_opsec = zia_dlp_dictionaries.cui_code_opsec
    cui_code_nnpi = zia_dlp_dictionaries.cui_code_nnpi
    cui_code_pcii = zia_dlp_dictionaries.cui_code_pcii
    cui_code_cvi = zia_dlp_dictionaries.cui_code_cvi
    cui_prox_expt = zia_dlp_dictionaries.cui_prox_expt
    cui_prox_tax = zia_dlp_dictionaries.cui_prox_tax
    cui_prox_lei = zia_dlp_dictionaries.cui_prox_lei
    cui_prox_crit = zia_dlp_dictionaries.cui_prox_crit
    cui_prox_nuc = zia_dlp_dictionaries.cui_prox_nuc
    cui_prox_intel = zia_dlp_dictionaries.cui_prox_intel
    cui_prox_legal = zia_dlp_dictionaries.cui_prox_legal
    cui_prox_procure = zia_dlp_dictionaries.cui_prox_procure
    legacy_fouo = zia_dlp_dictionaries.legacy_fouo
    legacy_les = zia_dlp_dictionaries.legacy_les
    legacy_sbu = zia_dlp_dictionaries.legacy_sbu
    legacy_distribution_statements = zia_dlp_dictionaries.legacy_distribution_statements
    cui_designation_indicator = zia_dlp_dictionaries.cui_designation_indicator
    cui_decontrol_context = zia_dlp_dictionaries.cui_decontrol_context
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    cui_detect_all = zia_dlp_engines.cui_detect_all
    cui_detect_block_grade = zia_dlp_engines.cui_detect_block_grade
    cui_detect_caution_grade = zia_dlp_engines.cui_detect_caution_grade
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.cui_block_marked_documents.name,
    zia_dlp_web_rules.cui_caution_weak_markings.name,
    zia_dlp_web_rules.cui_monitor_all.name,
    zia_ssl_inspection_rules.cui_ssl_decrypt_file_share_webmail_ai.name,
    zia_cloud_app_control_rule.cui_cac_ai_no_upload.name,
  ]
}
