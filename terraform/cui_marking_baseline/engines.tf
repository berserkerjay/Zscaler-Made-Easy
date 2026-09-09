# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "cui_detect_all" {
  name                         = "CUI-Detect-All"
  description                  = "Full CUI detection surface: banner grammar, category tokens, legacy markings, malformed-marking proximity, and designation blocks. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((((D${zia_dlp_dictionaries.cui_banner_structural.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_banner_ldc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_portionmark_structural.id}.S > 1) OR (D${zia_dlp_dictionaries.cui_code_cti.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_prvcy.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_propin.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_ssel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_isvi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_opsec.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_nnpi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_pcii.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_cvi.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_fouo.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_les.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_sbu.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_distribution_statements.id}.S > 0)) OR ((D${zia_dlp_dictionaries.cui_prox_expt.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_tax.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_lei.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_crit.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_nuc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_intel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_legal.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_procure.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_ldc_standalone.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_designation_indicator.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_basic_bare.id}.S > 2)))) AND NOT (D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0)"
}

resource "zia_dlp_engines" "cui_detect_block_grade" {
  name                         = "CUI-Detect-Block-Grade"
  description                  = "High-precision signals intended to BLOCK (16 dictionaries with their minimum counts), minus the exclusion dictionaries. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_banner_structural.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_banner_ldc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_portionmark_structural.id}.S > 1) OR (D${zia_dlp_dictionaries.cui_code_cti.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_prvcy.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_propin.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_ssel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_isvi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_opsec.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_nnpi.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_pcii.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_code_cvi.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_fouo.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_les.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_sbu.id}.S > 0) OR (D${zia_dlp_dictionaries.legacy_distribution_statements.id}.S > 0))) AND NOT ((D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0))"
}

resource "zia_dlp_engines" "cui_detect_caution_grade" {
  name                         = "CUI-Detect-Caution-Grade"
  description                  = "Lower-precision signals intended to CAUTION (11 dictionaries with their minimum counts), minus the exclusion dictionaries. Never wire to BLOCK. [DLP-Check baseline cui_marking_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(((D${zia_dlp_dictionaries.cui_basic_bare.id}.S > 2) OR (D${zia_dlp_dictionaries.cui_ldc_standalone.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_expt.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_tax.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_lei.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_crit.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_nuc.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_intel.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_legal.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_prox_procure.id}.S > 0) OR (D${zia_dlp_dictionaries.cui_designation_indicator.id}.S > 2))) AND NOT ((D${zia_dlp_dictionaries.cui_decontrol_context.id}.S > 0))"
}

