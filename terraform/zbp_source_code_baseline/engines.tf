# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "zbp_python_code_detection_engine" {
  name                         = "ZBP-Python Code Detection Engine"
  description                  = "ZBP managed source-code DLP engine for Python. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_python_code_detection.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_javascript_code_detection_engine" {
  name                         = "ZBP-JavaScript Code Detection Engine"
  description                  = "ZBP managed source-code DLP engine for JavaScript. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_javascript_code_detection.id}.S > 0))"
}

resource "zia_dlp_engines" "zbp_shell_script_detection_engine" {
  name                         = "ZBP-Shell Script Detection Engine"
  description                  = "ZBP managed source-code DLP engine for shell scripts. [DLP-Check baseline zbp_source_code_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.zbp_shell_script_detection.id}.S > 0))"
}

