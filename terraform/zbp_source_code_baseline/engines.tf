# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "src_csharp" {
  name                         = "SRC-CSharp"
  description                  = "C# (C-Sharp) source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_csharp_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_csharp_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_cplusplus" {
  name                         = "SRC-CPlusPlus"
  description                  = "C++ source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_cplusplus_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_cplusplus_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_go" {
  name                         = "SRC-Go"
  description                  = "Go source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_go_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_go_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_html" {
  name                         = "SRC-HTML"
  description                  = "HTML source code: the Anchor fingerprint is present AND more than 3 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_html_signal.id}.S > 3) AND (D${zia_dlp_dictionaries.src_html_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_java" {
  name                         = "SRC-Java"
  description                  = "Java source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_java_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_java_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_javascript" {
  name                         = "SRC-JavaScript"
  description                  = "JavaScript source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_javascript_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_javascript_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_kotlin" {
  name                         = "SRC-Kotlin"
  description                  = "Kotlin source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_kotlin_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_kotlin_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_python" {
  name                         = "SRC-Python"
  description                  = "Python source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_python_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_python_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_rust" {
  name                         = "SRC-Rust"
  description                  = "Rust source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_rust_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_rust_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_sql" {
  name                         = "SRC-SQL"
  description                  = "SQL source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_sql_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_sql_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_swift" {
  name                         = "SRC-Swift"
  description                  = "Swift source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_swift_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_swift_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_typescript" {
  name                         = "SRC-TypeScript"
  description                  = "TypeScript source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_typescript_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_typescript_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_vbnet" {
  name                         = "SRC-VBNet"
  description                  = "Visual Basic (.NET) source code: the Anchor fingerprint is present AND more than 4 Signal matches accumulate (All/AND), which is what removes cousin-language false positives. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_vbnet_signal.id}.S > 4) AND (D${zia_dlp_dictionaries.src_vbnet_anchor.id}.S > 0))"
}

resource "zia_dlp_engines" "src_private_keys" {
  name                         = "SRC-Private Keys"
  description                  = "From the Fed pack's Private Keys engine. Plaintext private keys, JWK private keys, PGP and Bouncy Castle key exports and Zscaler's credential-leakage clone: the secrets that ride along with source code. [DLP-Check baseline zbp_source_code_baseline v4.16] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "((D${zia_dlp_dictionaries.src_private_keys_plaintext_regex.id}.S > 0) OR (D${zia_dlp_dictionaries.src_jwk_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.src_private_key.id}.S > 0) OR (D${zia_dlp_dictionaries.src_encrypted_or_ascii_armored_pgp_keys.id}.S > 0) OR (D${zia_dlp_dictionaries.src_encrypted_bouncy_castle_key_exports.id}.S > 0))"
}

