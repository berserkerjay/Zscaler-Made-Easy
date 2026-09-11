output "dictionaries" {
  value = { for k, r in {
    src_csharp_signal = zia_dlp_dictionaries.src_csharp_signal
    src_csharp_anchor = zia_dlp_dictionaries.src_csharp_anchor
    src_cplusplus_signal = zia_dlp_dictionaries.src_cplusplus_signal
    src_cplusplus_anchor = zia_dlp_dictionaries.src_cplusplus_anchor
    src_go_signal = zia_dlp_dictionaries.src_go_signal
    src_go_anchor = zia_dlp_dictionaries.src_go_anchor
    src_html_signal = zia_dlp_dictionaries.src_html_signal
    src_html_anchor = zia_dlp_dictionaries.src_html_anchor
    src_java_signal = zia_dlp_dictionaries.src_java_signal
    src_java_anchor = zia_dlp_dictionaries.src_java_anchor
    src_javascript_signal = zia_dlp_dictionaries.src_javascript_signal
    src_javascript_anchor = zia_dlp_dictionaries.src_javascript_anchor
    src_kotlin_signal = zia_dlp_dictionaries.src_kotlin_signal
    src_kotlin_anchor = zia_dlp_dictionaries.src_kotlin_anchor
    src_python_signal = zia_dlp_dictionaries.src_python_signal
    src_python_anchor = zia_dlp_dictionaries.src_python_anchor
    src_rust_signal = zia_dlp_dictionaries.src_rust_signal
    src_rust_anchor = zia_dlp_dictionaries.src_rust_anchor
    src_sql_signal = zia_dlp_dictionaries.src_sql_signal
    src_sql_anchor = zia_dlp_dictionaries.src_sql_anchor
    src_swift_signal = zia_dlp_dictionaries.src_swift_signal
    src_swift_anchor = zia_dlp_dictionaries.src_swift_anchor
    src_typescript_signal = zia_dlp_dictionaries.src_typescript_signal
    src_typescript_anchor = zia_dlp_dictionaries.src_typescript_anchor
    src_vbnet_signal = zia_dlp_dictionaries.src_vbnet_signal
    src_vbnet_anchor = zia_dlp_dictionaries.src_vbnet_anchor
  } : r.name => r.id }
}

output "engines" {
  value = { for k, r in {
    src_csharp = zia_dlp_engines.src_csharp
    src_cplusplus = zia_dlp_engines.src_cplusplus
    src_go = zia_dlp_engines.src_go
    src_html = zia_dlp_engines.src_html
    src_java = zia_dlp_engines.src_java
    src_javascript = zia_dlp_engines.src_javascript
    src_kotlin = zia_dlp_engines.src_kotlin
    src_python = zia_dlp_engines.src_python
    src_rust = zia_dlp_engines.src_rust
    src_sql = zia_dlp_engines.src_sql
    src_swift = zia_dlp_engines.src_swift
    src_typescript = zia_dlp_engines.src_typescript
    src_vbnet = zia_dlp_engines.src_vbnet
  } : r.name => r.id }
}

output "rules" {
  value = [
    zia_dlp_web_rules.src_csharp_code_to_ai_block.name,
    zia_dlp_web_rules.src_cplusplus_code_to_ai_block.name,
    zia_dlp_web_rules.src_go_code_to_ai_block.name,
    zia_dlp_web_rules.src_html_code_to_ai_block.name,
    zia_dlp_web_rules.src_java_code_to_ai_block.name,
    zia_dlp_web_rules.src_javascript_code_to_ai_block.name,
    zia_dlp_web_rules.src_kotlin_code_to_ai_block.name,
    zia_dlp_web_rules.src_python_code_to_ai_block.name,
    zia_dlp_web_rules.src_rust_code_to_ai_block.name,
    zia_dlp_web_rules.src_sql_code_to_ai_block.name,
    zia_dlp_web_rules.src_swift_code_to_ai_block.name,
    zia_dlp_web_rules.src_typescript_code_to_ai_block.name,
    zia_dlp_web_rules.src_vbnet_code_to_ai_block.name,
    zia_endpoint_dlp_rules.src_csharp_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_csharp_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_csharp_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_cplusplus_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_cplusplus_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_cplusplus_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_go_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_go_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_go_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_html_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_html_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_html_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_java_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_java_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_java_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_javascript_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_javascript_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_javascript_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_kotlin_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_kotlin_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_kotlin_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_python_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_python_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_python_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_rust_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_rust_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_rust_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_sql_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_sql_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_sql_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_swift_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_swift_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_swift_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_typescript_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_typescript_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_typescript_code_to_ai_email.name,
    zia_endpoint_dlp_rules.src_vbnet_code_to_ai_endpoint.name,
    zia_casb_dlp_rules.src_vbnet_code_to_ai_saas.name,
    zia_outbound_email_dlp.src_vbnet_code_to_ai_email.name,
  ]
}
