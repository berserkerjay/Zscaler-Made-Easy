# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.

resource "zia_dlp_engines" "pci_high" {
  name                         = "PCI - High"
  description                  = "PCI: bulk credit card data. Ten or more card numbers (predefined Credit Cards dictionary) in one file or transfer. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${data.zia_dlp_dictionaries.credit_cards.id}.S > 9)"
}

resource "zia_dlp_engines" "pci_medium" {
  name                         = "PCI - Medium"
  description                  = "PCI: several credit card numbers (3-9) in one file or transfer, predefined Credit Cards dictionary. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${data.zia_dlp_dictionaries.credit_cards.id}.S > 2)"
}

resource "zia_dlp_engines" "pci_low" {
  name                         = "PCI - Low"
  description                  = "PCI: any credit card number (1-2) in one file or transfer, predefined Credit Cards dictionary. [DLP-Check baseline zbp_endpoint_dlp_baseline v1.0] Terraform-managed."
  custom_dlp_engine            = true
  engine_expression            = "(D${data.zia_dlp_dictionaries.credit_cards.id}.S > 0)"
}

