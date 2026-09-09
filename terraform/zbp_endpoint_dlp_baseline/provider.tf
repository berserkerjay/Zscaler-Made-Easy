# Credentials come from variables (see terraform.tfvars.example) or, when the
# variables are left null, from ZSCALER_CLIENT_ID / ZSCALER_CLIENT_SECRET /
# ZSCALER_VANITY_DOMAIN / ZSCALER_CLOUD in the environment.

provider "zia" {
  client_id     = var.zscaler_client_id
  client_secret = var.zscaler_client_secret
  vanity_domain = var.zscaler_vanity_domain
  zscaler_cloud = var.zscaler_cloud
}
