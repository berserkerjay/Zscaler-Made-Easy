# ──────────────────────────────────────────────────────────────
# CJIS DLP Policy Pack — Terraform for AWS
# ──────────────────────────────────────────────────────────────
# Deploys the full CJIS DLP configuration (16 dictionaries,
# 10 engines, 9 policies) to a ZIA tenant using the official
# Zscaler Terraform provider, with state stored in S3.
#
# Usage:
#   cp terraform.tfvars.example terraform.tfvars
#   # fill in credentials
#   terraform init
#   terraform plan
#   terraform apply
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    zia = {
      source  = "zscaler/zia"
      version = "~> 3.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "zscaler-terraform-state"
    key            = "cjis-dlp/terraform.tfstate"
    region         = "us-gov-west-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "zia" {
  username = var.zia_username
  password = var.zia_password
  api_key  = var.zia_api_key
  cloud    = var.zia_cloud
}

provider "aws" {
  region = var.aws_region
}
