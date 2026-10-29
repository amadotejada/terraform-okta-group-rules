terraform {
  required_version = "~> 1.17"

  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 7.0"
    }
  }

  # S3 native locking (.tflock) so two people or runs can't apply at once.
  # bucket comes from -backend-config and region from AWS_REGION, both set by the workflows.
  backend "s3" {
    key          = "terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
