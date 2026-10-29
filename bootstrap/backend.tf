# The bootstrap workflow moves this file aside on the very first run, since the bucket doesn't exist yet.
# bucket comes from -backend-config and region from AWS_REGION, same as the main config.
terraform {
  backend "s3" {
    key          = "bootstrap/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}
