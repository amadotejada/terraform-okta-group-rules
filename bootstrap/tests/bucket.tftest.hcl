# Offline checks of the state bucket settings. No AWS access needed.
mock_provider "aws" {
  override_data {
    target = data.aws_iam_policy_document.state
    values = { json = "{}" }
  }
}

variables {
  aws_account_id = "123456789012"
  state_bucket   = "example-okta-group-rules-tfstate"
}

run "state_bucket_is_locked_down" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.bucket == var.state_bucket
    error_message = "Bucket name must come from state_bucket."
  }
  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "Versioning keeps old state versions for restores."
  }
  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.state.block_public_acls,
      aws_s3_bucket_public_access_block.state.block_public_policy,
      aws_s3_bucket_public_access_block.state.ignore_public_acls,
      aws_s3_bucket_public_access_block.state.restrict_public_buckets,
    ])
    error_message = "All public access must be blocked."
  }
  assert {
    condition     = one([for r in aws_s3_bucket_server_side_encryption_configuration.state.rule : one(r.apply_server_side_encryption_by_default).sse_algorithm]) == "AES256"
    error_message = "State must be encrypted at rest."
  }
}
