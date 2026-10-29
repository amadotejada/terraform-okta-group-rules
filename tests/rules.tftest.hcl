# Offline checks of the YAML loading and validation. No Okta or AWS access needed.
mock_provider "okta" {
  override_data {
    target = data.okta_groups.all
    values = {
      groups = [
        { id = "00g1", name = "github-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g2", name = "aws-readonly", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g3", name = "salesforce-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g4", name = "engineering", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g5", name = "aws-developers", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g6", name = "pagerduty-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g7", name = "gong-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g8", name = "zendesk-agents", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g9", name = "all-employees", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g10", name = "slack-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g11", name = "contractors", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
        { id = "00g12", name = "looker-users", type = "OKTA_GROUP", description = "", custom_profile_attributes = "" },
      ]
    }
  }
}

run "valid_rules_across_files" {
  command = plan
  variables {
    rules_dir = "tests/fixtures/valid"
  }

  assert {
    condition     = length(okta_group_rule.this) == 2
    error_message = "Expected one rule from each file."
  }
  assert {
    condition     = okta_group_rule.this["eng-platform-tr"].group_assignments == toset(["00g1", "00g2"])
    error_message = "Group names should resolve to Okta group IDs."
  }
  assert {
    condition     = okta_group_rule.this["sales-ae-tr"].status == "INACTIVE" && okta_group_rule.this["eng-platform-tr"].status == "ACTIVE"
    error_message = "Status should default to INACTIVE and honor ACTIVE."
  }
  assert {
    condition     = okta_group_rule.this["eng-platform-tr"].remove_assigned_users == false
    error_message = "Rules must never remove members on delete."
  }
}

run "examples_pass_the_rule_checks" {
  command = plan
  variables {
    rules_dir = "example-rules"
  }

  assert {
    condition     = length(okta_group_rule.this) == 7
    error_message = "Every example rule should load."
  }
}

run "imports_rules_with_an_okta_id" {
  command = plan
  variables {
    rules_dir = "tests/fixtures/import"
  }

  override_resource {
    target = okta_group_rule.this
    values = { id = "0pr1abc" }
  }

  assert {
    condition     = okta_group_rule.this["rule-a"].id == "0pr1abc"
    error_message = "A rule with an id should be imported, not created."
  }
}

run "duplicate_key_across_files" {
  command = plan
  variables { rules_dir = "tests/fixtures/dup-key" }
  expect_failures = [okta_group_rule.this]
}

run "duplicate_rule_name" {
  command = plan
  variables { rules_dir = "tests/fixtures/dup-name" }
  expect_failures = [okta_group_rule.this]
}

run "unknown_group" {
  command = plan
  variables { rules_dir = "tests/fixtures/unknown-group" }
  expect_failures = [okta_group_rule.this]
}

run "typo_in_setting" {
  command = plan
  variables { rules_dir = "tests/fixtures/typo" }
  expect_failures = [okta_group_rule.this]
}

run "name_too_long" {
  command = plan
  variables { rules_dir = "tests/fixtures/long-name" }
  expect_failures = [okta_group_rule.this]
}

run "same_group_twice" {
  command = plan
  variables { rules_dir = "tests/fixtures/dup-group" }
  expect_failures = [okta_group_rule.this]
}

run "key_not_lowercase" {
  command = plan
  variables { rules_dir = "tests/fixtures/bad-key" }
  expect_failures = [okta_group_rule.this]
}

run "same_okta_id_twice" {
  command = plan
  variables { rules_dir = "tests/fixtures/dup-id" }
  override_resource {
    target = okta_group_rule.this
    values = { id = "0pr1abc" }
  }
  expect_failures = [okta_group_rule.this]
}

run "blank_name" {
  command = plan
  variables { rules_dir = "tests/fixtures/null-name" }
  expect_failures = [okta_group_rule.this]
}

run "file_is_a_list" {
  command = plan
  variables { rules_dir = "tests/fixtures/list-file" }
  expect_failures = [okta_group_rule.this]
}
