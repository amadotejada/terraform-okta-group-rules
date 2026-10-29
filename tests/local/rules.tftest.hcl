# Offline checks of the real rules for scripts/check.sh, with the Okta group list from the last deploy.
# Not part of CI (terraform test only reads tests/ by default). Run it through scripts/check.sh.
mock_provider "okta" {
  override_data {
    target = data.okta_groups.all
    values = jsondecode(file(".terraform/offline-groups.json"))
  }
}

run "repo_rules" {
  command = plan

  # Rules with an id are imported; the mock needs an id to import.
  override_resource {
    target = okta_group_rule.this
    values = { id = "0prOFFLINE" }
  }
}
