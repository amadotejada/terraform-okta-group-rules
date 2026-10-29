# Credentials come from the OKTA_* env vars set by scripts/okta_rules.py provider-env.
provider "okta" {}

variable "rules_dir" {
  description = "Folder that holds the rule YAML files. Only the tests change this."
  type        = string
  default     = "rules"
}

data "okta_groups" "all" {
  type = "OKTA_GROUP"
}

locals {
  # Files with only comments or blank lines are skipped, yamldecode rejects them.
  rule_files = [for f in sort(fileset("${path.module}/${var.rules_dir}", "**/*.{yaml,yml}")) : f if length(regexall("(?m)^[^#\\s]", file("${path.module}/${var.rules_dir}/${f}"))) > 0]

  rule_items = flatten([
    for f in local.rule_files : [
      for key, rule in yamldecode(file("${path.module}/${var.rules_dir}/${f}")) : { key = key, file = f, rule = rule }
    ]
  ])

  # Grouped with ... so a key used in two files becomes a readable precondition error instead of a crash.
  items_by_key = { for item in local.rule_items : item.key => item... }
  rules        = { for key, items in local.items_by_key : key => items[0].rule }
  keys_by_name = { for key, rule in local.rules : try(coalesce(rule.name, ""), "") => key... }
  keys_by_id   = { for key, rule in local.rules : rule.id => key... if try(rule.id, null) != null }
  rule_groups  = { for key, rule in local.rules : key => try(tolist(rule.groups), []) }
  group_ids    = { for g in data.okta_groups.all.groups : g.name => g.id... }

  allowed_attributes = ["name", "expression", "groups", "status", "users_excluded", "id"]
}

resource "okta_group_rule" "this" {
  for_each = local.rules

  name              = each.value.name
  expression_value  = each.value.expression
  group_assignments = [for g in local.rule_groups[each.key] : local.group_ids[g][0]]
  status            = try(each.value.status, "INACTIVE") # only an explicit status: ACTIVE turns a rule on
  users_excluded    = try(each.value.users_excluded, null)

  # Deleting or replacing a rule must never pull people out of groups.
  remove_assigned_users = false

  lifecycle {
    precondition {
      condition     = length(local.items_by_key[each.key]) == 1
      error_message = "Rule key \"${each.key}\" is used in more than one file: ${join(", ", local.items_by_key[each.key][*].file)}. Each key must be unique."
    }
    precondition {
      condition     = can(regex("^[a-z0-9][a-z0-9-]*$", each.key)) && can(regex("[a-z]", each.key))
      error_message = "Rule key \"${each.key}\" (${local.items_by_key[each.key][0].file}) must be lowercase letters, numbers and dashes, and the file must be a map of rules, not a list."
    }
    precondition {
      condition     = can(keys(each.value)) && length(setsubtract(try(keys(each.value), []), local.allowed_attributes)) == 0
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) has unknown settings: ${join(", ", setsubtract(try(keys(each.value), []), local.allowed_attributes))}. Allowed: ${join(", ", local.allowed_attributes)}."
    }
    precondition {
      condition     = can(regex("^.{1,50}$", each.value.name))
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) needs a name between 1 and 50 characters."
    }
    precondition {
      condition     = length(local.keys_by_name[try(coalesce(each.value.name, ""), "")]) == 1
      error_message = "Rule name \"${try(coalesce(each.value.name, ""), "")}\" is used by more than one rule: ${join(", ", local.keys_by_name[try(coalesce(each.value.name, ""), "")])}. Names must be unique."
    }
    precondition {
      condition     = try(length(local.keys_by_id[each.value.id]) == 1, true)
      error_message = "Okta id \"${try(each.value.id, "")}\" is on more than one rule: ${join(", ", try(local.keys_by_id[each.value.id], []))}. Remove the id: line from the copy."
    }
    precondition {
      condition     = try(trimspace(each.value.expression) != "", false)
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) needs an expression."
    }
    precondition {
      condition     = contains(["ACTIVE", "INACTIVE"], try(each.value.status, "INACTIVE"))
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) status must be ACTIVE or INACTIVE. INVALID means Okta disabled the rule, usually because one of its groups was deleted. Fix it in Okta first."
    }
    precondition {
      condition     = length(local.rule_groups[each.key]) > 0
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) needs a list of groups."
    }
    precondition {
      condition     = length(distinct(local.rule_groups[each.key])) == length(local.rule_groups[each.key])
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) lists the same group more than once."
    }
    precondition {
      condition     = alltrue([for g in local.rule_groups[each.key] : contains(keys(local.group_ids), g)])
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) uses groups that don't exist in Okta: ${join(", ", [for g in local.rule_groups[each.key] : g if !contains(keys(local.group_ids), g)])}."
    }
    precondition {
      condition     = alltrue([for g in local.rule_groups[each.key] : length(lookup(local.group_ids, g, [])) < 2])
      error_message = "Rule \"${each.key}\" (${local.items_by_key[each.key][0].file}) uses group names that match more than one Okta group: ${join(", ", [for g in local.rule_groups[each.key] : g if length(lookup(local.group_ids, g, [])) > 1])}."
    }
  }
}

# Brings rules made in the Okta GUI under Terraform. The id is written by scripts/okta_rules.py export.
import {
  for_each = { for key, rule in local.rules : key => rule.id if try(rule.id, null) != null }
  to       = okta_group_rule.this[each.key]
  id       = each.value
}
