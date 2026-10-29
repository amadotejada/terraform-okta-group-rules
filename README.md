# Okta group rules as code

> [!TIP]
> **If this repo is useful to you, please consider giving it a ⭐**
>
> It helps others find it and encourages me to keep improving this repo and to open source more Okta and Terraform projects.
>
> Need help setting this up or want something custom for your org? [Reach out](https://github.com/amadotejada) for paid services.

**Contents**

- [Where things are](#where-things-are)
- [A rule](#a-rule)
- [Making a change](#making-a-change)
- [Examples](#examples)
  - [Create a group rule](#create-a-group-rule)
  - [Update a group rule](#update-a-group-rule)
  - [Delete a group rule](#delete-a-group-rule)
  - [Move a rule](#move-a-rule)
  - [Good to know](#good-to-know)
- [Reorgs and team renames](#reorgs-and-team-renames)
- [Drift (changes made in the Okta GUI)](#drift-changes-made-in-the-okta-gui)
- [Protections](#protections)
- [Running checks locally (optional)](#running-checks-locally-optional)
- [Setup](#setup)
  - [1. Okta service app](#1-okta-service-app)
  - [2. AWS](#2-aws)
  - [3. GitHub](#3-github)
  - [4. Create the state bucket](#4-create-the-state-bucket)
  - [5. Import your existing rules](#5-import-your-existing-rules)

A friendly way to start managing Okta group rules with Terraform. **Beginners are welcome.** You don't need to know Terraform, and nobody on your team ever has to run it by hand. If you can edit a YAML file and open a pull request, you can manage your group rules here.

Okta group rules live in this repo as YAML. You change a file, open a pull request, a teammate reviews it, and GitHub Actions applies it to Okta. Every change is checked before it merges and shown to you in plain language, so it's hard to break things by accident.

What you get:

- Rules as plain YAML, one file per team, with group **names** instead of IDs
- PR checks that catch typos, unknown groups, duplicate names and bad YAML before merge
- A plan preview on every PR with a table of exactly what will change in Okta
- Deploys that apply small changes right away and hold deletes or big changes for an approver
- A drift check that spots changes made in the Okta GUI and can import them into Git
- Optional Slack alerts

Use this repo as a template, follow [Setup](#setup), then import your existing rules.

## Where things are

| Path | What it is |
| --- | --- |
| `rules/<department>/<team>.yaml` | The rules for one team. This is the only folder you normally edit. |
| `rules/<department>/_department.yaml` | Rules for a whole department (no team in the expression). |
| `rules/multi-department/` | Rules that match several departments, one file per team. |
| `rules/org-wide.yaml` | Rules that match the whole org, with no department or team. |
| `rules/other/<rule>.yaml` | Rules that aren't about a department or team, e.g. group membership or one user. One file per rule. |
| `rules/imported.yaml` | Inbox, normally empty. GUI rules the import couldn't place, e.g. a rule that matches two teams. Move them to the right file. |
| `example-rules/` | One of each kind of rule file, to copy from. Never applied to Okta. |
| `main.tf`, `versions.tf` | Terraform that reads the YAML. You shouldn't need to touch it. |
| `bootstrap/` | Terraform for the S3 bucket that holds the state. |
| `scripts/okta_rules.py` | Helper used by the workflows (Okta login, drift check, plan summary). |
| `tests/` | Offline tests for the validation. |

```
rules/
  engineering/
    _department.yaml
    eng-platform.yaml
  multi-department/
    cs-onboarding.yaml
  other/
    vpn-users.yaml
  org-wide.yaml
  imported.yaml
```

Folder and file names come from the `user.department` and `user.team` values in the rule's expression, with lowercase letters and dashes, e.g. team `Eng - Platform` becomes `eng-platform.yaml`. Moving a rule to another file or folder changes nothing in Okta, so after a reorg you can rename a team file or move rules around freely. If your org uses other profile attributes, change `rule_file()` in `scripts/okta_rules.py`.

## A rule

```yaml
eng-platform-tr:
  name: Emp Eng - Platform TR
  expression: user.department == "Engineering" and user.team == "Platform"
  groups:
    - github-users
    - aws-readonly
  status: ACTIVE
```

- **Key** (`eng-platform-tr`): the rule's permanent ID in Terraform. Lowercase letters, numbers and dashes. **Never rename it.** It's fine if it still mentions an old team name.
- **name**: what Okta shows. Up to 50 characters, unique across all files. Safe to change.
- **expression**: the Okta expression, same as in the GUI.
- **groups**: Okta group **names**, not IDs. Each one must exist in Okta.
- **status**: `ACTIVE` or `INACTIVE`. **A rule is only on with `status: ACTIVE`.** Leave it out and the rule is created, or switched, to INACTIVE.
- Optional:
  - `users_excluded: [00u...]` to skip specific users.
  - `id:` is added by the import and only matters the first time. Leave it alone.

If you put something in the wrong place, the PR checks tell you which rule and which file, e.g. `Rule "eng-platform-tr" (engineering/eng-platform.yaml) uses groups that don't exist in Okta: githb-users`.

## Making a change

1. Create a branch, then edit the team's file. Adding, changing or deleting a rule is just adding, editing or removing its block. A new team gets a new file in its department folder.
2. Open a pull request. The **Validate** checks run:
   - format and YAML lint, so duplicate keys, bad indentation and typos are caught
   - a **Plan preview** with a table of exactly what will change in Okta and which gate it will hit
3. A teammate reviews and approves, then you merge.
4. **Deploy** runs on `main`:
   - **prod-auto**: 5 or fewer rules change and nothing is deleted. Applies right away.
   - **prod-gated**: more than 5 rules change, or any rule is deleted or replaced. A reviewer has to approve the run in GitHub first. The change table is at the top of the run page.
5. Slack gets a summary of what was applied. If something fails, Slack gets an alert with a link.

Two people can work at the same time. Conflicts only happen if you both edit the same rule. Deploys run one at a time, and the Terraform state is locked in S3 while a deploy runs.

## Examples

### Create a group rule

Add a block to the team's file, e.g. `rules/engineering/eng-mobile.yaml`. For a team that has no file yet, create `rules/<department>/<team>.yaml`.

```yaml
emp-eng-mobile-tr:
  name: Emp Eng - Mobile TR
  expression: (user.department=="Engineering") and (user.team=="Eng - Mobile")
  groups:
    - aws-developers
    - pagerduty-users
  status: ACTIVE
```

- Pick a new key: lowercase, dashes, unique across all files.
- **No `id:` line.** Terraform creates the rule in Okta and keeps track of its id itself. Copying an `id:` from another rule fails the PR checks.
- **`status: ACTIVE`** turns it on right away. Use `status: INACTIVE` to create it switched off and turn it on in a later PR.
- Plan preview shows `create`. Gate: **prod-auto**.

### Update a group rule

Edit the fields in place. Never change the key.

| You change | Plan shows | Gate |
| --- | --- | --- |
| `name` | `update` | prod-auto |
| `expression` | `update` | prod-auto |
| `status: ACTIVE` to `status: INACTIVE` (pause) | `update` | prod-auto |
| `status: INACTIVE` to `status: ACTIVE` (turn on) | `update` | prod-auto |
| add or remove a group in `groups` | `replace` (delete + create) | **prod-gated** |

For example, adding a group:

```yaml
emp-eng-mobile-tr:
  name: Emp Eng - Mobile TR
  expression: (user.department=="Engineering") and (user.team=="Eng - Mobile")
  groups:
    - aws-developers
    - pagerduty-users
    - github-users        # new
  status: ACTIVE
```

Changing more than 5 rules in one PR always goes through **prod-gated**.

### Delete a group rule

Remove the whole block, from the key down to its last line. If it was the only rule in the file, delete the file.

- Plan preview shows `delete`. Gate: **prod-gated**.
- People already in the rule's groups **stay** in them. Remove that membership separately if they should lose access.
- To stop a rule for a while instead of deleting it, use `status: INACTIVE`.

### Move a rule

Cut the block from one file and paste it into another, with the same key. Plan preview shows no changes, and nothing happens in Okta.

### Good to know

- **Adding or removing a group replaces the rule.** Okta can't edit a rule's groups in place, so Terraform deletes the rule and creates it again. That's why it always goes through prod-gated. Reordering the list, or updating a group's name after it was renamed in Okta, changes nothing.
- **Removing a group, or deleting a rule, does not remove people from groups.** Rules here never remove assigned users. If people should lose a group, clean up that membership separately.
- **Moving a rule between files does nothing in Okta.** The key stays the same, so reorgs that only move rules around are free.

## Reorgs and team renames

Your HR system updates Okta profiles on its own schedule, so for a while some people have the old team name and some have the new one. Pick one of these:

**Option 1, match both names (nobody waits):**
1. PR 1: widen the expression, e.g. `user.team == "Data - Analytics" or user.team == "Data - Insights"`. Update `name:` and any renamed groups.
2. Once profiles have caught up, PR 2: remove the old team name.

New joiners keep getting access the whole time.

**Option 2, pause the rule:**
1. PR 1: change to `status: INACTIVE`.
2. After profiles catch up, PR 2: update the expression and change back to `status: ACTIVE`.

Current members keep their groups. New joiners don't get added while it's paused.

**Option 3, delete, then recreate:**
1. PR 1: delete the rule block. This goes through prod-gated, and members keep their groups.
2. After profiles catch up, PR 2: add the rule back with the same key and the new team, without the `id:` line.

**If a group was renamed in Okta:** update the group name in the YAML. The group ID is the same, so Okta sees no change. Until you do, plans fail with "group doesn't exist".

## Drift (changes made in the Okta GUI)

Once a day (12:00 UTC), **Drift check** compares Okta with this repo. If someone changed, created or deleted a rule in the GUI, Slack gets a table of the differences. Then do one of these:

- **Undo it in Okta**, if the GUI change was a mistake. The next deploy that changes rules also puts Git's version back on every rule that was changed or deleted in the GUI, whatever the PR was about. That deploy always waits in **prod-gated**, and its table marks those rows `undoes a GUI change`, so a reviewer decides. To keep the GUI change, import it first.
- **Bring it into Git**: run **Actions > Drift check > Run workflow** with **import** checked. It pushes a branch like `okta-import/<your-username>/2026-10-28-1430` (UTC) and puts a link in the run summary. Open the PR from that link (opening it yourself is what starts the checks), review the diff, and merge. New GUI rules are filed by the department and team in their expression. Anything it can't place goes to `rules/imported.yaml`, so move those in the same PR. A rule left in `imported.yaml` moves to its folder on its own once its expression names a single team or department, or nothing at all (`other/`).

If a rule is deleted and recreated in the GUI, the import puts it back in the same file under a new key (e.g. `eng-platform-tr-2`), because Terraform sees it as a new rule.

The drift check skips itself while a Deploy is waiting or running, so merged changes that haven't been applied yet aren't reported as GUI drift.

## Protections

**Before a merge** (with the branch rules from [Setup](#setup))
- `main` can't be deleted or force-pushed.
- A PR can't merge until **Format, lint and offline tests** and **Plan preview** pass. The checks stop:
  - bad YAML, duplicate keys, typos in setting names
  - duplicate rule names or Okta ids, names over 50 characters
  - groups that don't exist in Okta, a status other than `ACTIVE` or `INACTIVE`

**During a deploy**
- Any delete or replace, more than 5 changes, or undoing a change made in the Okta GUI waits in **prod-gated** for a reviewer.
- Only the plan that was reviewed is applied (checked by checksum). If anything changed since, the apply stops with "Saved plan is stale". Start a new Deploy, don't re-run the old one.
- Renaming a rule's key shows as a delete + create, so it goes through prod-gated. If the rule still has an `id:` line, the plan fails instead.
- Deploys run one at a time, and the state is locked in S3 while one runs.
- PR plans and the drift check only get read access to Okta. Only the apply step can change rules.

**In Okta**
- Rules never remove people from groups, even when a rule is deleted or replaced. A test fails if anyone changes that.
- A rule is only on with `status: ACTIVE`. A missing status means INACTIVE.

**State**
- The S3 bucket can't be destroyed by Terraform (`prevent_destroy`). It keeps every version of the state, is encrypted, blocks public access and requires HTTPS.
- After every deploy, a copy of the state is committed to the `tfstate-backup` branch.

## Running checks locally (optional)

Run the same checks as a pull request before you push. **It never applies anything, and you don't need Okta or AWS access.**

```sh
scripts/check.sh            # all checks + plan preview
scripts/check.sh --no-plan  # checks only
```

The first run sets up Python tools in `.venv`. You'll see `pass`, `FAIL` (with the reason) or `skipped` for each check.

The plan preview compares your rules with the last deploy, from the `tfstate-backup` branch. It runs the same rule checks as the real plan (unknown groups, duplicate names, and so on) and shows the same change table and gate as the PR. It can't see changes made in the Okta GUI, so the PR's Plan preview is the final word. Until the first deploy there is no `tfstate-backup` branch, so the preview is skipped.

## Setup

Keep your copy of this repo **private**. The rules and the `tfstate-backup` branch describe your org's groups and teams.

Until the `TF_STATE_BUCKET` variable is set, every job that needs AWS or Okta skips itself, so a fresh copy stays green.

### 1. Okta service app

1. In the Okta admin console, create an **API Services** app with **Public key / Private key** client authentication, and add a key. Copy the private key as JWK.
2. Grant the scopes `okta.groups.read` (plans and drift) and `okta.groups.manage` (apply only).
3. Assign it the **Org Administrator** admin role. Without it, applies fail with "You do not have permission to perform the requested action".
4. Keep **Require DPoP** on. The provider and the script both support it.

### 2. AWS

1. An IAM role that GitHub Actions can assume through OIDC. Its trust policy must allow this repo's `main` branch and pull requests, i.e. the subjects `repo:<owner>/<repo>:ref:refs/heads/main` and `repo:<owner>/<repo>:pull_request`.
2. The role needs read and write on the state bucket's `terraform.tfstate` and `bootstrap/terraform.tfstate` keys and their `.tflock` files, plus `s3:ListBucket`. For the bootstrap run it also needs to create the bucket and manage its versioning, encryption, public access block and policy.

### 3. GitHub

**Secrets** (Settings > Secrets and variables > Actions):
- `OKTA_OAUTH`: the service app settings, as env-file text:
  ```
  OKTA_CLIENT_ID=0oa...
  OKTA_DOMAIN_URL=your-org.okta.com
  OKTA_PRIVATE_KEY_JWK={"kty":"RSA","kid":"...", ...}
  ```
- `SLACK_WEBHOOK` (optional): a Slack incoming webhook URL. Without it, Slack messages are skipped.

**Variables** (same page, Variables tab):
- `AWS_ACCOUNT_ID`: the account that holds the state bucket.
- `AWS_ROLE_ARN`: the role from step 2.
- `AWS_REGION` (optional): defaults to `us-east-1`.
- `TF_STATE_BUCKET`: a globally unique bucket name, e.g. `<your-org>-okta-group-rules-tfstate`.

**Environments** (Settings > Environments):
- `prod-auto`: no reviewers. Limit deployments to `main`.
- `prod-gated`: add the people who approve deletes and big changes as **required reviewers**. Limit deployments to `main`.

**Branch rules** (Settings > Rules):
- `main`: require a pull request with an approval and the **Format, lint and offline tests** and **Plan preview** checks. Block deletions and force pushes.
- `tfstate-backup`: block deletions and force pushes.

**Slack mentions (optional):** add `github-username: SlackMemberID` lines to `.github/slack-users.yaml` so alerts @mention the person who applied or imported. Anyone not listed shows as their GitHub username.

### 4. Create the state bucket

Run **Actions > Bootstrap state bucket > Run workflow** on `main`. It creates the bucket, then moves its own state into it. Run it again only after changing `bootstrap/`.

### 5. Import your existing rules

Run **Drift check** with **import** checked. It files every rule into its department and team file and pushes a branch for a PR. The plan preview should show only imports. Merge it, and from then on Git is the source of truth.
