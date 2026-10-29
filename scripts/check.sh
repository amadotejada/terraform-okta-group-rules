#!/usr/bin/env bash
# Runs the same checks as a pull request, then an offline plan preview. Never applies anything.
# Needs no Okta or AWS access: the preview compares your rules with the last deploy (tfstate-backup branch).
#   scripts/check.sh            all checks + plan preview
#   scripts/check.sh --no-plan  checks only

[ -t 1 ] && clear
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD

PLAN=1
case "${1:-}" in
  "") ;;
  --no-plan) PLAN=0 ;;
  -h | --help) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "Unknown option: $1 (try --help)"; exit 2 ;;
esac

if [ -t 1 ]; then G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' B=$'\e[1m' N=$'\e[0m'; else G='' R='' Y='' B='' N=''; fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
passed=0 failed=0 skipped=0

# step "Name" "how to fix (optional)" command...
step() {
  local name=$1 hint=$2
  shift 2
  printf '  %-30s' "$name"
  if "$@" >"$TMP/out" 2>&1; then
    echo "${G}pass${N}"
    passed=$((passed + 1))
  else
    echo "${R}FAIL${N}"
    # Drop Terraform progress lines, code-location details and repeats so the actual message stands out.
    grep -vE 'Refreshing state|Reading\.\.\.|Read complete|Preparing import|Import prepared|Importing from ID|Planning failed|\.tftest\.hcl\.\.\. |^[[:space:]]+run "|^Failure! |^[[:space:]]*$|^[[:space:]]+(on |[0-9]+:|│|├)' "$TMP/out" |
      awk '!seen[$0]++' | tail -40 | sed 's/^/      /'
    [ -n "$hint" ] && echo "      ${Y}Fix: $hint${N}"
    failed=$((failed + 1))
  fi
}

skip() {
  printf '  %-30s%s\n' "$1" "${Y}skipped${N}  $2"
  skipped=$((skipped + 1))
}

echo "${B}Setup${N}"
command -v terraform >/dev/null || { echo "  Terraform is missing. Install it: brew install hashicorp/tap/terraform"; exit 1; }
if [ ! -x .venv/bin/python ] || [ scripts/requirements.txt -nt .venv/.installed ]; then
  step "Python tools (.venv)" "" sh -c 'python3 -m venv .venv && .venv/bin/pip install -q -r scripts/requirements.txt && touch .venv/.installed'
  [ "$failed" = 0 ] || exit 1
else
  printf '  %-30s%s\n' "Python tools (.venv)" "${G}ready${N}"
fi

echo
echo "${B}Checks (same as the pull request)${N}"
step "Terraform format" "terraform fmt -recursive" terraform fmt -check -recursive
step "YAML lint" "" .venv/bin/yamllint -s rules example-rules tests/fixtures
step "Terraform validate" "" sh -c 'terraform init -backend=false -input=false -no-color -lockfile=readonly && terraform validate -no-color'
step "Rule checks (terraform test)" "" terraform test -no-color
step "Bootstrap validate + test" "" sh -c 'terraform -chdir=bootstrap init -backend=false -input=false -no-color -lockfile=readonly && terraform -chdir=bootstrap validate -no-color && terraform -chdir=bootstrap test -no-color'
step "Python unit tests" "" .venv/bin/python -m unittest -q scripts/test_okta_rules.py

offline_preview() {
  mkdir -p .terraform
  git show origin/tfstate-backup:terraform.tfstate >"$TMP/state.json" &&
    (cd "$TMP" && GITHUB_STEP_SUMMARY='' GITHUB_OUTPUT='' "$ROOT/.venv/bin/python" "$ROOT/scripts/okta_rules.py" \
      preview state.json --groups-out "$ROOT/.terraform/offline-groups.json") >/dev/null &&
    terraform test -no-color -test-directory=tests/local
}

# Same summary as the PR. Report files are written to the temp dir, not the repo.
show_summary() {
  echo
  sed '/^$/d; s/^### //; s/^/    /' "$TMP/summary.md"
}

echo
echo "${B}Plan preview (nothing is applied)${N}"
if [ "$PLAN" = 0 ]; then
  skip "Plan preview" "(--no-plan)"
elif [ "$failed" != 0 ]; then
  skip "Plan preview" "fix the failures above first"
# Last deploy's state from the tfstate-backup branch. If the fetch fails, the last fetched copy is used.
elif ! { git fetch -q origin tfstate-backup 2>/dev/null; git rev-parse -q --verify origin/tfstate-backup >/dev/null; }; then
  skip "Plan preview" "no tfstate-backup branch yet, the first deploy creates it"
else
  step "Rule checks + change preview" "" offline_preview
  if [ "$failed" = 0 ]; then
    show_summary
    echo "    ${Y}Compared with the last deploy, so Okta GUI changes don't show. The PR's Plan preview is the final word.${N}"
  fi
fi

echo
if [ "$failed" = 0 ]; then
  echo "${G}${B}Good:${N} $passed passed, $skipped skipped. Nothing was applied."
else
  echo "${R}${B}$failed failed${N}, $passed passed, $skipped skipped. Nothing was applied."
  exit 1
fi
