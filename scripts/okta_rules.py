#!/usr/bin/env python3
"""Helpers for the Okta group rules repo.

provider-env  Okta provider settings for Terraform (JWK secret converted to a PEM file)
export        pull rules from Okta into rules/*.yaml (drift check and GUI import)
summary       turn a Terraform plan into a readable change summary and pick the deploy gate
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
LOCAL_ENV_FILE = ROOT / "okta_oauth.env"
MAX_AUTO_CHANGES = 5
IMPORTED_FILE = "imported.yaml"
# Anything else (update, replace, changed in GUI, moved) gets :pencil2:.
SLACK_EMOJI = {"create": ":heavy_plus_sign:", "created in GUI": ":heavy_plus_sign:", "not applied": ":heavy_plus_sign:",
               "delete": ":heavy_minus_sign:", "deleted in GUI": ":heavy_minus_sign:"}
INBOX_NOTE = "# Inbox: new GUI rules the import couldn't place land here. Move them to the right file in the same PR.\n"

def parse_env(text):
    values = {}
    for key, raw in re.findall(r"^([A-Z_]+)=(.*?)(?=^[A-Z_]+=|\Z)", text, re.M | re.S):
        values[key] = raw.strip().strip("'\"")
    missing = {"OKTA_CLIENT_ID", "OKTA_DOMAIN_URL", "OKTA_PRIVATE_KEY_JWK"} - values.keys()
    if missing:
        sys.exit(f"Okta OAuth settings are missing: {', '.join(sorted(missing))}")
    domain = re.sub(r"^https?://", "", values["OKTA_DOMAIN_URL"]).strip("/")
    if not re.fullmatch(r"[a-z0-9-]+\.(okta|oktapreview|okta-emea)\.com", domain):
        sys.exit("OKTA_DOMAIN_URL must look like <org>.okta.com or <org>.oktapreview.com")
    return {"client_id": values["OKTA_CLIENT_ID"], "domain": domain, "jwk": json.loads(values["OKTA_PRIVATE_KEY_JWK"])}


def load_config():
    text = os.environ.get("OKTA_OAUTH") or (LOCAL_ENV_FILE.read_text() if LOCAL_ENV_FILE.exists() else "")
    if not text:
        sys.exit(f"Set OKTA_OAUTH or create {LOCAL_ENV_FILE.name}")
    return parse_env(text)


def client_assertion(cfg, token_url, now):
    import jwt

    claims = {"iss": cfg["client_id"], "sub": cfg["client_id"], "aud": token_url,
              "iat": now, "exp": now + 300, "jti": uuid.uuid4().hex}
    key = jwt.algorithms.RSAAlgorithm.from_jwk(cfg["jwk"])
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": cfg["jwk"]["kid"]})


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Okta:
    """Small Okta management API client. Every call carries a DPoP proof, so it works with DPoP-bound tokens."""

    def __init__(self, cfg, scopes):
        from cryptography.hazmat.primitives.asymmetric import ec

        self.base = f"https://{cfg['domain']}"
        self.dpop_key = ec.generate_private_key(ec.SECP256R1())
        self.nonce = self.token = None
        self.token_type = "DPoP"
        data, _ = self.call("POST", "/oauth2/v1/token", form=lambda url: {
            "grant_type": "client_credentials",
            "scope": " ".join(scopes),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion(cfg, url, int(time.time())),
        })
        self.token, self.token_type = data["access_token"], data.get("token_type", "Bearer")

    def proof(self, method, url):
        import jwt

        claims = {"htm": method, "htu": url.split("?")[0], "iat": int(time.time()), "jti": uuid.uuid4().hex}
        if self.nonce:
            claims["nonce"] = self.nonce
        if self.token:
            claims["ath"] = b64url(hashlib.sha256(self.token.encode()).digest())
        jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.dpop_key.public_key()))
        return jwt.encode(claims, self.dpop_key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": jwk})

    def call(self, method, url, form=None):
        url = url if url.startswith("https://") else self.base + url
        if not url.startswith(self.base + "/"):
            sys.exit(f"Refusing a URL outside the Okta org: {url}")
        for attempt in range(4):
            headers = {"Accept": "application/json"}
            if self.token_type == "DPoP":
                headers["DPoP"] = self.proof(method, url)
            if self.token:
                headers["Authorization"] = f"{self.token_type} {self.token}"
            body = urllib.parse.urlencode(form(url)).encode() if form else None
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                # host is pinned to the validated Okta org above
                with urllib.request.urlopen(req, timeout=30) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                    return json.load(resp), resp.headers
            except urllib.error.HTTPError as err:
                nonce = err.headers.get("DPoP-Nonce")
                if err.code in (400, 401) and nonce and nonce != self.nonce:
                    self.nonce = nonce
                    continue
                if err.code == 429 and attempt < 3:
                    reset = int(err.headers.get("X-Rate-Limit-Reset", time.time() + 10))
                    time.sleep(min(max(reset - time.time(), 1), 60))
                    continue
                sys.exit(f"Okta API {url.split('?')[0]} returned {err.code}: {err.read().decode()[:500]}")
        sys.exit(f"Okta API {url.split('?')[0]} kept failing")

    def get_all(self, path):
        url, items = path, []
        while url:
            data, headers = self.call("GET", url)
            items.extend(data)
            nxt = re.findall(r'<([^>]+)>;\s*rel="next"', ", ".join(headers.get_all("Link") or []))
            url = nxt[0] if nxt else None
        return items


def cmd_provider_env(args):
    """Okta provider settings. The provider does its own OAuth (with DPoP), it just needs the key as PEM."""
    import jwt
    from cryptography.hazmat.primitives import serialization

    cfg = load_config()
    key = jwt.algorithms.RSAAlgorithm.from_jwk(cfg["jwk"])
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = Path(os.environ.get("RUNNER_TEMP") or ROOT) / "okta_api_key.pem"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    os.chmod(path, 0o600)
    org, base = cfg["domain"].split(".", 1)
    env = {"OKTA_ORG_NAME": org, "OKTA_BASE_URL": base, "OKTA_API_CLIENT_ID": cfg["client_id"],
           "OKTA_API_PRIVATE_KEY_ID": cfg["jwk"]["kid"], "OKTA_API_PRIVATE_KEY": str(path), "OKTA_API_SCOPES": args.scopes}
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as fh:
            fh.writelines(f"{k}={v}\n" for k, v in env.items())
    else:
        print("\n".join(f"export {k}='{v}'" for k, v in env.items()))


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "rule"


def okta_rule_to_yaml(rule, group_names):
    out = {
        "name": rule["name"],
        "expression": rule["conditions"]["expression"]["value"],
        "groups": sorted(group_names.get(g, g) for g in rule["actions"]["assignUserToGroups"]["groupIds"]),
    }
    out["status"] = rule["status"]
    excluded = ((rule["conditions"].get("people") or {}).get("users") or {}).get("exclude") or []
    if excluded:
        out["users_excluded"] = sorted(excluded)
    return out


def rule_diff(old, new):
    """Readable list of what differs between two rule dicts (YAML shape, group names)."""
    notes = []
    for field in ("name", "expression"):
        if old.get(field) != new.get(field):
            notes.append(f"{field}: {old.get(field)!r} -> {new.get(field)!r}")
    if old.get("status", "INACTIVE") != new.get("status", "INACTIVE"):
        notes.append(f"status: {old.get('status', 'INACTIVE')} -> {new.get('status', 'INACTIVE')}")
    added = sorted(set(new.get("groups") or []) - set(old.get("groups") or []))
    removed = sorted(set(old.get("groups") or []) - set(new.get("groups") or []))
    if added or removed:
        notes.append("groups " + " ".join([f"+{g}" for g in added] + [f"-{g}" for g in removed]))
    if set(old.get("users_excluded") or []) != set(new.get("users_excluded") or []):
        notes.append("excluded users changed")
    return notes


def state_ids(state):
    ids = {}
    for res in state.get("resources", []):
        if res.get("mode") == "managed" and res.get("type") == "okta_group_rule":
            for inst in res.get("instances", []):
                ids[inst["index_key"]] = inst["attributes"]["id"]
    return ids


def rule_file(expression, key):
    """Where a new GUI rule goes, based on the department and team its expression matches on."""
    departments = sorted(set(re.findall(r'user\.department\s*==\s*"([^"]+)"', expression)))
    teams = sorted(set(re.findall(r'user\.team\s*==\s*"([^"]+)"', expression)))
    if not departments:
        if teams:
            return IMPORTED_FILE
        return "org-wide.yaml" if "user.organization" in expression else f"other/{key}.yaml"
    if len(teams) > 1:
        return IMPORTED_FILE
    folder = slug(departments[0]) if len(departments) == 1 else "multi-department"
    return f"{folder}/{slug(teams[0]) if teams else '_department'}.yaml"


def apply_export(files, okta_rules, group_names, ids_by_key):
    """Sync Okta rules into the loaded YAML files in place. Returns (rows, touched file names)."""
    rows, touched = [], set()
    okta_by_id = {r["id"]: r for r in okta_rules}
    # State ids count as seen so a merged-but-not-yet-applied delete is not re-added as a GUI rule.
    seen_ids, keys, deleted_files = set(ids_by_key.values()), set(), {}

    for fname, doc in files.items():
        for key in list(doc.keys()):
            keys.add(key)
            entry = doc[key]
            rule_id = ids_by_key.get(key) or entry.get("id")
            if not rule_id:
                rows.append((entry.get("name", key), "not applied", "in Git but not in Okta yet"))
                continue
            seen_ids.add(rule_id)
            if rule_id not in okta_by_id:
                del doc[key]
                touched.add(fname)
                deleted_files[entry.get("name")] = fname
                rows.append((entry.get("name", key), "deleted in GUI", f"removed {key} from {fname}"))
                continue
            current = okta_rule_to_yaml(okta_by_id[rule_id], group_names)
            # Groups listed by id compare as names, so they aren't reported as drift.
            mine = dict(entry, groups=[group_names.get(g, g) for g in entry.get("groups") or []])
            notes = rule_diff(mine, current)
            if not notes:
                continue
            for field in ("name", "expression", "status", "users_excluded"):
                if field in current and entry.get(field) != current[field]:
                    entry[field] = current[field]
                elif field not in current and field in entry:
                    del entry[field]
            if set(mine["groups"]) != set(current["groups"]):
                kept = [g for g in entry.get("groups") or [] if group_names.get(g, g) in current["groups"]]
                update_list(entry, "groups", kept + [g for g in current["groups"] if g not in mine["groups"]])
            touched.add(fname)
            rows.append((current["name"], "changed in GUI", "; ".join(notes)))

    # Rules waiting in the inbox move out once their expression says where they belong.
    inbox = files.get(IMPORTED_FILE, {})
    for key in list(inbox.keys()):
        fname = rule_file(inbox[key].get("expression") or "", key)
        if fname != IMPORTED_FILE:
            files.setdefault(fname, {})[key] = inbox.pop(key)
            touched.update({IMPORTED_FILE, fname})
            rows.append((files[fname][key].get("name", key), "moved", f"moved {key} from {IMPORTED_FILE} to {fname}"))

    for rule in sorted(okta_rules, key=lambda r: r["name"]):
        if rule["id"] in seen_ids:
            continue
        entry = okta_rule_to_yaml(rule, group_names)
        entry["id"] = rule["id"]
        # A new key on purpose: Terraform skips imports for a key it already has in state.
        key, n = slug(rule["name"]), 2
        while key in keys:
            key, n = f"{slug(rule['name'])}-{n}", n + 1
        keys.add(key)
        fname = deleted_files.get(rule["name"]) or rule_file(entry["expression"], key)
        files.setdefault(fname, {})[key] = entry
        touched.add(fname)
        rows.append((rule["name"], "created in GUI", f"added {key} to {fname}"))
    return rows, touched


def update_list(entry, field, values):
    """Replace a YAML list in place, keeping the comment or blank line ruamel parks on its last item."""
    seq = entry.get(field)
    if not hasattr(seq, "ca"):
        entry[field] = values
        return
    tail = seq.ca.items.pop(len(seq) - 1, None)
    seq[:] = values
    if tail:
        seq.ca.items[len(seq) - 1] = tail


def yaml_handler():
    from ruamel.yaml import YAML

    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 4096
    yaml.preserve_quotes = True
    return yaml


def backup_state():
    """The last deployed state from the tfstate-backup branch, so a local export needs no AWS access."""
    git = ["git", "-C", str(ROOT)]
    subprocess.run(git + ["fetch", "-q", "origin", "tfstate-backup"], check=False)
    show = subprocess.run(git + ["show", "origin/tfstate-backup:terraform.tfstate"], capture_output=True, text=True)
    if show.returncode:
        sys.exit("Couldn't read the tfstate-backup branch. Pass --state with a state file instead.")
    when = subprocess.run(git + ["log", "-1", "--format=%s, %cr", "origin/tfstate-backup"], capture_output=True, text=True)
    print(f"Using the last deployed state from tfstate-backup ({when.stdout.strip()})\n")
    return show.stdout


def cmd_export(args):
    # Read the state first so a missing state stops before any Okta calls. state pull prints nothing until the first apply.
    state_text = Path(args.state).read_text() if args.state else backup_state()
    cfg = load_config()
    okta = Okta(cfg, ["okta.groups.read"])
    groups = okta.get_all("/api/v1/groups?limit=200&search=" + urllib.parse.quote('type eq "OKTA_GROUP"'))
    group_names = {g["id"]: g["profile"]["name"] for g in groups}
    okta_rules = okta.get_all("/api/v1/groups/rules?limit=200")

    yaml = yaml_handler()
    RULES_DIR.mkdir(exist_ok=True)
    files = {str(p.relative_to(RULES_DIR)): yaml.load(p) or {} for p in sorted(RULES_DIR.rglob("*.y*ml"))}
    ids = state_ids(json.loads(state_text)) if state_text.strip() else {}
    rows, touched = apply_export(files, okta_rules, group_names, ids)
    for fname in touched:
        path = RULES_DIR / fname
        if files[fname]:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as fh:
                yaml.dump(files[fname], fh)
        elif fname == IMPORTED_FILE:
            path.write_text(INBOX_NOTE)
        else:
            path.unlink(missing_ok=True)

    drift = [r for r in rows if r[1] not in ("not applied", "moved")]
    title = f"Okta drift: {len(drift)} rule(s) differ between Okta and Git" if drift else "No drift: Okta matches Git"
    write_reports(title, rows, context=compared_with())
    write_outputs(changes=len(drift))
    print("\n".join(["Rule files changed:"] + [f"  rules/{f}" for f in sorted(touched)]) if touched else "No rule files changed.")


def plan_group_names(plan):
    for res in (plan.get("prior_state") or {}).get("values", {}).get("root_module", {}).get("resources", []):
        if res.get("address") == "data.okta_groups.all":
            return {g["id"]: g["name"] for g in res["values"].get("groups") or []}
    return {}


def plan_rule(values, group_names):
    if not values:
        return {}
    out = {k: values.get(k) for k in ("name", "status")}
    out["expression"] = values.get("expression_value")
    out["groups"] = sorted(group_names.get(g, g) for g in values.get("group_assignments") or [])
    out["users_excluded"] = values.get("users_excluded") or []
    return out


def summarize(plan):
    names = plan_group_names(plan)
    rows, counts = [], {"changes": 0, "deletes": 0, "imports": 0, "unchanged": 0}
    imported_ids, deleted_ids = set(), set()
    # Rules changed in the Okta GUI since the last apply. plan_rule() hides provider noise like users_excluded null vs [].
    drifted = {d.get("address") for d in plan.get("resource_drift", []) if d.get("type") == "okta_group_rule"
               and plan_rule(d["change"].get("before"), names) != plan_rule(d["change"].get("after"), names)}
    reverts = []
    for rc in plan.get("resource_changes", []):
        if rc.get("mode") != "managed" or rc.get("type") != "okta_group_rule":
            continue
        change = rc["change"]
        actions = change["actions"]
        before, after = plan_rule(change.get("before"), names), plan_rule(change.get("after"), names)
        if change.get("importing"):
            counts["imports"] += 1
            imported_ids.add(change["importing"].get("id"))
        if actions in (["no-op"], ["read"]):
            counts["unchanged"] += 0 if change.get("importing") else 1
            continue
        if actions == ["create"]:
            action, detail = "create", f"{len(after['groups'])} groups: {', '.join(after['groups'])}"
        elif actions == ["delete"]:
            action, detail = "delete", "rule removed, members keep their groups"
        elif actions == ["update"]:
            action, detail = "update", "; ".join(rule_diff(before, after))
        else:
            action, detail = "replace", "; ".join(rule_diff(before, after)) + " (groups can't be edited in place, so Okta recreates the rule)"
        if action in ("delete", "replace"):
            counts["deletes"] += 1
        if action == "delete":
            deleted_ids.add((change.get("before") or {}).get("id"))
        counts["changes"] += 1
        if rc.get("address") in drifted:
            reverts.append((after or before).get("name"))
            detail = "undoes a GUI change; " + detail
        rows.append(((after or before).get("name"), action, detail))

    clash = sorted(i for i in imported_ids & deleted_ids if i)
    if clash:
        raise SystemExit(f"A rule key was renamed on an imported rule (Okta id {', '.join(clash)}). "
                         "Keep the original key and change only `name:`, or this plan would delete the rule.")

    reasons = []
    if counts["changes"] > MAX_AUTO_CHANGES:
        reasons.append(f"{counts['changes']} changes (over {MAX_AUTO_CHANGES})")
    if counts["deletes"]:
        reasons.append(f"includes {counts['deletes']} delete/replace")
    if reverts:
        reasons.append(f"reverts {len(reverts)} Okta GUI change(s), import them first to keep them")
    environment = "prod-gated" if reasons else "prod-auto"
    why = ", ".join(reasons) if reasons else f"{MAX_AUTO_CHANGES} or fewer changes, no deletes"
    title = f"Okta group rules: {counts['changes']} change(s) -> {environment}"
    return title, rows, counts, environment, why


def commit_link(sha):
    server, repo = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    return f"[`{sha[:7]}`]({server}/{repo}/commit/{sha})" if server and repo else f"`{sha[:7]}`"


def compared_with():
    """Drift header: the main commit Okta was compared with, linked for review."""
    sha = os.environ.get("GITHUB_SHA")
    if not sha:
        return None
    line = f"Compared with main at {commit_link(sha)}"
    # On a schedule GITHUB_ACTOR is whoever last edited the cron, not someone who ran this.
    if os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        line += f"\n\nRun by @{os.environ.get('GITHUB_ACTOR', '?')}"
    return line


def write_reports(title, rows, footer="", context=None):
    header = [f"### {title}"]
    if context:
        header.append(context)
    elif os.environ.get("GITHUB_SHA"):
        # On PRs GITHUB_SHA is a temporary merge commit, so validate.yaml passes the branch's head commit.
        sha = os.environ.get("COMMIT_SHA") or os.environ["GITHUB_SHA"]
        header.append(f"Commit {commit_link(sha)} by @{os.environ.get('GITHUB_ACTOR', '?')}"
                      + (f": {os.environ['COMMIT_TITLE']}" if os.environ.get("COMMIT_TITLE") else ""))
    md = header + [""]
    if rows:
        md += ["| Rule | Action | What changes |", "| --- | --- | --- |"]
        md += [f"| {cell(r)} | {cell(a)} | {cell(d)} |" for r, a, d in rows]
    if footer:
        md += ["", footer]
    text = "\n".join(md) + "\n"
    slack = "\n".join([f"*{title}*"] + [f"{SLACK_EMOJI.get(a, ':pencil2:')} {a}: {r} - {d}" for r, a, d in rows[:20]]
                      + ([f"...and {len(rows) - 20} more"] if len(rows) > 20 else []))
    Path("summary.md").write_text(text)
    Path("slack.txt").write_text(slack + "\n")
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as fh:
            fh.write(text)


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_outputs(**values):
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as fh:
            fh.writelines(f"{k}={v}\n" for k, v in values.items())


def offline_plan(state, files):
    """Plan-shaped dict from the last deployed state and the YAML, so summarize() works without Okta access."""
    resources = state.get("resources", [])
    groups = next((r["instances"][0]["attributes"]["groups"] for r in resources
                   if r["mode"] == "data" and r["type"] == "okta_groups"), [])
    ids = {g["name"]: g["id"] for g in groups}
    deployed = {i["index_key"]: i["attributes"] for r in resources
                if r["mode"] == "managed" and r["type"] == "okta_group_rule" for i in r["instances"]}
    wanted = {key: rule for doc in files.values() for key, rule in doc.items()}
    changes = []
    for key in sorted(set(deployed) | set(wanted)):
        before, rule = deployed.get(key), wanted.get(key)
        after = rule and {"name": rule.get("name"), "status": rule.get("status", "INACTIVE"),
                          "expression_value": rule.get("expression"), "users_excluded": rule.get("users_excluded"),
                          "group_assignments": [ids.get(g, g) for g in rule.get("groups") or []]}
        change = {"before": before, "after": after}
        if before is None and rule.get("id"):
            change.update(actions=["no-op"], importing={"id": rule["id"]})
        elif before is None:
            change["actions"] = ["create"]
        elif after is None:
            change["actions"] = ["delete"]
        elif set(before.get("group_assignments") or []) != set(after["group_assignments"]):
            change["actions"] = ["delete", "create"]
        else:
            change["actions"] = ["update"] if plan_rule(before, {}) != plan_rule(after, {}) else ["no-op"]
        changes.append({"mode": "managed", "type": "okta_group_rule", "index": key,
                        "address": f'okta_group_rule.this["{key}"]', "change": change})
    return {"resource_changes": changes, "prior_state": {"values": {"root_module": {"resources": [
        {"address": "data.okta_groups.all", "values": {"groups": groups}}]}}}}


def cmd_preview(args):
    state = json.loads(Path(args.state).read_text())
    yaml = yaml_handler()
    files = {str(p.relative_to(RULES_DIR)): yaml.load(p) or {} for p in sorted(RULES_DIR.rglob("*.y*ml"))}
    plan = offline_plan(state, files)
    if args.groups_out:
        Path(args.groups_out).write_text(json.dumps({"groups": plan["prior_state"]["values"]["root_module"]["resources"][0]["values"]["groups"]}))
    title, rows, counts, _, why = summarize(plan)
    write_reports(title, rows, f"Gate: {why}. Imports: {counts['imports']}. Unchanged: {counts['unchanged']}.")


def cmd_summary(args):
    title, rows, counts, environment, why = summarize(json.loads(Path(args.plan).read_text()))
    write_reports(title, rows, f"Gate: {why}. Imports: {counts['imports']}. Unchanged: {counts['unchanged']}.")
    write_outputs(environment=environment, has_changes=str(counts["changes"] + counts["imports"] > 0).lower(), **counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(required=True)
    p = sub.add_parser("provider-env")
    p.add_argument("--scopes", default="okta.groups.read", help="comma separated")
    p.set_defaults(func=cmd_provider_env)
    p = sub.add_parser("export")
    # Never run without a state: rules Terraform created (no id: in YAML) would look like new GUI rules and get duplicated.
    p.add_argument("--state", help="terraform state pull output; defaults to the last deployed state from tfstate-backup")
    p.set_defaults(func=cmd_export)
    p = sub.add_parser("preview", help="offline change preview against a saved state, no Okta or AWS needed")
    p.add_argument("state", help="terraform.tfstate, e.g. from the tfstate-backup branch")
    p.add_argument("--groups-out", help="also write the state's Okta group list here, for the offline rule checks")
    p.set_defaults(func=cmd_preview)
    p = sub.add_parser("summary")
    p.add_argument("plan", help="terraform show -json tfplan output")
    p.set_defaults(func=cmd_summary)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
