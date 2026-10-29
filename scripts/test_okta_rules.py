import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import okta_rules  # noqa: E402


def make_jwk():
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key))
    jwk["kid"] = "test-kid"
    return key, jwk


def change(actions, before=None, after=None, importing=None, key="k"):
    rc = {"mode": "managed", "type": "okta_group_rule", "index": key, "address": f'okta_group_rule.this["{key}"]',
          "change": {"actions": actions, "before": before, "after": after}}
    if importing:
        rc["change"]["importing"] = {"id": importing}
    return rc


def rule(name, groups=("00g1",), expr='user.team == "A"', rule_id="0pr1"):
    return {"id": rule_id, "name": name, "status": "ACTIVE", "expression_value": expr, "group_assignments": list(groups)}


def plan(*changes, drift=()):
    return {"resource_changes": list(changes), "resource_drift": list(drift), "prior_state": {"values": {"root_module": {"resources": [
        {"address": "data.okta_groups.all", "values": {"groups": [{"id": "00g1", "name": "github-users"}, {"id": "00g2", "name": "looker"}]}}]}}}}


class ParseEnvTest(unittest.TestCase):
    def test_multiline_jwk_and_quotes(self):
        _, jwk = make_jwk()
        text = f"OKTA_CLIENT_ID='0oa123'\nOKTA_DOMAIN_URL='acme.oktapreview.com'\nOKTA_PRIVATE_KEY_JWK='{json.dumps(jwk, indent=4)}'\n"
        cfg = okta_rules.parse_env(text)
        self.assertEqual(cfg["client_id"], "0oa123")
        self.assertEqual(cfg["domain"], "acme.oktapreview.com")
        self.assertEqual(cfg["jwk"]["kid"], "test-kid")

    def test_rejects_non_okta_domain(self):
        with self.assertRaises(SystemExit):
            okta_rules.parse_env("OKTA_CLIENT_ID=a\nOKTA_DOMAIN_URL=evil.example.com\nOKTA_PRIVATE_KEY_JWK={}\n")

    def test_missing_values(self):
        with self.assertRaises(SystemExit):
            okta_rules.parse_env("OKTA_CLIENT_ID=a\n")


class ClientAssertionTest(unittest.TestCase):
    def test_signed_claims(self):
        import jwt

        key, jwk = make_jwk()
        url = "https://acme.oktapreview.com/oauth2/v1/token"
        token = okta_rules.client_assertion({"client_id": "0oa123", "jwk": jwk}, url, 1_000_000)
        claims = jwt.decode(token, key.public_key(), algorithms=["RS256"], audience=url, options={"verify_exp": False})
        self.assertEqual((claims["iss"], claims["sub"], claims["exp"] - claims["iat"]), ("0oa123", "0oa123", 300))
        self.assertEqual(jwt.get_unverified_header(token)["kid"], "test-kid")


class DpopTest(unittest.TestCase):
    def test_proof_binds_method_url_nonce_and_token(self):
        import jwt
        from cryptography.hazmat.primitives.asymmetric import ec

        client = okta_rules.Okta.__new__(okta_rules.Okta)
        client.dpop_key = ec.generate_private_key(ec.SECP256R1())
        client.nonce, client.token = "n1", "tok"
        proof = client.proof("GET", "https://acme.oktapreview.com/api/v1/groups/rules?limit=200")
        header = jwt.get_unverified_header(proof)
        claims = jwt.decode(proof, client.dpop_key.public_key(), algorithms=["ES256"])
        self.assertEqual((header["typ"], header["jwk"]["kty"]), ("dpop+jwt", "EC"))
        self.assertNotIn("d", header["jwk"])
        self.assertEqual(claims["htu"], "https://acme.oktapreview.com/api/v1/groups/rules")
        self.assertEqual((claims["htm"], claims["nonce"]), ("GET", "n1"))
        self.assertEqual(claims["ath"], okta_rules.b64url(__import__("hashlib").sha256(b"tok").digest()))

    def test_refuses_other_hosts(self):
        client = okta_rules.Okta.__new__(okta_rules.Okta)
        client.base = "https://acme.oktapreview.com"
        with self.assertRaises(SystemExit):
            client.call("GET", "https://evil.example.com/api/v1/groups")


class ProviderEnvTest(unittest.TestCase):
    def test_writes_private_pem_and_env(self):
        from cryptography.hazmat.primitives import serialization

        _, jwk = make_jwk()
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "env"
            os.environ.update(RUNNER_TEMP=tmp, GITHUB_ENV=str(env_file),
                              OKTA_OAUTH=f"OKTA_CLIENT_ID=0oa1\nOKTA_DOMAIN_URL=acme.oktapreview.com\nOKTA_PRIVATE_KEY_JWK='{json.dumps(jwk)}'\n")
            try:
                okta_rules.cmd_provider_env(type("A", (), {"scopes": "okta.groups.read"}))
            finally:
                for k in ("RUNNER_TEMP", "GITHUB_ENV", "OKTA_OAUTH"):
                    os.environ.pop(k)
            pem = Path(tmp) / "okta_api_key.pem"
            self.assertEqual(pem.stat().st_mode & 0o777, 0o600)
            serialization.load_pem_private_key(pem.read_bytes(), password=None)
            env = env_file.read_text()
            self.assertIn("OKTA_ORG_NAME=acme\n", env)
            self.assertIn("OKTA_BASE_URL=oktapreview.com\n", env)
            self.assertIn("OKTA_API_PRIVATE_KEY_ID=test-kid\n", env)
            self.assertNotIn("BEGIN", env)


class SummaryTest(unittest.TestCase):
    def test_five_creates_auto(self):
        _, _, counts, env, _ = okta_rules.summarize(plan(*[change(["create"], after=rule(f"r{i}")) for i in range(5)]))
        self.assertEqual((counts["changes"], env), (5, "prod-auto"))

    def test_six_changes_gated(self):
        _, _, counts, env, _ = okta_rules.summarize(plan(*[change(["create"], after=rule(f"r{i}")) for i in range(6)]))
        self.assertEqual((counts["changes"], env), (6, "prod-gated"))

    def test_any_delete_gated(self):
        title, rows, counts, env, why = okta_rules.summarize(plan(change(["delete"], before=rule("old"))))
        self.assertEqual((counts["deletes"], env), (1, "prod-gated"))
        self.assertIn("delete", why)
        self.assertNotIn("delete", title)

    def test_replace_counted_once_and_names_groups(self):
        _, rows, counts, env, _ = okta_rules.summarize(plan(change(["delete", "create"], before=rule("r"), after=rule("r", groups=("00g1", "00g2")))))
        self.assertEqual((counts["changes"], counts["deletes"], env), (1, 1, "prod-gated"))
        self.assertIn("+looker", rows[0][2])

    def test_update_shows_expression(self):
        _, rows, _, env, _ = okta_rules.summarize(plan(change(["update"], before=rule("r"), after=rule("r", expr='user.team == "B"'))))
        self.assertEqual(env, "prod-auto")
        self.assertIn('user.team == "B"', rows[0][2])

    def test_imports_not_counted(self):
        _, _, counts, env, _ = okta_rules.summarize(plan(*[change(["no-op"], before=rule(f"r{i}"), after=rule(f"r{i}"), importing=f"0pr{i}") for i in range(10)]))
        self.assertEqual((counts["changes"], counts["imports"], env), (0, 10, "prod-auto"))

    def test_renamed_imported_key_blocked(self):
        with self.assertRaises(SystemExit):
            okta_rules.summarize(plan(change(["delete"], before=rule("r", rule_id="0prX"), key="old"),
                                      change(["no-op"], after=rule("r", rule_id="0prX"), importing="0prX", key="new")))

    def test_replace_while_importing_is_not_a_rename(self):
        _, _, counts, env, _ = okta_rules.summarize(plan(change(["delete", "create"], before=rule("r", rule_id="0prA"), after=rule("r", groups=("00g2",)), importing="0prA")))
        self.assertEqual((counts["changes"], env), (1, "prod-gated"))

    def test_reverting_gui_change_gated(self):
        gui = change(["update"], before=rule("r"), after=rule("r", expr='user.team == "GUI"'))
        title, rows, _, env, why = okta_rules.summarize(plan(change(["update"], before=rule("r", expr='user.team == "GUI"'), after=rule("r")), drift=[gui]))
        self.assertEqual(env, "prod-gated")
        self.assertIn("reverts 1 Okta GUI change", why)
        self.assertTrue(rows[0][2].startswith("undoes a GUI change"))

    def test_drift_noise_and_imported_gui_changes_not_gated(self):
        noise = change(["update"], before=dict(rule("a"), users_excluded=None), after=dict(rule("a"), users_excluded=[]), key="a")
        imported = change(["update"], before=rule("b"), after=rule("b", expr='user.team == "GUI"'), key="b")
        _, _, _, env, _ = okta_rules.summarize(plan(change(["update"], before=rule("a"), after=rule("a", expr='user.team == "B"'), key="a"),
                                                 change(["no-op"], before=rule("b"), after=rule("b"), key="b"), drift=[noise, imported]))
        self.assertEqual(env, "prod-auto")

    def test_ignores_no_op_and_other_types(self):
        _, rows, counts, _, _ = okta_rules.summarize(plan(change(["no-op"], before=rule("r"), after=rule("r")),
                                                       {"mode": "data", "type": "okta_groups", "change": {"actions": ["read"]}}))
        self.assertEqual((rows, counts["unchanged"]), ([], 1))


def okta_rule(rule_id, name, groups, expr='user.team == "A"', status="ACTIVE"):
    return {"id": rule_id, "name": name, "status": status, "conditions": {"expression": {"value": expr}},
            "actions": {"assignUserToGroups": {"groupIds": groups}}}


class ExportTest(unittest.TestCase):
    names = {"00g1": "github-users", "00g2": "looker"}

    def files(self):
        return {"eng.yaml": {
            "eng-a": {"name": "Eng A", "expression": 'user.team == "A"', "groups": ["github-users"], "status": "ACTIVE"},
            "eng-b": {"name": "Eng B", "expression": 'user.team == "B"', "groups": ["looker"], "status": "ACTIVE"},
            "eng-new": {"name": "Eng New", "expression": "true", "groups": ["looker"]},
        }}

    def test_unchanged_produces_nothing(self):
        files = self.files()
        rows, touched = okta_rules.apply_export(files, [okta_rule("0pr1", "Eng A", ["00g1"]), okta_rule("0pr2", "Eng B", ["00g2"], 'user.team == "B"')],
                                                self.names, {"eng-a": "0pr1", "eng-b": "0pr2"})
        self.assertEqual(touched, set())
        self.assertEqual([r[1] for r in rows], ["not applied"])

    def test_update_delete_and_new(self):
        files = self.files()
        okta = [okta_rule("0pr1", "Eng A", ["00g1", "00g2"], 'user.team == "A2"'),
                okta_rule("0pr9", "Sales X", ["00g2"], '(user.department=="Sales") and (user.team=="Sales - AE")')]
        rows, touched = okta_rules.apply_export(files, okta, self.names, {"eng-a": "0pr1", "eng-b": "0pr2"})
        actions = {r[0]: r[1] for r in rows}
        self.assertEqual(actions, {"Eng A": "changed in GUI", "Eng B": "deleted in GUI", "Eng New": "not applied", "Sales X": "created in GUI"})
        self.assertEqual(files["eng.yaml"]["eng-a"]["groups"], ["github-users", "looker"])
        self.assertEqual(files["eng.yaml"]["eng-a"]["expression"], 'user.team == "A2"')
        self.assertNotIn("eng-b", files["eng.yaml"])
        self.assertEqual(files["sales/sales-ae.yaml"]["sales-x"]["id"], "0pr9")
        self.assertEqual(files["sales/sales-ae.yaml"]["sales-x"]["status"], "ACTIVE")
        self.assertEqual(touched, {"eng.yaml", "sales/sales-ae.yaml"})

    def test_recreated_in_gui_gets_new_key_in_same_file(self):
        files = self.files()
        rows, touched = okta_rules.apply_export(files, [okta_rule("0pr7", "Eng A", ["00g2"]), okta_rule("0pr2", "Eng B", ["00g2"], 'user.team == "B"')],
                                                self.names, {"eng-a": "0pr1", "eng-b": "0pr2"})
        self.assertNotIn("eng-a", files["eng.yaml"])
        self.assertEqual(files["eng.yaml"]["eng-a-2"]["id"], "0pr7")
        self.assertNotIn(okta_rules.IMPORTED_FILE, files)

    def test_pending_delete_not_readded(self):
        files = {"eng.yaml": {}}
        rows, touched = okta_rules.apply_export(files, [okta_rule("0pr1", "Eng A", ["00g1"])], self.names, {"eng-a": "0pr1"})
        self.assertEqual((rows, touched), ([], set()))

    def test_groups_update_keeps_next_rule_comment(self):
        yaml = okta_rules.yaml_handler()
        doc = yaml.load("eng-a:\n  name: Eng A\n  expression: 'true'\n  groups:\n    - github-users\n\n# owned by data team\neng-b:\n  name: Eng B\n  expression: 'true'\n  groups:\n    - looker\n")
        okta_rules.apply_export({"eng.yaml": doc}, [okta_rule("0pr1", "Eng A", ["00g2"], "true"), okta_rule("0pr2", "Eng B", ["00g2"], "true")],
                                self.names, {"eng-a": "0pr1", "eng-b": "0pr2"})
        out = io.StringIO()
        yaml.dump(doc, out)
        self.assertIn("    - looker\n\n# owned by data team\n", out.getvalue())

    def test_unplaceable_new_rule_goes_to_imported_with_unique_key(self):
        files = {"a.yaml": {"eng-a": {"name": "Other", "expression": "true", "groups": ["looker"], "id": "0pr1"}}}
        rows, _ = okta_rules.apply_export(files, [okta_rule("0pr1", "Other", ["00g2"], "true"), okta_rule("0pr2", "Eng A", ["00g1"])], self.names, {})
        self.assertIn("eng-a-2", files[okta_rules.IMPORTED_FILE])

    def test_inbox_rule_moves_once_placeable(self):
        files = {okta_rules.IMPORTED_FILE: {
            "eng-a": {"name": "Eng A", "expression": 'user.team == "A"', "groups": ["github-users"], "status": "ACTIVE", "id": "0pr1"},
            "looker": {"name": "Looker", "expression": 'isMemberOfAnyGroup("00g9")', "groups": ["looker"], "status": "ACTIVE", "id": "0pr2"},
        }}
        okta = [okta_rule("0pr1", "Eng A", ["00g1"], '(user.department=="Engineering") and (user.team=="A")'),
                okta_rule("0pr2", "Looker", ["00g2"], 'isMemberOfAnyGroup("00g9")')]
        rows, touched = okta_rules.apply_export(files, okta, self.names, {})
        self.assertEqual(files[okta_rules.IMPORTED_FILE], {})
        self.assertEqual(files["engineering/a.yaml"]["eng-a"]["expression"], '(user.department=="Engineering") and (user.team=="A")')
        self.assertIn("looker", files["other/looker.yaml"])
        self.assertEqual(touched, {okta_rules.IMPORTED_FILE, "engineering/a.yaml", "other/looker.yaml"})
        self.assertEqual(sorted(r[1] for r in rows), ["changed in GUI", "moved", "moved"])

    def test_round_trip_keeps_comments(self):
        yaml = okta_rules.yaml_handler()
        doc = yaml.load("# team owned\neng-a:\n  name: Eng A  # keep me\n  expression: 'user.team == \"A\"'\n  groups:\n    - github-users\n")
        okta_rules.apply_export({"eng.yaml": doc}, [okta_rule("0pr1", "Eng A", ["00g1", "00g2"])], self.names, {"eng-a": "0pr1"})
        out = io.StringIO()
        yaml.dump(doc, out)
        self.assertIn("# keep me", out.getvalue())
        self.assertIn("    - looker", out.getvalue())


class RuleFileTest(unittest.TestCase):
    org = '(user.organization=="100") and (user.userType=="Full Time" or user.userType=="Intern")'

    def test_placement(self):
        cases = {
            f'{self.org} and (user.department=="Business Operations" ) and (user.team=="Biz Ops - MDEV")': "business-operations/biz-ops-mdev.yaml",
            f'{self.org} and (user.department=="Engineering")': "engineering/_department.yaml",
            f'{self.org} and (user.department=="Client Strategy" or user.department=="Revenue" or user.department=="Sales") and (user.team=="CS - Implementation")': "multi-department/cs-implementation.yaml",
            f'{self.org} and (user.department=="Client Strategy" or user.department=="Revenue")': "multi-department/_department.yaml",
            self.org: "org-wide.yaml",
            'isMemberOfAnyGroup("00g1","00g2")': "other/looker-users.yaml",
            '(user.department=="Engineering") and (user.team=="A" or user.team=="B")': okta_rules.IMPORTED_FILE,
            'user.team == "A"': okta_rules.IMPORTED_FILE,
        }
        for expression, expected in cases.items():
            self.assertEqual(okta_rules.rule_file(expression, "looker-users"), expected, expression)


class ExamplesTest(unittest.TestCase):
    def test_examples_are_where_the_import_would_file_them(self):
        root = okta_rules.ROOT / "example-rules"
        paths = sorted(root.rglob("*.yaml"))
        self.assertTrue(paths)
        for path in paths:
            for key, entry in okta_rules.yaml_handler().load(path).items():
                self.assertEqual(okta_rules.rule_file(entry["expression"], key), str(path.relative_to(root)), key)


class BackupStateTest(unittest.TestCase):
    def run_git(self, show_code):
        def fake(cmd, **_):
            out = {"show": '{"serial": 9}', "log": "State after abc1234 (run 1), 2 hours ago"}.get(cmd[3], "")
            return mock.Mock(returncode=show_code if cmd[3] == "show" else 0, stdout=out)
        return fake

    def test_reads_backup_branch(self):
        with mock.patch.object(okta_rules.subprocess, "run", side_effect=self.run_git(0)), mock.patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(okta_rules.backup_state(), '{"serial": 9}')
        self.assertIn("State after abc1234 (run 1), 2 hours ago", out.getvalue())

    def test_missing_branch_stops_with_a_hint(self):
        with mock.patch.object(okta_rules.subprocess, "run", side_effect=self.run_git(128)):
            with self.assertRaises(SystemExit) as stop:
                okta_rules.backup_state()
        self.assertIn("--state", str(stop.exception))


class OfflinePlanTest(unittest.TestCase):
    def test_matches_what_terraform_would_plan(self):
        state = {"resources": [
            {"mode": "data", "type": "okta_groups", "instances": [{"attributes": {"groups": [
                {"id": "00g1", "name": "github-users"}, {"id": "00g2", "name": "looker"}]}}]},
            {"mode": "managed", "type": "okta_group_rule", "instances": [
                {"index_key": k, "attributes": dict(rule(k, groups=g), users_excluded=None)}
                for k, g in (("same", ("00g1",)), ("renamed", ("00g1",)), ("regrouped", ("00g1",)), ("gone", ("00g1",)))]}]}
        yaml_rule = {"expression": 'user.team == "A"', "status": "ACTIVE", "groups": ["github-users"]}
        files = {"a.yaml": {"same": dict(yaml_rule, name="same"), "renamed": dict(yaml_rule, name="new name"),
                            "regrouped": dict(yaml_rule, name="regrouped", groups=["github-users", "looker"])},
                 "b.yaml": {"new": dict(yaml_rule, name="new"), "adopted": dict(yaml_rule, name="adopted", id="0pr9")}}
        plan = okta_rules.offline_plan(state, files)
        actions = {rc["index"]: rc["change"]["actions"] for rc in plan["resource_changes"]}
        self.assertEqual(actions, {"same": ["no-op"], "renamed": ["update"], "regrouped": ["delete", "create"],
                                   "gone": ["delete"], "new": ["create"], "adopted": ["no-op"]})
        title, rows, counts, env, _ = okta_rules.summarize(plan)
        self.assertEqual((counts["changes"], counts["imports"], counts["unchanged"], env), (4, 1, 1, "prod-gated"))
        self.assertIn("+looker", dict((r, d) for r, _, d in rows)["regrouped"])

    def test_missing_status_means_inactive(self):
        state = {"resources": [{"mode": "managed", "type": "okta_group_rule",
                                "instances": [{"index_key": "r", "attributes": rule("r")}]}]}
        plan = okta_rules.offline_plan(state, {"a.yaml": {"r": {"name": "r", "expression": 'user.team == "A"', "groups": ["00g1"]}}})
        self.assertEqual(plan["resource_changes"][0]["change"]["actions"], ["update"])


class ReportTest(unittest.TestCase):
    def test_drift_header_links_commit_and_names_only_manual_runners(self):
        env = {"GITHUB_SHA": "64f3c1e0123456789", "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "o/r",
               "GITHUB_ACTOR": "someone", "GITHUB_EVENT_NAME": "schedule"}
        with mock.patch.dict(os.environ, env):
            line = okta_rules.compared_with()
            self.assertEqual(line, "Compared with main at [`64f3c1e`](https://github.com/o/r/commit/64f3c1e0123456789)")
            os.environ["GITHUB_EVENT_NAME"] = "workflow_dispatch"
            self.assertTrue(okta_rules.compared_with().endswith(")\n\nRun by @someone"))
        with mock.patch.dict(os.environ, {"GITHUB_SHA": ""}):
            self.assertIsNone(okta_rules.compared_with())

    def test_plan_header_links_pr_head_commit(self):
        env = {"GITHUB_SHA": "merge000000", "COMMIT_SHA": "head111111", "GITHUB_SERVER_URL": "https://github.com",
               "GITHUB_REPOSITORY": "o/r", "GITHUB_ACTOR": "someone", "COMMIT_TITLE": "Add rule", "GITHUB_STEP_SUMMARY": ""}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env):
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                okta_rules.write_reports("t", [])
                self.assertIn("Commit [`head111`](https://github.com/o/r/commit/head111111) by @someone: Add rule", Path("summary.md").read_text())
            finally:
                os.chdir(cwd)

    def test_pipes_escaped_and_files_written(self):
        # Blank so CI's real job summary doesn't get this test's table.
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                okta_rules.write_reports("t", [("r", "update", 'a == "x" || b')])
                self.assertIn("\\|\\|", Path("summary.md").read_text())
                self.assertIn(":pencil2: update: r", Path("slack.txt").read_text())
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
