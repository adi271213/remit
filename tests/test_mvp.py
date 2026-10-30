from pathlib import Path
from itertools import product
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from privilege_check.cli import main
from privilege_check.report import markdown
from privilege_check.scan import compare, permissions
from privilege_check.sources import InputError, MAX_FILE, Snapshot, directory, git_snapshot

WF = ".github/workflows/ci.yml"
BASE = "on: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo fixture\n"


def write(root, tree):
    for name, text in tree.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def cli(args):
    output = io.StringIO()
    with patch("sys.stdout", output):
        code = main(args)
    return code, json.loads(output.getvalue())


class Acceptance(unittest.TestCase):
    pass


def acceptance_method(case):
    def test(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            base, head = root / "base", root / "head"
            base.mkdir()
            head.mkdir()
            write(base, case["base"])
            head_files = case["head"]
            if "head_path" in case:
                head_files = {case["head_path"]: next(iter(head_files.values()))}
            write(head, head_files)
            if case.get("missing_dir"):
                head = root / "missing"
            # Scanner must not execute scripts or make network connections.
            with patch("socket.socket", side_effect=AssertionError("network access")), patch("subprocess.run", side_effect=AssertionError("executed code")):
                code, report = cli(["scan", "--dirs", str(base), str(head)])
            expected = case["expected"]
            if expected == "grant":
                self.assertEqual(code, 0, report)
                self.assertEqual(report["analysis"], "complete", report)
                self.assertIn(case["rule"], [f["rule"] for f in report["findings"]], report)
                self.assertEqual(report["review"], "suggested")
            elif expected == "neutral":
                self.assertEqual((code, report["analysis"], report["findings"]), (0, "complete", []), report)
            elif expected == "incomplete":
                self.assertEqual((code, report["analysis"]), (2, "incomplete"), report)
            else:
                self.assertEqual((code, report["analysis"]), (2, "error"), report)
            self.assertFalse((root / "SHOULD_NOT_EXIST").exists())
            self.assertFalse((ROOT / "SHOULD_NOT_EXIST").exists())
    return test


for fixture in json.loads((ROOT / "tests/cases.json").read_text()):
    setattr(Acceptance, "test_" + fixture["id"], acceptance_method(fixture))


class Semantics(unittest.TestCase):
    def scan(self, head, base=BASE, defaults=None):
        return compare(Snapshot("base", {WF: base}), Snapshot("head", {WF: head}), defaults)

    def test_new_workflow(self):
        result = compare(Snapshot("base", {}), Snapshot("head", {WF: BASE.replace("permissions: {}", "permissions: {packages: write}")}))
        self.assertEqual(result["findings"][0]["job"], "test")
        self.assertEqual(result["findings"][0]["after"], {"packages": "write"})

    def test_selected_trigger_additions_in_all_supported_forms(self):
        events = ("pull_request_target", "workflow_run", "issue_comment", "issues",
                  "discussion", "discussion_comment")
        for event in events:
            for declaration in (f"on: {event}", f"on: [push, {event}]",
                                f"on:\n  push:\n  {event}:"):
                with self.subTest(event=event, declaration=declaration):
                    head = BASE.replace("on: push", declaration)
                    for old in ({WF: BASE}, {}):
                        result = compare(Snapshot("base", old), Snapshot("head", {WF: head}))
                        self.assertEqual((result["analysis"], result["review"]), ("complete", "suggested"))
                        self.assertEqual([(f["rule"], f["after"]) for f in result["findings"]], [("WF003", event)])

    def test_existing_or_removed_review_trigger_is_not_a_new_grant(self):
        for event in ("pull_request_target", "workflow_run", "issue_comment", "issues",
                      "discussion", "discussion_comment"):
            base = BASE.replace("on: push", f"on: [push, {event}]")
            for head in (base.replace("echo fixture", "echo changed"),
                         base.replace(f"[push, {event}]", f"[{event}, push]"), BASE):
                with self.subTest(event=event, head=head):
                    result = self.scan(head, base)
                    self.assertEqual((result["analysis"], result["findings"]), ("complete", []))

    def test_existing_trigger_filter_edits_remain_outside_coverage(self):
        base = BASE.replace("on: push", "on:\n  issue_comment:\n    types: [created]")
        result = self.scan(base.replace("[created]", "[created, edited]"), base)
        self.assertEqual((result["analysis"], result["findings"]), ("complete", []))
        self.assertIn("Trigger filter changes", " ".join(result["limitations"]))

    def test_review_trigger_finding_survives_unknown_token_defaults(self):
        base = BASE
        head = BASE.replace("on: push", "on: [push, issue_comment]").replace("permissions: {}\n", "")
        result = self.scan(head, base)
        self.assertEqual((result["analysis"], result["review"]), ("incomplete", "suggested"))
        self.assertEqual([(f["rule"], f["after"]) for f in result["findings"]], [("WF003", "issue_comment")])

    def test_pr_merge_context_events_are_not_default_branch_trigger_findings(self):
        for event in ("pull_request", "pull_request_review", "pull_request_review_comment"):
            with self.subTest(event=event):
                result = self.scan(BASE.replace("on: push", f"on: [push, {event}]"))
                self.assertEqual((result["analysis"], result["findings"]), ("complete", []))
                self.assertIn("selected event names only", " ".join(result["limitations"]))

    def test_null_trigger_remains_error_without_hiding_known_scope_change(self):
        head = BASE.replace("on: push", "on: ~").replace("permissions: {}", "permissions: {contents: write}")
        result = self.scan(head)
        self.assertEqual((result["analysis"], result["review"]), ("error", "suggested"))
        self.assertEqual([f["rule"] for f in result["findings"]], ["WF001"])

    def test_per_job_evidence(self):
        head = BASE.replace("permissions: {}", "permissions: {packages: write}")
        result = self.scan(head)
        self.assertEqual(result["findings"][0]["before"], {"packages": "none"})

    def test_read_increase_is_recorded(self):
        result = self.scan(BASE.replace("permissions: {}", "permissions: {issues: read}"))
        self.assertEqual(result["findings"][0]["after"], {"issues": "read"})

    def test_read_all_does_not_enable_oidc(self):
        self.assertEqual(permissions("read-all")["id-token"], "none")
        self.assertEqual(permissions("write-all")["vulnerability-alerts"], "read")

    def test_defaults_allow_comparison(self):
        base = BASE.replace("permissions: {}\n", "")
        head = base.replace("runs-on: ubuntu-latest", "runs-on: ubuntu-latest\n    permissions: {contents: write}")
        result = self.scan(head, base, {"contents": "read"})
        self.assertEqual(result["analysis"], "complete")
        self.assertEqual(result["findings"][0]["before"], {"contents": "read"})

    def test_unknown_base_is_not_assumed_none(self):
        base = BASE.replace("permissions: {}\n", "")
        result = self.scan(BASE.replace("permissions: {}", "permissions: {contents: write}"), base)
        self.assertEqual(result["analysis"], "incomplete")
        self.assertEqual(result["findings"], [])

    def test_unchanged_inheritance_is_symbolic_and_disclosed(self):
        base = BASE.replace("permissions: {}\n", "")
        result = self.scan(base.replace("echo fixture", "echo changed"), base)
        self.assertEqual((result["analysis"], result["findings"]), ("complete", []))
        self.assertEqual(result["inheritedComparisons"], [{"file": WF, "job": "test"}])
        self.assertIsNone(result["defaultPermissions"])
        self.assertIn("defaults stay fixed", markdown(result))

    def test_symbolic_equality_for_every_representative_default_vector(self):
        base = BASE.replace("permissions: {}\n", "")
        head = base.replace("echo fixture", "echo changed")
        for contents, issues, oidc in product(("none", "read", "write"), ("none", "read", "write"), ("none", "write")):
            with self.subTest(contents=contents, issues=issues, oidc=oidc):
                resolved = self.scan(head, base, {"contents": contents, "issues": issues, "id-token": oidc})
                self.assertEqual((resolved["analysis"], resolved["findings"]), ("complete", []))

    def test_transitions_to_and_from_unknown_remain_incomplete(self):
        inherited = BASE.replace("permissions: {}\n", "")
        for explicit in (BASE, BASE.replace("permissions: {}", "permissions: {contents: read}"), BASE.replace("permissions: {}", "permissions: write-all")):
            for base, head in ((explicit, inherited), (inherited, explicit)):
                with self.subTest(base=base, head=head):
                    result = self.scan(head, base)
                    self.assertEqual(result["analysis"], "incomplete")
                    self.assertEqual(result["inheritedComparisons"], [])

    def test_new_inherited_job_and_renamed_job_remain_incomplete(self):
        base = BASE.replace("permissions: {}\n", "")
        for head in (base.replace("test:", "renamed:"), base + "  added:\n    runs-on: ubuntu-latest\n    steps: [{run: echo new}]\n"):
            result = self.scan(head, base)
            self.assertEqual(result["analysis"], "incomplete")
        new_workflow = compare(Snapshot("base", {}), Snapshot("head", {WF: base}))
        self.assertEqual(new_workflow["analysis"], "incomplete")

    def test_dropping_job_or_workflow_override_remains_incomplete(self):
        inherited = BASE.replace("permissions: {}\n", "")
        job_override = inherited.replace("runs-on:", "permissions: {}\n    runs-on:")
        for base in (BASE, job_override):
            result = self.scan(inherited, base)
            self.assertEqual(result["analysis"], "incomplete")

    def test_other_rules_survive_symbolic_token_comparison(self):
        base = BASE.replace("permissions: {}\n", "")
        head = base.replace("on: push", "on: [push, pull_request_target]").replace("echo fixture", "echo ${{ secrets.PUBLISH_TOKEN }}")
        result = self.scan(head, base)
        self.assertEqual(result["analysis"], "complete")
        self.assertEqual({f["rule"] for f in result["findings"]}, {"WF003", "WF004"})

    def test_explicit_sibling_grant_survives_inherited_equality(self):
        base = BASE.replace("permissions: {}\n", "") + "  publish:\n    permissions: {}\n    runs-on: ubuntu-latest\n    steps: [{run: echo publish}]\n"
        head = base.replace("echo fixture", "echo changed").replace("permissions: {}", "permissions: {id-token: write}")
        result = self.scan(head, base)
        self.assertEqual(result["analysis"], "complete")
        self.assertEqual([(f["job"], f["after"]) for f in result["findings"]], [("publish", {"id-token": "write"})])

    def test_dynamic_secret_and_invalid_yaml_still_fail_closed(self):
        base = BASE.replace("permissions: {}\n", "")
        self.assertEqual(self.scan(base.replace("echo fixture", "echo ${{ secrets[inputs.name] }}"), base)["analysis"], "incomplete")
        self.assertEqual(self.scan(base + "permissions: null\n", base)["analysis"], "error")

    def test_literal_text_is_not_a_secret_reference(self):
        head = BASE.replace("echo fixture", "echo secrets.PUBLISH_TOKEN")
        self.assertEqual(self.scan(head)["findings"], [])

    def test_dynamic_head_keeps_provable_literal_secret_additions(self):
        base = BASE.replace("echo fixture", "echo ${{ secrets.EXISTING }}")
        for expression in ("secrets.NEW_TOKEN", "secrets['NEW_TOKEN']", "toJSON(secrets)"):
            with self.subTest(expression=expression):
                head = base.replace("echo ${{ secrets.EXISTING }}", "echo ${{ secrets.EXISTING }} ${{ " + expression + " }} ${{ secrets[inputs.which] }}")
                result = self.scan(head, base)
                self.assertEqual((result["analysis"], result["review"]), ("incomplete", "suggested"))
                self.assertEqual([f["after"] for f in result["findings"]], ["all available secrets" if "toJSON" in expression else "NEW_TOKEN"])

    def test_dynamic_base_does_not_invent_secret_additions(self):
        base = BASE.replace("echo fixture", "echo ${{ secrets[inputs.which] }}")
        for suffix in ("", " ${{ secrets[inputs.other] }}"):
            result = self.scan(BASE.replace("echo fixture", "echo ${{ secrets.NEW_TOKEN }}" + suffix), base)
            self.assertEqual((result["analysis"], result["findings"]), ("incomplete", []))

    def test_secret_text_in_expression_string_is_ignored(self):
        head = BASE.replace("echo fixture", "echo ${{ format('secrets.TOKEN') }}")
        self.assertEqual(self.scan(head)["findings"], [])

    def test_other_context_named_secrets_is_ignored(self):
        head = BASE.replace("echo fixture", "echo ${{ inputs.secrets.TOKEN }}")
        self.assertEqual(self.scan(head)["findings"], [])

    def test_implicit_token_reference_is_not_secret_expansion(self):
        head = BASE.replace("echo fixture", "echo ${{ secrets.GITHUB_TOKEN }}")
        self.assertEqual(self.scan(head)["findings"], [])

    def test_entire_secret_context(self):
        head = BASE.replace("echo fixture", "echo ${{ toJSON(secrets) }}")
        self.assertEqual(self.scan(head)["findings"][0]["after"], "all available secrets")

    def test_existing_all_secrets_to_explicit_is_reduction(self):
        base = BASE.replace("echo fixture", "echo ${{ toJSON(secrets) }}")
        head = BASE.replace("echo fixture", "echo ${{ secrets.TOKEN }}")
        self.assertEqual(self.scan(head, base)["findings"], [])

    def test_invalid_scope_is_not_clean(self):
        result = self.scan(BASE.replace("permissions: {}", "permissions: {unknown-scope: write}"))
        self.assertEqual(result["analysis"], "error")

    def test_invalid_oidc_read(self):
        self.assertEqual(self.scan(BASE.replace("permissions: {}", "permissions: {id-token: read}"))["analysis"], "error")

    def test_omission_differs_from_explicit_null(self):
        self.assertEqual(self.scan(BASE.replace("permissions: {}", "permissions: null"))["analysis"], "error")

    def test_aliases_are_supported(self):
        # Aliases are analyzed (bounded), not rejected outright.
        head = BASE.replace("permissions: {}", "permissions: &p {}\nextra: *p")
        self.assertEqual(self.scan(head)["analysis"], "complete")

    def test_custom_yaml_tags_do_not_execute(self):
        result = self.scan("!!python/object/apply:os.system ['touch SHOULD_NOT_EXIST']")
        self.assertEqual(result["analysis"], "error")
        self.assertFalse((ROOT / "SHOULD_NOT_EXIST").exists())

    def test_invalid_yaml_diagnostic_does_not_leak_source(self):
        result = self.scan("jobs: [VERY_PRIVATE_LITERAL")
        self.assertNotIn("VERY_PRIVATE_LITERAL", json.dumps(result))

    def test_map_reordering_is_neutral(self):
        doc = yaml.safe_load(BASE)
        head = yaml.safe_dump(doc, sort_keys=True)
        self.assertEqual(self.scan(head)["findings"], [])

    def test_output_is_deterministic(self):
        head = BASE.replace("permissions: {}", "permissions: {packages: write, contents: write}")
        self.assertEqual(json.dumps(self.scan(head)), json.dumps(self.scan(head)))

    def test_markdown_escapes_untrusted_names(self):
        head = BASE.replace("test:", "'test|<img src=x>`':").replace("permissions: {}", "permissions: {packages: write}")
        text = markdown(self.scan(head))
        self.assertNotIn("<img", text)
        self.assertIn("&#124;", text)
        self.assertIn("&#96;", text)

    def test_markdown_names_cannot_insert_links_or_images(self):
        name = "test![pixel](https://example.invalid/pixel.png)_[open](https://example.invalid/)_"
        head = BASE.replace("test:", f"'{name}':").replace("permissions: {}", "permissions: {packages: write}")
        result = self.scan(head)
        self.assertEqual(result["analysis"], "complete")
        self.assertEqual(result["findings"][0]["job"], name)
        text = markdown(result)
        self.assertNotIn("![pixel]", text)
        self.assertNotIn("](", text)
        self.assertIn("&#33;&#91;pixel&#93;&#40;", text)
        self.assertIn("&#95;&#91;open&#93;", text)

    def test_markdown_diagnostic_filename_stays_literal(self):
        path = ".github/workflows/[open](evil)_name_\\|.yml"
        result = compare(Snapshot("base", {}), Snapshot("head", {path: "jobs: [unclosed"}))
        self.assertEqual(result["analysis"], "error")
        text = markdown(result)
        self.assertNotIn("](", text)
        self.assertIn("&#92;&#124;", text)
        self.assertIn("&#91;open&#93;", text)

    def test_boundary_message_does_not_offer_auto_merge(self):
        text = markdown(self.scan(BASE.replace("echo fixture", "echo changed")))
        self.assertIn("No supported privilege expansions detected", text)
        self.assertNotIn("Safe to auto-merge", text)


class SourcesAndIntegration(unittest.TestCase):
    def test_symlinked_workflow_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {"external.yml": BASE})
            folder = root / ".github/workflows"
            folder.mkdir(parents=True)
            (folder / "ci.yml").symlink_to(root / "external.yml")
            with self.assertRaises(InputError):
                directory(root)

    def test_symlinked_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "outside").mkdir()
            (root / ".github").symlink_to(root / "outside")
            with self.assertRaises(InputError):
                directory(root)

    def test_oversized_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {WF: "#" * (MAX_FILE + 1)})
            with self.assertRaises(InputError):
                directory(root)

    def test_invalid_utf8_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {WF: BASE})
            (root / WF).write_bytes(b"\xff")
            with self.assertRaises(InputError):
                directory(root)

    def test_nested_workflows_are_out_of_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, {".github/workflows/nested/ci.yml": BASE})
            self.assertEqual(directory(root).files, {})

    def test_repo_policy_file_is_not_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, head = root / "base", root / "head"
            base.mkdir(); head.mkdir()
            write(base, {WF: BASE})
            write(head, {WF: BASE.replace("permissions: {}", "permissions: {packages: write}"),
                         ".privilege-check.yml": "suppress: ['*']"})
            code, report = cli(["scan", "--dirs", str(base), str(head)])
            self.assertEqual(code, 0)
            self.assertEqual(report["review"], "suggested")

    def repo(self, path):
        def git(*args):
            return subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True, text=True).stdout.strip()
        git("init", "-q", "-b", "main")
        git("config", "user.name", "Local test")
        git("config", "user.email", "test@example.invalid")
        git("config", "commit.gpgsign", "false")
        write(path, {WF: BASE})
        git("add", ".")
        git("commit", "-qm", "base")
        return git

    def test_git_records_exact_commits_without_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = self.repo(root)
            base = git("rev-parse", "HEAD")
            write(root, {WF: BASE.replace("permissions: {}", "permissions: {packages: write}")})
            git("commit", "-qam", "head")
            head = git("rev-parse", "HEAD")
            before = git("status", "--porcelain")
            report = compare(git_snapshot(root, base), git_snapshot(root, head))
            self.assertEqual((report["base"], report["head"]), (base, head))
            self.assertEqual(report["review"], "suggested")
            self.assertEqual(git("status", "--porcelain"), before)

    def test_comparison_uses_supplied_base_not_merge_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = self.repo(root)
            first = git("rev-parse", "HEAD")
            write(root, {WF: BASE.replace("permissions: {}", "permissions: {packages: write}")})
            git("commit", "-qam", "head")
            head = git("rev-parse", "HEAD")
            git("checkout", "-qb", "target", first)
            write(root, {WF: BASE.replace("permissions: {}", "permissions: {packages: write}")})
            git("commit", "-qam", "target moves")
            report = compare(git_snapshot(root, "target"), git_snapshot(root, head))
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["base"], git("rev-parse", "target"))

    def test_git_replacement_refs_cannot_hide_a_grant(self):
        for replace_kind in ("commit", "blob"):
            with self.subTest(kind=replace_kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                git = self.repo(root)
                base = git("rev-parse", "HEAD")
                write(root, {WF: BASE.replace("permissions: {}", "permissions: {contents: write}")})
                git("commit", "-qam", "grant")
                head = git("rev-parse", "HEAD")
                old, new = (base, head) if replace_kind == "commit" else (git("rev-parse", base + ":" + WF), git("rev-parse", head + ":" + WF))
                git("replace", new, old)
                report = compare(git_snapshot(root, base), git_snapshot(root, head))
                self.assertEqual((report["base"], report["head"]), (base, head))
                self.assertEqual([f["after"] for f in report["findings"]], [{"contents": "write"}])

    def test_git_caller_environment_cannot_redirect_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = self.repo(root)
            commit = git("rev-parse", "HEAD")
            with patch.dict(os.environ, {"GIT_DIR": str(root / "missing"),
                                        "GIT_WORK_TREE": str(root / "missing"),
                                        "GIT_CONFIG_COUNT": "not-a-number",
                                        "GIT_CONFIG_PARAMETERS": "invalid"}):
                snapshot = git_snapshot(root, commit)
            self.assertEqual((snapshot.identity, snapshot.files), (commit, {WF: BASE}))

    def test_missing_git_ref_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo(Path(tmp))
            code, report = cli(["scan", "--repo", tmp, "--base", "missing", "--head", "HEAD"])
            self.assertEqual((code, report["analysis"]), (2, "error"))

    def test_action_entry_generates_summary_using_event_shas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = self.repo(root)
            base = git("rev-parse", "HEAD")
            write(root, {WF: BASE.replace("permissions: {}", "permissions: {packages: write}")})
            git("commit", "-qam", "head")
            head = git("rev-parse", "HEAD")
            event = root / "event.json"
            event.write_text(json.dumps({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}))
            summary = root / "summary.md"
            env = {**os.environ, "PRIVILEGE_BASE": "", "PRIVILEGE_HEAD": "", "PRIVILEGE_DEFAULTS": "",
                   "PRIVILEGE_REPOSITORY": str(root), "GITHUB_EVENT_PATH": str(event), "GITHUB_STEP_SUMMARY": str(summary)}
            cp = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/action_entry.py")], env=env, capture_output=True, text=True)
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertEqual(json.loads(cp.stdout)["review"], "suggested")
            self.assertIn("Review suggested", summary.read_text())

    def test_action_rejects_non_sha_input(self):
        env = {**os.environ, "PRIVILEGE_BASE": "--help", "PRIVILEGE_HEAD": "x"}
        cp = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/action_entry.py")], env=env, capture_output=True, text=True)
        self.assertEqual(cp.returncode, 2)
        self.assertEqual(cp.stdout, "")

    def test_default_permissions_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, report = cli(["scan", "--dirs", tmp, tmp, "--default-permissions", "not json"])
            self.assertEqual((code, report["analysis"]), (2, "error"))

    def test_defaults_require_explicit_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, report = cli(["scan", "--dirs", tmp, tmp, "--default-permissions", '"write-all"'])
            self.assertEqual((code, report["analysis"]), (2, "error"))

    def test_read_only_cli_does_not_write_github_environment_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "github-output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(output)}):
                code, _ = cli(["scan", "--dirs", tmp, tmp])
            self.assertEqual(code, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
