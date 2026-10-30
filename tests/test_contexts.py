from pathlib import Path
import sys
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from privilege_check.scan import compare
from privilege_check.sources import Snapshot

WF = '.github/workflows/ci.yml'


def workflow(runner='ubuntu-latest', environment=None, matrix=None):
    job = {'runs-on': runner, 'steps': [{'run': 'echo fixture'}]}
    if environment is not None: job['environment'] = environment
    if matrix is not None: job['strategy'] = {'matrix': matrix}
    return yaml.safe_dump({'on': 'push', 'permissions': {}, 'jobs': {'test': job}}, sort_keys=False)


def scan(before, after):
    return compare(Snapshot('base', {WF: before}), Snapshot('head', {WF: after}))


class Contexts(unittest.TestCase):
    def test_self_hosted_transition_and_new_job(self):
        text = workflow(['self-hosted', 'prod'])
        for result in (scan(workflow(), text), compare(Snapshot('base', {}), Snapshot('head', {WF: text}))):
            self.assertEqual(result['analysis'], 'complete')
            self.assertEqual([f['rule'] for f in result['findings']], ['WF005'])
            self.assertEqual(result['findings'][0]['after']['labels'], ['prod', 'self-hosted'])

    def test_hosted_version_update_and_new_hosted_job_are_quiet(self):
        for result in (scan(workflow('ubuntu-22.04'), workflow('ubuntu-24.04')),
                       compare(Snapshot('base', {}), Snapshot('head', {WF: workflow()}))):
            self.assertEqual((result['analysis'], result['findings']), ('complete', []))

    def test_label_order_case_and_mapping_are_equivalent(self):
        result = scan(workflow(['self-hosted', 'prod']), workflow({'labels': ['PROD', 'SELF-HOSTED']}))
        self.assertEqual((result['analysis'], result['findings']), ('complete', []))

    def test_custom_labels_and_groups_are_reviewed_without_ownership_claim(self):
        for runner in ('internal-build', {'group': 'prod'}, {'group': 'prod', 'labels': 'linux'}):
            with self.subTest(runner=runner):
                r = scan(workflow(), workflow(runner))
                self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])
                self.assertIn('not verified', r['findings'][0]['message'])

    def test_moving_to_known_hosted_selection_is_not_a_runner_finding(self):
        self.assertEqual(scan(workflow(['self-hosted', 'prod']), workflow())['findings'], [])

    def test_changed_dynamic_runner_is_incomplete_with_known_selection_change(self):
        r = scan(workflow(), workflow('${{ vars.RUNNER }}'))
        self.assertEqual((r['analysis'], r['review']), ('incomplete', 'suggested'))
        self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])

    def test_unchanged_unresolved_selection_is_symbolic_and_disclosed(self):
        before = workflow('${{ vars.RUNNER }}', '${{ vars.TARGET }}')
        r = scan(before, before.replace('echo fixture', 'echo changed'))
        self.assertEqual((r['analysis'], r['findings']), ('complete', []))
        self.assertEqual(len(r['assumptions']), 2)

    def test_static_matrix_runner_resolution_catches_new_self_hosted_option(self):
        before = workflow('${{ matrix.os }}', matrix={'os': ['ubuntu-latest']})
        after = workflow('${{ matrix.os }}', matrix={'os': ['ubuntu-latest', 'self-hosted']})
        r = scan(before, after)
        self.assertEqual(r['analysis'], 'complete')
        self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])

    def test_static_matrix_hosted_updates_stay_quiet(self):
        r = scan(workflow('${{ matrix.os }}', matrix={'os': ['ubuntu-22.04']}),
                 workflow('${{ matrix.os }}', matrix={'os': ['ubuntu-24.04', 'windows-latest']}))
        self.assertEqual((r['analysis'], r['findings']), ('complete', []))

    def test_matrix_label_combinations_are_not_reduced_to_their_union(self):
        runner = ['self-hosted', '${{ matrix.pool }}', '${{ matrix.arch }}']
        before = {'include': [{'pool': 'prod', 'arch': 'x64'}, {'pool': 'test', 'arch': 'arm64'}]}
        after = {'include': [{'pool': 'prod', 'arch': 'arm64'}, {'pool': 'test', 'arch': 'x64'}]}
        r = scan(workflow(runner, matrix=before), workflow(runner, matrix=after))
        self.assertEqual((r['analysis'], r['review']), ('complete', 'suggested'))
        self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])
        f = r['findings'][0]
        self.assertEqual(f['before']['labels'], f['after']['labels'])
        self.assertNotEqual(f['before']['targets'], f['after']['targets'])

    def test_matrix_group_and_label_correlation_is_preserved(self):
        runner = {'group': '${{ matrix.pool }}', 'labels': '${{ matrix.arch }}'}
        before = {'include': [{'pool': 'prod', 'arch': 'x64'}, {'pool': 'test', 'arch': 'arm64'}]}
        after = {'include': [{'pool': 'prod', 'arch': 'arm64'}, {'pool': 'test', 'arch': 'x64'}]}
        r = scan(workflow(runner, matrix=before), workflow(runner, matrix=after))
        self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])

    def test_equivalent_matrix_targets_ignore_row_order_and_unrelated_axes(self):
        runner = ['self-hosted', '${{ matrix.pool }}', '${{ matrix.arch }}']
        rows = [{'pool': 'prod', 'arch': 'x64'}, {'pool': 'test', 'arch': 'arm64'}]
        before = {'include': rows}
        after = {'include': [{**row, 'python': '3.14'} for row in reversed(rows)]}
        r = scan(workflow(runner, matrix=before), workflow(runner, matrix=after))
        self.assertEqual((r['analysis'], r['findings']), ('complete', []))

    def test_literal_conjunction_differs_from_matrix_alternatives(self):
        before = workflow(['self-hosted', 'prod'])
        after = workflow('${{ matrix.runner }}', matrix={'runner': ['self-hosted', 'prod']})
        r = scan(before, after)
        self.assertEqual([f['rule'] for f in r['findings']], ['WF005'])

    def test_current_standard_runner_labels_stay_quiet(self):
        for runner in ('ubuntu-22.04-arm', 'windows-11-vs2026-arm', 'xcode-27'):
            with self.subTest(runner=runner):
                r = scan(workflow(), workflow(runner))
                self.assertEqual((r['analysis'], r['findings']), ('complete', []))

    def test_include_only_matrix_and_exclusions(self):
        before = workflow('${{ matrix.os }}', matrix={'include': [{'os': 'ubuntu-latest'}]})
        after = workflow('${{ matrix.os }}', matrix={'include': [{'os': 'self-hosted'}]})
        self.assertEqual([f['rule'] for f in scan(before, after)['findings']], ['WF005'])
        excluded = workflow('${{ matrix.os }}', matrix={'os': ['self-hosted'], 'exclude': [{'os': 'self-hosted'}]})
        self.assertEqual(scan(before, excluded)['analysis'], 'incomplete')

    def test_literal_exclusions_do_not_turn_python_updates_into_runner_changes(self):
        before = {'os': ['ubuntu-latest', 'windows-latest'], 'python': ['3.11'],
                  'exclude': [{'os': 'windows-latest', 'python': '3.11'}]}
        after = {**before, 'python': ['3.11', '3.12']}
        r = scan(workflow('${{ matrix.os }}', matrix=before), workflow('${{ matrix.os }}', matrix=after))
        self.assertEqual((r['analysis'], r['findings']), ('complete', []))

    def test_changed_unresolved_context_does_not_invent_target_change(self):
        r = scan(workflow('${{ matrix.runner.name }}', matrix={'runner': [{'name': 'a'}]}),
                 workflow('${{ matrix.runner.name }}', matrix={'runner': [{'name': 'b'}]}))
        self.assertEqual((r['analysis'], r['findings']), ('incomplete', []))

    def test_include_can_override_added_fields_but_not_original_axes(self):
        before = workflow('${{ matrix.runner }}', matrix={'python': ['3.11'], 'include': [{'runner': 'ubuntu-latest'}]})
        after = workflow('${{ matrix.runner }}', matrix={'python': ['3.11'], 'include': [{'runner': 'ubuntu-latest'}, {'runner': 'self-hosted'}]})
        r = scan(before, after)
        self.assertEqual(r['findings'][0]['after']['labels'], ['self-hosted'])

    def test_environment_add_remove_and_change(self):
        for before, after in ((workflow(), workflow(environment='production')),
                              (workflow(environment='production'), workflow()),
                              (workflow(environment='staging'), workflow(environment='production'))):
            r = scan(before, after)
            self.assertEqual((r['analysis'], r['review']), ('complete', 'suggested'))
            self.assertEqual([f['rule'] for f in r['findings']], ['WF007'])

    def test_environment_name_forms_case_and_url_are_equivalent(self):
        before = workflow(environment='production')
        after = workflow(environment={'name': 'PRODUCTION', 'url': 'https://example.invalid'})
        self.assertEqual(scan(before, after)['findings'], [])

    def test_environment_change_with_existing_secret_is_retained(self):
        before = workflow().replace('echo fixture', 'echo ${{ secrets.DEPLOY_KEY }}')
        after = before.replace('    runs-on:', '    environment: production\n    runs-on:')
        r = scan(before, after)
        self.assertEqual([f['rule'] for f in r['findings']], ['WF007'])

    def test_dynamic_environment_is_incomplete_with_context_finding(self):
        r = scan(workflow(), workflow(environment='${{ inputs.target }}'))
        self.assertEqual(r['analysis'], 'incomplete')
        self.assertEqual([f['rule'] for f in r['findings']], ['WF007'])

    def test_environment_matrix_change_is_resolved(self):
        before = workflow(environment='${{ matrix.env }}', matrix={'env': ['staging']})
        after = workflow(environment='${{ matrix.env }}', matrix={'env': ['production']})
        self.assertEqual(scan(before, after)['findings'][0]['after'], {'names': ['production']})

    def test_invalid_contexts_do_not_hide_known_token_change(self):
        for kwargs in ({'runner': 42}, {'runner': {'labels': []}}, {'environment': {'url': 'bad'}}):
            before = workflow()
            after = workflow(**kwargs).replace('permissions: {}', 'permissions: {contents: write}')
            r = scan(before, after)
            self.assertEqual(r['analysis'], 'error')
            self.assertIn('WF001', [f['rule'] for f in r['findings']])

    def test_reusable_call_has_no_invented_runner_or_environment(self):
        before = "on: push\npermissions: {}\njobs:\n  test:\n    uses: owner/repo/.github/workflows/ci.yml@main\n"
        self.assertEqual(scan(before, before.replace('@main', '@stable'))['findings'], [])
