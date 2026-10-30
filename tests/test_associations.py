"""Regressions for runner/environment bindings, rather than independent sets."""
from itertools import combinations
from pathlib import Path
import random
import sys
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from privilege_check.scan import compare
from privilege_check.sources import Snapshot

WF = '.github/workflows/deploy.yml'
BASE = [{'runner': 'ubuntu-latest', 'target': 'production'},
        {'runner': 'self-hosted', 'target': 'staging'}]
SWAPPED = [{'runner': 'ubuntu-latest', 'target': 'staging'},
           {'runner': 'self-hosted', 'target': 'production'}]


def workflow(rows=None, *, matrix=None, runner='${{ matrix.runner }}', environment='${{ matrix.target }}'):
    job = {'runs-on': runner, 'environment': environment,
           'strategy': {'matrix': matrix if matrix is not None else {'include': rows}},
           'steps': [{'run': 'echo fixture'}]}
    return yaml.safe_dump({'on': 'workflow_dispatch', 'permissions': {}, 'jobs': {'deploy': job}}, sort_keys=False)


def scan(before, after):
    return compare(Snapshot('base', {WF: before}), Snapshot('head', {WF: after}))


class Associations(unittest.TestCase):
    def test_same_individual_sets_with_new_pairing_merit_review(self):
        report = scan(workflow(BASE), workflow(SWAPPED))
        self.assertEqual((report['analysis'], report['review']), ('complete', 'suggested'))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])
        finding = report['findings'][0]
        self.assertEqual((finding['file'], finding['job']), (WF, 'deploy'))
        self.assertIn({'labels': ['self-hosted'], 'groups': [], 'environment': 'production'}, finding['after']['pairs'])
        self.assertNotEqual(finding['before']['pairs'], finding['after']['pairs'])
        self.assertIn('not verified', finding['message'])

    def test_group_label_and_environment_remain_bound_to_one_row(self):
        before = [{**row, 'group': 'internal', 'arch': 'x64'} for row in BASE]
        after = [{**row, 'group': 'internal', 'arch': 'x64'} for row in SWAPPED]
        runner = {'group': '${{ matrix.group }}', 'labels': ['${{ matrix.runner }}', '${{ matrix.arch }}']}
        report = scan(workflow(before, runner=runner), workflow(after, runner=runner))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])
        self.assertIn({'labels': ['self-hosted', 'x64'], 'groups': ['internal'], 'environment': 'production'},
                      report['findings'][0]['after']['pairs'])

    def test_exclude_changes_can_rearrange_pairs_without_changing_sets(self):
        axes = {'runner': ['ubuntu-latest', 'self-hosted'], 'target': ['staging', 'production']}
        report = scan(workflow(matrix={**axes, 'exclude': SWAPPED}), workflow(matrix={**axes, 'exclude': BASE}))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])

    def test_include_overrides_added_environment_fields_in_order(self):
        axes = {'runner': ['ubuntu-latest', 'self-hosted']}
        before = {**axes, 'include': [{'target': 'staging'}, {'runner': 'ubuntu-latest', 'target': 'production'}]}
        after = {**axes, 'include': [{'target': 'production'}, {'runner': 'ubuntu-latest', 'target': 'staging'}]}
        report = scan(workflow(matrix=before), workflow(matrix=after))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])
        self.assertEqual(len(report['findings'][0]['after']['pairs']), 2)

    def test_order_duplicates_case_and_unrelated_axes_stay_quiet(self):
        changed = [{**row, 'runner': row['runner'].upper(), 'target': row['target'].upper(), 'python': '3.14'}
                   for row in reversed(BASE)]
        report = scan(workflow(BASE), workflow(changed + changed))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_environment_mapping_url_edit_stays_quiet(self):
        report = scan(workflow(BASE), workflow(BASE, environment={'name': '${{ matrix.target }}', 'url': 'https://example.invalid'}))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_standard_hosted_version_update_stays_quiet(self):
        after = [{**row, 'runner': 'ubuntu-24.04'} if row['runner'] == 'ubuntu-latest' else row for row in BASE]
        report = scan(workflow(BASE), workflow(after))
        # WF005 already reviews the changed selection containing a custom runner;
        # the association rule must not duplicate it.
        self.assertNotIn('WF008', [f['rule'] for f in report['findings']])
        before_hosted = [{**row, 'runner': 'ubuntu-22.04'} for row in BASE]
        after_hosted = [{**row, 'runner': 'ubuntu-24.04'} for row in BASE]
        report = scan(workflow(before_hosted), workflow(after_hosted))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_existing_runner_or_environment_findings_are_not_duplicated(self):
        for after in ([{**row, 'runner': 'internal-prod'} for row in BASE],
                      [{**row, 'target': 'new-environment'} for row in BASE]):
            report = scan(workflow(BASE), workflow(after))
            self.assertTrue(report['findings'])
            self.assertNotIn('WF008', [f['rule'] for f in report['findings']])

    def test_only_removed_pairs_do_not_introduce_new_associations(self):
        report = scan(workflow(BASE + SWAPPED), workflow(BASE))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_added_pair_is_detected_even_when_no_pair_is_removed(self):
        report = scan(workflow(BASE), workflow(BASE + SWAPPED[:1]))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])

    def test_known_pairing_survives_an_error_in_another_workflow(self):
        report = compare(Snapshot('base', {WF: workflow(BASE)}),
                         Snapshot('head', {WF: workflow(SWAPPED), '.github/workflows/broken.yml': 'jobs: [broken'}))
        self.assertEqual((report['analysis'], report['review']), ('error', 'suggested'))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])
        self.assertTrue(report['diagnostics'])

    def test_hosted_runner_pair_swap_is_still_a_configured_association_change(self):
        before = [{**row, 'runner': row['runner'].replace('self-hosted', 'windows-latest')} for row in BASE]
        after = [{**row, 'runner': row['runner'].replace('self-hosted', 'windows-latest')} for row in SWAPPED]
        self.assertEqual([f['rule'] for f in scan(workflow(before), workflow(after))['findings']], ['WF008'])

    def test_no_environment_does_not_invent_an_association(self):
        before, after = yaml.safe_load(workflow(BASE)), yaml.safe_load(workflow(SWAPPED))
        for document in (before, after):
            del document['jobs']['deploy']['environment']
        report = scan(yaml.safe_dump(before), yaml.safe_dump(after))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_equivalent_literal_and_matrix_targets_stay_quiet(self):
        before = workflow(BASE, runner='self-hosted', environment='production')
        after = workflow([{'runner': 'self-hosted', 'target': 'production'}])
        report = scan(before, after)
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_unresolved_association_does_not_become_complete_or_invent_pairs(self):
        # The matrix and unresolved environment are unchanged. A changed runner
        # selector reverses which matrix row selects each known runner.
        rows = [{**row, 'alternate': other['runner']} for row, other in zip(BASE, SWAPPED[::-1])]
        before = workflow(rows, environment='${{ vars.TARGET }}')
        after = workflow(rows, runner='${{ matrix.alternate }}', environment='${{ vars.TARGET }}')
        report = scan(before, after)
        self.assertEqual((report['analysis'], report['findings']), ('incomplete', []))
        self.assertTrue(any('association' in d['reason'] for d in report['diagnostics']))

    def test_unchanged_unresolved_context_still_compares_symbolically(self):
        before = workflow(BASE, environment='${{ vars.TARGET }}')
        report = scan(before, before.replace('echo fixture', 'echo changed'))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))
        self.assertTrue(report['assumptions'])

    def test_equivalent_selectors_do_not_make_unchanged_unknown_context_incomplete(self):
        for runner_before, runner_after, env_before, env_after in (
                ('self-hosted', 'SELF-HOSTED', '${{ vars.TARGET }}', '${{ vars.TARGET }}'),
                ('self-hosted', {'labels': ['SELF-HOSTED', 'self-hosted']}, '${{ vars.TARGET }}', '${{ vars.TARGET }}'),
                ('${{ vars.RUNNER }}', '${{ vars.RUNNER }}', 'production', {'name': 'PRODUCTION'}),
                ('${{ matrix.runner }}', '${{matrix.runner}}', '${{ vars.TARGET }}', '${{ vars.TARGET }}')):
            with self.subTest(runner=runner_after, environment=env_after):
                report = scan(workflow(BASE, runner=runner_before, environment=env_before),
                              workflow(BASE, runner=runner_after, environment=env_after))
                self.assertEqual((report['analysis'], report['findings']), ('complete', []))
                self.assertEqual(report['diagnostics'], [])
                self.assertTrue(report['assumptions'])

    def test_dynamic_or_missing_matrix_values_remain_incomplete(self):
        for rows in ([{**BASE[0], 'target': '${{ vars.TARGET }}'}, BASE[1]],
                     [BASE[0], {'runner': 'self-hosted'}]):
            report = scan(workflow(BASE), workflow(rows))
            self.assertEqual(report['analysis'], 'incomplete')
            self.assertNotIn('WF008', [f['rule'] for f in report['findings']])

    def test_matrix_variable_names_are_case_insensitive(self):
        before = [{'Runner': r['runner'], 'TARGET': r['target']} for r in BASE]
        after = [{'Runner': r['runner'], 'TARGET': r['target']} for r in SWAPPED]
        report = scan(workflow(before, runner='${{ MATRIX.RUNNER }}'), workflow(after, runner='${{ matrix.runner }}'))
        self.assertEqual((report['analysis'], [f['rule'] for f in report['findings']]), ('complete', ['WF008']))
        axes = {'Runner': ['ubuntu-latest', 'self-hosted'], 'TARGET': ['staging', 'production']}
        report = scan(workflow(matrix={**axes, 'exclude': after}), workflow(matrix={**axes, 'exclude': before}))
        self.assertEqual([f['rule'] for f in report['findings']], ['WF008'])
        report = scan(workflow(BASE, environment='${{ vars.TARGET }}'),
                      workflow(BASE, runner='${{ MATRIX.RUNNER }}', environment='${{ vars.TARGET }}'))
        self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_ambiguous_case_duplicate_matrix_fields_are_incomplete(self):
        for matrix in ({'runner': ['ubuntu-latest'], 'RUNNER': ['self-hosted'], 'target': ['production']},
                       {'include': [{'runner': 'ubuntu-latest', 'RUNNER': 'self-hosted', 'target': 'production'}]}):
            report = scan(workflow(BASE), workflow(matrix=matrix))
            self.assertEqual(report['analysis'], 'incomplete')
            self.assertNotIn('WF008', [f['rule'] for f in report['findings']])

    def test_equivalent_axes_exclusions_and_include_representations(self):
        edges = BASE + SWAPPED
        for count in range(1, 5):
            for rows in combinations(edges, count):
                excluded = [row for row in edges if row not in rows]
                matrix = {'runner': ['ubuntu-latest', 'self-hosted'], 'target': ['staging', 'production'],
                          'exclude': excluded, 'include': list(rows)}
                report = scan(workflow(list(rows)), workflow(matrix=matrix))
                self.assertEqual((report['analysis'], report['findings']), ('complete', []))

    def test_seeded_three_by_three_relations_preserve_new_pair_detection(self):
        rng = random.Random(7081)
        runners, environments = ['ubuntu-latest', 'self-hosted', 'internal'], ['production', 'staging', 'test']
        edges = [(r, e) for r in runners for e in environments]
        for _ in range(200):
            relations = []
            for _ in range(2):
                permutation = rng.sample(environments, len(environments))
                pairs = set(zip(runners, permutation)) | set(rng.sample(edges, rng.randrange(10)))
                relations.append(pairs)
            before, after = [[{'runner': r, 'target': e} for r, e in sorted(pairs)] for pairs in relations]
            report = scan(workflow(before), workflow(after))
            self.assertEqual(report['analysis'], 'complete')
            self.assertEqual([f['rule'] for f in report['findings']], ['WF008'] if relations[1] - relations[0] else [])

    def test_matrix_bound_is_enforced_for_joint_comparison(self):
        rows = [{'runner': 'self-hosted' if i % 2 else 'ubuntu-latest', 'target': 'env-' + str(i)} for i in range(256)]
        swapped = [{**row, 'runner': rows[(i + 1) % 256]['runner']} for i, row in enumerate(rows)]
        report = scan(workflow(rows), workflow(swapped))
        self.assertEqual((report['analysis'], [f['rule'] for f in report['findings']]), ('complete', ['WF008']))
        self.assertEqual(len(report['findings'][0]['after']['pairs']), 256)
        report = scan(workflow(rows), workflow(swapped + [swapped[0]]))
        self.assertEqual(report['analysis'], 'incomplete')
        self.assertNotIn('WF008', [f['rule'] for f in report['findings']])

    def test_all_small_relations_with_equal_marginals(self):
        edges = BASE + SWAPPED
        subsets = [list(items) for count in range(1, 5) for items in combinations(edges, count)]
        def marginals(rows):
            return ({r['runner'] for r in rows}, {r['target'] for r in rows})
        for before in subsets:
            for after in subsets:
                if marginals(before) != marginals(after):
                    continue
                with self.subTest(before=before, after=after):
                    report = scan(workflow(before), workflow(after))
                    added = {(r['runner'], r['target']) for r in after} - {(r['runner'], r['target']) for r in before}
                    self.assertEqual(report['analysis'], 'complete')
                    self.assertEqual([f['rule'] for f in report['findings']], ['WF008'] if added else [])


if __name__ == '__main__':
    unittest.main()
