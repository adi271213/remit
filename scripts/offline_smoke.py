"""Exercise the real Action controller; CI adds a disconnected network namespace."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def read_outputs(path):
    lines = path.read_text().splitlines(); result = {}
    while lines:
        key, delimiter = lines.pop(0).split('<<', 1); values = []
        while lines[0] != delimiter: values.append(lines.pop(0))
        lines.pop(0); result[key] = '\n'.join(values)
    return result


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--network-namespace', action='store_true')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp); repo = folder / 'repo'; repo.mkdir()
        def git(*values):
            return subprocess.check_output(['git', '-C', str(repo), *values], text=True, stderr=subprocess.DEVNULL).strip()
        git('init', '-q', '-b', 'main'); git('config', 'user.name', 'Offline fixture')
        git('config', 'user.email', 'fixture@example.invalid'); git('config', 'commit.gpgsign', 'false')
        file = repo / '.github/workflows/ci.yml'; file.parent.mkdir(parents=True)
        base_text = 'on: workflow_dispatch\npermissions: {}\njobs:\n  test: &job\n    runs-on: ubuntu-latest\n    steps: [{run: echo fixture}]\n  replica: *job\n'
        grant_text = base_text.replace('permissions: {}', 'permissions: {id-token: write}').replace('runs-on: ubuntu-latest', 'runs-on: [self-hosted, prod]\n    environment: production')
        association_base = (ROOT / 'examples/association-base/.github/workflows/deploy.yml').read_text()
        association_head = (ROOT / 'examples/association-head/.github/workflows/deploy.yml').read_text()
        unresolved_base = (association_base.replace('target: production', 'target: production\n            alternate: self-hosted')
                           .replace('target: staging', 'target: staging\n            alternate: ubuntu-latest')
                           .replace('environment: ${{ matrix.target }}', 'environment: ${{ vars.TARGET }}'))
        unresolved_head = unresolved_base.replace('runs-on: ${{ matrix.runner }}', 'runs-on: ${{ matrix.alternate }}')
        fixtures = [('grants', base_text, grant_text, {'WF001', 'WF005', 'WF007'}, 6, 'complete'),
                    ('association', association_base, association_head, {'WF008'}, 1, 'complete'),
                    ('unresolved-association', unresolved_base, unresolved_head, set(), 0, 'incomplete')]
        hosted = json.loads((ROOT / 'tests/hosted_cases.json').read_text())
        for case in ('hyphen-neutral', 'hyphen-secret', 'hyphen-association'):
            item = hosted[case]
            fixtures.append((case, item['base'], item['head'], set(item['rules']), len(item['rules']), item['analysis']))
        # Proposed Python modules are data, never imports of the isolated Action.
        (repo / 'yaml.py').write_text('raise RuntimeError("PROPOSED_IMPORT_EXECUTED")')
        for case, before, after, rules, count, analysis in fixtures:
            file.write_text(before); git('add', '.github'); git('commit', '--allow-empty', '-qm', case + ' base'); base = git('rev-parse', 'HEAD')
            file.write_text(after); git('commit', '--allow-empty', '-qam', case + ' head'); head = git('rev-parse', 'HEAD')
            for mode in ('advisory', 'require-complete'):
                prefix = case + '-' + mode
                env = {'PATH': os.environ['PATH'], 'RUNNER_TEMP': tmp, 'PRIVILEGE_MODE': mode,
                       'PRIVILEGE_BASE': base, 'PRIVILEGE_HEAD': head, 'PRIVILEGE_DEFAULTS': '',
                       'PRIVILEGE_REPOSITORY': str(repo), 'GITHUB_OUTPUT': str(folder / (prefix + '.out')),
                       'GITHUB_STEP_SUMMARY': str(folder / (prefix + '.md')), 'PYTHONPATH': str(repo)}
                command = [sys.executable, '-I', '-S', str(ROOT / 'scripts/action_runner.py')]
                if args.network_namespace:
                    command = ['sudo', 'unshare', '--net', '--', 'setpriv', '--reuid', str(os.getuid()),
                               '--regid', str(os.getgid()), '--clear-groups', 'env',
                               *[f'{key}={value}' for key, value in env.items()], *command]
                start = time.monotonic()
                cp = subprocess.run(command, env={**os.environ, **env}, cwd=repo, capture_output=True, text=True, timeout=30)
                code = 0 if analysis == 'complete' else 2
                review = 'suggested' if count else ('none' if analysis == 'complete' else 'unknown')
                if cp.returncode != (0 if mode == 'advisory' else code):
                    raise RuntimeError('Offline Action failed: ' + cp.stdout[-1000:] + cp.stderr[-1000:])
                outputs = read_outputs(Path(env['GITHUB_OUTPUT']))
                report = json.loads(Path(outputs['report-path']).read_text())
                assert outputs['analysis-status'] == report['analysis'] == analysis
                assert outputs['review-status'] == report['action']['reviewStatus'] == review
                assert outputs['analysis-exit-code'] == str(code)
                assert {f['rule'] for f in report['findings']} == rules and len(report['findings']) == count
                assert (outputs['base-sha'], outputs['head-sha']) == (base, head)
                summary = Path(env['GITHUB_STEP_SUMMARY']).read_text()
                assert 'not approval to merge' in summary
                if case in ('association', 'hyphen-association'):
                    assert 'WF008' in summary and 'Before' in summary and 'After' in summary
                if analysis != 'complete':
                    assert report['diagnostics'] and 'Analysis incomplete' in summary
                print('WPC_OFFLINE_RESULT=' + json.dumps({'case': case, 'mode': mode, 'analysis': analysis, 'review': review,
                      'rules': sorted(rules), 'networkNamespace': args.network_namespace,
                      'seconds': round(time.monotonic() - start, 3)}))


if __name__ == '__main__': main()
