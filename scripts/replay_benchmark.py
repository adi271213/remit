"""Fetch hash-pinned public workflows, or replay their verified offline cache."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from privilege_check.scan import compare
from privilege_check.sources import Snapshot, MAX_FILE


def facts(items):
    return Counter(json.dumps({k: f[k] for k in ('rule', 'file', 'job', 'before', 'after')}, sort_keys=True) for f in items)


def load_blob(file, cache, offline):
    digest = file['sha256']
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('Invalid content digest')
    path = cache / digest
    if path.exists(): data = path.read_bytes()
    else:
        if offline: raise ValueError('Missing offline input: ' + digest)
        url = file['url']
        if urllib.parse.urlsplit(url).hostname != 'raw.githubusercontent.com':
            raise ValueError('Unexpected source host')
        with urllib.request.urlopen(url, timeout=30) as response: data = response.read(MAX_FILE + 1)
    if len(data) > MAX_FILE or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Input size/hash mismatch: ' + digest)
    if not path.exists(): path.write_bytes(data)
    return data.decode('utf-8-sig')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, default=ROOT / '.benchmark-cache')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--limit', type=int)
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmark-results.json')
    args = parser.parse_args();args.cache.mkdir(parents=True, exist_ok=True)
    manifest = ROOT / 'benchmarks/manifest.jsonl'
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != (ROOT / 'benchmarks/manifest.sha256').read_text().strip():
        raise ValueError('Manifest hash mismatch')
    records = [json.loads(line) for line in manifest.read_text().splitlines()]
    if args.limit:
        if args.limit < 1: raise ValueError('Limit must be positive')
        records = records[:args.limit]
    results = []
    for case in records:
        files = {'base': {}, 'head': {}}
        for file in case['files']: files[file['side']][file['path']] = load_blob(file, args.cache, args.offline)
        report = compare(Snapshot(case['base'], files['base']), Snapshot(case['head'], files['head']))
        legacy = [f for f in report['findings'] if f['rule'] in ('WF001', 'WF003', 'WF004')]
        results.append({'id': case['id'], 'pr': case['pr'], 'legacyFactsMatch': facts(legacy) == facts(case['expectedLegacyFacts']),
                        'historicalAnalysis': case['historicalAnalysis'], 'report': report})
    summary = {'cases': len(results), 'allInputsHashVerified': True, 'legacyFactsMatch': all(r['legacyFactsMatch'] for r in results),
               'legacyExpectedFacts': sum(len(c['expectedLegacyFacts']) for c in records),
               'analysis': dict(Counter(r['report']['analysis'] for r in results)),
               'findingsByRule': dict(Counter(f['rule'] for r in results for f in r['report']['findings'])),
               'scope': 'Selected historical regression replay. Legacy labels are self-authored; new context findings are not independently adjudicated. Not precision/recall.'}
    args.output.write_text(json.dumps({'summary': summary, 'results': results}, indent=2)+'\n')
    print(json.dumps(summary, indent=2))
    return 0 if summary['legacyFactsMatch'] else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print('Replay failed: ' + str(exc), file=sys.stderr);raise SystemExit(2)
