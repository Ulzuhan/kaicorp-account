#!/usr/bin/env python3
"""Ejecuta sólo la lista revisada; nunca la presenta como suite completa."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'tools/ci/partial-tests.json').read_text())
    selected, deferred = manifest['selected'], manifest['deferred']
    if len(selected) != 80 or len(deferred) != 98:
        raise ValueError('Selection changed: review the explicit validation scope first')
    inventory = set()
    for source in (ROOT / 'internal').rglob('*_test.go'):
        text = source.read_text()
        if re.search(r'^func (?:TestMain|init)\(', text, re.MULTILINE):
            raise ValueError('Unreviewed test initialization: ' + str(source.relative_to(ROOT)))
        inventory.update((str(source.relative_to(ROOT)), name) for name in
                         re.findall(r'^func (Test\w+)\(t \*testing\.T\)', text, re.MULTILINE))
    allowed = {(x['file'], x['name']) for x in selected}
    excluded = {(x['file'], x['name']) for x in deferred}
    if len(allowed) != 80 or len(excluded) != 98 or allowed & excluded or inventory != allowed | excluded:
        raise ValueError('Test inventory changed; no unreviewed test may be silently added or omitted')
    for item in selected:
        if hashlib.sha256((ROOT / item['file']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Selected test source changed: ' + item['file'])
        if item['package'] != './' + str(Path(item['file']).parent):
            raise ValueError('Unexpected package mapping')
    names = {x['name'] for x in selected}
    if len(names) != 80:
        raise ValueError('Test names must be unique for this reviewed selection')
    command = ['go', 'test', '-json', '-count=1', '-timeout=120s', '-p=1',
               '-run', '^(' + '|'.join(sorted(names)) + ')$',
               *sorted({x['package'] for x in selected})]
    print('PARTIAL ONLY: 80 allowed tests; 98 deferred; no full-suite or race claim.', flush=True)
    if args.check_only:
        print(json.dumps({'selected': 80, 'deferred': 98, 'command': command}))
        return 0
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ACCOUNT_', 'GOTRUE_'))}
    env.update(CGO_ENABLED='0')
    seen, passed = set(), set()
    bad = False
    process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    with (ROOT / 'partial-tests.jsonl').open('w') as log:
        for line in process.stdout:
            print(line, end='', flush=True)
            log.write(line)
            try:
                event = json.loads(line)
            except ValueError:
                continue
            name = event.get('Test', '')
            top = name.split('/', 1)[0]
            if name and top not in names:
                bad = True
                process.terminate()
            if event.get('Action') in ('skip', 'fail'):
                bad = True
            if name and '/' not in name:
                if event.get('Action') == 'run':
                    seen.add(name)
                if event.get('Action') == 'pass':
                    passed.add(name)
    code = process.wait()
    if code or bad or seen != names or passed != names:
        print('Selected tests failed, skipped or did not execute exactly; full validation remains blocked.', file=sys.stderr)
        return 1
    print('80 allowed tests passed. 98 deferred; NOT ready to merge or deploy.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
