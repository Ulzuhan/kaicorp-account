#!/usr/bin/env python3
"""Ejecuta toda la suite revisada en la base efímera de GitHub Actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'tools/ci/full-tests.json').read_text())
    selected, deferred = manifest['selected'], manifest['deferred']
    if len(selected) != 178 or deferred or manifest['selected_count'] != 178 or manifest['deferred_count'] != 0:
        raise ValueError('Full-suite inventory changed: review the validation scope first')
    inventory = set()
    for source in ROOT.rglob('*_test.go'):
        text = source.read_text()
        if re.search(r'^func (?:TestMain|init)\(', text, re.MULTILINE):
            raise ValueError('Unreviewed test initialization: ' + str(source.relative_to(ROOT)))
        inventory.update((str(source.relative_to(ROOT)), name) for name in
                         re.findall(r'^func (Test\w+)\(t \*testing\.T\)', text, re.MULTILINE))
    allowed = {(x['file'], x['name']) for x in selected}
    if len(allowed) != 178 or inventory != allowed:
        raise ValueError('Test inventory changed; no test may be silently added or omitted')
    for item in selected:
        if hashlib.sha256((ROOT / item['file']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Selected test source changed: ' + item['file'])
        if item['package'] != './' + str(Path(item['file']).parent):
            raise ValueError('Unexpected package mapping')
    names = {x['name'] for x in selected}
    if len(names) != 178:
        raise ValueError('Test names must be unique for this reviewed suite')
    command = ['go', 'test', '-race', '-json', '-count=1', '-timeout=180s', '-p=1',
               './...']
    print('FULL SUITE: 178 reviewed tests with race detector and ephemeral PostgreSQL.', flush=True)
    if args.check_only:
        print(json.dumps({'selected': 178, 'deferred': 0, 'command': command}))
        return 0
    env = {k: v for k, v in os.environ.items() if not k.startswith(('ACCOUNT_', 'GOTRUE_'))}
    # Sólo el servicio PostgreSQL efímero de este job; nunca una URL del usuario.
    dsn = os.environ.get('ACCOUNT_FULL_TEST_DATABASE_URL', '')
    parsed = urlparse(dsn)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or parsed.scheme != 'postgres'
            or parsed.hostname != '127.0.0.1' or parsed.port != 5432
            or parsed.username != 'postgres' or parsed.password is not None
            or parsed.path != '/postgres' or parsed.query != 'sslmode=disable'
            or parsed.fragment):
        raise ValueError('Only the explicitly configured ephemeral GitHub job database is allowed')
    env.update(CGO_ENABLED='1', ACCOUNT_BINDING_TEST_DATABASE_URL=dsn,
               ACCOUNT_CONSENT_TEST_DATABASE_URL=dsn)
    seen, passed = set(), set()
    bad = False
    process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    with (ROOT / 'full-tests.jsonl').open('w') as log:
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
            if event.get('Action') == 'fail' or (name and event.get('Action') == 'skip'):
                bad = True
            if name and '/' not in name:
                if event.get('Action') == 'run':
                    seen.add(name)
                if event.get('Action') == 'pass':
                    passed.add(name)
    code = process.wait()
    if code or bad or seen != names or passed != names:
        print('The full suite failed, skipped tests or did not execute exactly.', file=sys.stderr)
        return 1
    print('All 178 tests passed with race detector; zero deferred.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
