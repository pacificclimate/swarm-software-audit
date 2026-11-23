#!/usr/bin/env python3
"""Opt-in smoke test against a real registry; no Docker daemon or SSH required."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

source = Path(__file__).resolve()
if len(source.parents) > 2:
    sys.path.insert(0, str(source.parents[2]))
sys.path.insert(0, '/opt/swarm-software-audit')
import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', required=True, help='fully qualified repository@sha256:digest')
    parser.add_argument('--platform', default='linux/amd64')
    args = parser.parse_args()
    targets = audit.validate_inventory({'images': [{'reference': args.reference, 'platform': args.platform}]})
    with tempfile.TemporaryDirectory(prefix='registry-smoke-') as directory:
        root = Path(directory)
        images, problems = audit.collect(targets, root, root)
        assert not problems, problems
        value = audit.read_json(images[0]['sbom'])['sbom']
        assert value['artifacts'], 'no packages cataloged'
        assert 'rawConfig' not in value['source']['metadata']
        assert not images[0]['cached']
        second, problems = audit.collect(targets, root, root)
        assert not problems and second[0]['cached'], problems
        print(json.dumps({'result': 'passed', 'packages': len(value['artifacts']),
                          'checks': ['registry catalog', 'image config redaction', 'SBOM cache reuse']}))


if __name__ == '__main__':
    main()
