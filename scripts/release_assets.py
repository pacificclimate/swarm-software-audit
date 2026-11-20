#!/usr/bin/env python3
"""Prepare versioned host helpers and their checksum manifest for a release."""
import argparse
import hashlib
from pathlib import Path
import shutil


def build(destination):
    root = Path(__file__).resolve().parents[1]
    destination.mkdir(parents=True, exist_ok=True)
    lines = []
    for source in [root / 'host/host.py', root / 'host/dispatch.py', root / 'LICENSE']:
        target = destination / source.name
        shutil.copyfile(source, target)
        lines.append(hashlib.sha256(target.read_bytes()).hexdigest() + '  ' + target.name)
    (destination / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    build(parser.parse_args().output)
