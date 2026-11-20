#!/usr/bin/python3 -I
"""Forced SSH command: exact verbs only; no shell interpolation."""
import os
import sys

OPERATIONS = {'audit inventory-v1': 'inventory-v1', 'audit sbom-v1': 'sbom-v1'}


def main():
    operation = OPERATIONS.get(os.environ.get('SSH_ORIGINAL_COMMAND', ''))
    if operation is None:
        print('Command denied', file=sys.stderr)
        return 126
    os.execve('/usr/bin/sudo', ['sudo', '-n', '/usr/local/libexec/kestra-audit-root', operation],
              {'PATH': '/usr/bin:/bin', 'HOME': '/var/empty'})


if __name__ == '__main__':
    sys.exit(main())
