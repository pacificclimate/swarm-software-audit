"""Exercise real Linux credentials and timeout cleanup in the disposable host."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('host', '/usr/local/libexec/kestra-audit-root')
# Installed helper has no .py extension.
if spec is None:
    from importlib.machinery import SourceFileLoader
    spec = importlib.util.spec_from_loader('host', SourceFileLoader('host', '/usr/local/libexec/kestra-audit-root'))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
config = json.loads(host.CONFIG.read_text())
host.enter_workspace_identity(config)
assert os.getresuid() == (1111, 1111, 0)
root, maximum, reserve = host.workspace_settings(config)
with tempfile.TemporaryDirectory(dir=root) as directory:
    work = Path(directory)
    host.DOCKER = [sys.executable, '-I', '-c', 'import os,json; print(json.dumps([os.getuid(),os.geteuid()]))']
    with tempfile.TemporaryFile(dir=work) as output:
        host.run_bounded([], output, work, 1, 4096, time.monotonic() + 5)
        assert os.fstat(output.fileno()).st_uid == 1111
        output.seek(0)
        assert json.load(output) == [1111, 0], 'Docker child credentials incorrect'
    host.DOCKER = [sys.executable, '-I', '-c', 'import time; time.sleep(30)']
    with tempfile.TemporaryFile(dir=work) as output:
        try:
            host.run_bounded([], output, work, 1, 4096, time.monotonic() + .1)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError('timeout did not stop the elevated child')
assert os.geteuid() == 1111
print('Workspace ownership and elevated-child timeout checks passed')
