import glob
import os
import shutil
import subprocess

import pytest


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_every_static_script_parses():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    bad = []
    for f in sorted(glob.glob(os.path.join(root, "static", "*.js"))):
        r = subprocess.run(["node", "--check", f], capture_output=True, text=True)
        if r.returncode:
            bad.append((os.path.basename(f), r.stderr[-300:]))
    assert not bad, bad
