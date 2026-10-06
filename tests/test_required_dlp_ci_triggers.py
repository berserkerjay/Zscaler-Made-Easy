"""Keep full PR/main verification without duplicate feature-branch push runs."""
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('file,jobs', [
    ('tests.yml', ('test', 'browser-acceptance', 'supply-chain', 'windows-lock', 'container')),
    ('native-install.yml', ('native-install',)),
])
def test_full_checks_run_on_pr_and_main_with_manual_dispatch(file, jobs):
    source = (ROOT / '.github/workflows' / file).read_text()
    triggers = source.split('permissions:', 1)[0]
    assert 'push:\n    branches: ["main"]' in triggers
    assert '  pull_request:\n' in triggers and '  workflow_dispatch:\n' in triggers
    assert '["**"]' not in triggers
    for job in jobs:
        assert '\n  ' + job + ':\n' in source
    if file == 'native-install.yml':
        for platform in ('ubuntu-24.04', 'macos-15', 'macos-15-intel', 'windows-2025'):
            assert platform in source
        assert 'python: ["3.11", "3.14"]' in source
