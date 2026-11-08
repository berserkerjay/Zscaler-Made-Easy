"""--version and `completion bash|zsh|powershell` for log_pipeline_cli and
the assessment command line (cli_extras). Generated from argparse; no
tenant, no network."""
from __future__ import annotations

import subprocess

import pytest

import cli_extras
import dlp_assessment_full_auto as fa
import log_pipeline_cli as lp

SHELLS = ("bash", "zsh", "powershell")


def test_version_prints_the_app_version_and_build(monkeypatch, capsys):
    """ASVS V14.1.1 · CWE-1104: --version prints the package version, plus the build commit when one is recorded, and exits 0."""
    monkeypatch.setenv("DLP_CHECK_BUILD_COMMIT", "abc1234def")
    for run in (lambda: lp.main(["--version"]), lambda: fa.main(["--version"])):
        with pytest.raises(SystemExit) as ex:
            run()
        assert ex.value.code == 0
        out = capsys.readouterr().out.strip()
        assert cli_extras.app_version() in out and "(build abc1234def)" in out and out.split()[1][0].isdigit()


def test_version_without_a_build(monkeypatch):
    """ASVS V14.1.1 · CWE-1104: no recorded build leaves just the version; a build string is stripped to safe characters."""
    monkeypatch.delenv("DLP_CHECK_BUILD_COMMIT", raising=False)
    assert "build" not in cli_extras.app_version()
    monkeypatch.setenv("DLP_CHECK_BUILD_COMMIT", "a;rm -rf /")
    assert ";" not in cli_extras.app_version() and " /" not in cli_extras.app_version()


@pytest.mark.parametrize("shell", SHELLS)
def test_log_pipeline_completion_lists_every_subcommand(shell, capsys):
    """ASVS V5.1.3 · CWE-20: the completion for the log pipeline names every subcommand its parser has, and the shells after `completion`."""
    assert lp.main(["completion", shell]) == 0
    out = capsys.readouterr().out
    for sub in ("health", "reports", "reindex", "regen", "export", "deliver", "selftest", "completion", "--version"):
        assert sub in out, (shell, sub)
    for sh in SHELLS:
        assert sh in out


@pytest.mark.parametrize("shell", SHELLS)
def test_assessment_completion_lists_options_and_choices(shell, capsys):
    """ASVS V5.1.3 · CWE-20: the assessment completion has every option and the --scope choices, built from its parser."""
    with pytest.raises(SystemExit) as ex:
        fa.main(["completion", shell])
    assert ex.value.code == 0
    out = capsys.readouterr().out
    for w in ("--config", "--output", "--scope", "--version", "--check-data", "--repair-data", "full", "zcc", "completion"):
        assert w in out, (shell, w)


def test_a_new_option_shows_up_without_a_second_list():
    """ASVS V1.14.1 · CWE-1059: the script is generated from the parser: an option added to it appears in the output."""
    ap = fa.build_parser()
    ap.add_argument("--brand-new-flag")
    assert "--brand-new-flag" in cli_extras.completion("bash", "x", ap)


def test_bad_shell_is_refused(capsys):
    """ASVS V5.1.3 · CWE-20: an unknown shell is refused (exit 2) and prints no script."""
    with pytest.raises(SystemExit) as ex:
        fa.main(["completion", "fish"])
    assert ex.value.code == 2 and capsys.readouterr().out == ""
    with pytest.raises(SystemExit):
        lp.main(["completion", "fish"])
    with pytest.raises(ValueError):
        cli_extras.completion("fish", "x", fa.build_parser())


def test_bash_script_is_valid_bash(tmp_path):
    """ASVS V5.3.1 · CWE-94: the generated bash script parses with `bash -n` and contains no command substitution but compgen."""
    script = cli_extras.completion("bash", "log_pipeline_cli", lp.build_parser())
    p = tmp_path / "c.bash"
    p.write_text(script)
    assert subprocess.run(["bash", "-n", str(p)], capture_output=True).returncode == 0
    assert script.count("$(") == script.count("$(compgen")
