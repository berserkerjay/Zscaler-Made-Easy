"""--version and `completion bash|zsh|powershell` for the command lines.

Both are generated from the command's own argparse parser, so a new option
or subcommand shows up in the completion without a second list to keep.
Nothing here reads a tenant or any stored data.
"""
from __future__ import annotations

import argparse
import os
import re
from typing import Any, Dict, List, Optional, Tuple

SHELLS = ("bash", "zsh", "powershell")
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def app_version() -> str:
    """The app version (the installed package, else pyproject.toml beside this file), plus the build commit when one is recorded."""
    ver = ""
    try:
        import importlib.metadata as md
        ver = md.version("dlp-check")
    except Exception:  # noqa: BLE001
        pass
    if not ver:
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyproject.toml"), encoding="utf-8") as f:
                m = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M)
            ver = m.group(1) if m else ""
        except OSError:
            pass
    build = os.environ.get("DLP_CHECK_BUILD_COMMIT", "").strip()
    out = ver or "unknown"
    if build and build != "unknown":
        out += f" (build {_SAFE.sub('', build)[:12]})"
    return out


def add_version(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--version", action="version", version=f"%(prog)s {app_version()}")


def _walk(ap: argparse.ArgumentParser) -> Tuple[List[str], Dict[str, Any], Dict[str, List[str]]]:
    """(the parser's option strings, {subcommand: its parser}, {option: its choices})."""
    opts: List[str] = []
    subs: Dict[str, Any] = {}
    choices: Dict[str, List[str]] = {}
    for a in ap._actions:
        if isinstance(a, argparse._SubParsersAction):
            subs.update(a.choices)
        else:
            opts += list(a.option_strings)
            if a.choices and a.option_strings:
                for o in a.option_strings:
                    choices[o] = [str(c) for c in a.choices]
    return opts, subs, choices


def completion(shell: str, prog: str, ap: argparse.ArgumentParser, extra_subcommands: Tuple[str, ...] = ("completion",)) -> str:
    """The completion script for `shell`, built from `ap`."""
    if shell not in SHELLS:
        raise ValueError(f"shell must be one of: {', '.join(SHELLS)}")
    opts, subs, choices = _walk(ap)
    names = sorted(set(subs) | set(extra_subcommands))
    fn = "_" + _SAFE.sub("_", prog)
    if shell == "bash":
        cases = "".join(f'    {o}) COMPREPLY=( $(compgen -W "{" ".join(c)}" -- "$cur") ); return 0;;\n' for o, c in sorted(choices.items()))
        sub_cases = "".join(f'    {n}) COMPREPLY=( $(compgen -W "{" ".join(sorted(_walk(subs[n])[0]))}" -- "$cur") ); return 0;;\n' for n in sorted(subs))
        return (f'# bash completion for {prog}\n{fn}() {{\n  local cur prev\n  cur="${{COMP_WORDS[COMP_CWORD]}}"; prev="${{COMP_WORDS[COMP_CWORD-1]}}"\n'
                f'  case "$prev" in\n{cases}  completion) COMPREPLY=( $(compgen -W "{" ".join(SHELLS)}" -- "$cur") ); return 0;;\n{sub_cases}  esac\n'
                f'  COMPREPLY=( $(compgen -W "{" ".join(sorted(opts))} {" ".join(names)}" -- "$cur") )\n}}\ncomplete -F {fn} {prog}\n')
    if shell == "zsh":
        lines = [f"#compdef {prog}", f"{fn}() {{", "  local -a words_list"]
        lines.append(f"  words_list=({' '.join(sorted(opts) + names)})")
        lines.append("  case $words[CURRENT-1] in")
        for o, c in sorted(choices.items()):
            lines.append(f"    {o}) compadd -- {' '.join(c)}; return;;")
        lines.append(f"    completion) compadd -- {' '.join(SHELLS)}; return;;")
        lines.append("  esac")
        lines.append("  compadd -- $words_list")
        lines.append("}")
        lines.append(f"compdef {fn} {prog}")
        return "\n".join(lines) + "\n"
    words = " ".join(f"'{w}'" for w in sorted(opts) + names)
    sh = " ".join(f"'{s}'" for s in SHELLS)
    ch = "".join(f"    if ($prev -eq '{o}') {{ @({', '.join(repr(x) for x in c)}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}; return }}\n"
                 for o, c in sorted(choices.items()))
    return (f"# PowerShell completion for {prog}\nRegister-ArgumentCompleter -Native -CommandName '{prog}' -ScriptBlock {{\n  param($wordToComplete, $commandAst, $cursorPosition)\n"
            f"  $prev = if ($commandAst.CommandElements.Count -gt 1) {{ $commandAst.CommandElements[-1].ToString() }} else {{ '' }}\n"
            f"  if ($prev -eq 'completion') {{ @({sh}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}; return }}\n{ch}"
            f"  @({words}) | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{ [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }}\n}}\n")


def handle_completion(argv: Optional[List[str]], prog: str, build_parser: Any) -> Optional[int]:
    """If argv is `completion SHELL`, print the script built from build_parser() and return 0 (2 for a bad shell); else None."""
    import sys
    if not argv or argv[0] != "completion":
        return None
    if len(argv) != 2 or argv[1] not in SHELLS:
        print(f"usage: {prog} completion {{{'|'.join(SHELLS)}}}", file=sys.stderr)
        return 2
    sys.stdout.write(completion(argv[1], prog, build_parser()))
    return 0
