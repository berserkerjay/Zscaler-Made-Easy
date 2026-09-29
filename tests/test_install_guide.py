"""The install guide a new IT person follows, and the overview of what
the app does, stay true to the repository.

"Ensure there are clear install instructions that are so easy to follow
that a new IT guy can follow the instructions in the repo", with the
follow-ups: the prerequisites name both sign-in methods (OneAPI and the
classic ZIA API), and an overview of what the app can do lives in the
repo. Every file and link the guide names must exist, the words it uses
must be the app's own, and the Windows scripts must do what it says.
"""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _exists(*parts):
    return os.path.exists(os.path.join(ROOT, *parts))


INSTALL = _read("INSTALL.md")
FLAT = re.sub(r"\s+", " ", INSTALL)   # the guide's prose, line breaks folded, for phrase checks
OVERVIEW = _read("docs", "OVERVIEW.md")
README = _read("README.md")
STARTED = _read("GETTING_STARTED.md")


def test_the_install_guide_names_only_files_that_exist_and_links_that_resolve():
    named = set(re.findall(r"`([A-Za-z0-9_./-]+\.(?:bat|sh|md|vbs|example|txt|log|json))`", INSTALL))
    # Files the guide tells the reader to look for or run must be in the repository; files the app
    # writes at run time (its log, the token file, the settings copy) are expected not to be.
    written_at_runtime = {"server.log", "launcher.log", "ui_token.txt", "local_settings.bat", "local_settings.env"}
    missing = sorted(n for n in named if n not in written_at_runtime and not _exists(*n.split("/")))
    assert not missing, f"INSTALL.md names files that are not in the repository: {missing}"
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", INSTALL):
        if target.startswith("http"):
            continue
        assert _exists(*target.split("/")), f"INSTALL.md links to {target}, which does not exist"
    anchors = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-") for h in re.findall(r"^#{2,3} (.+)$", INSTALL, re.M)}
    for frag in re.findall(r"\]\(#([^)]+)\)", INSTALL):
        assert frag in anchors, f"INSTALL.md links to #{frag}, which is not one of its headings"


def test_the_install_guide_has_the_sections_a_first_timer_needs():
    for heading in ("Before you start", "Two ways to get the files", "## Windows", "## Mac", "## Linux", "Run it in a container instead",
                    "How you know it worked", "First run: the UI token", "Connecting to a Zscaler tenant", "Work laptop",
                    "Starting, stopping, updating and removing it later", "If something goes wrong", "Where to get help"):
        assert heading in INSTALL, heading
    # Both sign-in methods, with what to collect for each, before the reader installs anything.
    before = INSTALL.split("## Two ways to get the files")[0]
    assert "OneAPI" in before and "Classic ZIA API" in before
    for field in ("Vanity domain", "Client ID", "Client secret", "Admin username", "Admin password", "API key"):
        assert field.lower() in before.lower(), field
    assert "private" in before, "the reader is told the repository is private and needs access"


def test_the_install_guide_uses_the_apps_own_words():
    assert "UI token" in INSTALL and "sign-in code" not in INSTALL, "the app calls it the UI token everywhere"
    assert "Add python.exe to PATH" in INSTALL, "the current python.org installer's checkbox label"
    assert "server.log" in INSTALL and "launcher.log" in INSTALL, "where the Windows server's output goes"
    assert "STOP_Zscaler_Assessment.bat" in INSTALL and "Closing the browser does not stop it" in INSTALL
    assert "Open http://localhost:8000/?token=" in INSTALL, "what start.sh prints, quoted"
    assert "Python is not installed or only the Microsoft Store stub was found." in INSTALL, "the start script's real message"
    assert "ERROR: Python is not installed." in INSTALL, "the installer's real message"
    assert "QA (qa)" in INSTALL and "Development (dev)" in INSTALL and "Stable (main)" in INSTALL, "the Branch dropdown's labels as shown"
    assert "--console" in INSTALL, "the way to see why a silent start failed"
    assert "./stop.sh` is only for a server started with `./start.sh --background`" in FLAT
    assert "Not Now" in INSTALL and "quit Terminal" in INSTALL, "the Mac developer-tools dialog and the reopen after installing Python"
    assert "download.docker.com/linux/ubuntu" in INSTALL and "docker-compose-plugin" in INSTALL, "Docker's own repository: Ubuntu's docker.io is too old"
    assert "console window" not in INSTALL, "no console window ever opens on Windows"


def test_the_windows_installer_does_what_the_guide_says():
    bat = _read("INSTALL_Zscaler_Assessment.bat")
    assert "sys.version_info >= (3, 11)" in bat, "an old Python first on PATH is refused with its version named"
    assert "INSTALL FAILED" in bat and bat.index("INSTALL FAILED") < bat.index("Installation complete!"), "a failed pip install never reads as complete"
    failed = bat[bat.index("INSTALL FAILED"):bat.index("[2/2]")]
    assert "pause" in failed and "exit /b 1" in failed, "the window stays open on failure, and the shortcuts are not made"
    assert 'call "%INSTALL_DIR%\\local_settings.bat"' in bat and "PIP_CERT" in bat, "the CA bundle and proxy apply to the install too"
    closing = bat[bat.index("Installation complete!"):]
    assert "console window" not in closing and "server.log" in closing and "STOP_Zscaler_Assessment.bat" in closing, "the closing text matches the silent launcher"
    label = bat.index("\n:oldpython")
    main_flow = bat[:label]
    assert main_flow.rstrip().endswith("exit /b 0"), "a bare exit closes the Command Prompt that called it"
    assert "goto :oldpython" in main_flow and bat[label:].rstrip().endswith("exit /b 1")
    # No expanded Python path inside a parenthesised block: "C:\Program Files (x86)\..." would close the block early.
    import re
    for block in re.findall(r"if errorlevel 1 \((.*?)\n\)", bat, re.S):
        assert "%PYTHON_EXE%" not in block and "%PYTHON_VER%" not in block, block[:80]
    assert "No desktop shortcut could be made" in bat and "Test-Path" in bat, "a locked-down PowerShell that makes no shortcut is said"
    assert "Add python.exe to PATH" in bat


def test_stop_and_uninstall_find_the_server_by_its_port():
    stop = _read("STOP_Zscaler_Assessment.bat")
    assert "ZSCALER_PORT" in stop and 'call "%~dp0local_settings.bat"' in stop, "a port changed in local_settings.bat is honoured"
    un = "\n".join(l for l in _read("UNINSTALL_Zscaler_Assessment.bat").splitlines() if not l.strip().upper().startswith("REM"))
    assert "pythonw.exe" not in un and "WindowTitle" not in un, "the server runs as python.exe under a differently titled window"
    assert "netstat -ano" in un and "ZSCALER_PORT" in un, "the uninstaller stops the server the way STOP does"
    assert "zscaler_launcher.vbs" not in un, "a file that never existed"


def test_the_silent_launcher_waits_for_the_server_before_reading_the_token():
    vbs = _read("START_Zscaler_Assessment.vbs")
    assert "Do While Not Pinging() And waited < 30000" in vbs and "WScript.Sleep 4000" not in vbs
    assert vbs.index("Do While Not Pinging()") < vbs.index('tokenPath = dir & "\\ui_token.txt"'), "the token file is read once the server answers, so it is never stale"


def test_the_unix_installer_reads_the_settings_file_and_says_how_to_stop():
    sh = _read("install.sh")
    assert ". ./local_settings.env" in sh and "PIP_CERT" in sh and sh.index(". ./local_settings.env") < sh.index("--require-hashes")
    assert "Ctrl-C stops it" in sh and "./stop.sh stops that" in sh


def test_the_overview_covers_every_function_the_app_explains():
    js = _read("static", "explain.js")
    names = re.findall(r"^\s+group: '[^']+', name: '((?:[^'\\]|\\.)+)'", js, re.M)
    assert len(names) >= 30, "the catalogue of functions was found"
    missing = []
    for raw in names:
        name = raw.replace("\\'", "'")
        short = re.split(r" \(| — ", name)[0]
        if short not in OVERVIEW:
            missing.append(name)
    assert not missing, f"docs/OVERVIEW.md does not mention: {missing}"
    for group in ("Start", "Find the gaps", "Close the gaps", "Reference", "Troubleshoot"):
        assert f"### {group}" in OVERVIEW, group
    for heading in ("In one paragraph", "What it never does", "Two ways to sign in to a tenant", "Limits, and what is still to come"):
        assert heading in OVERVIEW, heading
    assert "OneAPI" in OVERVIEW and "Classic ZIA API" in OVERVIEW
    assert "write mode" in OVERVIEW and "create and delete DLP policy" in OVERVIEW, "what write mode allows, in the user's words"
    assert "disabled" in OVERVIEW.lower() and "monitor-only" in OVERVIEW
    for pack_dir in ("cjis_policy_pack", "fed_policy_pack", "global_banking_baseline", "healthcare_phi_baseline", "zbp_enterprise_baseline", "zbp_source_code_baseline"):
        assert _exists(pack_dir), pack_dir
    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", OVERVIEW):
        if not target.startswith("http"):
            assert _exists("docs", *target.split("/")), f"OVERVIEW.md links to {target}"


def test_the_readme_and_the_getting_started_guide_agree_with_the_install_guide():
    assert "docs/OVERVIEW.md" in README and "INSTALL.md" in README and "GETTING_STARTED.md" in README
    assert "This repository is public" not in README, "the repository is private; INSTALL.md and GETTING_STARTED.md say so"
    assert "docs/DLP_Assessment_Step_by_Step_Guide.docx" not in README and _exists("DLP_Assessment_Step_by_Step_Guide.docx")
    assert "Add python.exe to PATH" in README and "Add Python to PATH" not in STARTED
    heads = [h for h in re.findall(r"^## (1[a-c]?)\.", STARTED, re.M)]
    assert heads == ["1", "1a", "1b", "1c"], heads
    assert "INSTALL.md" in STARTED.split("## 1a.")[0], "section 1 sends the reader to the walkthrough"
    assert "local_settings.env" in STARTED.split("## 1b.")[1].split("## 1c.")[0], "the Mac/Linux settings file is covered beside the Windows one"
    assert "Activation is never done by the tool" not in STARTED, "a deploy or removal activates; the guide says what does and what does not"


def test_the_unlock_dialog_and_the_update_help_do_not_assume_a_windows_console():
    for name in ("ui_auth.js", "report_theme.js"):
        assert "server console" not in _read("static", name), name
    guide = _read("static", "guide.js")
    body = guide[guide.index("function _gdUpdateHelp()"):]
    body = body[:body.index("\n}\n")]
    assert "local_settings.env" in body and "./install.sh" in body and "fresh ZIP" in body
    import app_update as au
    src = _read("app_update.py")
    assert "xcode-select --install" in src and "fresh ZIP" in src and "run INSTALL_Zscaler_Assessment.bat from the clone" not in src
    assert 'echo $! > "{pid}"' in src, "an in-app update on Mac/Linux records server.pid so ./stop.sh works afterwards"
    assert "./start.sh" in au.manual_restart_hint("/tmp/x") or os.name == "nt"
    # `python3 app_update.py` from a terminal installs the new dependencies into the app's own .venv, not the system Python.
    assert 'os.path.join(args.dir, ".venv", "bin", "python")' in src


def test_the_container_prints_an_address_a_person_can_open():
    """docker-compose publishes the container's 0.0.0.0 on the host's
    127.0.0.1; the log must say localhost and not warn about a network
    bind that the compose file has already contained."""
    src = _read("dlp_api_server.py")
    assert 'DLP_CHECK_IN_CONTAINER' in src and "in_container and host == '0.0.0.0'" in src
    assert "docker-compose.yml publishes it on 127.0.0.1:{port} of this machine only" in src
    assert "docker-compose.yml publishes it on 127.0.0.1:8000 of this machine only" in INSTALL, "the guide quotes the line the reader will see"


def test_the_scripts_fixed_after_the_second_round_of_readers():
    # An in-app update on Mac/Linux: only the server is the background job, so server.pid holds the server's pid
    # (bash does not exec the last command of a backgrounded `cd && nohup` list; dash does).
    import app_update as au
    if os.name != "nt":
        cmd = au.restart_command("/tmp/x")[2]
        assert '|| exit 1; nohup' in cmd and '&& nohup' not in cmd and cmd.rstrip().endswith('echo $! > "/tmp/x/server.pid"')
    # A venv left half-made by a missing python3-venv is rebuilt, not trusted.
    sh = _read("install.sh")
    assert "-m pip --version" in sh and "rm -rf .venv; fail" in sh
    # --background never offers the previous run's token and waits for this run's address.
    st = _read("start.sh")
    assert st.index("rm -f ui_token.txt") < st.index("nohup .venv/bin/python") and 'grep -q "Open http" server.log' in st
    # A ")" inside a for-block's echo is escaped.
    assert "^(was listening on :%ZSCALER_PORT%^)" in _read("STOP_Zscaler_Assessment.bat")
    assert "4 s after the start" not in _read("START_Zscaler_Assessment.vbs")
    # cmd reads a .bat in the OEM code page: the Windows scripts are plain ASCII.
    import glob
    for path in glob.glob(os.path.join(ROOT, "*.bat")) + glob.glob(os.path.join(ROOT, "*.vbs")):
        data = open(path, "rb").read()
        assert all(b < 128 for b in data), os.path.basename(path)


def test_the_container_keeps_what_the_guide_says_it_keeps():
    df = _read("Dockerfile")
    for var in ("DLP_CHECK_PROFILES=/data", "DLP_CHECK_DEPLOYMENTS=/data", "DLP_CHECK_AUDIT=/data", "DLP_CHECK_UI_TOKEN_DIR=/data",
                "DLP_CHECK_DIGESTS=/data", "DLPCHECK_PROPOSALS_FILE=/data", "DLP_CHECK_GUIDANCE_STATE=/data", "DLP_CHECK_SAAS_MATRIX=/data"):
        assert var in df, var
    assert "DLP_CHECK_USER_PACKS: /data" in _read("docker-compose.yml")
    assert "DLP_CHECK_CHECKS_CONFIG" not in df, "checks_config.json ships with the app; the overview says it is read-only in the container"
    flat = re.sub(r"\s+", " ", INSTALL)
    assert "digests, proposals, the guidance state and the token file" in flat and "ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND" in flat


def test_the_overview_states_its_exceptions_and_uses_the_apps_names():
    flat = re.sub(r"\s+", " ", OVERVIEW)
    assert "Step 3b deletes every existing Inline Web DLP rule" in flat and "restore_drift" in flat, "the two ways something the customer has is overwritten"
    assert "a migrated rule carries the action approved in its decisions file" in flat
    assert "the switch is refused" in flat and "ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND" in flat, "write mode in the container"
    assert "dlp_mcp_server.py" in flat and ".venv/bin/dlp-check-assess" in flat and "RUN_Continuous_Evaluation.bat" in flat
    assert "SMTP relay or Teams/Slack webhook" in flat and "Microsoft Learn" in flat, "every host the app reaches"
    import json
    for pj in ("cjis_policy_pack", "fed_policy_pack", "global_banking_baseline", "healthcare_phi_baseline", "zbp_enterprise_baseline", "zbp_source_code_baseline"):
        name = json.load(open(os.path.join(ROOT, pj, "pack.json"), encoding="utf-8"))["name"]
        assert f"| {name} |" in OVERVIEW, name
    # The app's own help no longer says an admin must activate after a deploy.
    assert "an admin must click Activate" not in _read("static", "explain.js")
    assert "Activate in the ZIA portal, then enable rules" not in _read("static", "guide.js")
    assert "An admin must click **Activate**" not in STARTED


def test_the_container_option_says_how_to_install_docker_step_by_step():
    """"Install instructions: you forgot the steps to install Docker": the
    container option walks a first-timer through installing Docker on
    Windows, Mac and Linux, with a check after each, before Step 2."""
    step1 = INSTALL[INSTALL.index("**Step 1 — Install Docker.**"):INSTALL.index("**Step 2 — Get the code**, the same way as above")]
    flat = re.sub(r"\s+", " ", re.sub(r"\n>\s?", "\n", step1))   # quoted blocks read as plain text
    # Windows: WSL 2, the installer's own screens, first start, the docker-users group.
    for phrase in ("wsl --install --no-distribution", "Docker Desktop for Windows - x86_64", "Use WSL 2 instead of Hyper-V (recommended)",
                   "Close and restart", "Engine running", "net localgroup docker-users", "Run as administrator"):
        assert phrase in flat, phrase
    # Mac: which chip, the matching download, the drag to Applications, first start.
    for phrase in ("About This Mac", "Docker Desktop for Mac with Apple silicon", "Applications", "Use recommended settings"):
        assert phrase in flat, phrase
    # Linux: Docker's repository, the packages, the service, the group, the re-login.
    for phrase in ("download.docker.com/linux/ubuntu", "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin",
                   "sudo systemctl enable --now docker", "sudo usermod -aG docker $USER", "log out and back in", "docs.docker.com/engine/install/"):
        assert phrase in flat, phrase
    # A check that must pass before going on, the Compose version the compose file needs, the licence, TLS inspection.
    assert flat.count("docker run --rm hello-world") >= 2 and "Hello from Docker!" in flat and "2.24 or newer" in flat
    assert "fewer than 250 employees" in flat and "CERTIFICATE_VERIFY_FAILED" in flat and "Settings → Resources → Proxies" in flat
    assert "services.dlp-check.env_file.0 must be a string" in INSTALL and "Cannot connect to the Docker daemon" in INSTALL, "troubleshooting rows"
    # The compose file really needs 2.24: its env_file uses the long syntax.
    compose = _read("docker-compose.yml")
    assert "required: false" in compose
