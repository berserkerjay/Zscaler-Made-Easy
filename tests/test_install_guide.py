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
    written_at_runtime = {"server.log", "launcher.log", "ui_token.txt", "local_settings.bat", "local_settings.env", "update_container.log",
                          "store_keys.json", "/data/store_keys.json"}   # the store encryption key file (store_crypto.py)
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
    assert "private" in before and "set by its owner" in " ".join(before.split()), \
        "the reader is told the owner sets the visibility and that a private repository needs access"


def test_the_install_guide_uses_the_apps_own_words():
    assert "UI token" in INSTALL and "sign-in code" not in INSTALL, "the app calls it the UI token everywhere"
    assert "Add python.exe to PATH" in INSTALL, "the current python.org installer's checkbox label"
    assert "server.log" in INSTALL and "launcher.log" in INSTALL, "where the Windows server's output goes"
    assert "STOP_Zscaler_Made_Easy.bat" in INSTALL and "Closing the browser does not stop it" in INSTALL
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
    bat = _read("INSTALL_Zscaler_Made_Easy.bat")
    assert "sys.version_info >= (3, 11)" in bat, "an old Python first on PATH is refused with its version named"
    assert "INSTALL FAILED" in bat and bat.index("INSTALL FAILED") < bat.index("Installation complete!"), "a failed pip install never reads as complete"
    failed = bat[bat.index("INSTALL FAILED"):bat.index("[2/2]")]
    assert "pause" in failed and "exit /b 1" in failed, "the window stays open on failure, and the shortcuts are not made"
    assert 'call "%INSTALL_DIR%\\local_settings.bat"' in bat and "PIP_CERT" in bat, "the CA bundle and proxy apply to the install too"
    closing = bat[bat.index("Installation complete!"):]
    assert "console window" not in closing and "server.log" in closing and "STOP_Zscaler_Made_Easy.bat" in closing, "the closing text matches the silent launcher"
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
    stop = _read("STOP_Zscaler_Made_Easy.bat")
    assert "ZSCALER_PORT" in stop and 'call "%~dp0local_settings.bat"' in stop, "a port changed in local_settings.bat is honoured"
    un = "\n".join(l for l in _read("UNINSTALL_Zscaler_Made_Easy.bat").splitlines() if not l.strip().upper().startswith("REM"))
    assert "pythonw.exe" not in un and "WindowTitle" not in un, "the server runs as python.exe under a differently titled window"
    assert "netstat -ano" in un and "ZSCALER_PORT" in un, "the uninstaller stops the server the way STOP does"
    assert "zscaler_launcher.vbs" not in un, "a file that never existed"


def test_the_silent_launcher_waits_for_the_server_before_reading_the_token():
    vbs = _read("START_Zscaler_Made_Easy.vbs")
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
    assert "This repository is public" not in README, "the owner sets the visibility; README.md never claims it is public"
    assert "docs/DLP_Assessment_Step_by_Step_Guide.docx" not in README and _exists("DLP_Assessment_Step_by_Step_Guide.docx")
    assert "Add python.exe to PATH" in README and "Add Python to PATH" not in STARTED
    heads = [h for h in re.findall(r"^## (1[a-c]?)\.", STARTED, re.M)]
    assert heads == ["1", "1a", "1b", "1c"], heads
    assert "INSTALL.md" in STARTED.split("## 1a.")[0], "section 1 sends the reader to the walkthrough"
    assert "local_settings.env" in STARTED.split("## 1b.")[1].split("## 1c.")[0], "the Mac/Linux settings file is covered beside the Windows one"
    assert "Activation is never done by the tool" not in STARTED, "a deploy or removal activates; the guide says what does and what does not"


def test_no_top_level_doc_or_the_licence_claims_the_repository_is_public():
    # The code is open source (Apache-2.0), but the owner sets whether the
    # repository is public; no document may claim it is. LICENSE once said
    # "This repository is public", which the README-only check missed.
    names = sorted(n for n in os.listdir(ROOT) if n == "LICENSE" or n.lower().endswith(".md"))
    assert "LICENSE" in names and "README.md" in names and "SECURITY.md" in names, names
    for name in names:
        text = " ".join(_read(name).split()).lower()
        for claim in ("this repository is public", "the repository is public", "being publicly readable"):
            assert claim not in text, f"{name} says {claim!r}; the repository's visibility is set by its owner"
    licence = " ".join(_read("LICENSE").split())
    assert licence.startswith("Apache License Version 2.0, January 2004"), "LICENSE is the Apache License 2.0 text, nothing added"
    readme = " ".join(_read("README.md").split())
    assert "Apache License 2.0" in readme and "set by its owner" in readme, "README states the licence and who sets the visibility"
    for name in ("INSTALL.md", "GETTING_STARTED.md", "SECURITY.md"):
        text = " ".join(_read(name).split())
        assert "the repository is private, so" not in text.lower(), f"{name} states the visibility as a fact, not conditionally"


def test_the_unlock_dialog_and_the_update_help_do_not_assume_a_windows_console():
    for name in ("ui_auth.js", "report_theme.js"):
        assert "server console" not in _read("static", name), name
    guide = _read("static", "guide.js")
    body = guide[guide.index("function _gdUpdateHelp()"):]
    body = body[:body.index("\n}\n")]
    assert "local_settings.env" in body and "./install.sh" in body and "fresh ZIP" in body
    import app_update as au
    src = _read("app_update.py")
    assert "xcode-select --install" in src and "fresh ZIP" in src and "run INSTALL_Zscaler_Made_Easy.bat from the clone" not in src
    assert 'echo $! > "{pid}"' in src, "an in-app update on Mac/Linux records server.pid so ./stop.sh works afterwards"
    assert "./start.sh" in au.manual_restart_hint("/tmp/x") or os.name == "nt"
    # `python3 app_update.py` from a terminal installs the new dependencies into the app's own .venv, not the system Python.
    assert 'os.path.join(args.dir, ".venv", "bin", "python")' in src


def test_the_container_prints_an_address_a_person_can_open():
    """docker-compose publishes the container's 0.0.0.0 on the host's
    127.0.0.1; the log must say localhost and not warn about a network
    bind that the compose file has already contained."""
    src = _read("dlp_api_server.py")
    assert 'DLP_CHECK_IN_CONTAINER' in src and "in_container and host == all_interfaces" in src
    assert 'all_interfaces = "0.0.0.0"' in src
    assert "docker-compose.yml publishes it on 127.0.0.1:{shown_port} of this machine only" in src
    assert "docker-compose.yml publishes it on 127.0.0.1:8001 of this machine only" in INSTALL, "the guide quotes the line the reader will see"


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
    assert "^(was listening on :%ZSCALER_PORT%^)" in _read("STOP_Zscaler_Made_Easy.bat")
    assert "4 s after the start" not in _read("START_Zscaler_Made_Easy.vbs")
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
    # Whatever works on a local install works in the container: approved
    # check references and the update / best-practice caches land on /data.
    assert "DLP_CHECK_CHECKS_CONFIG=/data/checks_config.json" in df and "XDG_CACHE_HOME=/data/cache" in df
    flat = re.sub(r"\s+", " ", INSTALL)
    assert "digests, proposals, the guidance state and the token file" in flat and "ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND" in flat


def test_the_overview_states_its_exceptions_and_uses_the_apps_names():
    flat = re.sub(r"\s+", " ", OVERVIEW)
    assert "Step 3b deletes every existing Inline Web DLP rule" in flat and "restore_drift" in flat, "the two ways something the customer has is overwritten"
    assert "a migrated rule carries the action approved in its decisions file" in flat
    assert "the switch is refused" in flat and "ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND" in flat, "write mode in the container"
    assert "dlp_mcp_server.py" in flat and ".venv/bin/zscaler-made-easy-assess" in flat and "RUN_Continuous_Evaluation.bat" in flat
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
    step1 = INSTALL[INSTALL.index("**Step 1 — Install Docker.**"):INSTALL.index("**Step 2 — Get the code with git.**")]
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
    assert "services.zscaler-made-easy.env_file.0 must be a string" in INSTALL and "Cannot connect to the Docker daemon" in INSTALL, "troubleshooting rows"
    # The compose file really needs 2.24: its env_file uses the long syntax.
    compose = _read("docker-compose.yml")
    assert "required: false" in compose


def test_a_fresh_container_install_is_spelled_out_for_windows_mac_and_linux():
    """"What do I type to pull down the docker image and load it for a fresh
    install", "the instructions should account for a fresh install of a
    container on mac windows or linux": there is no image to pull, so the
    guide says so, clones with git on each system (the update script needs a
    clone) and builds with the update script, which stamps the commit."""
    part = INSTALL[INSTALL.index("## Run it in a container instead"):INSTALL.index("**Everyday use:**")]
    flat = re.sub(r"\s+", " ", part)
    assert "no ready-made image to download" in flat
    assert "Use `git clone`, not a ZIP" in flat and "Download ZIP" not in flat
    assert flat.count("git clone https://github.com/berserkerjay/Zscaler-Made-Easy.git") >= 4, "short version for two shells, Step 2 on Windows and Mac"
    for piece in ("cd $HOME\\Documents","cd ~/Documents", "Git Credential Manager", "personal access token", "command line developer tools",
                  "update_container.ps1 -Force", "./update_container.sh --force", "bash update_container.sh --force", "docker logs zscaler-made-easy"):
        assert piece in flat, piece
    everyday = INSTALL[INSTALL.index("**Everyday use:**"):]
    assert "docker compose down -v" in everyday and "cannot be undone" in everyday
    readme = _read("README.md")
    quick = readme[readme.index("## Quick start (container)"):]
    assert "update_container.ps1 -Force" in quick and "./update_container.sh --force" in quick and "no published image" in quick
    for flag in ("--force)", ):
        assert flag in _read("update_container.sh")
    assert "[switch]$Force" in _read("update_container.ps1")


def test_the_container_installs_with_docker_commands_only():
    """"I should be able to use the docker command line and put the command in
    there to download the files from GH and install": Docker fetches the
    private repository itself with a token passed as a build secret, and a
    TLS-inspection certificate comes in through --build-context certs=."""
    part = INSTALL[INSTALL.index("### Install with Docker commands only"):INSTALL.index("### Build and run it by hand")]
    url = '"https://github.com/berserkerjay/Zscaler-Made-Easy.git#main"'
    assert part.count("--secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN") == 3 and part.count(url) == 3
    assert "Contents*: **Read-only**" in part.replace("\n", " ") and "Read-Host" in part and "read -rsp" in part
    assert "--build-context certs=$HOME\dlp-certs" in part and "--build-context certs=$HOME/dlp-certs" in part
    assert "docker rm -f zscaler-made-easy" in part and "docker logs zscaler-made-easy" in part
    df = _read("Dockerfile")
    assert "FROM scratch AS certs\nCOPY certs/ /" in df.replace("\r\n", "\n") and "COPY --from=certs / /tmp/extra-ca/" in df
    assert "COPY certs/ /tmp/extra-ca/" not in df, "the certificates must come through the overridable stage"


def test_the_container_can_be_built_and_run_by_hand_with_the_same_settings_as_compose():
    guide = open(os.path.join(ROOT, "INSTALL.md")).read()
    part = guide.split("### Build and run it by hand")[1].split("## First run")[0]
    for piece in ("docker build -t zscaler-made-easy:local .", "docker volume create zscaler-made-easy-data", "-v zscaler-made-easy-data:/data",
                  "-p 127.0.0.1:8001:8000", "DLP_CHECK_HOST_PORT=8001", "DLP_CHECK_HOST_BIND=127.0.0.1", "--read-only", "--cap-drop ALL",
                  "no-new-privileges:true", "--restart unless-stopped", "docker logs zscaler-made-easy"):
        assert piece in part, piece
    # The app judges exposure by DLP_CHECK_HOST_BIND in the container; the old override is gone.
    assert "ZSCALER_ALLOW_NONLOCAL_BIND" not in part
    compose = open(os.path.join(ROOT, "docker-compose.yml")).read()
    assert "${DLP_CHECK_HOST_BIND:-127.0.0.1}:${DLP_CHECK_HOST_PORT:-8001}:8000" in compose and "zscaler-made-easy-data:/data" in compose and "mem_limit: 1g" in compose


def test_the_container_can_run_beside_a_local_install_on_another_host_port():
    compose = open(os.path.join(ROOT, "docker-compose.yml")).read()
    assert '"${DLP_CHECK_HOST_BIND:-127.0.0.1}:${DLP_CHECK_HOST_PORT:-8001}:8000"' in compose, "loopback only, 8001 by default so it runs beside a local install on 8000"
    assert 'DLP_CHECK_HOST_PORT: "${DLP_CHECK_HOST_PORT:-8001}"' in compose, "the container prints the address with the host port"
    src = open(os.path.join(ROOT, "dlp_api_server.py")).read()
    assert 'os.environ.get("DLP_CHECK_HOST_PORT"' in src
    guide = open(os.path.join(ROOT, "INSTALL.md")).read()
    assert "DLP_CHECK_HOST_PORT=8002" in guide and "-p 127.0.0.1:8001:8000" in guide and "http://localhost:8001" in guide
