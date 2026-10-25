# Installing Zscaler Made Easy — a walkthrough for someone doing this for the first time

This page assumes you have never installed a developer tool before. It
does not assume you know what Python, Git, Docker or a terminal are; each
one is explained the first time it comes up. Pick **one** of the four
options: [Windows](#windows), [Mac](#mac), [Linux](#linux), or
[a container](#run-it-in-a-container-instead). If you are not sure, use
the one that matches the computer you are on now; the container option is
for a shared server rather than a laptop.

Budget about 15 minutes. Not sure what the app is for? Read
[docs/OVERVIEW.md](docs/OVERVIEW.md) first; it is a five-minute tour.

---

## Before you start — a checklist

Tick these off before you begin. Nothing here touches a Zscaler tenant:
installing only puts the program on your computer.

- [ ] **A computer to run it on.** Windows 10 or 11, macOS, or Linux, or a
      server with Docker. No administrator rights are needed on Windows
      (Python installs per user). On a Mac the python.org installer asks
      for your Mac password and needs an administrator account; without
      one, ask IT to install Python 3.11 or newer for you, or use the
      container option. On Linux you may need `sudo` to install Python.
- [ ] **Internet access** to `github.com` (the code), `python.org` (the
      Python installer) and `pypi.org` (the libraries the installer
      downloads); for the container also Docker Hub
      (`registry-1.docker.io`) and `deb.debian.org`. On a work laptop that
      goes through Zscaler or a proxy, read the
      [work laptop box](#work-laptop-tls-inspection-or-a-proxy) before you
      start; it changes one step.
- [ ] **Access to the GitHub repository** `github.com/berserkerjay/DLP-Check`.
      It is **private**: someone on the team must add your GitHub account
      first. If the page says "404" or asks you to sign in and then still
      refuses, that is the reason.
- [ ] **A decision: ZIP or Git.** See
      [Two ways to get the files](#two-ways-to-get-the-files) below. Git is
      one extra install and lets the app update itself; a ZIP is simpler
      but has to be re-downloaded to update.

You do **not** need Zscaler credentials to install. You need them later,
when you connect to a tenant, and the app accepts either of two sign-in
methods; ask the customer's Zscaler admin for one of these sets:

| Sign-in method | What to collect | Where the admin finds it |
|---|---|---|
| **OneAPI** (the usual one: the tenant has ZIdentity) | Zscaler cloud, Vanity domain, API client ID, API client secret | ZIdentity → Integration → API Clients → Add API Client. The secret is shown once, when the client is created. |
| **Classic ZIA API** (a tenant that has not enabled ZIdentity; ZIA only) | Zscaler cloud, Admin username, Admin password, API key | ZIA Administration → API Key Management for the key; a ZIA admin allowed to use the API for the username and password. |

`GETTING_STARTED.md` section 2 explains both in detail and what role the
API client needs. Keep going here; connecting comes after installing.

---

## Two ways to get the files

Either way works on every platform. Pick one and use the matching steps
below.

| | **Git** (recommended if you will keep using the app) | **ZIP** (simplest for a one-off) |
|---|---|---|
| What it needs | Installing Git once (free, two minutes) and signing in to GitHub once | Nothing extra |
| Updating later | Click **Update app** inside the app, or double-click `UPDATE_Zscaler_Assessment.bat` on Windows | Stop the app, download a fresh ZIP, replace the folder, run the installer again |
| Trying a fix before it is released (the **Branch** dropdown) | Works | Not available |

---

## Windows

**Step 1 — Install Python.**
Python is the language this program is written in; your computer needs
it installed once, the same way it needs a PDF reader to open a PDF.

1. Go to `python.org/downloads` and click the yellow **Download Python
   3.x.y** button (it offers the right version for Windows).
2. Open the downloaded file.
3. On the very first screen, **tick the box "Add python.exe to PATH"**
   near the bottom, before clicking Install. (Older installers call it
   "Add Python 3.x to PATH".) This is the step almost everyone forgets;
   skipping it makes every later step fail. **Untick** "Use admin
   privileges when installing py.exe" (it starts ticked; you do not need
   it).
4. Click **Install Now** and wait for "Setup was successful", then Close.

**Step 2 — Get the program's files onto your computer.**

*Option A: with Git (recommended).*

1. Go to `git-scm.com/download/win`, download **64-bit Git for Windows
   Setup**, open it and click **Next** through every screen with the
   defaults, with one exception on a work laptop: on the screen **Choose
   HTTPS transport backend**, pick **Use the native Windows Secure Channel
   library** (so Git trusts the same certificates Windows does; behind
   Zscaler or a proxy the default backend fails with "SSL certificate
   problem: unable to get local issuer certificate"). Then **Install** and
   **Finish**. If Git is already installed, the same thing is one command
   in a Command Prompt: `git config --global http.sslBackend schannel`.
2. Open a Command Prompt: press the Windows key, type `cmd`, press Enter.
   A black window with a blinking cursor opens; you type commands into it.
3. Type these two lines, pressing Enter after each:

   ```
   cd %USERPROFILE%\Documents
   git clone https://github.com/berserkerjay/DLP-Check.git
   ```

   A window titled **Connect to GitHub** opens the first time: choose
   **Sign in with your browser**, sign in to GitHub, and come back. The
   Command Prompt then prints a few lines and stops. You now have a folder
   `Documents\DLP-Check`.
4. Open that folder in File Explorer (type `explorer Zscaler Made Easy` in the same
   window and press Enter).

*Option B: a ZIP.*

1. In your browser, go to `github.com/berserkerjay/DLP-Check` and sign in
   if it asks.
2. Click the green **Code** button, then **Download ZIP**.
3. Find the downloaded ZIP (usually in Downloads), right-click it, choose
   **Extract All…**, then **Extract**. Windows creates a folder named
   `DLP-Check-main`; open it, and open the `DLP-Check-main` folder
   **inside** it (the ZIP has a folder within a folder).
4. Move that inner folder somewhere you will remember, for example
   `Documents`, so its path is `Documents\DLP-Check-main`.

Either way you should now see a file called `INSTALL_Zscaler_Assessment`
(Windows may hide the `.bat` ending; its type shows as "Windows Batch
File").

**On a work laptop behind Zscaler or a proxy: create `local_settings.bat`
now**, before Step 3, as the [work laptop box](#work-laptop-tls-inspection-or-a-proxy)
describes. The installer reads it.

**Step 3 — Run the installer.**

1. Double-click `INSTALL_Zscaler_Assessment.bat`. If Windows asks "Are you
   sure you want to run this software?", click **Run**; if it shows
   "Windows protected your PC", click **More info**, then **Run anyway**.
   Both happen because the file came from the internet.
2. A black window opens and prints "Found Python: …" and then
   "[1/2] Installing Python dependencies...". It can sit with no new
   output for one to three minutes; that is normal, it is downloading.
3. **Success** looks like this: it prints "Installation complete!" and the
   window closes by itself after five seconds. A shortcut named
   **Zscaler Assessment** is now on your desktop and in the Start menu.
4. **Failure** looks like one of two things, and either way the window
   stays open with "Press any key to continue": a line starting
   **ERROR:** (Python missing, or an old Python found first; see
   [If something goes wrong](#if-something-goes-wrong)), or the banner
   **INSTALL FAILED** (the dependency download; the usual cause is no
   access to `pypi.org`, see the work laptop box). Fix the cause and
   double-click the installer again; it is safe to rerun.

The installer creates a private `.venv` in the app folder on Windows, Mac
and Linux. It installs the hash-pinned dependencies and the `dlp-check`,
`dlp-check-assess` and `dlp-check-evaluate` commands there. It does not
change your system Python packages. Rerunning the installer repairs an
incomplete environment and keeps your existing local settings. If that
incomplete environment is activated, run `deactivate` first; the installer
refuses to delete the interpreter it is currently using. Windows
launch and update scripts prefer this private interpreter; an older
installation can migrate by rerunning the installer.

**Step 4 — Open it.**
Double-click the **Zscaler Assessment** desktop shortcut. Within about
ten seconds your browser opens to the app. **Nothing else appears on
screen**: the program runs in the background with no window, and what it
prints goes into a file named `server.log` in the app folder. To stop it,
double-click `STOP_Zscaler_Assessment.bat` in the app folder; closing the
browser does not stop it.

No shortcut on the desktop (some company laptops do not let the installer
make one; it says so)? Double-click `START_Zscaler_Assessment` (a
"Windows Batch File") in the app folder instead; it starts the same way.

If nothing happens when you double-click the shortcut: in the app folder,
click File Explorer's address bar, type `cmd`, press Enter, then type
`START_Zscaler_Assessment.bat --console` and press Enter. The window that
stays open shows the reason; if the app does start this way, the window
prints a `UI token:` line and the browser asks for that token (copy it
from the window, or open the `Open http://localhost:8000/?token=…`
address it prints). Leave that window open while you use the app;
closing it stops the app. `launcher.log` in the app folder records why a
silent start failed.

That's it. See **[How you know it worked](#how-you-know-it-worked)** below.

---

## Mac

**Step 1 — Install Python 3.11 or newer.**
Open **Terminal** (press `Cmd + Space`, type `Terminal`, press Enter; a
plain text window opens where you type commands). Type this and press
Enter:

```bash
python3 --version
```

- If a window pops up saying "The python3 command requires the command
  line developer tools. Would you like to install the tools now?", click
  **Not Now** (that route installs an old Python).
- If it prints `Python 3.11`, `3.12`, `3.13` or newer, skip to Step 2.
  Note that **3.9 and 3.10 are older** than 3.11 even though 9 and 10
  look bigger.
- Otherwise go to `python.org/downloads`, click the yellow **Download
  Python 3.x.y** button, open the downloaded `.pkg`, and click Continue,
  Agree and Install through the installer. It asks for your Mac password
  (an administrator account is needed; see the checklist).
- **Then quit Terminal (`Cmd + Q`) and open it again.** The Terminal
  window that was already open cannot see the new Python. Run
  `python3 --version` once more; it must now print 3.11 or newer.

**Step 2 — Get the program's files onto your computer.**

*Option A: with Git (recommended).* In Terminal, type these lines,
pressing Enter after each:

```bash
cd ~/Documents
git clone https://github.com/berserkerjay/DLP-Check.git
```

The first time, macOS asks to install the "command line developer tools";
click **Install** and wait (a few minutes), then run the `git clone` line
again. GitHub asks you to sign in: a browser window or a username and
password prompt. (For the password, GitHub wants a *personal access
token*, not your account password; GitHub's own help page "Creating a
personal access token" walks you through it.) You now have a folder
`Documents/DLP-Check`.

*Option B: a ZIP.* In your browser, sign in to GitHub, go to
`github.com/berserkerjay/DLP-Check`, click the green **Code** button, then
**Download ZIP**. Safari extracts it into Downloads as a folder named
`DLP-Check-main`; double-click the ZIP if it did not. Move that folder
into Documents.

**Step 3 — Install and start, from Terminal.**
You need to move *into* the folder before running anything. `cd` means
"change directory". Type `cd `, then a space, then drag the folder from
Finder straight into the Terminal window (this fills in the path), then
press Enter. If macOS asks whether Terminal may access your Documents
folder, click **OK**. Then run:

```bash
./install.sh        # sets everything up; takes a minute or two
./start.sh          # starts the app and opens your browser
```

If Terminal says `Permission denied` on `./install.sh`, run
`chmod +x install.sh start.sh stop.sh` once and try again.

**Success looks like this:** Terminal prints

```
  Zscaler Made Easy
  UI token: …
  (also in …/ui_token.txt; the launcher opens the browser with it, anyone else gets 401)
  Open http://localhost:8000/?token=… in your browser
```

and then appears to stop, with no new prompt. That is normal: the app is
running in that window. (Two notices above those lines that say
`DeprecationWarning: on_event is deprecated` are harmless; ignore them.)
Your browser opens by itself within a few seconds; if it does not, copy
the whole `http://localhost:8000/?token=…` line into Safari's address bar.

Leave that Terminal window open while you use the app. To stop it, press
`Ctrl + C` in that window (or close it; when macOS asks "Do you want to
terminate running processes?", click **Terminate**). `./stop.sh` is only
for a server started with `./start.sh --background`, or one that restarted
itself after **Update app** (see the table below).

That's it. See **[How you know it worked](#how-you-know-it-worked)** below.

---

## Linux

**Step 1 — Install Python 3.11 or newer, plus the two extras Linux
leaves out.** Open a terminal (look for "Terminal" or "Console" in your
applications menu) and run the line for your distribution **even if
Python is already installed**: Ubuntu and Debian ship Python without
`python3-venv` (which `install.sh` needs) and without `git`.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git

# Fedora / RHEL
sudo dnf install -y python3 python3-pip git
```

Then check the version:

```bash
python3 --version
```

It must print 3.11 or newer (3.12 on Ubuntu 24.04, for example). If it
is older, your distribution is too old for the packaged Python; install a
current one from `python.org` or a newer distribution release.

**Step 2 — Get the code.** With `git` installed (Step 1 of this section
did that), this is the easiest way, and it lets the app update itself
later. GitHub
refuses account passwords over git, so first make a **personal access
token** once: on `github.com`, click your avatar → **Settings** →
**Developer settings** → **Personal access tokens** → **Tokens (classic)**
→ **Generate new token**, tick **repo**, generate, and copy the token
(it is shown once). Then:

```bash
git config --global credential.helper store   # remember the sign-in, so updates work later
cd ~
git clone https://github.com/berserkerjay/DLP-Check.git
cd Zscaler Made Easy
```

When `git clone` asks `Username for 'https://github.com':`, type your
GitHub username; when it asks `Password for …:`, paste the **token**, not
your password (nothing is shown while you paste; press Enter). If you
would rather not use git, download the ZIP from the repository's **Code →
Download ZIP** button, extract it (`unzip DLP-Check-main.zip`), and `cd`
into the extracted folder.

**Step 3 — Install and start.**

```bash
./install.sh        # sets everything up; takes a minute or two
./start.sh          # starts the app and prints the address to open
```

`start.sh` prints `UI token: …` and `Open http://localhost:8000/?token=…
in your browser`; open that address if the browser does not open by
itself. Leave the terminal open while you use the app; `Ctrl + C` stops
it.

To run it without holding a terminal, use `./start.sh --background`: it
starts the server detached, writes its output to `server.log` and its
process id to `server.pid`, prints the address to open, and keeps the UI
token in `ui_token.txt` in the same folder. `./stop.sh` stops a server
started that way, or one that restarted itself after **Update app**; a
server running in a terminal window is stopped with `Ctrl + C` there.

That's it. See **[How you know it worked](#how-you-know-it-worked)** below.

---

## Run it in a container instead

A **container** is a sealed copy of the app with everything it needs, so
it does not depend on what is already on the computer (no separate Python
install, nothing that can conflict with other software). Pick this for a
shared server, or if you would rather not install Python on your own
machine. It works the same way on Windows, Mac and Linux.

There is no ready-made image to download: Docker builds the image on your
computer from the code, so a fresh install is *install Docker, get the
code with git, build it*. The steps below walk through each one. If you
have done this before, here is the short version (after Step 1, in the
folder you want the app in):

```powershell
# Windows (PowerShell)
git clone https://github.com/berserkerjay/DLP-Check.git
cd Zscaler Made Easy
powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force
docker logs dlp-check
```

```bash
# Mac (Terminal) or Linux
git clone https://github.com/berserkerjay/DLP-Check.git
cd Zscaler Made Easy
./update_container.sh --force
docker logs dlp-check
```

Then open the `http://localhost:8001/?token=…` address that
`docker logs` prints.

No git on the computer? Docker can fetch the code from GitHub itself:
see [Install with Docker commands only](#install-with-docker-commands-only-no-git-nothing-to-download).

**Step 1 — Install Docker.**
Docker is the program that runs containers. Follow the part for your
computer, then do the check at the end of it; do not go on to Step 2
until the check passes. Allow 15–30 minutes, most of it downloads and a
restart.

> **Licence note for companies.** Docker Desktop (Windows and Mac) is
> free for personal use, education and businesses with fewer than 250
> employees *and* under US$10 million in annual revenue. A larger company
> needs a paid Docker subscription for it, so check with IT before
> installing it on a work computer. Docker Engine on Linux (the Linux
> part below) has no such licence requirement.

*Windows 10 (22H2 or later) or Windows 11, 64-bit.* You need
administrator rights on the computer for this part; if you do not have
them, ask IT to do steps 1 to 3 for you.

1. **Turn on WSL 2** (the Windows feature Docker runs on). Click Start,
   type `PowerShell`, right-click **Windows PowerShell**, choose **Run as
   administrator**, click **Yes**. In the blue window type:

   ```powershell
   wsl --install --no-distribution
   ```

   and press Enter. When it finishes, restart the computer. (If it says
   WSL is already installed, run `wsl --update` instead; no restart is
   needed then.)
2. **Download Docker Desktop.** Go to
   `docs.docker.com/desktop/setup/install/windows-install/` and click
   **Docker Desktop for Windows - x86_64** (or **- Arm (Beta)** only on an
   ARM laptop, such as a Snapdragon Surface; Settings → System → About →
   *System type* tells you which).
3. **Install it.** Double-click `Docker Desktop Installer.exe` (in
   Downloads), click **Yes** when Windows asks. On the *Configuration*
   screen leave **Use WSL 2 instead of Hyper-V (recommended)** ticked and
   click **OK**. When it says *Installation succeeded*, click **Close and
   restart** (or **Close and log out**, then sign back in).
4. **Start it once.** Click Start, type `Docker Desktop`, open it. Accept
   the *Docker Subscription Service Agreement*. When it offers to sign
   in, click **Continue without signing in** (or **Skip**); skip the
   survey too. Wait until the bottom-left corner of the Docker Desktop
   window says **Engine running** in green (the first start takes a
   minute or two).
5. **If it says "You are not allowed to use Docker, you must be in the
   docker-users group":** the account that installed Docker is in that
   group, yours is not. In an administrator PowerShell (as in step 1) run
   `net localgroup docker-users "%USERNAME%" /add` with your Windows user
   name in place of `%USERNAME%`, then sign out of Windows and back in.

*Mac (macOS 13 or later; Docker supports the current macOS and the two
before it).* You need your Mac's administrator password.

1. **Find out which Mac you have:** Apple menu → **About This Mac**. If
   it shows **Chip: Apple M1/M2/M3/M4…** you have Apple silicon; if it
   shows **Processor: … Intel …** you have an Intel Mac.
2. **Download Docker Desktop.** Go to
   `docs.docker.com/desktop/setup/install/mac-install/` and click
   **Docker Desktop for Mac with Apple silicon** or **… with Intel chip**
   to match.
3. **Install it.** Open `Docker.dmg` from Downloads and drag the Docker
   whale onto the **Applications** folder in the window that opens.
4. **Start it once.** Open **Applications** and double-click **Docker**.
   When macOS asks "Docker is an app downloaded from the internet. Are you
   sure you want to open it?", click **Open**. Accept the agreement,
   choose **Use recommended settings**, click **Finish** and type your Mac
   password. When it offers to sign in, click **Continue without signing
   in** (or **Skip**). Wait until the whale icon in the menu bar at the top
   of the screen stops animating and Docker Desktop shows **Engine
   running**.

*Checking Docker Desktop (Windows or Mac).* Open a **new** terminal
(PowerShell on Windows, Terminal on Mac; a window opened before the
install cannot see Docker) and run these three commands one at a time:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

The first prints `Docker version …`; the second must print **2.24 or
newer** (older Compose does not understand this app's
`docker-compose.yml`; *Check for updates* in Docker Desktop's menu fixes
that); the third downloads a tiny test image and prints **Hello from
Docker!**. Docker Desktop must be running whenever you use the app: it
starts with the computer unless you turn that off in its settings.

*Linux (Ubuntu or Debian, including a server with no desktop).* Install
Docker Engine from Docker's own package repository; the `docker.io`
package Ubuntu ships is often too old for this app. Paste these commands
one block at a time into a terminal (they ask for your `sudo` password):

```bash
# 1. Tools and Docker's signing key
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# 2. Docker's repository for this Ubuntu release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 3. Docker Engine, Compose and git
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git

# 4. Start Docker now and at every boot, and let your user run it without sudo
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

On **Debian**, change both `linux/ubuntu` to `linux/debian` in steps 1
and 2. On **Fedora or RHEL**, follow the page for your distribution at
`docs.docker.com/engine/install/` instead, then do step 4 above.

Then **log out and back in** (on a server: close the SSH session and
connect again), so the `docker` group applies. *Check:* run

```bash
docker ps
docker compose version
docker run --rm hello-world
```

`docker ps` must print a (possibly empty) table headed `CONTAINER ID`,
not "permission denied while trying to connect to the Docker daemon
socket" (that means the log-out has not happened yet);
`docker compose version` must print **2.24 or newer**; the last command
prints **Hello from Docker!**.

*On a work network with TLS inspection (Zscaler or another proxy):* the
Docker download and `hello-world` usually work, because Docker Desktop
trusts the certificates Windows and macOS trust. The app's own build
(Step 3) downloads Python libraries from `pypi.org` inside the build,
which does not trust your company's inspection certificate, and stops
with `CERTIFICATE_VERIFY_FAILED` ("unable to get local issuer
certificate") at step `[6/8]`. Fix it once, before Step 3: put your
company's root certificate in the app's `certs` folder, and the build and
the running app both trust it.

- **Windows** (PowerShell, in the app folder), for Zscaler:

  ```powershell
  $c = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Zscaler Root CA*" } | Select-Object -First 1
  if (-not $c) { "Zscaler Root CA not found: ask IT for the root certificate as a Base-64 .crt file and save it in the certs folder" } else { "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" | Set-Content -Encoding ascii -NoNewline certs\zscaler-root.crt; "Saved certs\zscaler-root.crt" }
  ```

- **Mac** (Terminal, in the app folder):
  `security find-certificate -c "Zscaler Root CA" -p > certs/zscaler-root.crt`
- **Linux:** copy the root certificate IT gave you (Base-64 / PEM, the
  text that starts `-----BEGIN CERTIFICATE-----`) into `certs/`.
- **Another inspection product:** ask IT for its root certificate as a
  Base-64 file and save it in `certs/` with the ending `.crt`.

Then build again (`docker compose up -d --build`). The build log says
`extra root certificates added: 1`. The certificate file stays on your
machine: files in `certs/` are git-ignored. Instead of a certificate, IT
can also exempt `pypi.org` and `files.pythonhosted.org` from inspection.
For a proxy, set it in Docker Desktop under **Settings → Resources →
Proxies** (Linux: `docs.docker.com/engine/daemon/proxy/`).

**Step 2 — Get the code with git.** Use `git clone`, not a ZIP: the
update script (Step 3 and every update after it) only works in a git
clone. The repository is private, so git asks you to sign in to GitHub
the first time.

- **Windows:** if `git --version` in PowerShell says "not recognized",
  install Git for Windows as in [Windows](#windows) Step 2 (`git-scm.com`),
  then open a **new** PowerShell window. Then:

  ```powershell
  cd $HOME\Documents
  git clone https://github.com/berserkerjay/DLP-Check.git
  cd Zscaler Made Easy
  ```

  A browser window opens to sign in to GitHub (Git Credential Manager);
  sign in with the account that has access, and git remembers it, so
  later updates do not ask again.

- **Mac:** in Terminal:

  ```bash
  cd ~/Documents
  git clone https://github.com/berserkerjay/DLP-Check.git
  cd Zscaler Made Easy
  ```

  If macOS offers to install the "command line developer tools", click
  **Install**, wait, and run the `git clone` line again. When git asks
  for a password, paste a GitHub **personal access token**, not your
  account password (how to make one: [Linux](#linux) Step 2). The macOS
  keychain remembers it.

- **Linux:** `git` came with Docker in Step 1. Make a personal access
  token and clone exactly as in [Linux](#linux) Step 2 (the
  `credential.helper store` line keeps the sign-in for later updates).

**Step 3 — Build and run.** In the same terminal, still in the
`Zscaler Made Easy` folder, run the update script with *force*. On a fresh
install it builds the image, stamps it with the git commit it was built
from (so the app can tell you when GitHub has a newer one) and starts
the container in the background:

```powershell
powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force   # Windows
```

```bash
./update_container.sh --force                                            # Mac, Linux
```

(On Mac or Linux, if it says `Permission denied`, run
`bash update_container.sh --force` instead.) The first build takes a few
minutes while it downloads and builds everything. If it stops with
`CERTIFICATE_VERIFY_FAILED`, you are behind TLS inspection: see the note
at the end of Step 1. When the prompt comes back, run:

```bash
docker logs dlp-check
```

The last lines it prints are:

```
  UI token: …
  (also in /data/ui_token.txt; the launcher opens the browser with it, anyone else gets 401)
  Open http://localhost:8001/?token=… in your browser
  (inside the container the server listens on every address; docker-compose.yml publishes it on 127.0.0.1:8001 of this machine only)
```

Open that address in your browser on the same machine. The app keeps
running in the background, also after a restart of the computer, until
you stop it; you can close the terminal.

**Finding the UI token again:** run `docker logs dlp-check`, or
`docker compose exec dlp-check cat /data/ui_token.txt` in the app folder.

**On a shared server (no desktop on it):** Steps 2 and 3 are the same
over SSH (the Linux commands). The container starts again by itself
after a reboot until you run `docker compose down`. It listens on the server's own `127.0.0.1:8001`
only, on purpose. To use it from your PC as one person, open a tunnel
from your PC and then browse to `http://localhost:8001/?token=…` on your
PC:

```bash
ssh -L 8001:127.0.0.1:8001 you@server
```

For a team, keep the `127.0.0.1:` at the start of the `ports:` line in
`docker-compose.yml` exactly as it is and put a reverse proxy with
sign-in in front (`SECURITY.md` says how). To publish it beyond the
server's loopback instead, set `DLP_CHECK_HOST_BIND` in `.env` (the
`ports:` line reads it): the app then refuses to start unless SSO is
configured, and says so in `docker compose logs`. SSO is off by default;
turn it on with ZSCALER_SSO_ENABLED=1 plus the ZSCALER_SSO_* settings
(`SECURITY.md`). Do not edit the `127.0.0.1:` out of the `ports:` line by
hand: the app only knows where it is published from `DLP_CHECK_HOST_BIND`.

**Everyday use:**
- Stop it: `docker compose down` in the app folder.
- Start it again later: `docker compose up -d` in the app folder (no
  `--build` needed unless the code changed).
- Start over from scratch: `docker compose down -v` deletes the
  container **and everything it saved** (tenant profiles, deployment
  records, audit log; this cannot be undone), then run Step 3 again.
- Update it: from the app folder run the update script. It pulls the
  latest code from GitHub and rebuilds the container only when there is
  something new; saved data stays, and the app restarts with a new UI
  token (`docker logs dlp-check`). The folder must be a `git clone`.

  ```
  powershell -ExecutionPolicy Bypass -File .\update_container.ps1     # Windows
  ./update_container.sh                                                # Mac, Linux
  ```

- **Choose the branch it updates from:** `main` (what customers run),
  `qa` or `dev` (changes before they are promoted: dev → qa → main).
  Add the branch once; the folder stays on it, so later runs and the
  daily schedule keep updating from it:

  ```
  powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Branch qa   # Windows
  ./update_container.sh --branch qa                                     # Mac, Linux
  ```

  In the app, Home > Update app shows these commands for the branch
  picked in its Branch list.
- **Automatic updates:** run the same script once with `-Schedule`
  (Windows) or `--schedule` (Mac, Linux). The computer then runs it every
  day at 03:17 (Windows also runs it at the next start if it was off).
  `-Unschedule` / `--unschedule` stops it. What it did is in
  `update_container.log` in the app folder. It stops, without changing
  anything, if a file in the folder was edited by hand.
- **Update notice in the app:** a minute after the page opens, and every
  6 hours while it stays open, the app checks GitHub and shows a notice at
  the top when a newer build is out (both for the container and for a
  local install). Because the repository is private, the container needs
  a read-only GitHub token for that check: create a fine-grained token on
  GitHub (*Settings → Developer settings → Fine-grained tokens*, only this
  repository, *Contents: read*), put `DLP_CHECK_GITHUB_TOKEN=<the token>`
  in the `.env` file next to `docker-compose.yml`, and run
  `docker compose up -d`. Without it everything else works; only the
  notice stays silent.

What the app saves (tenant profiles, deployment records, the audit log,
uploaded packs, digests, proposals, the guidance state and the token
file) lives outside the container in a Docker-managed storage area
called `dlpcheck-data`, so it survives rebuilds and updates. To
deploy from the container, click **Enable write mode** in Deploy policy
packs and type the confirmation phrase, as on a laptop: the switch is
offered because the container is published on this machine's loopback
only (`DLP_CHECK_HOST_BIND`, `127.0.0.1` unless you change it). If you
publish it beyond loopback the switch is refused; then put
`ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND` in a `.env` file next to
`docker-compose.yml` and run `docker compose up -d` again.

---

## How you know it worked

Your browser shows a dark page headed **Zscaler Made Easy**,
with a row of tool buttons (Start, Find the gaps, Close the gaps,
Reference, Troubleshoot) and, below, **Connect to the tenant** with a
form for the sign-in details. The **Start here** card names the folder
the app runs from and, for a Git install, the build (the git commit).

If instead the page asks you for a **UI token**, that is expected the
first time you open the address by hand; the next section says where the
token is. If the browser says it cannot connect, the app has not started:
see [If something goes wrong](#if-something-goes-wrong).

Nothing is connected to Zscaler yet. The app only reaches a tenant once
you type in credentials and click **Authenticate**.

**Ports:** the container is on `http://localhost:8001`, so it runs side
by side with a local install, which uses 8000. Each has its own UI token
and its own saved data. For another port, put `DLP_CHECK_HOST_PORT=8002`
(or any free port) in a file named `.env` in the app folder and run
`docker compose up -d` again; `docker logs dlp-check` prints the address.

### Install with Docker commands only (no git, nothing to download)

Docker can fetch the code from GitHub itself and build it, so you need
nothing but Docker (Step 1) and a terminal. It is the same image as
above, run with the same settings as `docker-compose.yml`.

**1. A GitHub token for Docker.** The repository is private, so Docker
needs a read-only token to fetch it. On `github.com`: your avatar →
**Settings** → **Developer settings** → **Personal access tokens** →
**Fine-grained tokens** → **Generate new token**; *Repository access*:
**Only select repositories** → `Zscaler Made Easy`; *Permissions* → *Contents*:
**Read-only**; generate and copy it. Hand it to Docker for this terminal
window only (it is not saved anywhere):

```powershell
$env:GIT_AUTH_TOKEN = Read-Host "GitHub token"                 # Windows (PowerShell): paste, Enter
```

```bash
read -rsp "GitHub token: " GIT_AUTH_TOKEN; export GIT_AUTH_TOKEN; echo   # Mac, Linux: paste, Enter (nothing shows)
```

**2. Build it straight from GitHub.** The same line on every system
(`#main` is the branch; `#qa` or `#dev` for those):

```
docker build --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN --build-arg DLP_CHECK_BUILD_BRANCH=main -t dlp-check:local "https://github.com/berserkerjay/DLP-Check.git#main"
```

*Behind TLS inspection (Zscaler or another proxy)* the build stops with
`CERTIFICATE_VERIFY_FAILED`. Save the root certificate in a folder of its
own and hand that folder to the build with `--build-context certs=…`:

```powershell
# Windows (PowerShell), for Zscaler
New-Item -ItemType Directory -Force $HOME\dlp-certs | Out-Null
$c = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Zscaler Root CA*" } | Select-Object -First 1
"-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n" | Set-Content -Encoding ascii -NoNewline $HOME\dlp-certs\zscaler-root.crt
docker build --build-context certs=$HOME\dlp-certs --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN --build-arg DLP_CHECK_BUILD_BRANCH=main -t dlp-check:local "https://github.com/berserkerjay/DLP-Check.git#main"
```

```bash
# Mac, for Zscaler (Linux: copy the .crt file IT gave you into ~/dlp-certs instead)
mkdir -p ~/dlp-certs && security find-certificate -c "Zscaler Root CA" -p > ~/dlp-certs/zscaler-root.crt
docker build --build-context certs=$HOME/dlp-certs --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN --build-arg DLP_CHECK_BUILD_BRANCH=main -t dlp-check:local "https://github.com/berserkerjay/DLP-Check.git#main"
```

The build log then says `extra root certificates added: 1`.

**3. Create the storage volume and run it:** steps 2 and 3 of
[Build and run it by hand](#build-and-run-it-by-hand-without-docker-compose)
below, exactly as written (`docker volume create dlpcheck-data`, then the
`docker run` line for your system). Then `docker logs dlp-check` prints
the `http://localhost:8001/?token=…` address to open.

**Update it:** in a new terminal, step 1 (the token) and step 2 (the
build) again, which fetch the latest code, then replace the container;
the volume keeps your data:

```
docker rm -f dlp-check
```

and run the `docker run` line again. The *update available* notice in
the app stays silent for an install made this way, because the build does
not know which commit it fetched; run the update whenever you want the
latest.

### Build and run it by hand (without Docker Compose)

Use this when the server has Docker but not the Compose plugin, or when
your team manages containers with plain `docker` commands. It builds the
same image and runs it with the same settings as `docker-compose.yml`.
Run every command from the app folder (the one that holds `Dockerfile`).

**1. Build the image** from the `Dockerfile`:

```bash
docker build -t dlp-check:local .
```

**2. Create the storage volume** once. Everything the app saves lives in
it, mounted at `/data` inside the container:

```bash
docker volume create dlpcheck-data
```

**3. Run the container.** Mac and Linux:

```bash
docker run -d --name dlp-check \
  -p 127.0.0.1:8001:8000 \
  -v dlpcheck-data:/data \
  -e DLP_CHECK_HOST_PORT=8001   -e DLP_CHECK_HOST_BIND=127.0.0.1 \
  -e DLP_CHECK_USER_PACKS=/data/user_packs \
  --read-only --tmpfs /tmp:size=256m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 256 --memory 1g \
  --restart unless-stopped \
  dlp-check:local
```

Windows (PowerShell or Command Prompt), the same command on one line:

```
docker run -d --name dlp-check -p 127.0.0.1:8001:8000 -v dlpcheck-data:/data -e DLP_CHECK_HOST_PORT=8001 -e DLP_CHECK_HOST_BIND=127.0.0.1 -e DLP_CHECK_USER_PACKS=/data/user_packs --read-only --tmpfs /tmp:size=256m --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 --memory 1g --restart unless-stopped dlp-check:local
```

What each part does:

| Part | Why |
|---|---|
| `-p 127.0.0.1:8001:8000` | Publishes the app on port 8001 of this machine only (the local install uses 8000). Keep the `127.0.0.1:`; see the warning above about `0.0.0.0`. |
| `-v dlpcheck-data:/data` | Mounts the storage volume, so profiles, deployment records, the audit log, uploaded packs and the token survive rebuilds. |
| `-e DLP_CHECK_HOST_BIND=127.0.0.1` | Tells the app it is published on this machine's loopback only (match the `-p 127.0.0.1:` part), so **Enable write mode** is offered in the browser. Leave it out and the switch is refused. Set it to anything other than loopback and the app refuses to start unless SSO is configured. |
| `--read-only --tmpfs /tmp` | The app folder stays read-only; only `/data` and a small `/tmp` are writable. |
| `--cap-drop ALL --security-opt no-new-privileges:true` | The container gets no extra Linux privileges. |
| `--restart unless-stopped` | Starts again after a reboot until you stop it. |

Credentials or other settings from a file: add `--env-file .env` before
`dlp-check:local`. To allow deploys, click **Enable write mode** in the
app, or put `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND` in that `.env` file.

**4. Open it.** Read the UI token and open the address it prints:

```bash
docker logs dlp-check
```

**Checks and everyday use:**

```bash
docker ps --filter name=dlp-check          # STATUS should say "healthy" after about 30 seconds
docker exec dlp-check cat /data/ui_token.txt   # the UI token again
docker stop dlp-check                      # stop it
docker start dlp-check                     # start it again
```

**Update it** after getting the latest code: build again, then replace
the container. The volume keeps your data.

```bash
docker build -t dlp-check:local .
docker rm -f dlp-check
```

Then run the step 3 command again.

**Remove it completely**, data included: `docker rm -f dlp-check`, then
`docker volume rm dlpcheck-data`, then `docker image rm dlp-check:local`.

---

## First run: the UI token

The app mints a **UI token** every time it starts: a short string of
letters and numbers that keeps anyone else on the same computer from
opening the app. Normally you never see it, because the shortcut or
`start.sh` opens the browser with the token already in the address. If a
page ever asks for it, here is where it is:

- **Windows:** the file `ui_token` (a text file, full name `ui_token.txt`)
  in the app folder. Open it with Notepad and copy the whole line. The
  server has no window of its own on Windows; what it prints goes into
  `server.log` in the same folder.
- **Mac / Linux:** the line `UI token: …` in the terminal window that runs
  the app, and the same `ui_token.txt` file in the app folder.
- **Container:** `docker logs dlp-check`, or
  `docker compose exec dlp-check cat /data/ui_token.txt`.

Paste it into the page when asked. Your browser keeps it for 12 hours, or
until the app restarts: a restart mints a new token, so after one, open
the app from the shortcut (or the new link the terminal prints) again. If
the page says "That UI token is not valid for this server", that is what
happened.

The token is this machine's own sign-in, not your Zscaler credentials and
not multi-factor authentication: treat it like a password. On your own
computer the app refuses to start on a network address unless sign-in
through an identity provider is set up (`SECURITY.md`); a token alone is
not considered enough once the app is reachable beyond your machine. The
container makes the same check on the host address it is published on
(`DLP_CHECK_HOST_BIND`, `127.0.0.1` by default), so as shipped it starts
without SSO.

SSO is off by default; turn it on with ZSCALER_SSO_ENABLED=1 plus the
ZSCALER_SSO_* settings. With SSO on there is no UI token: each person
signs in at your identity provider, the page shows **Signed in as … ·
Sign out**, and the token is neither printed nor written to
`ui_token.txt` (scripts that sent it must sign in instead).

---

## Connecting to a Zscaler tenant

Once you are in, **Connect to the tenant** has a **Sign-in method**
choice and the fields for it:

- **OneAPI** (the default): Zscaler cloud, Vanity domain, API client ID,
  API client secret.
- **Classic ZIA API**: Zscaler cloud, Admin username, Admin password, API
  key. For a tenant that has not enabled ZIdentity; it covers ZIA only (no
  ZPA, Client Connector or ZDX checks).

Type the values, click **Authenticate**, and read the line it answers
with ("Signed in to <tenant>", or "Could not connect:" with a plain
reason). Authenticate only signs in; it reads nothing from the tenant. `GETTING_STARTED.md` section 2 says what to ask the
customer's admin for and section 3 walks through the first connection;
that is the next document to read.

---

## Work laptop: TLS inspection or a proxy

Many work laptops sit behind Zscaler Client Connector or a corporate proxy
that inspects secure traffic. Then the installer cannot download from
`pypi.org` ("SSL: CERTIFICATE_VERIFY_FAILED" in the failure lines) and
**Authenticate** later says "intercepted by TLS inspection". The fix is to
tell the app where your organisation's root certificate is. You need it
in a file; your IT team may hand you one, or export it yourself:

- **Windows:** press `Win + R`, type `certmgr.msc`, Enter. Open **Trusted
  Root Certification Authorities → Certificates**, find the one named for
  your inspecting product (for example "Zscaler Root CA"), right-click it,
  **All Tasks → Export…**, choose **Base-64 encoded X.509 (.CER)**, and
  save it as `C:\certs\zscaler-root-ca.cer` (create the folder).
- **Mac:** open **Keychain Access**, choose the **System** keychain and
  **Certificates**, find the root certificate, then **File → Export
  Items…** and save it in `.pem` format, for example to
  `~/certs/zscaler-root-ca.pem`.

Then put its path in the settings file the launchers read (it is
git-ignored, so updates never overwrite it):

- **Windows** — `local_settings.bat`. First make file endings visible:
  in File Explorer, **View → Show → File name extensions**. In the app
  folder, right-click `local_settings.bat.example`, **Copy**, then
  **Paste**, and rename the copy to `local_settings.bat`. Right-click it
  and choose **Edit** (it opens in Notepad). Find the line
  `REM set REQUESTS_CA_BUNDLE=C:\certs\zscaler-root-ca.pem`, delete the
  `REM ` at the start and change the path to your file, for example
  `set REQUESTS_CA_BUNDLE=C:\certs\zscaler-root-ca.cer`. For a proxy,
  do the same to the `HTTPS_PROXY` line. Save.
- **Mac / Linux** — `local_settings.env`. `./install.sh` creates it from
  the example; to have it before installing, run
  `cp local_settings.env.example local_settings.env` first. Open it
  (`open -e local_settings.env` on a Mac, or `nano local_settings.env`),
  remove the `#` in front of `REQUESTS_CA_BUNDLE=` and put your file's
  path after the `=`; likewise `HTTPS_PROXY=` for a proxy. Save.

Do this **before** running the installer if the install fails, and
restart the app after any change (STOP then the shortcut on Windows;
`Ctrl + C` then `./start.sh` on Mac and Linux). The **Start here** card
shows the CA bundle in use, so you can check it took.

---

## Starting, stopping, updating and removing it later

| I want to… | Windows | Mac / Linux |
|---|---|---|
| Open the app | Double-click the **Zscaler Assessment** desktop shortcut | `./start.sh` in the app folder |
| Close it | Double-click `STOP_Zscaler_Assessment.bat`. Closing the browser does not stop it; it keeps running in the background until you do | `Ctrl + C` in the terminal window running it; `./stop.sh` if you started it with `./start.sh --background` or it restarted itself after **Update app** |
| Get the latest version (Git install) | Click **Update app** on the Start here card (it reads **Update app now** when a newer build was found), or double-click `UPDATE_Zscaler_Assessment.bat` | Click **Update app** inside the app. Afterwards the Terminal window returns to a prompt and the app keeps running in the background (its output now goes to `server.log`); stop it with `./stop.sh`, not `Ctrl + C`. A second browser tab may open; close either. Or stop it, run `git pull`, then `./install.sh` and `./start.sh` |
| Get the latest version (ZIP install) | Stop the app, download a fresh ZIP, replace the folder (keep your `local_settings.bat`), double-click the installer again | Stop the app, download a fresh ZIP, replace the folder (keep `local_settings.env`), run `./install.sh` and `./start.sh` |
| Try a fix before it is released (Git install) | Pick **QA (qa)** or **Development (dev)** in the **Branch** dropdown next to the Update button, then click Update app; pick **Stable (main)** to go back | Same dropdown; or stop the app (`Ctrl + C`, or `./stop.sh`), run `.venv/bin/python app_update.py --branch dev` (`--branch main` to go back), then `./start.sh` |
| Remove it completely | Double-click `STOP_Zscaler_Assessment.bat`, then `UNINSTALL_Zscaler_Assessment.bat` (removes the shortcuts), then delete the folder | Stop it, then delete the app's folder |

(Container: to update, get the latest code and run `docker compose up
--build` again; to remove it, `docker compose down -v` deletes the
container and its saved data, then delete the folder.)

---

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `ERROR: Python is not installed.` (installer) or `Python is not installed or only the Microsoft Store stub was found.` (Windows start) | Python is missing, or was installed without "Add python.exe to PATH" | Not installed: install it from `python.org` and tick **Add python.exe to PATH**. Installed without the tick: run the python.org installer again, choose **Modify**, **Next**, tick **Add Python to environment variables**, **Install** |
| `this app needs Python 3.11 or newer; … is Python 3.9.x` (installer) | An older Python installed by another tool comes first on PATH | Install the current version from `python.org` with the PATH box ticked, or uninstall the old one, then rerun the installer |
| `INSTALL FAILED` with `CERTIFICATE_VERIFY_FAILED`, `ProxyError` or `Could not fetch URL` above it | The laptop cannot reach `pypi.org` directly | Follow the [work laptop box](#work-laptop-tls-inspection-or-a-proxy), then rerun the installer |
| A window: "The python3 command requires the command line developer tools" (Mac) | The Mac has no usable Python yet | Click **Not Now**, install from `python.org`, quit and reopen Terminal |
| `Python 3.11 or newer was not found` from `./install.sh` (Mac) right after installing Python | The open Terminal window cannot see the new Python | Quit Terminal (`Cmd + Q`), open it again, run `./install.sh` again |
| `python3: command not found` (Linux) | Python is not installed | Install it as in Linux Step 1 |
| `Permission denied` running `./install.sh` | The script is not marked as runnable yet | Run `chmod +x install.sh start.sh stop.sh` once, then try again |
| `Operation not permitted` on every command (Mac) | Terminal was refused access to Documents | System Settings → Privacy & Security → Files and Folders → Terminal: allow Documents, then try again |
| The browser says it can't connect / "site can't be reached" | The app is not running, or has not finished starting | Wait ten seconds and refresh. Still nothing? Windows: open `server.log` in Notepad; a last line ending in `ModuleNotFoundError` means the install did not finish, so rerun the installer. Mac/Linux: read the terminal window |
| Nothing at all happens when you double-click the shortcut (Windows) | The silent launcher was blocked or failed | Run `START_Zscaler_Assessment.bat --console` from a Command Prompt in the app folder and read the window; check `launcher.log` |
| `Windows Script Host access is disabled on this machine` | Your company blocks `.vbs` launchers, which the shortcut uses | Open a Command Prompt in the app folder and run `START_Zscaler_Assessment.bat --console`; leave that window open while you use the app (closing it stops the app) |
| `permission denied while trying to connect to the Docker daemon socket` | Your user may not talk to Docker yet | `sudo usermod -aG docker $USER`, then log out and back in; or put `sudo` in front of the docker commands |
| `docker: command not found` or `'docker' is not recognized` | Docker is not installed, or the terminal was opened before it was | Install Docker (container Step 1), then open a new terminal |
| `Cannot connect to the Docker daemon` or `error during connect` | Docker Desktop is not running (Windows, Mac), or the Docker service is stopped (Linux) | Start Docker Desktop and wait for **Engine running**; on Linux `sudo systemctl start docker` |
| `WSL 2 installation is incomplete` or `Virtualization support not detected` (Windows) | WSL 2 is not set up, or virtualization is off in the computer's firmware | Run `wsl --install --no-distribution` in an administrator PowerShell and restart; if virtualization is off, ask IT to turn on Intel VT-x or AMD-V in the BIOS/UEFI |
| `You are not allowed to use Docker, you must be in the docker-users group` (Windows) | Your Windows account is not in the docker-users group | Container Step 1, Windows step 5 |
| `services.dlp-check.env_file.0 must be a string` | Docker Compose is older than 2.24 | Update Docker Desktop (*Check for updates*), or on Linux install Docker from Docker's repository as in container Step 1 |
| `CERTIFICATE_VERIFY_FAILED` during `docker compose up --build` (step `[6/8]`, `pip install`) | The build's downloads go through TLS inspection | Put the company root certificate in the `certs` folder and build again: *On a work network with TLS inspection* under container Step 1 has the one-line export |
| Asked for a UI token you don't have | You opened the address by hand, or the app restarted | Find it as described in [First run](#first-run-the-ui-token) |
| `That UI token is not valid for this server` | The app restarted and minted a new token | Open the app from the shortcut again, or read the new token from `ui_token.txt` |
| `port 8000 … is already in use` | A previous copy of the app is still running (or something else uses port 8000) | Windows: `STOP_Zscaler_Assessment.bat` (it stops whatever listens on the port). Mac/Linux: `Ctrl + C` in the other terminal, or `./stop.sh` |
| `Nothing to stop: no server started by ./start.sh --background is running.` | The app is running in a terminal window, not in the background | Press `Ctrl + C` in that window |
| Authenticate says "intercepted by TLS inspection", or any certificate error | Your company's network intercepts secure traffic | Follow the [work laptop box](#work-laptop-tls-inspection-or-a-proxy) and restart the app |

---

## Where to get help

- Copy the **exact message** you see, in full; it is the fastest way to
  get help. On Windows the server's messages are in `server.log` and the
  launcher's in `launcher.log`, both in the app folder.
- Inside the app, **What does everything do?** (the first button in the
  toolbar) explains every function in plain English, and every report tab
  opens with a "What is this page, and why it matters" box.
- `GETTING_STARTED.md` section 8 covers what goes wrong *after* installing
  (credentials, permissions, preflight).
- For a security problem in the app itself, `SECURITY.md` says how to
  report it.
- With access to the repository, open an issue at
  `github.com/berserkerjay/DLP-Check/issues` and paste the message.

## Native install verification

The **Native local installs** CI workflow runs the actual installers from
both a Git clone and an extracted ZIP, in paths containing spaces. It checks
fresh install, reinstall, settings retention, native dependencies, command
registration, startup, authentication, read-only defaults, the new pages,
shutdown and restart. The installed environment also runs the real Chrome
flow/reference acceptance suite. Results record the exact commit, Python
version and observed OS/CPU architecture.

The matrix targets Linux and Windows x64 plus macOS Apple silicon with
Python 3.11 and 3.14, and Intel macOS with Python 3.11. A green run verifies
those combinations for its recorded commit. Other Python versions, OS
releases, CPUs and company-managed laptops need their own verification. If selecting an interpreter explicitly, set
`DLP_CHECK_PYTHON` to its full executable path before running the installer.

Local synthetic TLS tests check an approved CA bundle, rejection of an
unknown root or wrong hostname, HTTPS proxy tunneling, NO_PROXY, and
hash-verified pip downloads. They keep TLS verification enabled. They do
not validate a real enterprise Zscaler CA, OS trust-store enrollment,
company PAC/proxy authentication or a live tenant. Those require a separate
authorized check on the actual managed network.
