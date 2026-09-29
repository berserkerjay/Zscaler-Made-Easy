# Installing DLP-Check — a walkthrough for someone doing this for the first time

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
      server with Docker. No administrator rights are needed on Windows or
      Mac (Python installs per user); on Linux you may need `sudo` to
      install Python.
- [ ] **Internet access** to `github.com` (the code) and `python.org` (the
      installer). On a work laptop that goes through Zscaler or a proxy,
      read the [work laptop box](#work-laptop-tls-inspection-or-a-proxy)
      before you start; it changes one step.
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
| **OneAPI** (the usual one: the tenant has ZIdentity) | Cloud, vanity domain, Client ID, Client secret | ZIdentity → Integration → API Clients → Add API Client. The secret is shown once, when the client is created. |
| **Classic ZIA API** (a tenant that has not enabled ZIdentity; ZIA only) | Cloud, admin username, admin password, API key | ZIA Administration → API Key Management for the key; a ZIA admin allowed to use the API for the username and password. |

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
   skipping it makes every later step fail. Leave "Use admin privileges
   when installing py.exe" unticked.
4. Click **Install Now** and wait for "Setup was successful", then Close.

**Step 2 — Get the program's files onto your computer.**

*Option A: with Git (recommended).*

1. Go to `git-scm.com/download/win`, download **64-bit Git for Windows
   Setup**, open it and click **Next** through every screen with the
   defaults, then **Install** and **Finish**.
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
4. Open that folder in File Explorer (type `explorer DLP-Check` in the same
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
4. **Failure** looks like this: the window prints **INSTALL FAILED** and
   stays open. The lines above it say why; the usual causes are no access
   to `pypi.org` (see the work laptop box) or an old Python found first
   (see [If something goes wrong](#if-something-goes-wrong)). Fix the
   cause and double-click the installer again; it is safe to rerun.

**Step 4 — Open it.**
Double-click the **Zscaler Assessment** desktop shortcut. Within about
ten seconds your browser opens to the app. **Nothing else appears on
screen**: the program runs in the background with no window, and what it
prints goes into a file named `server.log` in the app folder. To stop it,
double-click `STOP_Zscaler_Assessment.bat` in the app folder; closing the
browser does not stop it.

If nothing happens when you double-click the shortcut: in the app folder,
click File Explorer's address bar, type `cmd`, press Enter, then type
`START_Zscaler_Assessment.bat --console` and press Enter. The window that
stays open shows the reason. `launcher.log` in the app folder records why
a silent start failed.

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
  Agree and Install through the installer.
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
  Zscaler Platform Assessment
  UI token: …
  Open http://localhost:8000/?token=… in your browser
```

and then appears to stop, with no new prompt. That is normal: the app is
running in that window. Your browser opens by itself within a few seconds;
if it does not, copy the whole `http://localhost:8000/?token=…` line into
Safari's address bar.

Leave that Terminal window open while you use the app. To stop it, press
`Ctrl + C` in that window (or close it; when macOS asks "Do you want to
terminate running processes?", click **Terminate**). `./stop.sh` is only
for a server started with `./start.sh --background`.

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

**Step 2 — Get the code.** With `git` installed (Step 1 did that), this
is the easiest way, and it lets the app update itself later. GitHub
refuses account passwords over git, so first make a **personal access
token** once: on `github.com`, click your avatar → **Settings** →
**Developer settings** → **Personal access tokens** → **Tokens (classic)**
→ **Generate new token**, tick **repo**, generate, and copy the token
(it is shown once). Then:

```bash
git config --global credential.helper store   # remember the sign-in, so updates work later
cd ~
git clone https://github.com/berserkerjay/DLP-Check.git
cd DLP-Check
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
started that way (and only that way).

That's it. See **[How you know it worked](#how-you-know-it-worked)** below.

---

## Run it in a container instead

A **container** is a sealed copy of the app with everything it needs, so
it does not depend on what is already on the computer (no separate Python
install, nothing that can conflict with other software). Pick this for a
shared server, or if you would rather not install Python on your own
machine. It works the same way on Windows, Mac and Linux.

**Step 1 — Install Docker.**
Docker is the program that runs containers.

- **Windows or Mac:** go to `docker.com/products/docker-desktop`, download
  **Docker Desktop**, install it like any other application, and open it
  once so it finishes its own setup (it may ask you to restart).
- **Linux:** install Docker and its compose plugin with your package
  manager, for example on Ubuntu:

  ```bash
  sudo apt update && sudo apt install -y docker.io docker-compose-v2
  sudo usermod -aG docker $USER     # lets your user talk to Docker without sudo
  ```

  then **log out and back in** (or put `sudo` in front of every `docker`
  command below). Check with `docker compose version`; it must print a
  version, not "permission denied".

**Step 2 — Get the code**, the same way as above: sign in to GitHub, go
to the repository page, **Code → Download ZIP**, extract it somewhere you
will remember (or `git clone` it, if you have git; see the Linux section
for the sign-in token).

**Step 3 — Build and run.**
Open a terminal (Terminal on Mac, PowerShell or Command Prompt on
Windows, your terminal app on Linux), move into the extracted folder
(`cd `, then drag the folder in, then Enter), and run:

```bash
docker compose up --build
```

The first run takes a few minutes while it downloads and builds
everything; it prints its progress the whole time. Once it settles, the
last lines it prints are:

```
  UI token: …
  Open http://localhost:8000/?token=… in your browser
  (inside the container the server listens on every address; docker-compose.yml publishes it on 127.0.0.1:8000 of this machine only)
```

Open that address in your browser on the same machine.

**Finding the UI token again:** run `docker logs dlp-check` from another
terminal in the same folder (same `cd` trick), or
`docker compose exec dlp-check cat /data/ui_token.txt`.

**On a shared server (no desktop on it):** get the code onto the server
with `git clone` on the server itself (Linux section, Step 2) or copy the
ZIP over with `scp` and `unzip` it; `cd DLP-Check` (no dragging). Run it
detached so it does not hold your SSH session:

```bash
docker compose up --build -d
docker compose logs dlp-check      # the UI token and the address
```

The container starts again by itself after a reboot until you run
`docker compose down`. It listens on the server's own `127.0.0.1:8000`
only, on purpose. To use it from your PC as one person, open a tunnel
from your PC and then browse to `http://localhost:8000/?token=…` on your
PC:

```bash
ssh -L 8000:127.0.0.1:8000 you@server
```

For a team, keep the `127.0.0.1:` at the start of the `ports:` line in
`docker-compose.yml` exactly as it is and put a reverse proxy with
sign-in in front (`SECURITY.md` says how). **Do not** change that line to
`0.0.0.0`: inside the container the "must not listen on the network
without SSO" check is switched off by design, so that `127.0.0.1:` is the
only thing keeping the app off the network.

**Everyday use:**
- Stop it: `Ctrl + C` in the window running `docker compose up`, or
  `docker compose down` from another window in the same folder (that is
  the real stop for a detached container).
- Start it again later: `docker compose up` (`-d` on a server; no
  `--build` needed unless the code changed).
- Update it: get the latest code (`git pull`, or download a fresh ZIP and
  replace the folder) and run `docker compose up --build` again. The
  in-app **Update app** button does not apply inside a container.

Everything the app saves (tenant profiles, the audit log, uploaded packs,
the token file) lives outside the container in a Docker-managed storage
area called `dlpcheck-data`, so it survives rebuilds and updates.

---

## How you know it worked

Your browser shows a dark page headed **Zscaler Platform Assessment**,
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
not considered enough once the app is reachable beyond your machine. In
the container that check is off by design, and the `127.0.0.1:` in
`docker-compose.yml` is what keeps it off the network (see the container
section).

---

## Connecting to a Zscaler tenant

Once you are in, **Connect to the tenant** has a **Sign-in method**
choice and the fields for it:

- **OneAPI** (the default): Cloud, Vanity domain, Client ID, Client secret.
- **Classic ZIA API**: Cloud, Admin username, Admin password, API key. For a
  tenant that has not enabled ZIdentity; it covers ZIA only (no ZPA,
  Client Connector or ZDX checks).

Type the values, click **Authenticate**, and read the line it answers
with ("Connected: N dictionaries, N engines, N web DLP rules", or a plain
reason why not). `GETTING_STARTED.md` section 2 says what to ask the
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
| Close it | Double-click `STOP_Zscaler_Assessment.bat`. Closing the browser does not stop it; it keeps running in the background until you do | `Ctrl + C` in the terminal window running it; `./stop.sh` if you started it with `./start.sh --background` |
| Get the latest version (Git install) | Click **Update app** on the Start here card (it reads **Update app now** when a newer build was found), or double-click `UPDATE_Zscaler_Assessment.bat` | Click **Update app** inside the app; or stop it, run `git pull`, then `./install.sh` and `./start.sh` |
| Get the latest version (ZIP install) | Stop the app, download a fresh ZIP, replace the folder (keep your `local_settings.bat`), double-click the installer again | Stop the app, download a fresh ZIP, replace the folder (keep `local_settings.env`), run `./install.sh` and `./start.sh` |
| Try a fix before it is released (Git install) | Pick **QA (qa)** or **Development (dev)** in the **Branch** dropdown next to the Update button, then click Update app; pick **Stable (main)** to go back | Same dropdown; or `.venv/bin/python app_update.py --branch dev` (`--branch main` to go back), then `./install.sh` and `./start.sh` |
| Remove it completely | Double-click `STOP_Zscaler_Assessment.bat`, then `UNINSTALL_Zscaler_Assessment.bat` (removes the shortcuts), then delete the folder | Stop it, then delete the app's folder |

(Container: to update, get the latest code and run `docker compose up
--build` again; to remove it, `docker compose down -v` deletes the
container and its saved data, then delete the folder.)

---

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `ERROR: Python is not installed.` (installer) or `Python is not installed or only the Microsoft Store stub was found.` (Windows start) | Python is missing, or was installed without "Add python.exe to PATH" | Install it from `python.org` and tick **Add python.exe to PATH** this time |
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
