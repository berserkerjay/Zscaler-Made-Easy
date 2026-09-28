# Installing DLP-Check — a walkthrough for someone doing this for the first time

This page assumes you have never installed a developer tool before. It
does not assume you know what Python, Git, Docker or a terminal are —
each one is explained the first time it comes up. Pick **one** of the four
options below: Windows, Mac, Linux, or a container. If you are not sure
which to pick, use the one that matches the computer you're on now
(Windows, Mac or Linux); the container option is for someone who wants
to run this on a shared server instead of their own laptop.

Budget about 15 minutes. You will need:
- The computer you plan to run it on (Windows, Mac or Linux).
- An internet connection.
- Access to this GitHub repository (`berserkerjay/DLP-Check`). It is
  private, so someone needs to have added your GitHub account, or you
  need to be signed in to an account that already has access.

Nothing here touches your Zscaler tenant. Installing just puts the
program on your computer; it does not connect to anything until you
type in tenant credentials later and click Authenticate.

---

## Windows

**Step 1 — Install Python.**
Python is the language this program is written in; your computer needs
it installed once, the same way it needs a PDF reader to open a PDF.

1. Go to python.org/downloads and click the big **Download Python**
   button. (It offers the right version for Windows automatically.)
2. Open the downloaded file.
3. On the very first screen, **tick the box that says "Add Python to
   PATH"** near the bottom, before clicking Install. This is the step
   almost everyone forgets, and skipping it causes every step after this
   one to fail with an error mentioning "python is not recognized."
4. Click **Install Now** and wait for it to finish.

**Step 2 — Get the program's files onto your computer.**

1. In your browser, go to the repository page on GitHub
   (`github.com/berserkerjay/DLP-Check`) and sign in if it asks.
2. Click the green **Code** button, then **Download ZIP**.
3. Find the downloaded ZIP file (usually in your Downloads folder),
   right-click it, and choose **Extract All…**. Extract it somewhere you
   will remember, for example directly in `Documents`.
4. Open the extracted folder. You should see a file named
   `INSTALL_Zscaler_Assessment.bat` inside it.

**Step 3 — Run the installer.**

1. Double-click `INSTALL_Zscaler_Assessment.bat`.
2. A black window opens and prints a few lines while it installs; this
   is normal and expected — it is not broken. Wait for it to say
   **Installation complete!** and press any key to close it.
3. A shortcut named **Zscaler Assessment** now sits on your desktop and
   in your Start Menu.

**Step 4 — Open it.**
Double-click the **Zscaler Assessment** desktop shortcut. Your browser
opens by itself to the app; a small window may flash briefly in the
background (that is the program running quietly — leave it alone, do
not close it while you're using the app).

That's it — you're installed. See **[First run](#first-run)** below for
what to do once the app is open.

---

## Mac

**Step 1 — Check whether Python is already installed.**
Recent Macs often already have a usable Python. Open **Terminal**
(press `Cmd + Space`, type `Terminal`, press Enter — this opens a plain
text window where you type commands instead of clicking). Type this and
press Enter:

```bash
python3 --version
```

If it prints `Python 3.11` or higher, skip to Step 2. If it prints
something older, says "command not found," or you're not sure, go to
python.org/downloads/macos, download the macOS installer, open it, and
click through the installer with the default options.

**Step 2 — Get the program's files onto your computer.**

1. In your browser, sign in to GitHub and go to the repository page
   (`github.com/berserkerjay/DLP-Check`).
2. Click the green **Code** button, then **Download ZIP**.
3. The ZIP usually extracts itself into your Downloads folder (double-
   click it if it doesn't). You should end up with a folder named
   something like `DLP-Check-main`.
4. Move that folder somewhere you'll remember, for example into your
   home folder or Documents.

**Step 3 — Install and start, from Terminal.**
In the same Terminal window from Step 1, you need to move *into* the
folder you just extracted before running anything. `cd` means "change
directory" (move into a folder). Type `cd `, then a space, then drag the
extracted folder from Finder straight into the Terminal window — this
fills in the correct path for you — then press Enter. Then run:

```bash
./install.sh        # sets everything up; takes a minute or two
./start.sh           # starts the app and opens your browser
```

If Terminal says `Permission denied` on `./install.sh`, run
`chmod +x install.sh start.sh stop.sh` once and try again.

Leave that Terminal window open while you use the app — closing it
stops the server. To stop on purpose, either close the window or press
`Ctrl + C` inside it.

That's it — you're installed. See **[First run](#first-run)** below.

---

## Linux

**Step 1 — Install Python 3.11 or newer, if you don't already have it.**
Open a terminal (how to do this varies by desktop, but there is almost
always one in your applications menu — look for "Terminal" or
"Console"). Check what you have:

```bash
python3 --version
```

If it's 3.11 or newer, move on. Otherwise, install it with your
distribution's package manager, for example:

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git

# Fedora / RHEL
sudo dnf install -y python3 python3-pip git
```

**Step 2 — Get the code.** If `git` is installed (the command above
installs it on Debian/Ubuntu/Fedora), this is the easiest way:

```bash
git clone https://github.com/berserkerjay/DLP-Check.git
cd DLP-Check
```

It will ask you to sign in to GitHub the first time. If you'd rather not
use git, download the ZIP from the repository's **Code → Download ZIP**
button in your browser instead, and extract it, then `cd` into the
extracted folder.

**Step 3 — Install and start.**

```bash
./install.sh        # sets everything up; takes a minute or two
./start.sh           # starts the app and prints the address to open
```

`start.sh` prints a web address (`http://127.0.0.1:8000/...`) — open it
in your browser if it doesn't open by itself. Leave the terminal window
open while you use the app; `Ctrl + C` stops it, or run `./stop.sh` from
another terminal in the same folder if you started it with
`./start.sh --background`.

That's it — you're installed. See **[First run](#first-run)** below.

---

## Run it in a container instead

A **container** is a self-contained, sealed-off copy of the app and
everything it needs to run, so it doesn't depend on what's already on
the computer (no separate Python install, nothing that can conflict with
other software). This is the option to pick for a shared server, or if
you'd rather not install Python directly on your own machine. It works
the same way on Windows, Mac and Linux.

**Step 1 — Install Docker.**
Docker is the program that runs containers.

- **Windows or Mac:** go to docker.com/products/docker-desktop, download
  **Docker Desktop**, install it like any other application, and open it
  once so it finishes its own setup (it may ask you to restart).
- **Linux:** install `docker` and the `docker compose` plugin with your
  distribution's package manager, for example
  `sudo apt install -y docker.io docker-compose-plugin` on Debian/Ubuntu.

**Step 2 — Get the code**, the same way as above: sign in to GitHub, go
to the repository page, **Code → Download ZIP**, extract it somewhere
you'll remember. (Or `git clone` it, if you have git.)

**Step 3 — Build and run.**
Open a terminal (Terminal on Mac, PowerShell or Command Prompt on
Windows, your terminal app on Linux), move into the extracted folder
(`cd `, then drag the folder in, then Enter — same trick as the Mac
instructions above), and run:

```bash
docker compose up --build
```

The first run takes a few minutes while it downloads and builds
everything; it prints its progress the whole time. Once it settles, open
`http://localhost:8000` in your browser.

**Finding the one-time sign-in code:** in a second terminal window, in
the same folder, run:

```bash
docker logs dlp-check
```

and look for the token near the top of the output (see **First run**
below for what to do with it).

**Everyday use:**
- Stop it: `Ctrl + C` in the window running `docker compose up`, or
  `docker compose down` from another window in the same folder.
- Start it again later: `docker compose up` (no `--build` needed unless
  the code changed).
- Update it: pull the latest code (`git pull`, or download a fresh ZIP
  and replace the folder) and run `docker compose up --build` again.

Everything the app saves (tenant profiles, the audit log, uploaded
packs) lives outside the container in a Docker-managed storage area
called `dlpcheck-data`, so it survives rebuilds and updates.

---

## First run

Whichever option you picked, the browser opens to the app automatically
(or you opened the printed address yourself). The very first thing it
may ask for is a **one-time sign-in code** — a short string of letters
and numbers, so that nobody else on the same computer can open the app
without you. Where to find it:

- **Windows/Mac/Linux (not a container):** the app tells you this on
  first open, and it's also saved in a file named `ui_token.txt` in the
  same folder as the program, in case you need it again.
- **Container:** run `docker logs dlp-check` as described above.

Paste it into the page when asked; your browser remembers it for 12
hours, so you won't be asked again for a while.

That code is a shared secret for this machine, not multi-factor
authentication — treat it like a password, and don't publish it or leave
it somewhere anyone else can read it. If you ever need this server
reachable from more than just your own machine, it refuses to start
that way unless you have also set up sign-in through an identity
provider (`SECURITY.md`) — a token by itself is not considered enough
once the app is reachable beyond your machine.

Once you're in, the page has fields for the customer's Zscaler tenant
details (cloud, vanity domain, a Client ID and Client Secret). You get
those from the customer's Zscaler admin — that part is covered in
`GETTING_STARTED.md`, the next document to read once installation is
done.

---

## Starting, stopping, updating and removing it later

| I want to… | Windows | Mac / Linux |
|---|---|---|
| Open the app | Double-click the **Zscaler Assessment** desktop shortcut | `./start.sh` in the app folder |
| Close it | Double-click `STOP_Zscaler_Assessment.bat`, or just don't reopen it | `Ctrl + C` in its terminal window, or `./stop.sh` |
| Get the latest version | Click **Update app now** inside the app (Start here card), or double-click `UPDATE_Zscaler_Assessment.bat` | Click **Update app now** inside the app, or `python3 app_update.py` then `./start.sh` |
| Try a fix before it is released | Pick **QA** or **Development** in the **Branch** dropdown next to the Update button, then update; pick **Stable (main)** to go back. Or `UPDATE_Zscaler_Assessment.bat dev` | Same dropdown, or `python3 app_update.py --branch dev` (`--branch main` to go back) |
| Remove it completely | Double-click `UNINSTALL_Zscaler_Assessment.bat`, then delete the folder | Delete the app's folder |

(Container: to update, get the latest code and run `docker compose up
--build` again; to remove it, `docker compose down -v` deletes the
container and its saved data, then delete the folder.)

---

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `'python' is not recognized...` (Windows) | Python wasn't added to PATH during install | Reinstall Python from python.org and make sure to tick **Add Python to PATH** this time |
| `python3: command not found` (Mac/Linux) | Python isn't installed, or isn't the right version | Install it as described in Step 1 for your system above |
| `Permission denied` running `./install.sh` | The script isn't marked as runnable yet | Run `chmod +x install.sh start.sh stop.sh` once, then try again |
| The browser says it can't connect / "site can't be reached" | The app isn't running, or hasn't finished starting yet | Wait a few seconds and refresh; make sure the terminal window (or the background process on Windows) is still open |
| Asked for a token you don't have | First-time sign-in, or the browser forgot it | Find it as described in **First run** above |
| "Address already in use" / port 8000 busy | Something else is already using port 8000, often a previous copy of this same app still running | Close any other terminal windows running `start.sh` or `docker compose up`, or on Windows run `STOP_Zscaler_Assessment.bat` first |
| Anything mentioning "TLS inspection" or a certificate error | Your company's network intercepts secure traffic (common on a work laptop) | See the "Settings that survive updates" section in `GETTING_STARTED.md` |

If none of these match what you're seeing, the exact error message is
usually the fastest way to get help — copy it in full when you ask.
