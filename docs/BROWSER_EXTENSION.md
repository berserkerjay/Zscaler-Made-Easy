# DLP-Check companion browser extension

A small Chrome and Edge extension that works **with** the DLP-Check app on
your computer. It is a launcher, not a second copy of the app: everything
that reads or changes a Zscaler tenant still happens in the app, with its
sign-in, UI token, write mode and audit log.

## What it does

- **Analyze this site.** The toolbar button shows the site you are on;
  *Analyze this site* opens the Path analyzer with it filled in: what
  Zscaler does to a user's traffic to that destination, hop by hop.
- **Right-click.** On a link, a selected hostname, URL or IP address, or
  the page itself: *Analyze … with DLP-Check* does the same.
- **Shortcuts.** The popup opens DLP-Check, the Path analyzer, the Live DLP
  feed, the Flow animator and the help page.
- **Status.** The popup says whether the app is running at the address set
  in the extension's settings.

Nothing runs on its own: the Path analyzer opens with the destination
filled in and waits for you to click *Analyze*.

## Install

1. Download it from DLP-Check: **Advanced settings → Browser extension →
   Download the extension** (or use the `browser_extension` folder of the
   repository).
2. Unzip `dlp-check-extension.zip` somewhere it can stay.
3. Open `chrome://extensions` (Edge: `edge://extensions`) and turn on
   **Developer mode**.
4. Click **Load unpacked** and pick the `dlp-check-extension` folder.
5. Pin the extension. If the app is not at `http://127.0.0.1:8000` (the
   container listens on `http://127.0.0.1:8001`), open the extension's
   **Settings** and enter the address.

Managed browsers may block unpacked extensions; IT can allow it by policy
(`ExtensionInstallAllowlist`) or package it for the Chrome Web Store or
Microsoft Edge Add-ons.

## Security and privacy

- **No credentials, no tenant data.** The extension stores one setting,
  the app's address. It never sees a client secret, the UI token or a
  tenant answer; the app's own pages do the work.
- **Least privilege.** `activeTab` (the tab you click the button on, only
  then), `contextMenus` and `storage`. It has no access to the pages you
  browse, no content scripts and no `tabs` or `cookies` permission.
- **This computer only.** It talks only to `127.0.0.1` or `localhost`
  (host permissions and its Content Security Policy both say so), and the
  settings page refuses any other address.
- **Nothing extra leaves the page.** An address is passed on without its
  query string or fragment (where session tokens and personal data tend to
  be), and a selection is used only when it is a single hostname, URL or
  IP address, never a sentence or an e-mail address.
- **One request of its own.** `GET /api/ping`, which needs no sign-in and
  answers only `{"ok": true}`; an answer without that is reported as
  "something else is listening there".

## Why a companion and not the whole app as an extension

The app's Python side (Zscaler's SDK, background jobs that wait out ZIA's
rate limit for up to an hour, the OS keychain for secrets, the audit log
and deployment history) cannot run inside a browser extension: Chrome
stops an extension's background worker after a few minutes, and extension
storage is not encrypted. Keeping the work in the app and the extension as
a launcher keeps every safeguard the app has.
