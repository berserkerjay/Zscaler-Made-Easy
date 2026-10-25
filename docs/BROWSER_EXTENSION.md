# DLP-Check companion browser extension

A small Chrome and Edge extension that works **with** the DLP-Check app on
your computer. It is a launcher, not a second copy of the app: everything
that reads or changes a Zscaler tenant still happens in the app, with its
sign-in, UI token, write mode and audit log.

## What it does

### In the Zscaler admin console (like ZHERO, with DLP-Check's data)
- **Badges.** On the ZIA admin console, a DLP-Check badge appears next to
  every object DLP-Check read from the tenant, wherever the console shows
  its exact name:
  - DLP dictionaries, engines and rules;
  - URL filtering, Cloud App Control, SSL inspection, Cloud Firewall and
    File Type Control rules;
  - URL categories (every custom one, and the predefined ones a rule
    uses), locations and location groups, departments, groups, rule
    labels, network services, network applications (and their groups),
    and source and destination IP groups.

  A badge says the object's most serious finding ("shadowed", "monitor
  only", "disabled", "unused") or what uses it ("used in 4 rules",
  "2 engines, 3 rules"), or, for a policy rule, where it sits ("order 3 ·
  block"). When several objects share a name (a URL category and a rule
  called the same), the badge says "2 objects" and the panel lists them.
  Off until you switch it on in the extension's settings, which asks your
  browser to allow the extension on the console's address
  (admin.zscaler.net and the other Zscaler clouds).
- **Side panel.** Click a badge, or *Open the side panel* in the popup:
  - *On this page*: the objects the console page shows, filtered by kind;
  - *Search*: everything DLP-Check read, by name, filtered by kind (DLP,
    policies, objects);
  - an object's detail: what it uses (per kind) and what uses it (per
    policy: URL filtering, Cloud Firewall, Inline Web DLP...), each one a
    link, the policy pack that created it, and its findings; a rule the
    Shadowed rules page analyses links to that page in DLP-Check;
  - *Staged*: stage DLP dictionaries, engines and rules across console
    pages, then export them in one go as a JSON pack, Terraform or both,
    with or without what they use (*Export from tenant* covers DLP only,
    so other kinds are not staged; they open DLP-Check instead).
- **Read the tenant.** The panel's *Read the tenant* asks DLP-Check to
  read it, read-only and only what the Scope page puts in scope: the DLP
  channels marked Zscaler; the URL filtering, SSL inspection, Cloud App
  Control and File Type Control rules with DLP or ZIA platform ticked;
  the Cloud Firewall rules with ZIA platform ticked. The answer is reused
  for 30 minutes until you read again.
- **What the index holds, and what it does not.** Names, counts, states,
  orders, actions and findings. Never a user name (a rule's users,
  excluded users, override users and devices are not read into it), a
  description, who last changed a rule, a category's URLs or keywords, or
  a secret. The objects referenced by name come from the rules
  themselves, so a location or group no rule in scope uses is not listed.
  Each kind is capped at 300 objects (the ones with findings and the most
  used first); the panel says how many more there are. Predefined URL
  categories have no display name in the API: DLP-Check names them after
  their ID ("NEWS_AND_MEDIA" → "News and Media"), which is the console's
  usual spelling but not guaranteed. A custom category no rule uses is
  reported as unused for the policies DLP-Check read (Bandwidth Control,
  Sandbox and the other policies that can use a category are not read).

The flow follows ZHERO's (badge → panel → stage → act), but every answer
comes from DLP-Check, and anything that changes the tenant (deploy,
remove, fix) stays in DLP-Check behind write mode, its preview and the
audit log.

### Anywhere
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
  then), `contextMenus`, `storage`, `sidePanel` and `scripting` (to add the
  console badges once you allow them). The ZIA admin consoles are an
  *optional* permission, asked for only when you switch the badges on and
  removed when you switch them off. No other site, no `tabs`, `cookies` or
  `webRequest` permission.
- **The console page stays in the browser.** The badge script compares the
  text on the console page with the names DLP-Check read, inside the page,
  and draws its badges in a closed shadow root. Nothing from the console
  page is sent anywhere; a badge click sends only the key of an object
  DLP-Check already knows. The read is kept in the browser's session
  storage and is gone when the browser closes.
- **Narrow trust in the app.** The extension has a fixed ID (the public key
  in its manifest), and DLP-Check accepts requests from it only on its
  read-only endpoints: the console index and *Export from tenant* (and
  Stop on that export). A deploy, removal, fix or setting change from the
  extension's origin is refused. It signs in with DLP-Check's own sign-in
  in this browser (open DLP-Check once); it never stores a token.
  `DLP_CHECK_EXTENSION_ID` moves that trust to a repacked build, or `off`
  removes it.
- **This computer only.** It talks only to `127.0.0.1` or `localhost`
  (host permissions and its Content Security Policy both say so), and the
  settings page refuses any other address.
- **Nothing extra leaves the page.** An address is passed on without its
  query string or fragment (where session tokens and personal data tend to
  be), and a selection is used only when it is a single hostname, URL or
  IP address, never a sentence or an e-mail address.
- **What it calls.** `GET /api/ping` (no sign-in; an answer other than
  DLP-Check's `{"ok": true}` is reported as "something else is listening
  there"), and from the side panel `GET /api/tenant-profiles`,
  `POST /api/console-index` and *Export from tenant*'s job.

## Why a companion and not the whole app as an extension

The app's Python side (Zscaler's SDK, background jobs that wait out ZIA's
rate limit for up to an hour, the OS keychain for secrets, the audit log
and deployment history) cannot run inside a browser extension: Chrome
stops an extension's background worker after a few minutes, and extension
storage is not encrypted. Keeping the work in the app and the extension as
a launcher keeps every safeguard the app has.
