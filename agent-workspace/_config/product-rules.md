# Product rules (never weaken)

## Reading
- **Scope rule.** Read only what the Scope page has ticked (`scope_permissions.py`). A request for anything not ticked is refused with a 400 **before** any sign-in or client is built. New areas get a Scope key.
- **Read-only by default.** Assessment, analysis, exports, snapshots and backups only read.
- Tests never contact a real tenant or real Zscaler service: use the fakes in `tests/` and `sample_tenant.py` (a full made-up tenant, Larkspur Freight). Add every new read to the sample tenant so every page works offline.

## Writing
- Every tenant write goes through `admin_ops` / `pack_ops` (see `safe-writes.md`): plan → preview with plan hash → the four gates (write mode, a writer, a named assessor, a typed confirmation) → re-read each object right before its write (a change since the preview is a conflict, never overwritten) → read-back → recorded Undo → audit log naming the actor.
- Deletes and anything irreversible ask for a stronger typed phrase (`DELETE <name>`, `DELETE <n> OBJECTS`) checked on the **server**, and the preview says plainly when Undo can't restore something.
- New rules and objects are created disabled or monitor-only unless the admin ticks otherwise. Nothing is ever applied unattended: scheduled work produces plans a named person approves (`change_queue.py`, four-eyes).
- Writes are refused on the sample tenant and opened snapshots (rehearsal only).

## Secrets and personal data
- No secret (client secret, UI token, password, key, provisioning key, OTP, PSK) in logs, results, job logs, plans, records, audit, exports, snapshots, backups, browser storage, errors or commits. Mask with `tenant_auth.mask_secrets`. A secret the admin must see is shown once, held in memory only, bound to the person, and dropped.
- Personal data (user names, hostnames, emails) is counted, not listed, unless the page's purpose needs it or the admin opts in.

## Untrusted input
- Uploads, pasted text, tenant strings and fetched lists: cap size, depth and count; parse defensively (no `eval`, no executing PAC, hardened XML); reject or count malformed parts; escape on every output (HTML, SVG, Markdown, CSV/XLSX formula cells via `csv_safe`, PDF, DOCX, Terraform).

## Outbound calls
- Only the tenant by default. Any other host: optional, off by default, a fixed allow-listed URL, no redirects, TLS verified, size-capped, schema-validated, cached with its fetch date, manual import for offline use, failing safe to "unknown", and declared in SECURITY.md.

## Analysis honesty
- A condition the evaluator can't establish is "unknown" with a reason, never "match". Zscaler behaviour not verified against the SDK or Zscaler's documentation is marked **assumed** in a code comment.

## Platform
- Localhost by default; UI token, origin and CSRF checks stay; public API contracts change only additively; Docker container stays non-root and read-only.
