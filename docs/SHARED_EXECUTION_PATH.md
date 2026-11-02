# The shared execution path

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Every policy pack, whatever it is called or which industry it serves, gets
into a Zscaler tenant and out of it through **one** path. This page says
what that path is, what it promises, and what someone adding a pack or a
new kind of object must do to stay on it.

An interactive walk-through of the same path is in the app: open **Deploy
Policy Packs** and click **How a deployment works** (also at
`/report/deploy-flow`).

## 1. Where the path lives

| Step | File | What it does |
|---|---|---|
| Plan | `pack_deploy.py` → `preflight()` | Reads the tenant once, compares it with the selected packs, and writes a plan: what will be created, what already exists and is reused, what is blocked and why. Nothing is written. |
| Validate | `pack_ops.py` → `validate()` | One validator for every kind of object (dictionary, engine, endpoint application group, rule on any channel). Runs inside the plan and at upload, **before any request reaches ZIA**. |
| Write | `pack_ops.py` → `create()`, `update()`, `delete()` through `call()` | The only functions in the app that name a Zscaler SDK write method. `call()` turns every SDK answer into the same shape, retries what time clears, and never lets one object's failure stop the run. |
| Record | `pack_ops.py` → `Recorder` | One result per object (what the screens show) and one structured event per write (what the log and support use), in the same shape for a deploy, a removal and an undo. |
| Deploy | `pack_deploy.py` → `apply()` | Runs the approved plan: dictionaries, then engines, then endpoint application groups, then rules (parents before their sub-rules). Activates, waits for ZIA to report ACTIVE, reads the tenant back. |
| Remove | `pack_removal.py` → `_execute()` | Runs a removal plan in tiers: rules and application groups, then engines, then dictionaries. Activates and waits between tiers, reads the tenant again right before the engine tier and the dictionary tier and leaves alone anything a rule or a surviving engine now uses (`_users_now`), retries what time clears, reads the tenant back. Used by *Remove rules…* (the picker) and *Undo*; the API's whole-pack plans (`plan_removal`) remain for scripts. |
| Verify | `pack_deploy.py` → `verify_pack()` and the read-back inside `apply()` / `_execute()` | Always the planner, run again after activation. There is no second comparison with its own rules. |

The Fed policy pack was the first pack deployed in production; its
original importer (`fed_policy_pack/dlp_stand_alone_import.py`) is kept as
the reference this path is measured against. The app never runs it.

## 2. What the path promises

1. **Names and limits are checked before any write.** Every refusal a
   real tenant has given is a rule in `validate()` and its helpers in
   `dlp_importer.py` and `pack_channels.py`: the allowed characters in a
   name, dictionary and engine descriptions of at most 255 characters,
   SaaS rule names of at most 31, rule descriptions of at most 10 240,
   at most 8 patterns of 256 bytes and 256 phrases of 3–128 bytes per
   dictionary, no confidence score on a custom dictionary and always one
   on a copy of a predefined dictionary, the Web DLP protocol set, one
   transfer method per endpoint rule, admin rank 0–7. A pack that breaks
   one is blocked in the plan with the reason, in plain words.
2. **Dependencies come first, dependents go first.** Create order is
   `pack_ops.CREATE_ORDER`: dictionary → engine → application group →
   rule (parent rule before its sub-rules). Delete order is
   `pack_ops.DELETE_TIERS`: rules and application groups → activate →
   engines → activate → dictionaries → activate, always in that order,
   with a wait for ACTIVE after each activation, because ZIA validates a
   delete against the activated configuration. The activation after a
   tier runs whenever a delete in that tier reached ZIA, even when every
   one was refused, so the next tier starts from a settled tenant; a tier
   that sent nothing (objects already gone or kept, a run stopped before
   its first call) is not followed by one, so a stopped run publishes
   nothing it did not write.
3. **ZIA's limits are handled the same way for every kind.** A rate
   limit (429), a busy tenant (502/503/504) or a timeout is retried up to
   three times with backoff inside `call()`; a create answered by a
   timeout or a 5xx may have been applied all the same, so it is sent
   again only after a read by name shows it is not there (`name_check`),
   and otherwise reported as not sent again. One write run per tenant at
   a time (`tenant_run`): a second one is refused as busy, nothing read or
   written. Inside a run, a 403 on a
   create, update or delete ("Resource Access Blocked", "Forbidden": ZIA
   blocking the client after a burst, or a pending change being applied)
   is answered inside `call()` by an activation of the tenant's pending
   configuration, a 15-second wait and another try (with the same
   transient retries), up to five times; each activation is logged. A
   403 about the rule's rank is not retried (activating changes nothing
   about it), a 401 is not (the credentials are refused), and a 403 that
   is still there after the five activations stops the run (rule 7): it
   is about the client, not the object. Outside a run — a proposal's
   single field change — nothing is activated. The Delete all rules
   step of the migration wizard follows the same 403 rule through the
   raw client. A delete refused because the object is "in use" is tried
   again after the tier is activated, up to three passes (a 403 is never
   one of those). A SaaS rule whose position ZIA refuses is placed at a
   position ZIA accepts after the tenant's rules are re-read. Anything
   else fails once and is reported once.
4. **Deploying twice changes nothing.** The plan reuses every object by
   name; a second run creates nothing, fails nothing and never makes a
   second object with the same name on any channel.
5. **Removing takes everything the pack put in, and nothing else.** A
   removal plan finds a pack's objects by the provenance tag the deploy
   writes into every description and by name; it keeps anything a rule or
   engine outside the pack still uses and says so; it reports leftovers
   after a fresh read. An object whose id now carries a different name is
   never deleted.
6. **Every failure says what failed and why.** Each result carries the
   object's kind and name, the status, ZIA's own message, its error code
   and HTTP status when ZIA gave them, how many attempts were made and,
   for every refusal the app knows, a plain-language explanation of what
   it means and what to do (`pack_ops.EXPLANATIONS`). The log line reads
   `[kind] name: status — ZIA's message. What this means: …`.
7. **A refusal no later write can get past stops the run at once.** Some
   answers are about the whole tenant, not one object: an admin session
   holding the ZIA edit lock (`EDIT_LOCK_NOT_AVAILABLE`), the hourly
   request limit (the SDK's `RetryTooLong`), refused credentials (401),
   a client without the DLP write permission (403), a 403 still there
   after the five activations of rule 3. Trying the next 75 objects
   against them takes twenty minutes and looks like a hang.
   Every run opens `pack_ops.run_scope()`; inside it the first such
   refusal (`fatal_reason()`) stops the run: later writes return at once
   with code `STOPPED`, are recorded as *skipped — not attempted*, the
   log carries one `STOPPED — nothing more is written. …` line with the
   reason in words, activation and the read-back still run so what was
   written is live and recorded, and the result's `stopped` says why.
   The operator's Stop (a cancel event passed to `apply()` / `remove()`)
   works the same way, and it is seen everywhere a write can wait: a
   write waiting for ZIA's rate limit (`call()` binds
   `zia_rate.stopping_on` for the run) or for a retry's backoff is not
   sent after the wait but comes back `STOPPED`; an activation refused
   for its rate is not sent again, and one still waiting for the
   activation limit when Stop is pressed is not sent. The one
   activation of what was written before Stop is deliberate and logged;
   after Stop the run does not then poll ZIA for the activation status
   (`pc.wait_active`), and a Stop pressed while it polls ends the polling.
   Export and journey reads honour Stop the same way while they wait
   for ZIA's read limit. The SDK itself is built with bounded waits
   (`dlp_api_server.SDK_REQUEST_TIMEOUT`, `SDK_MAX_RETRY_SECONDS`): a
   request has a timeout, and a Retry-After longer than 30 s is not slept
   through but reported. The assessment client
   (`dlp_assessment_full_auto.Client`) does the same: a 429 asking for
   more than 30 s, or naming an hourly limit, is not retried; the tenant
   is held for the whole wait (`zia_rate.hold(..., reads=True)`) and
   every job on it, in any process, sends nothing until it has passed.
   A refused read holds every job's reads on the tenant; a hold after a
   refused write leaves reads alone.
8. **A duplicate the plan did not see is reused, not fatal.** ZIA compares
   names without regard to case, and a predefined dictionary's display
   name (CRED_LEAKAGE is shown as "Private Key") is taken too. A pack
   dictionary that carries one of the display names Zscaler Made Easy knows
   (`dlp_importer.PREDEFINED_DISPLAY_NAMES`) is renamed `Z-<name>` when
   the pack is loaded, its engine references rewritten, and the plan and
   the deploy log say so (`heal_predefined_names`, applied by every
   loader the way `ship_monitor` is; the pack file is never modified).
   One the list does not know is still marked as a conflict in the plan,
   with the fix in words. If ZIA still refuses a create as a duplicate at
   write time (an object made between the plan and the write), the
   existing object is looked up by name and reused, so its dependents are
   built instead of skipped.

## 3. What a run returns

`apply()`, `remove()`, `remove_deployment()`, `remove_selected()` and
`undo()` all return:

- `status` — `applied` / `partial` / `failed` (deploy) or `removed` /
  `partial` / `nothing` / `failed` (removal); `blocked` when write mode
  is off, `plan_changed` or `stale` when the tenant changed since the
  plan was approved (nothing is written then).
- `results` — one entry per object: `kind`, `name`, `status`, and when
  relevant `channel`, `id`, `reason`, `error`, `explanation`, `code`,
  `http_status`, `attempts`.
- `events` — one entry per write with the keys in `pack_ops.EVENT_KEYS`
  (`ts`, `run`, `op`, `kind`, `channel`, `name`, `id`, `status`, `error`,
  `explanation`, `reason`, `code`, `http_status`, `attempts`).
- `summary` — counts by status; `channels` — counts per channel (deploy).
- `read_check` / `verification` — what the read-back found.
- `activation` and `activation_required`.
- `stopped` — why the run stopped writing before the end, in words, or
  `null` when it ran through (promise 7).

The same entries are written to the Python logger `dlp_check.packs`.

### Background jobs

A deploy or removal is minutes of API calls, an activation, a wait for
ACTIVE and a read-back. The GUI does not wait on one HTTP request for
that: `POST /api/dlp-packs/apply/start` and
`POST /api/dlp-packs/removal/apply/start` (and
`POST /api/dlp-packs/terraform/start` for the Terraform hand-off, whose
zip is then fetched from `GET /api/dlp-packs/jobs/{id}/download`) run the
same function as the waiting endpoint in a thread (`pack_jobs.py`) and
return a job id at once; every tenant read logs each step
(`fetch_tenant`), so a minute of API calls is never silent;
`GET /api/dlp-packs/jobs/{id}?since=N` returns the status, the elapsed
time, the log lines from `N` on and, once finished, the same result the
waiting endpoint returns; `POST /api/dlp-packs/jobs/{id}/cancel` is the
Stop button. The waiting endpoints stay for scripts.

## 4. Adding a pack

A pack is data, never code. Put a directory beside the others with
`pack.json` and `configs/dlp_dictionaries.json`, `dlp_engines.json`,
`dlp_policies.json` (see `POLICY_PACKS.md`). Then:

1. Run `python tools/fan_out_channels.py` so every web rule gets its
   Endpoint, SaaS and Email mirror in the shape the Fed pack proved.
2. Run `python pack_terraform.py --out terraform` so the Terraform
   hand-off matches.
3. Run `python -m pytest tests`. `tests/test_pack_conventions.py`
   compares the pack with the Fed pack's rule shape and every ZIA limit;
   `tests/test_zia_contract.py` deploys it on a tenant that refuses what
   ZIA refuses; `tests/test_shared_path.py` deploys it twice and tears it
   down.

Nothing else is needed: the pack is deployed, verified and removed by the
same code as every other pack. A pack directory must not contain deploy
code, and nothing in the app may call an SDK write method directly —
`tests/test_shared_path.py::test_no_module_writes_to_the_tenant_outside_the_shared_path`
fails the build with the file and line if it does.

## 5. Adding a new kind of object

If ZIA gains a new object type a pack should carry:

1. Add the kind to `pack_ops.KINDS`, and its place in `CREATE_ORDER` and
   `DELETE_TIERS`.
2. Teach `pack_ops.validate()` its names and limits, with the tenant's
   own words in the message.
3. Add the create / update / delete branches in `pack_ops.create()`,
   `update()` and `delete()`; list it in `pack_ops.current_names()` so the
   identity check works before a delete.
4. Plan it in `pack_deploy.py` (`_plan_*`) and read it in
   `pack_channels.fetch_channel_state()`.
5. Add its refusal to the strict tenant in `tests/test_zia_contract.py`
   and a shipped example to a pack.

## 6. What is deliberately outside the path

- `rule_migrator.py` reorders and re-creates a tenant's **existing** Web
  DLP rules for the Evaluate-All migration. It is a tenant tool, not a
  pack deploy, and is gated by write mode and its own dry run.
- `proposal_apply.py` changes one field of one existing rule when a
  person approves a proposal from the continuous evaluation. It writes
  through `pack_ops.update()`.
