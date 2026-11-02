# Zscaler Made Easy vs zbp-automation

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

A comparison of two approaches to putting Zscaler DLP best-practice
configuration into a tenant. First written 2026-09-09; **refreshed
2026-10-31** against `berserkerjay/Zscaler-Made-Easy` at `dev` and the
owner's fork `berserkerjay/zbp-automation` (upstream
`mkoyfman/zbp-automation`, still the single commit `3aa1fdc`). Every item
the 2026-09-09 version listed under "what to take from each" has since
been built into Zscaler Made Easy; section 6 says where.

## 1. What each one is

**zbp-automation** is a set of three independent Terraform workspaces.
Each one declares a fixed Zscaler Best Practice ("ZBP") configuration
as `zscaler/zia` provider resources and applies it with `terraform
apply`. There is no UI, no server, and no assessment. Two of the three
workspaces are produced by Python generators from private source files
on the author's machine.

**Zscaler Made Easy** is an application. A FastAPI server and a browser GUI run
on the administrator's machine, read the tenant through OneAPI, score it
against 300+ checks, map findings to compliance frameworks, and (behind
explicit write gates) deploy, update and remove policy packs through a
guided preflight, approve and apply flow. Every pack is also generated as
a Terraform workspace for the same `zscaler/zia` provider, from the same
pack JSON the in-app deploy reads.

They overlap on shipping a pack of dictionaries, engines and rules into a
tenant, and now also on Terraform: Zscaler Made Easy produces the kind of
workspace zbp-automation is, for every pack it ships. Everything else is
different.

## 2. Facts side by side

| | zbp-automation | Zscaler Made Easy |
|---|---|---|
| Shape | 3 Terraform workspaces + 2 generator scripts | FastAPI server, browser GUI (many pages), CLI scripts, MCP server, a generated Terraform workspace per pack |
| Size | 29 files, ~4.2k lines (1.8k of it generated/exported JSON) | ~210k lines of Python (tests included), about 290 API endpoints |
| History | 1 commit | Continuous development (see CHANGELOG.md) |
| Tenant reads | None beyond provider data sources | 300+ automated checks, ZCC diagnostics, bypass inventory, DLP efficacy scoring, traffic path and SSL inspection flow |
| Packs shipped | Enterprise (31 dict / 9 eng / 6 web rules), Endpoint (3 rules, 5 sub-rules, 1 app group), Source-code (3 dict / 3 eng / 1 rule) | Six: Fed (72 dict / 17 eng / 68 rules), CJIS (26 / 14 / 56), Global Banking (36 / 13 / 52), Healthcare PHI (28 / 12 / 48), ZBP Enterprise (31 / 9 / 36), Source Code to AI (31 / 14 / 56); each pack's rules on all four channels |
| Channels | Web DLP, Endpoint DLP | Web DLP, Endpoint DLP, SaaS Security API (CASB), Email DLP (plus the ZIA control policies the builders and Bulk changes manage) |
| Endpoint depth | Parent rules, sub-rules, application groups, user-confirmation template lookup, `ANY` expansion | Parent rules, sub-rules, application groups, user-confirmation template for CONFIRM, transfer method per rule, and a literal `["ANY"]` trust or risk level list expanded to every level (deploy and Terraform); `ANY` mixed with levels is refused with the reason |
| Apply model | Declarative, Terraform state, `plan`/`apply`/`destroy`/`import` | In the app: name-matched plan, create or reuse, an opt-in converge mode that updates differing pack objects, in-app removal. As Terraform: generated workspaces, with `import {}` blocks in gap mode |
| Pre-apply safety | `terraform plan`; README warns to import or clean up existing `ZBP-` objects by hand | Preflight resolves every dependency against the live tenant, flags conflicts, rule-order shift, enforcing actions, rule cap; plan hash binds approval; post-apply verify |
| Existing objects | Terraform tries to create duplicates unless imported | Reused by name; differences reported, or overwritten only in converge mode; gap-mode Terraform imports them |
| Provider / API | Provider 4.7.26 (enterprise) and 4.8.0 (endpoint, source-code), OneAPI auth | zscaler-sdk-python OneAPI in the app; generated workspaces pin provider `~> 4.8` with OneAPI variables (the hand-written 3.x CJIS module is retired) |
| Activation | `zia_activation_status` resource in every workspace | The in-app deploy activates once after the last write (on by default, can be turned off); workspaces carry `zia_activation_status` behind `var.activate` |
| Credentials | `TF_VAR_*` / `ZSCALER_*` env or ignored `terraform.tfvars`, marked sensitive | Typed into the GUI per session, env fallback, secret kept only in the browser tab unless "remember" is ticked on a saved profile (keyring, else the owner-only profile file), masked in errors; workspace variables are `sensitive` |
| Write protection | None beyond Terraform's plan/apply prompt | Read-only by default; every write needs write mode, a writer, a named assessor and a typed confirmation, then plan hash, re-read before write, read-back, Undo and the audit log |
| Tests / CI | None | 5,000+ pytest tests (browser checks included); GitHub Actions runs them, JS syntax, `terraform fmt -check` and `validate` on the generated workspaces |
| Reproducibility | Generators hard-code absolute paths on the author's machine to a private skill and private tenant exports; only the generated output is usable by others | Everything needed is in the repo; packs are plain JSON under `configs/`; `terraform/<pack>/` is regenerated from them |
| Docs | Clear per-workspace READMEs; honest about provider limitations; migration guide | README, OVERVIEW, ARCHITECTURE, POLICY_PACKS guide, GETTING_STARTED, in-app help on every control |
| Distribution | `terraform init/apply` from a checkout | Windows installer, desktop shortcut, update/stop scripts, a no-install edition |

## 3. zbp-automation

### Pros

- **Real infrastructure-as-code.** Terraform state gives an exact record
  of what the tool owns, a diff on every run, `destroy` in
  dependency-safe order, and `import` for objects that already exist.
  Re-running is idempotent by construction.
- **Native provider resources for Endpoint DLP.** It uses the 4.8.0
  primitives (`zia_endpoint_dlp_rules`, `zia_endpoint_dlp_sub_rules`,
  `zia_endpoint_dlp_application_group`) and handles the awkward parts:
  expanding `ANY` selectors the provider rejects, resolving the default
  user-confirmation template for `CONFIRM`, and `ignore_changes` for the
  application-group field the API does not read back. (Zscaler Made Easy
  now does all of these too.)
- **Managed-name convention.** Every object gets a `ZBP-` / `zbp-`
  prefix and a description recording its provenance.
- **Dynamic AI/ML scope.** The source-code workspace resolves the
  current `AI_ML` cloud-application catalogue at plan time with a
  precondition that fails loudly if it resolves to nothing.
- **Activation is part of the graph.** `zia_activation_status` depends
  on the rules, so a successful apply ends activated.
- **Small and legible.** A reviewer can read the entire thing in an
  hour. Provider versions are pinned and lock files are committed.
- **Honest documentation.** Each README states what the provider cannot
  do (`include_ssn_numbers`, `hierarchical_dictionary`), warns about
  existing objects, and recommends `-parallelism=1`.

### Cons

- **Not reproducible from source.** Both generators default to absolute
  paths on the author's machine and import a private `fed_policy_pack`
  skill module. Nobody else can regenerate the enterprise template or
  the endpoint JSON. Only the committed outputs are usable.
- **No pre-apply intelligence.** If `ZBP-` objects exist, Terraform will
  try to create duplicates and fail on name collisions. There is no
  conflict detection, no dependency check for the three `PCI - *`
  engines the endpoint pack requires, and no impact statement.
- **Silent rule-order collisions.** `policy_starting_order` defaults to
  1. In a tenant with existing web DLP rules this inserts at the top and
  shifts every rule down, with nothing telling the operator.
- **Enterprise rules ship disabled.** All six web DLP rules are
  `state = DISABLED`, `action = ALLOW`, `protocols = ANY_RULE`,
  `severity = INFO`. Safe, but a monitor pack that monitors nothing
  until someone edits six rules in the portal.
- **No tests, no CI, one commit.** `terraform validate` is documented
  but not automated.
- **658 lines of superseded code.** `scripts/endpoint_dlp_tf.py` is the
  old `local-exec` wrapper the migration guide tells you not to use. It
  reaches into the SDK's private `_request_executor` and will break on
  an SDK update.
- **Provider drift between workspaces.** Enterprise is pinned to exactly
  `4.7.26`; the others to `4.8.0`.
- **Narrow scope by design.** Web and endpoint only; no CASB or email
  DLP; no way to see what the tenant looks like before or after.

## 4. Zscaler Made Easy

### Pros

- **Assessment first.** 300+ checks, bypass inventory, DLP efficacy
  scoring, ZCC endpoint diagnostics, traffic and SSL inspection flow,
  compliance mapping, Word, PDF and Excel reports. The deploy features
  sit on top of a clear picture of the current state.
- **Preflight is the strongest part of either project.** Before a write,
  the planner merges the selected packs, resolves every dictionary,
  engine, template, SaaS tenant, notification template, label and
  application class by name against the live tenant, and classifies
  each item as create, reuse, update, kept-as-is, conflict, blocked or
  skipped. It reports rule-order shift with before/after numbers, the
  web DLP rule cap, enforcing versus monitor-only actions, rank-0 use,
  and changes to existing tenant objects. The approval is bound to a plan
  hash, so a tenant that changed between review and apply is refused.
- **A lifecycle in the app and in Terraform.** Packs deploy, update in
  place in converge mode, and are removed in dependency order
  (`pack_removal.py`: only objects the app tagged or a pack names, and
  anything a customer object still uses is kept and listed). The same
  packs are generated as Terraform workspaces (static, or gap mode with
  `import {}` blocks for what already exists), so a platform team gets
  state, drift and `destroy` from the provider.
- **Four channels with prerequisite checks.** Web, endpoint, SaaS
  Security API and email rules share one dictionary-engine chain; each
  channel's tenant prerequisites are checked, and Endpoint DLP has
  sub-rules, application groups and the CONFIRM template.
- **Provenance on every object.** Each description ends with
  `[<assessor> pack <id> v<version>]`, so a tenant admin can see who put
  an object there and from which pack; packs ship `ZBP-`-style names.
- **Dynamic `AI_ML` scope** for the source-code pack, with a preflight
  blocker when it resolves to nothing (and the same in Terraform).
- **Explicit write gates.** Read-only by default; write mode, a writer,
  a named assessor and a typed confirmation for every change, a re-read
  right before each write, read-back, Undo and the audit log.
- **More than packs.** Bulk changes (rule state, rule order, URL
  categories, ZPA segment domains and settings), builders for ZPA, Client
  Connector, ZDX and AI Guard objects, a custom URL category analyzer that
  continues past its per-run cap, migration from other DLP vendors.
- **Tested and continuously checked.** Thousands of tests, browser
  checks, and CI that also runs `terraform fmt -check` and `validate` on
  the generated workspaces.
- **Usable by non-engineers.** Installer, guided steps, plain-language
  impact cards and help on every control. No Terraform knowledge
  required.
- **Self-contained packs.** A pack is a folder of JSON; adding one needs
  no code, and a zbp-style `.tf.json` can be imported as a pack
  (`tools/pack_from_terraform.py`).

### Cons

- **Name-matched ownership in the app.** The in-app deploy owns objects
  by name and provenance tag, not by a state file; converge mode and
  removal work on that basis. Teams that want state use the generated
  Terraform instead.
- **Big surface.** A large Python code base and many GUI pages carry
  real maintenance cost.
- **Imperative writes.** The in-app apply path is Python calling the SDK
  object by object. It is careful (re-read, read-back, Undo), but it is
  bespoke code that has to be kept correct, where Terraform gets
  correctness from the provider.
- **No deploy-time name prefix.** A pack's names are what the pack
  declares; an operator cannot choose a prefix at deploy time (it would
  work against reuse by name).
- **Credentials live in a browser tab.** The secret is not persisted
  unless "remember" is ticked on a saved profile, but it is typed into a
  page and sent with every request. Fine for a single-user desktop tool,
  weaker than `sensitive` Terraform variables in a CI pipeline (which the
  generated workspaces use).
- **No endpoint-only pack.** The PCI-only Endpoint DLP pack was retired
  (2026-09-11) because every pack now mirrors its rules onto Endpoint DLP;
  see section 6.

## 5. Head to head

**Safety before writing:** Zscaler Made Easy, clearly. Terraform's `plan` shows
resource-level intent; Zscaler Made Easy's preflight shows tenant-level impact
and refuses to proceed on conflicts or drift.

**Safety after writing:** now close. zbp-automation has Terraform's state,
`destroy`, `import` and diff. Zscaler Made Easy has read-back, Undo, the
audit log, converge mode and in-app removal, and hands the same packs over
as Terraform workspaces for teams that want state.

**Coverage:** Zscaler Made Easy on channels (four versus two), on Endpoint
DLP depth (now at parity) and on everything that is not deployment.

**Portability and reuse:** Zscaler Made Easy. Everything is in the repo and
packs are plain JSON. zbp-automation's outputs are reusable; its inputs
and generators are not.

**Engineering hygiene:** Zscaler Made Easy on tests, CI and history, and now
on pinned providers and `terraform fmt`/`validate` in CI too.
zbp-automation on small blast radius.

**Operator experience:** Zscaler Made Easy for an administrator; for a
platform engineer with a Terraform pipeline, either: zbp-automation's
three workspaces, or Zscaler Made Easy's generated one for any pack.

## 6. What to take from each

Into Zscaler Made Easy: everything the 2026-09-09 version recommended is
built.

1. **Terraform generated from the pack JSON**, provider `~> 4.8`, OneAPI
   variables, `D${…}.S` dictionary references, predefined dictionaries as
   data sources and `zia_activation_status`: done (`pack_terraform.py`,
   `terraform/<pack>/` for all six packs, static and gap modes). The
   hand-written 3.x CJIS module is retired (now generated, the S3 backend
   commented out).
2. **Endpoint sub-rules and application groups, the CONFIRM template and
   `ANY` expansion**: done (`pack_channels.py` sub-rules and application
   groups; the default user-confirmation template in deploy and
   Terraform; a literal `["ANY"]` device trust or user risk level list is
   expanded to every level on load, in deploy and Terraform alike, and
   `ANY` mixed with other levels, or an unknown level, is refused).
3. **Managed names and provenance**: done (`pack_deploy.py` provenance
   tags in every description; packs declare their prefix). A prefix the
   operator picks at deploy time is left out on purpose (it conflicts
   with reuse by name).
4. **Dynamic `AI_ML` scoping** with a blocker when it resolves to
   nothing: done (`pack_channels.py`, and in Terraform).
5. **Activation as the final step**: done, on by default and optional
   (`pack_deploy.py` `activate`; Terraform `var.activate`).
6. **Lifecycle (plan, import, update, remove)**: done (gap mode
   `import {}` blocks; converge mode; `pack_removal.py`).
7. **CI** `terraform fmt -check` and `validate`, multi-platform lock
   files: done (`.github/workflows/tests.yml`, `tools/terraform_samples.py`).
8. **Import a zbp-style `.tf.json` as a pack**: done
   (`tools/pack_from_terraform.py`).

The **Endpoint DLP pack content** (3 rules, 5 sub-rules, 1 application
group, PCI engines) shipped once as `zbp_endpoint_dlp_baseline` and was
retired on 2026-09-11 (CHANGELOG "Packs"): every pack now mirrors its
rules onto Endpoint DLP, so a PCI-only endpoint pack added no coverage.
The machinery it needed stays (sub-rules, application groups, CONFIRM,
`ANY` expansion), and *Remove rules from this tenant* still recognises the
retired pack's objects by name (`pack_removal.py`). If a dedicated endpoint pack
is wanted again, it can be built on that machinery.

Into zbp-automation, if it were being maintained here:

1. Preflight against the live tenant before `apply`, or at minimum a
   data-source check that the required engines exist and a warning on
   rule-order shift.
2. Remove the absolute paths; vendor the pack JSON so the generators run
   anywhere.
3. Delete the superseded `endpoint_dlp_tf.py`.
4. A CI job running `terraform fmt -check` and `validate` per workspace.
5. Align both workspaces on one provider version.

## 7. Bottom line

zbp-automation is a clean, honest set of Terraform templates that does
one thing with proper state management. It is not a product: it cannot
be regenerated by anyone but its author, has no tests, and leaves every
tenant-awareness problem to the operator.

Zscaler Made Easy is a product. It assesses, explains, deploys with more
pre-write safety than Terraform offers, covers four channels, is tested,
and has closed the gaps the first comparison found: every pack is now a
generated Terraform workspace for the same provider, Endpoint DLP has
sub-rules, application groups, CONFIRM and `ANY` expansion, and packs can
be updated and removed in the app. What remains different is the
ownership model inside the app (by name and provenance tag rather than a
state file), and that is a choice: teams that want state take the
Terraform workspace.
