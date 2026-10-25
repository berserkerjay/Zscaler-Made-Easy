# Zscaler Made Easy vs zbp-automation

A comparison of two approaches to putting Zscaler DLP best-practice
configuration into a tenant. Written 2026-09-09 against
`berserkerjay/DLP-Check` at `main` and the fork
`berserkerjay/zbp-automation` (upstream `mkoyfman/zbp-automation`,
single commit `3aa1fdc`).

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
an explicit write gate) deploy policy packs through a guided preflight,
approve and apply flow. Terraform exists for one pack as a secondary
export.

They overlap on exactly one thing: shipping a pack of dictionaries,
engines and rules into a tenant. Everything else is different.

## 2. Facts side by side

| | zbp-automation | Zscaler Made Easy |
|---|---|---|
| Shape | 3 Terraform workspaces + 2 generator scripts | FastAPI server, single-page GUI, CLI scripts, MCP server |
| Size | 29 files, ~4.2k lines (1.8k of it generated/exported JSON) | 67 tracked source files, ~19k lines Python, 5.7k-line GUI, 50 API endpoints |
| History | 1 commit | Continuous development, 7 merged PRs this week alone |
| Tenant reads | None beyond provider data sources | 308 automated checks, ZCC diagnostics, bypass inventory, DLP efficacy scoring |
| Packs shipped | Enterprise (31 dict / 9 eng / 6 web rules), Endpoint (3 rules, 5 sub-rules, 1 app group), Source-code (3 dict / 3 eng / 1 rule) | Fed (49 dict / 17 eng / 13 rules), CJIS (16 dict / 10 eng / 13 rules) |
| Channels | Web DLP, Endpoint DLP | Web DLP, Endpoint DLP, SaaS Security API (CASB), Email DLP |
| Endpoint depth | Parent rules, sub-rules, application groups, user-confirmation template lookup | Parent rules only |
| Apply model | Declarative, Terraform state, `plan`/`apply`/`destroy`/`import` | Imperative, name-matched, create-or-reuse, never overwrite, no destroy |
| Pre-apply safety | `terraform plan`; README warns to import or clean up existing `ZBP-` objects by hand | Preflight resolves every dependency against the live tenant, flags conflicts, rule-order shift, enforcing actions, rule cap; plan hash binds approval; consent checkbox; post-apply verify |
| Existing objects | Terraform tries to create duplicates unless imported | Reused by name; content differences reported as warnings |
| Provider / API | Provider 4.7.26 (enterprise) and 4.8.0 (endpoint, source-code), OneAPI auth | zscaler-sdk-python OneAPI everywhere; the one Terraform module pins provider `~> 3.0` with legacy username/password/API-key auth |
| Activation | `zia_activation_status` resource in every workspace | Reminder card after deploy; activation left to the admin |
| Credentials | `TF_VAR_*` / `ZSCALER_*` env or ignored `terraform.tfvars`, marked sensitive | Typed into the GUI per session, env fallback, secret kept only in the browser tab unless "remember" is ticked on a saved profile (keyring, else the owner-only profile file), masked in errors |
| Write protection | None beyond Terraform's plan/apply prompt | Server refuses all writes unless `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`; separate launcher |
| Tests / CI | None | 32 pytest tests; GitHub Actions runs compile, JS syntax, tests, and a server smoke test on every push |
| Reproducibility | Generators hard-code `/Users/michaelkoyfman/...` paths to a private MCP skill and private tenant exports; only the generated output is usable by others | Everything needed is in the repo; packs are plain JSON under `configs/` |
| Docs | Clear per-workspace READMEs; honest about provider limitations; migration guide | README, ARCHITECTURE, POLICY_PACKS guide, GETTING_STARTED, Word checklists |
| Distribution | `terraform init/apply` from a checkout | Windows installer, desktop shortcut, update/stop scripts |

## 3. zbp-automation

### Pros

- **Real infrastructure-as-code.** Terraform state gives what Zscaler Made Easy
  does not have: an exact record of what the tool owns, a diff on every
  run, `destroy` in dependency-safe order, and `import` for objects that
  already exist. Re-running is idempotent by construction.
- **Native provider resources for Endpoint DLP.** It uses the 4.8.0
  primitives (`zia_endpoint_dlp_rules`, `zia_endpoint_dlp_sub_rules`,
  `zia_endpoint_dlp_application_group`) and handles the awkward parts:
  expanding `ANY` selectors the provider rejects, resolving the default
  user-confirmation template for `CONFIRM`, and `ignore_changes` for the
  application-group field the API does not read back. Zscaler Made Easy's
  endpoint channel has none of this depth.
- **Managed-name convention.** Every object gets a `ZBP-` / `zbp-`
  prefix and a description recording its provenance. Anyone looking at
  the tenant can tell what the tool created.
- **Dynamic AI/ML scope.** The source-code workspace resolves the
  current `AI_ML` cloud-application catalogue at plan time with a
  precondition that fails loudly if it resolves to nothing. New Zscaler
  AI classifications are picked up automatically.
- **Activation is part of the graph.** `zia_activation_status` depends
  on the rules, so a successful apply ends activated.
- **Small and legible.** A reviewer can read the entire thing in an
  hour. Provider versions are pinned and lock files are committed.
- **Honest documentation.** Each README states what the provider cannot
  do (`include_ssn_numbers`, `hierarchical_dictionary`), warns about
  existing objects, and recommends `-parallelism=1`.

### Cons

- **Not reproducible from source.** Both generators default to absolute
  paths on the author's Mac and import a private `fed_policy_pack`
  skill module. Nobody else can regenerate the enterprise template or
  the endpoint JSON. Only the committed outputs are usable.
- **No pre-apply intelligence.** If `ZBP-` objects exist, Terraform will
  try to create duplicates and fail on name collisions. The README's
  answer is "clean the tenant or import by hand". There is no conflict
  detection, no dependency check for the three `PCI - *` engines the
  endpoint pack requires, and no impact statement.
- **Silent rule-order collisions.** `policy_starting_order` defaults to
  1. In a tenant with existing web DLP rules this inserts at the top and
  shifts every rule down, with nothing telling the operator.
- **Enterprise rules ship disabled.** All six web DLP rules are
  `state = DISABLED`, `action = ALLOW`, `protocols = ANY_RULE`,
  `severity = INFO`. Safe, but a monitor pack that monitors nothing
  until someone edits six rules in the portal.
- **No tests, no CI, one commit.** `terraform validate` is documented
  but not automated. Nothing guards a regeneration from breaking the
  templates.
- **658 lines of superseded code.** `scripts/endpoint_dlp_tf.py` is the
  old `local-exec` wrapper the migration guide tells you not to use. It
  reaches into the SDK's private `_request_executor` and will break on
  an SDK update.
- **Provider drift between workspaces.** Enterprise is pinned to exactly
  `4.7.26`; the others to `4.8.0`. Two `init` runs in one repo.
- **Narrow scope by design.** Web and endpoint only; no CASB or email
  DLP; no way to see what the tenant looks like before or after.

## 4. Zscaler Made Easy

### Pros

- **Assessment first.** Nothing else here reads the tenant. 308 checks,
  bypass inventory, DLP efficacy scoring, ZCC endpoint diagnostics,
  compliance mapping to eight frameworks, Word and CSV reports. The
  deploy features sit on top of a clear picture of the current state.
- **Preflight is the strongest part of either project.** Before a write,
  the planner merges the selected packs, resolves every dictionary,
  engine, template, SaaS tenant, notification template and label by
  name against the live tenant, and classifies each item as create,
  reuse, kept-as-is, conflict, blocked or skipped. It reports rule-order
  shift with concrete before/after numbers, the 127-rule web DLP cap,
  enforcing versus monitor-only actions, rank-0 use, and modifications
  to existing tenant objects. The approval is bound to a plan hash, so a
  tenant that changed between review and apply is refused.
- **Never overwrites.** Existing objects are reused; differences are
  surfaced, not clobbered. Deploy is per-item isolated and followed by a
  verification read.
- **Four channels with prerequisite checks.** Web, endpoint, SaaS
  Security API and email rules share one dictionary-engine chain, and
  each channel's tenant prerequisites are checked and listed.
- **Explicit write gate.** The server refuses any write unless an
  environment variable is set to a specific phrase and a separate
  launcher is used. Read-only is the default posture.
- **Tested and continuously checked.** Planner, executor, channel
  resolution, and the GUI injection all have tests; CI runs them plus
  a live server smoke test on every push.
- **Usable by non-engineers.** Installer, desktop shortcut, a guided
  four-step sheet with a dependency flow diagram, plain-language impact
  cards, and a consent step. No Terraform knowledge required.
- **Self-contained packs.** A pack is a folder of JSON; adding one needs
  no code. Both packs are complete in the repo.

### Cons

- **No state, so no lifecycle.** Zscaler Made Easy can create and verify, but it
  cannot destroy what it created, detect drift after the fact, or show a
  diff against a previous apply. "Reuse by name" is the whole ownership
  model. If a pack changes, the tool cannot update objects it made
  earlier; it reports them as "kept as-is (differs)".
- **The Terraform export is behind the rest of the tool.** The CJIS
  module pins provider `~> 3.0` with legacy username/password/API-key
  auth and a hard-coded GovCloud S3 backend, while every other part of
  the app is OneAPI. It is hand-written rather than generated from the
  pack JSON, so it can drift from `configs/`. zbp-automation is on
  4.7/4.8 with OneAPI auth.
- **Endpoint channel is shallow.** No sub-rules, no application groups,
  no user-confirmation template resolution. zbp-automation's endpoint
  pack cannot be expressed as a Zscaler Made Easy pack today.
- **Big surface, monolithic GUI.** ~19k lines of Python and a 5.7k-line
  single-file page carry real maintenance cost, and this week's history
  shows it: a pop-out feature and an injection helper both broke the
  credential form in ways only a browser test caught.
- **Imperative writes.** The apply path is Python calling the SDK
  object by object. It is careful, but it is bespoke code that has to be
  kept correct, where Terraform gets correctness from the provider.
- **Activation is manual.** After a deploy the admin still has to
  activate in the portal.
- **Credentials live in a browser tab.** The secret is not persisted unless "remember" is ticked on a saved profile,
  but it is typed into a page and sent with every request. Fine for a
  single-user desktop tool, weaker than `sensitive` Terraform variables
  in a CI pipeline.

## 5. Head to head

**Safety before writing:** Zscaler Made Easy, clearly. Terraform's `plan` shows
resource-level intent; Zscaler Made Easy's preflight shows tenant-level impact
and refuses to proceed on conflicts or drift.

**Safety after writing:** zbp-automation. State, destroy, import and
diff are the whole point of Terraform, and Zscaler Made Easy has no equivalent.

**Coverage:** Zscaler Made Easy on channels (four versus two) and on everything
that is not deployment. zbp-automation on endpoint depth.

**Portability and reuse:** Zscaler Made Easy. Everything is in the repo and
packs are plain JSON. zbp-automation's outputs are reusable; its inputs
and generators are not.

**Engineering hygiene:** Zscaler Made Easy on tests, CI and history.
zbp-automation on pinned providers, lock files and small blast radius.

**Operator experience:** Zscaler Made Easy for an administrator; zbp-automation
for a platform engineer with an existing Terraform pipeline.

## 6. What to take from each

Into Zscaler Made Easy, in priority order:

1. **Generate Terraform from the pack JSON** the way
   `generate_zbp_enterprise_tf.py` does, targeting provider 4.8.x with
   OneAPI variables, dictionary references as
   `D${zia_dlp_dictionaries.x.id}.S`, predefined and template
   dictionaries as data sources, and a `zia_activation_status` resource.
   Retire the hand-written 3.x CJIS module. This gives every pack a
   state-managed lifecycle without changing Deploy Studio.
2. **Endpoint sub-rules and application groups** in `pack_channels.py`,
   including `ANY` selector expansion and default user-confirmation
   template lookup for `CONFIRM`.
3. **A managed-name prefix** option per pack (`ZBP-` style) with
   provenance in descriptions, so tenant admins can see what the tool
   created and the reuse-by-name model gets a namespace.
4. **Dynamic `AI_ML` scoping** as a pack policy option, with a
   preflight blocker if it resolves to nothing.
5. **Optional activation** as the final apply step, off by default.

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
one thing with proper state management, and it handles Endpoint DLP
more completely than Zscaler Made Easy does. It is not a product: it cannot be
regenerated by anyone but its author, has no tests, and leaves every
tenant-awareness problem to the operator.

Zscaler Made Easy is a product. It assesses, explains, deploys with more
pre-write safety than Terraform offers, covers four channels, and is
tested. Its real gap is lifecycle: it cannot own, update or remove what
it created. The right move is not to choose between them but to add
zbp-automation's model as Zscaler Made Easy's Terraform export, generated from
the same pack JSON that Deploy Studio already reads.
