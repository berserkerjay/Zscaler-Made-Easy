# Architecture: independence between modules

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Single rule that governs every action in this app:

> **The only shared dependency between modules is tenant credentials
> (the `Client` object). Each user-visible action is self-contained
> and never kicks off execution in another module.**

## Why

Cross-module triggering creates two failure modes that this app
specifically tries to avoid:

1. **Surprise side effects.** Clicking *Step 4: Activate* used to
   silently run Step 1's full probe (rule fetch, order-safety
   calculation, action breakdown). Users couldn't see or stop it.
2. **Hidden dependencies.** A bug in module A can break module B if
   B implicitly calls A. Each module should be verifiable in
   isolation against just `(Client, its own params) → result`.

## Concrete implications

### What modules MAY share
- The authenticated `Client` object (tenant credentials + HTTP session
  + token cache + LRU response cache). This is the single approved
  shared dependency.

### What modules MUST NOT share
- Function calls into another module's main entry point.
  *Example:* `enable_evaluate_all_rules` cannot call
  `assess_current_status`. It uses the private helper
  `_probe_eval_all_field` which does only the minimal probe it needs.
- Implicit chains where one user action triggers another. Every dispatch
  must originate from an explicit user click or an explicit `await` chain
  in the same handler.
- Cached state from another module's execution. If Step 4 needs to know
  the current mode, it probes for it itself (cheap — ~3 endpoint hits)
  rather than reaching into Step 1's last-run output.

### Allowed: explicit caller-side composition
A caller (the GUI, a script, the prompt-bar dispatcher) MAY orchestrate
multiple modules in sequence as long as each call is independent and the
caller decides the order. Example:

    rules = fetch_current_rules(client, "web_dlp")    # Step 2
    plan  = optimize_for_eval_all(rules)              # Step 3 (pure fn)
    enable_evaluate_all_rules(client, dry_run=False)  # Step 4

That's fine — the caller is composing. What's not fine is Step 4's
implementation reaching into Step 1.

## Verification

Each module has a smoke test in its commit message that confirms it
runs against just `(Client, params) → result` with no side effects on
sibling modules. New PRs touching cross-module call sites should
preserve this rule and add a test demonstrating it.
