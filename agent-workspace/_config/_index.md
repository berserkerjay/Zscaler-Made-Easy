# What rules apply? (index)

Read this table, then load only the files your stage's Inputs name.

| File | Summary |
|------|---------|
| product-rules.md | The non-negotiable safety rules in full: gates, scope, secrets, untrusted input, outbound calls, unknown-not-match |
| safe-writes.md | The one write engine (`admin_ops`): how a change is planned, previewed, gated, re-read, written, read back, undone and audited; a skeleton for a new operation type |
| scope-and-routes.md | Adding an API route: Scope-page keys, the 400-before-sign-in rule, the safety tables and the team-mode route rules every route must appear in |
| testing.md | Test style (standards line, determinism, fakes, sample tenant), which test files cover what, browser test setup, the shared runners, what "proved" means |
| shared-files.md | Files every branch touches (CHANGELOG, release marks, help catalogue, registries, generated docs) and exactly how to edit and merge each |
| ui.md | Page conventions: plain words, `?` help marks, `*` release marks, AA contrast, keyboard, 320px, escaping on output |
| zscaler-sdk.md | Working with the installed Zscaler SDK: verifying calls and fields, the client builders, raw calls outside the SDK, marking assumptions |
| naming.md | The naming rules: product name, forbidden names, old-name guard |
| git.md | Branches, worktrees, commits, attribution lines, PR flow, what never to do with git |
