# Stage 2 — Build: implement one spec

**One job:** implement exactly one accepted spec on its own branch, with tests that prove it. You do not merge, and you do not change what the spec didn't ask for.

## Inputs
- `_config/token-efficiency.md` (always).
- `output/<run>/specs/<slug>.md` (your spec).
- `_config/_index.md`, then: `product-rules.md`, `git.md`, `testing.md`, `shared-files.md`; `safe-writes.md` if the spec writes to a tenant; `scope-and-routes.md` if it adds a route; `ui.md` if it changes a page; `zscaler-sdk.md` if it calls the API.
- Only the source files the spec's **Files** section names (plus what they import that you must call).

## Process
1. Create the worktree and branch named in `_config/git.md` (never work in the main checkout).
2. Write the acceptance tests first; run them and see them fail.
3. Implement until they pass. Verify every Zscaler API detail against the installed SDK or mark it assumed in a code comment and in your output.
4. Register new routes, write types, help entries and release marks as the config files say.
5. Run your tests plus the existing test files for every module you touched (`_config/testing.md`); not the full suite.
6. Commit early and often; push the branch.

## Outputs
- The pushed branch.
- `output/<run>/build/<slug>.md`: branch and last commit · what was built (with SDK calls) · assumed items · files changed · tests added and the counts you ran · shared files touched · anything left open.

## Review gate
Stage 3 verifies the branch against the spec before it is merged.
