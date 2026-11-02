# Stage 3 — Verify: is it really done?

**One job:** check, skeptically and read-only, that a branch (or the app) does what a spec or feature list says. You did not build it; don't trust its report, its CHANGELOG or its docs. You do not fix anything.

## Inputs
- `_config/token-efficiency.md` (always).
- What to check against: `output/<run>/specs/<slug>.md`, or a feature table you were given.
- What was claimed: `output/<run>/build/<slug>.md` (claims to test, not facts).
- The code: the branch, read with `git show <branch>:<path>` / `git grep`, or a detached worktree.
- `_config/product-rules.md` and `_config/naming.md`.

## Process
1. For each acceptance test or feature row: find the implementation (file:line) and the test that proves it. No test, no ✅.
2. Rate each: ✅ present and proven · ◐ partial (say exactly what's missing) · ❌ absent · N/A by design (say why).
3. Check the safety promises in `IDENTITY.md` for everything the branch adds: gates, scope, secrets, untrusted input, outbound calls.
4. Grep for the forbidden names in `_config/naming.md`.
5. List what rests on "assumed" Zscaler behaviour or is proven only against fakes.

## Outputs
- `output/<run>/verify/<slug>.md`: a table (item · status · evidence · gap), the safety checklist, a fix for every non-✅ item, and counts.

## Review gate
Non-✅ items go back to stage 1 as new specs; a clean report lets stage 4 merge the branch.
