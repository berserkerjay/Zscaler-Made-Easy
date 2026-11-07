# Stage 4 — Integrate: one green tree

**One job:** merge verified branches into the integration branch and make the combined code pass the full suite. You resolve conflicts and fix integration breakage; you don't add features.

## Inputs
- `_config/token-efficiency.md` (always).
- `output/<run>/merge-queue.md`: the verified branches, in order, with any merge notes.
- `_config/shared-files.md` (how each conflicting file is resolved), `_config/git.md`, `_config/testing.md`.
- The verify reports in `output/<run>/verify/` for the branches you merge.

## Process
1. Merge one branch at a time (`--no-ff`); resolve each conflict as `_config/shared-files.md` says, never by taking one side blindly; regenerate generated files with their own tools.
2. After each merge: syntax checks and the targeted tests for the areas both sides touched. Push.
3. Every few merges, and at the end, run the full suite through the shared runner; rerun failing files alone to separate load timeouts from real failures; fix integration breakage; send real defects back to stage 1.
4. When the full suite is 0 failed: record the test run with the score tool, regenerate the score, push.
5. Archive child cloud sessions once their work is merged; answer their questions and blocked prompts yourself (the coordinator), never leave them for the owner.

## Outputs
- The integration branch, pushed, with a full-suite run of 0 failed.
- `output/<run>/integrate.md`: merges done · each conflict and how it was resolved · defects found per branch · final counts.

## Review gate
The coordinating session reads the report before stage 5.
