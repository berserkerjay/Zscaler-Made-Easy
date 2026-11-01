# Run outputs

Each run of the pipeline gets a folder here, `output/<run>/`, holding the plain-text hand-offs between stages:

```
output/<run>/
  specs/<slug>.md        stage 1 — what to build (edit before stage 2 if you disagree)
  build/<slug>.md        stage 2 — what was built, on which branch, with test counts
  verify/<slug>.md       stage 3 — independent check, item by item
  merge-queue.md         stage 4 input — verified branches in order, with notes
  integrate.md           stage 4 — merges, conflicts, defects, final counts
  release.md             stage 5 — hosting checks, PRs, update command
```

Every file is an edit surface: the reviewer can change it before the next stage reads it. Run folders are not committed (they can hold tenant-specific or third-party detail); only this README is.
