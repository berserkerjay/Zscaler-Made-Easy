# Patch transfer bundle (temporary)

Carries two commits for `claude/review-repo-xRk8y` as a gzip+base64 git mbox,
split into hash-verified chunks, because the authoring sandbox lost its git
push path. Run `bash transfer/apply.sh` from a clone with push access.

Commits carried (on top of 4e17c78cb166863bcaa6588435ebdee0bc55a834):

1. Policy pack Deploy Studio: multi-pack preflight, impact review, approval gate
2. Deploy Studio: dependency flow diagram (templates → dictionaries → engines → policies)

The script deletes this branch after a successful push.
