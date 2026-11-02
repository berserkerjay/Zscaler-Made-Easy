# Where do I go?

Find your stage, open its `CONTEXT.md`, and load only what its **Inputs** list names.

| You were asked to… | Stage |
|---|---|
| turn a request, a gap or a finding into a buildable task | `stages/01-spec/` |
| implement one task spec | `stages/02-build/` |
| check a built branch (or the app) against a spec or a feature list | `stages/03-verify/` |
| merge finished branches and get the combined code green | `stages/04-integrate/` |
| validate hosting and promote to `main` | `stages/05-release/` |

- Rules that apply: `_config/_index.md` (read the index, then only the files your stage names).
- Facts about the code: `references/_index.md` (architecture map, task-to-files map, "assumed" register).
- Work of a run: `output/<run>/` — each stage reads the previous stage's file there and writes its own.

Keep your context small: a stage should need 2,000–8,000 tokens of these files, not the whole repository.
