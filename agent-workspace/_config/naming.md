# Naming

- The product is **Zscaler Made Easy**. The old names (the first repository name and the first product name) must not appear in user-facing places; `tests/test_old_repo_name.py` and `tests/test_product_name.py` guard this, with a short list of kept forms (environment variables, HTTP header names, provenance tags, legacy clean-up) — don't add to it without a reason.
- **Never name third-party tools, their authors, their organisations or their brand words** in code, UI, docs, tests, commit messages or branch names — even tools whose ideas a feature follows. Describe the capability instead ("a community tool that exports allowlists"). The coordinating session keeps the list of names and the verify stage greps for them.
- Zscaler's own products and Zscaler's official tools (SDKs, Terraform providers) may be named.
- Commit messages and code never contain model names or identifiers of the AI that wrote them, beyond the required attribution lines (`git.md`).
