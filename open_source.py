"""The open-source note every Zscaler Made Easy document carries: Apache-2.0, built from information Zscaler and third parties provide.

One wording, kept here so the document generators (tools/quality_score.py,
tools/security_test_matrix.py, tools/agent_workspace.py, tools/sbom_enrich.py,
pack_terraform.py) and the tests use the same words as the hand-written
documents and the app's help page (static/help.html) and Advanced settings
(static/report_advanced.html).
"""

# Markdown form: the bold lead-in, then the note.
NOTE_MD = ("**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). "
           "It is built entirely from information provided by Zscaler (its public documentation, public API and "
           "open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an "
           "official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.")

# The same words without markup, for plain-text files and the app's pages.
NOTE_TEXT = NOTE_MD.replace("**", "")

# What a test looks for after collapsing whitespace and markup: the note
# without its lead-in, so a wrapped or re-marked-up copy still matches.
NOTE_BODY = NOTE_TEXT.split("Open source. ", 1)[1]
