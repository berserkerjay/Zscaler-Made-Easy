# Example local plugin (not loaded by default)

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

A tiny plugin showing the local plugin API. It is **not** loaded: plugins
load only from the folder `DLP_CHECK_PLUGINS_DIR` names, only when local
plugins are switched on in Advanced settings, and only when an admin has
approved the plugin's exact SHA-256 there. Read SECURITY.md ("Local
plugins") before using any plugin: a plugin is code that runs inside the
app with the app's privileges.
