# Example local plugin (not loaded by default)

A tiny plugin showing the local plugin API. It is **not** loaded: plugins
load only from the folder `DLP_CHECK_PLUGINS_DIR` names, only when local
plugins are switched on in Advanced settings, and only when an admin has
approved the plugin's exact SHA-256 there. Read SECURITY.md ("Local
plugins") before using any plugin: a plugin is code that runs inside the
app with the app's privileges.
