// Help on hover: the words for every control, per page (see hover_help.js).
// One JSON object: page key (the URL path, "*" for every page, "ext:..." for
// the browser extension's pages) -> CSS selector -> what the control does,
// what input it expects, and its effect (local, read, write, download, nav).
// The first selector that matches a control wins, so specific keys come
// first. Plain text only. Keep it the one place these words live: a control's
// native title is converted into its entry, not kept beside it. The browser
// extension ships a byte-identical copy (browser_extension/help_catalog.js).
window.HELP_CATALOG = {
 "pages": {
  "*": {
   "button.wn-mark": {
    "what": "Marks something that is new in this version. The first line says what is new.",
    "input": "Nothing to type. Point at it, focus it or click it to read what is new.",
    "effect": "local"
   },
   "#advWnHide": {
    "what": "Hides the * marks on new features, on every page of this app.",
    "input": "Ticked hides the marks. Unticked shows them. The choice is kept in this browser only.",
    "effect": "local"
   },
   "#faOpenBtn": {
    "what": "Opens Find anything: one search box over pages, glossary words, tenant objects, findings and to-dos. Find anything (Ctrl+J or /)",
    "input": "Nothing to type. Just click it. Ctrl+J or / opens it from the keyboard too.",
    "effect": "local"
   },
   "#faInput": {
    "what": "Searches pages, glossary words, rules, dictionaries, findings and your to-dos as you type. Typos are fine.",
    "input": "Optional. A few words, like export to Terraform, engine, or a rule name. Up and down arrows pick a result, Enter opens it.",
    "effect": "local"
   },
   "#faBack .fa-head button.fa-x": {
    "what": "Closes Find anything and goes back to where you were.",
    "input": "Nothing to type. Just click it. Esc does the same.",
    "effect": "local"
   },
   "#faLoad": {
    "what": "Reads the tenant objects in scope, like rules, dictionaries and engines, so you can search them too. It only reads.",
    "input": "Nothing to type. Sign in to the tenant first, or pick a saved tenant profile.",
    "effect": "read"
   },
   "#faBack button.fa-x[aria-label^=\"Remove tag\"]": {
    "what": "Removes this tag from the object. Tags are kept on this computer, not in the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#faBack button.fa-x[aria-label^=\"Delete to-do\"]": {
    "what": "Deletes this to-do from the object. Notes are kept on this computer, not in the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#faBack button.fa-x[aria-label=\"Delete this comment\"]": {
    "what": "Deletes this comment from the object. Notes are kept on this computer, not in the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#faTagIn": {
    "what": "Types a new tag for this object, like PHI or review.",
    "input": "Optional. A short word. Press Enter or click Add tag to save it.",
    "effect": "local"
   },
   "#faTodoIn": {
    "what": "Types a new to-do for this object.",
    "input": "Optional. A short sentence, like Enable after the change window. Press Enter or click Add to-do.",
    "effect": "local"
   },
   "#faComIn": {
    "what": "Types a comment about this object for your team.",
    "input": "Optional. Free text. Press Enter or click Add comment. Shift+Enter starts a new line.",
    "effect": "local"
   },
   "#faBack .fa-notes input[type=\"checkbox\"]": {
    "what": "Marks this to-do done, or open again.",
    "input": "Ticked means done. Unticked means still open.",
    "effect": "local"
   },
   "#faBack .fa-notes button.fa-btn": {
    "what": "Saves what you typed in the box beside it as a tag, to-do or comment on this object. It is kept on this computer, never in the tenant.",
    "input": "Type in the box beside it first.",
    "effect": "local"
   },
   "#faBack .fa-card .fa-row button.fa-btn": {
    "what": "Opens the page of the app that works on this item, or shows the finding in the results.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#faBack .fa-card button.fa-btn": {
    "what": "Goes back to the list of search results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#faBack a.fa-btn": {
    "what": "Opens the page this item belongs to, like the glossary on the help page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#faBack button.fa-chip": {
    "what": "Shows the details of this object: what it uses, what uses it, and its findings.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpSafetyBanner .sb-leave": {
    "what": "Leaves the sample tenant or the offline snapshot in this browser, then reloads the page on the live tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpSafetyBanner .sb-write .sb-btn": {
    "what": "Turns write mode off for this server, so the app can no longer change the tenant. It is read-only again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#themeToggleBtn": {
    "what": "Switches between the light and the dark look. Every tab of the app follows the choice.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows the rest of the page introduction, or folds it away again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#backHomeBtn": {
    "what": "Goes back to the assessment page. Back to the assessment page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "a[href=\"/\"]": {
    "what": "Back to the assessment page. It returns to the tab that opened this one, or loads the main page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpUnlockToken": {
    "what": "Takes this app's own UI token, which unlocks the app in this browser. It is not your Zscaler sign-in.",
    "input": "Required. Paste the token from the file ui_token.txt next to the app, or from server.log.",
    "effect": "local"
   },
   "#dlpUnlockGo": {
    "what": "Unlocks this app with the UI token you pasted.",
    "input": "Paste the UI token in the box first.",
    "effect": "local"
   },
   "#dlpUnlockCancel": {
    "what": "Closes the unlock box without unlocking. The page stays locked.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpNoticeOk": {
    "what": "Closes this message.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "dialog.dlp-dlg summary": {
    "what": "Shows or hides the technical detail behind this message.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpPhraseInput": {
    "what": "Takes the confirmation phrase shown above. Typing it proves you mean it.",
    "input": "Required. Type the phrase shown above exactly as shown.",
    "effect": "confirm"
   },
   "#dlpPhraseGo": {
    "what": "Confirms the action with the phrase you typed.",
    "input": "Type the confirmation phrase in the box first.",
    "effect": "confirm"
   },
   "#dlpPhraseCancel": {
    "what": "Closes this box and does nothing.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpAskGo": {
    "what": "Says yes to the question above and goes ahead.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpAskCancel": {
    "what": "Says no to the question above. Nothing happens.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpSignOut": {
    "what": "Signs you out of this app in this browser.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpTeamLink": {
    "what": "Opens the Team server page: who you are, what you may do on each tenant profile, and for an administrator the accounts and access.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpSsoBar a": {
    "what": "Opens your company sign-in page to sign in to this app again.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#xpBox summary": {
    "what": "Shows or hides the box that says what this page is, why it matters, and what to do next.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#xpBox a": {
    "what": "Opens the help page with every function of the app explained, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#xpHide": {
    "what": "Hides these explanation boxes by default on every page, or shows them again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.sm-term": {
    "what": "Explains this word in one or two short sentences, right under the sentence.",
    "input": "Nothing to type. Click it again to hide the meaning.",
    "effect": "local"
   },
   "#evalAllFlow a[href=\"/report/evalall\"]": {
    "what": "Opens the decision diagram for Evaluate All Rules in its own tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#evalAllFlow a": {
    "what": "Opens the Zscaler help article on DLP rules with Evaluate All Rules turned on, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#evalAllFlow summary": {
    "what": "Shows or hides how ZIA decides with Evaluate All Rules, and what happens on a tie.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "details.bp-sec summary": {
    "what": "Shows or hides this list of bypass items. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".bp-card details summary": {
    "what": "Shows which sections could not be read, and why.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpUpdateHow": {
    "what": "Starts the update of this app, or shows how to update it in a container. It does not touch your tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpUpdateLater": {
    "what": "Hides this update notice until a newer build comes out.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpUpstreamDetails": {
    "what": "Opens Beacon in a new tab, with what changed in the Zscaler SDK, API or Terraform provider.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpUpstreamLater": {
    "what": "Hides this notice about Zscaler changes for now.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#postureSummary button": {
    "what": "Opens Improve my score in a new tab, at the part this button names.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#rdConnect a.rd-link": {
    "what": "Opens Required API access in a new tab: everything this API client can and cannot do.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button[onclick=\"dlpReadiness.run()\"]": {
    "what": "Checks again what this API client can do: its API role and licences, only for what is in scope.",
    "input": "Nothing to type. Sign in to the tenant first.",
    "effect": "read"
   },
   "details.rd-steps summary": {
    "what": "Shows or hides the steps to ask your admin for, so this part works.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dzHowTo": {
    "what": "Opens a step-by-step walk-through of what a deployment and a removal do, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpDeployModal button.dz-close": {
    "what": "Closes Deploy policy packs.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"closeDlpPacksModal()\"]": {
    "what": "Closes Deploy policy packs. Nothing more is sent to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzSetWriteMode(true)\"]": {
    "what": "Turns on write mode for this server, so a deploy or a removal can change the tenant. It lasts until the server restarts.",
    "input": "Nothing to type here. A box then asks you to type the confirmation phrase.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzSetWriteMode(false)\"]": {
    "what": "Turns write mode off. The app goes back to read-only.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzTogglePack(\"]": {
    "what": "Selects this policy pack for the preflight and the deploy.",
    "input": "Ticked means the pack is selected. Clicking the card does the same.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzSetChannel(\"]": {
    "what": "Outbound email DLP for onboarded Microsoft 365 / Gmail tenants.",
    "input": "Ticked means deploy into that channel. Unticked skips the pack's rules for it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick*=\"_dzToggleDetail(\"]": {
    "what": "Shows or hides the dictionaries, engines and policies in this pack.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick*=\"_dzJourney(\"]": {
    "what": "Read-only: places every object of this policy pack in the tenant (missing, deployed, monitoring, enforcing, customized) and shows the stage reached and the next steps.",
    "input": "Nothing to type. Sign in to the tenant first.",
    "effect": "read"
   },
   "#dlpDeployModal #dzBody button[onclick*=\"openToolTab('terraform'\"]": {
    "what": "Hand this pack to a platform team as a Terraform workspace (official zscaler/zia provider): what you get, how to run it, download. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpDeployModal #dzFoot button[onclick*=\"openToolTab('terraform'\"]": {
    "what": "Close this gap with Terraform instead. It opens the hand-off page for the selected packs. In gap mode the first terraform plan creates only what is missing here and imports the rest.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpDeployModal button[onclick^=\"_dzFromTenant(\"][onclick$=\", true)\"]": {
    "what": "Rebuilds this pack from the dictionary pairs in the preview. Only the pack files in this app change. Nothing is written to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick*=\"_dzFromTenant(\"]": {
    "what": "Read the tenant's own source-code dictionaries (an Anchor and a Signal per language, paired by name), preview the pairing, then rebuild this pack from them: dictionaries keep their tenant names, each language gets one engine (Signal > N AND Anchor > 0), the old pack dictionaries and engines are dropped.",
    "input": "Two boxes ask for a dictionary name prefix (optional) and the Signal match count, like 4.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick=\"DZ.fromTenant=null;_dzRenderSelect()\"]": {
    "what": "Drops this preview. The pack stays as it was.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"DZ.showAllPacks\"]": {
    "what": "Shows every pack, or only the packs for this customer's industry.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"DZ.options.apply_tweaks\"]": {
    "what": "Lets packs adjust confidence on existing dictionaries, like Medical to Low. Each change is listed for approval.",
    "input": "Ticked means the tweaks are planned. Unticked leaves existing dictionaries alone.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"DZ.options.use_rank_0\"]": {
    "what": "Gives new rules rank 0, so they win over rules made by lower-ranked admins. Use it only to fix ordering conflicts.",
    "input": "Ticked means rank 0. Leave it unticked unless you need it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovePick()\"]": {
    "what": "Lists every DLP rule in the tenant, on every channel, so you can tick the ones to remove. Listing reads only.",
    "input": "Nothing to type. Sign in first. Removing later needs write mode.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick=\"_dzExportPick()\"]": {
    "what": "Lists the tenant's DLP rules, custom engines and custom dictionaries, so you can export them as a pack. It only reads.",
    "input": "Nothing to type. Sign in to the tenant first.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick=\"_dzInventoryXlsx()\"]": {
    "what": "Reads the tenant's DLP dictionaries, engines and rules in scope and saves them as an Excel workbook.",
    "input": "Nothing to type. Sign in to the tenant first.",
    "effect": "download"
   },
   "#dzJobStop[title^=\"Send nothing more\"]": {
    "what": "Stops the deploy. Send nothing more after the write in flight; what was written is activated and recorded",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dzJobStop[title^=\"Delete nothing more\"]": {
    "what": "Stops the removal. Delete nothing more after the delete in flight; what was deleted is activated",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dzJobStop[title^=\"Stop reading the tenant\"]": {
    "what": "Stops the Terraform hand-off. Stop reading the tenant; nothing is downloaded",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dzJobStop": {
    "what": "Stops the job that is running. What is done so far is kept.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRunPreflight()\"]": {
    "what": "Runs preflight: reads the tenant and works out what the selected packs would create, keep or skip. Nothing is written.",
    "input": "Select at least one pack first. Sign in to the tenant first.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick=\"DZ.step=3;DZ.consent=false;_dzRender()\"]": {
    "what": "Goes on to the approve step, which shows exactly what will be written.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"DZ.step=1;DZ.report=null\"]": {
    "what": "Starts again at the pack list to deploy more packs.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"DZ.step=\"]": {
    "what": "Goes back one step. Nothing is written.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"_dzPlanDownload(\"]": {
    "what": "Saves the deployment plan as a file for change approval, with a sign-off block.",
    "input": "Nothing to type. Run preflight first.",
    "effect": "download"
   },
   "#dzRequestApproval": {
    "what": "File this plan in the change queue for another writer to approve. Nothing is written now; an approved request is applied from the change queue after the plan is checked against the tenant again.",
    "input": "Nothing to type. Run preflight first.",
    "effect": "local"
   },
   "#dzRequestRemovalApproval": {
    "what": "File this removal plan in the change queue for another writer to approve. Nothing is removed now.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal a[href=\"/report/queue\"]": {
    "what": "Opens the change queue in a new tab, where the request waits for approval.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dzConsent": {
    "what": "Confirms you reviewed this plan and you authorize these changes to the tenant.",
    "input": "Tick it to unlock Deploy to tenant.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzApply()\"]": {
    "what": "Deploys the approved plan: creates the dictionaries, engines and rules, then activates and reads the tenant back. Every rule arrives disabled.",
    "input": "Needs write mode on, a named assessor and a typed confirmation. Tick the consent box first.",
    "effect": "write"
   },
   "#dlpDeployModal button[onclick=\"_dzUndoLast()\"]": {
    "what": "Delete everything this deployment just created. You review the removal plan before anything goes.",
    "input": "Needs write mode on, a named assessor and a typed confirmation.",
    "effect": "write"
   },
   "#dlpDeployModal button[onclick*=\"_dzUndo('\"]": {
    "what": "Undoes a past deployment. Delete what this deployment created, after you review the removal plan.",
    "input": "Needs write mode on, a named assessor and a typed confirmation.",
    "effect": "write"
   },
   "#dlpDeployModal input[onchange^=\"_dzPickToggle(\"]": {
    "what": "Ticks this rule, engine or dictionary for removal.",
    "input": "Ticked means it goes into the removal preview.",
    "effect": "local"
   },
   "#dlpDeployModal input[aria-label=\"Filter rules\"]": {
    "what": "Filters the list below by name.",
    "input": "Optional. Part of a rule, engine or pack name, like PHI.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"_dzPickSet(r\"][onclick*=\"tagged\"]": {
    "what": "Ticks every rule that Zscaler Made Easy created.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"_dzPickSet(r\"][onclick*=\"ENABLED\"]": {
    "what": "Ticks every rule that is disabled.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"_dzPickSet(()\"][onclick*=\"true\"]": {
    "what": "Ticks every item shown in the list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick^=\"_dzPickSet(()\"][onclick*=\"false\"]": {
    "what": "Clears every tick in the list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalClose()\"]": {
    "what": "Leaves the removal and goes back to the packs. Nothing is removed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalPickPreview()\"]": {
    "what": "Reads the tenant and previews the removal: the ticked items plus the engines and dictionaries only they use. Nothing is deleted.",
    "input": "Tick at least one item first.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick^=\"DZ.removal.step=\"]": {
    "what": "Moves between the removal steps. Nothing is deleted.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalReport()\"]": {
    "what": "Opens the removal plan as a printable page, to print or save as PDF.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#rmConsent": {
    "what": "Confirms you read the list and you authorize the permanent removal of these objects.",
    "input": "Tick it to unlock Remove now.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalApply()\"]": {
    "what": "Removes the listed objects from the tenant for good, in dependency order, then verifies with a fresh read.",
    "input": "Needs write mode on, a named assessor and a typed confirmation. Tick the consent box first.",
    "effect": "write"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalVerifyAgain()\"]": {
    "what": "Reads the tenant again to check that nothing of the removed objects is left.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#dlpDeployModal button[onclick=\"_dzRemovalLeftovers()\"]": {
    "what": "Makes a new removal plan for the objects still in the tenant. You approve it before anything is deleted.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick^=\"_dzFlowZoom(-\"]": {
    "what": "Zooms the flow diagram out.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick=\"_dzFlowZoom(0)\"]": {
    "what": "Fits the flow diagram to the width of the window.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick^=\"_dzFlowZoom(\"]": {
    "what": "Zooms the flow diagram in.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick=\"_dzFlowOpenTab()\"]": {
    "what": "Open this flow in its own tab, full width, with a details panel. It stays live while this window is open.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button[role=\"tab\"][onclick^=\"DZ.view='flow'\"]": {
    "what": "Shows the plan as a flow diagram: dictionaries feed engines, engines feed rules.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[role=\"tab\"][onclick^=\"DZ.view='list'\"]": {
    "what": "Shows the plan as lists grouped by what will happen.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-expr]": {
    "what": "Copies this engine's expression, with dictionary ids, to the clipboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzExportFile('')\"]": {
    "what": "Saves the whole exported pack as one zip file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dlpDeployModal button[onclick^=\"_dzExportFile(\"]": {
    "what": "Saves just this part of the exported pack as its own file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dlpDeployModal button[onclick^=\"DZ.exportPack.result=null\"]": {
    "what": "Goes back to pick again what to export.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzExportClose()\"]": {
    "what": "Closes the export and goes back to the packs.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzExportToggleObj(\"]": {
    "what": "Ticks this dictionary or engine for the export.",
    "input": "Ticked means it goes into the pack.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzExportToggle(\"]": {
    "what": "Ticks this rule for the export.",
    "input": "Ticked means it goes into the pack.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick*=\"_dzExportSetObj(\"][onclick*=\"true\"]": {
    "what": "Ticks every item shown in this list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick*=\"_dzExportSetObj(\"]": {
    "what": "Clears every tick in this list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzExportSet(true)\"]": {
    "what": "Ticks every rule shown.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzExportSet(false)\"]": {
    "what": "Clears every ticked rule.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzExportPart(\"]": {
    "what": "Picks which kinds of objects to export: dictionaries, engines, rules, or the ZIA policy framework.",
    "input": "Ticked means that kind goes into the export.",
    "effect": "local"
   },
   "#dlpDeployModal input[onchange^=\"_dzExportOpt('deps'\"]": {
    "what": "On: engines bring the dictionaries they use, rules the engines and dictionaries they use. Off: only what you picked; what it uses is named and must already exist where it goes.",
    "input": "Ticked means include what they use.",
    "effect": "local"
   },
   "#dlpDeployModal input[name=\"dzExportFmt\"]": {
    "what": "Picks the export format: a JSON pack, a Terraform workspace, or both.",
    "input": "Pick one.",
    "effect": "local"
   },
   "#dlpDeployModal input[aria-label=\"Pack name\"]": {
    "what": "Names the exported pack.",
    "input": "Optional. Up to 120 characters, like Acme DLP export.",
    "effect": "local"
   },
   "#dlpDeployModal button[onclick=\"_dzExportRun()\"]": {
    "what": "Reads the ticked objects from the tenant, builds the pack and saves it as a file.",
    "input": "Tick at least one item first.",
    "effect": "download"
   },
   "#dlpDeployModal details summary": {
    "what": "Shows or hides this part of the plan or result.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#terraformModal button[onclick=\"closeTerraformModal()\"]": {
    "what": "Closes the Terraform hand-off.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[onchange^=\"_tfToggle(\"]": {
    "what": "Picks this pack for the Terraform workspace.",
    "input": "Ticked means the pack goes into the download.",
    "effect": "local"
   },
   "input[name=\"tfMode\"][value=\"gap\"]": {
    "what": "Gap mode: reads the tenant first and imports what already exists, so the first terraform plan creates only what is missing.",
    "input": "Needs the tenant details on the assessment page, or a profile with a remembered client secret.",
    "effect": "local"
   },
   "input[name=\"tfMode\"][value=\"static\"]": {
    "what": "Static mode: no tenant access and no credentials. The workspace describes the whole pack.",
    "input": "Pick this or Gap mode.",
    "effect": "local"
   },
   "button[onclick=\"_tfDownload()\"]": {
    "what": "Builds the Terraform workspace for the picked packs and saves it as one zip. Gap mode reads the tenant first.",
    "input": "Pick at least one pack first.",
    "effect": "download"
   },
   "#terraformModal details summary": {
    "what": "Shows or hides this part of the hand-off.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/": {
   ".tool-group button[onclick=\"openSimpleMode()\"]": {
    "what": "Seven big tasks in plain words (connect, check, fix, protect, why was something blocked, what changed, a report for your boss), one question per screen. Nothing changes your Zscaler without your yes.",
    "input": "Nothing to type. Just click it. It opens in this tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openFindAnything()\"]": {
    "what": "One search box over the whole app: pages and what they do, glossary words, the tenant's rules and dictionaries from the last read, the findings on screen and your to-dos. Typos are fine. Ctrl+J (Cmd+J on a Mac) or / opens it from any page.",
    "input": "Nothing to type. Just click it. Or press Ctrl+J or / on the keyboard.",
    "effect": "local"
   },
   ".tool-group button[onclick=\"openHelpTab()\"]": {
    "what": "Every function of this app explained in plain English: what it is, why the customer cares, when to use it, what you get. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openPovTab()\"]": {
    "what": "Plan a customer proof of value for a saved tenant profile: intake, success criteria, a runbook of tests per product with pass or fail, notes and evidence, Prove it with the Path analyzer, a synthetic test kit, the timeline and follow-ups, and a report built from what actually ran. Never changes the tenant. Opens in a new tab.",
    "input": "Nothing to type. Just click it. A saved tenant profile helps.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openDataFlowTab()\"]": {
    "what": "One report: the path the configuration gives each traffic class (Client Connector app profile and forwarding profile by name, PAC, Cloud App Control, URL, SSL, File Type, DLP) with the reference diagram on top, visibility across every cloud app category, and where inspection is lost on those paths (bypasses and SSL blind spots). Opens in a new tab.",
    "input": "Nothing to type here. Needs the sign-in details under Connect to the tenant (or the sample tenant) and what to check ticked on the Scope page. Reads the tenant before the tab fills in.",
    "effect": "read"
   },
   ".tool-group button[onclick=\"openZpaTab()\"]": {
    "what": "Reads the ZPA configuration once (only when ZPA is ticked on the Scope page) and runs the ZPA analysis templates: unreachable access rules, unused or overlapping segments, over-broad domains and ports, bypasses, connector redundancy. Diagnose tells you, for one user and destination, which segment matches and which access rule decides. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. The tab reads ZPA only when you ask, and needs ZPA ticked on the Scope page and the ZPA customer ID.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openDevicePostureTab()\"]": {
    "what": "Reads the ZPA posture profiles, trusted networks and access rules (only when ZPA is ticked on the Scope page), sorts each profile into a family (domain join, EDR, certificate, marker...), links it to the rules that use it as must pass or must fail, flags rules to sensitive apps with no posture check, and shows every rule's conditions in plain words. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. The tab reads only when you ask, and needs ZPA ticked on the Scope page and the ZPA customer ID.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openPathAnalyzerTab()\"]": {
    "what": "Type a URL, a hostname or an IP address. Reads the tenant as it is right now and shows the path a user's traffic takes to that destination, hop by hop, with one verdict in plain words and every rule or profile that blocks or impacts it named. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. You type the destination in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openFlowAnimatorTab()\"]": {
    "what": "Animates your Path analyzer result hop by hop, what happens inside DLP (match counts, engine thresholds, near misses), a policy-pack deployment, live DLP incidents and every Data Security Architect flow. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openLiveFeedTab()\"]": {
    "what": "Polls Workflow Automation's DLP incidents live: who, the rule and dictionaries that matched, the destination, and whether the rule enforced it or only logged it, with a running seen / enforced / monitor / FP:TP tally. Covers DLP-matched traffic only, not every ZIA transaction — the page says so. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you start the feed in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openShadowRulesTab()\"]": {
    "what": "Reads the DLP, URL filtering, Cloud App Control, SSL inspection and Cloud Firewall rules in scope and lists every rule that can never match or never act: shadowed by a broader rule, below a catch-all, duplicated, superseded, disabled or naming objects that no longer exist. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Analyze in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openBrowserSecurityTab()\"]": {
    "what": "Reads the Zero Trust Browser isolation profiles and the rules that use them, ZIA Browser Control and the ZPA browser side (Browser Access, managed browsers, Privileged Remote Access), only what the Scope page puts in scope, and names each data protection gap with a fix. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Read in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openCloudConnectorTab()\"]": {
    "what": "Reads the Cloud & Branch Connector set-up: connector groups, forwarding rules, gateways, locations and admins. Names each gap with a fix. Needs Cloud & Branch Connector ticked on the Scope page. Never reads a key value or a provisioning URL. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Read in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openOtherProductsTab()\"]": {
    "what": "Reads Zero Trust Branch, EASM, Business Insights, Zero Trust Cellular and Microsegmentation. Only the ones ticked on the Scope page are read. Lists what the tenant has and checks it. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Read in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openToolTab('efficacy')\"]": {
    "what": "Scores every custom dictionary and engine for false-positive risk and tests sample text against them. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Scoring starts only when you click Score tenant there.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openDetectionHealthTab()\"]": {
    "what": "What the DLP rules actually do, measured from Workflow Automation incidents and the analysts' verdicts: false-positive rate per rule, engine and dictionary; dead rules; monitor-only rules ready to promote; and whether incidents reach Workflow Automation cloud-to-cloud or through an ICAP Incident Receiver. Read-only. Opens in a new tab.",
    "input": "Nothing to type here. Needs the sign-in details under Connect to the tenant (or the sample tenant). Reads the last 30 days of incidents and the rules before the tab fills in.",
    "effect": "read"
   },
   ".tool-group button[onclick=\"openInsightsTab()\"]": {
    "what": "Reads ZIA Insights for a time window: web traffic allowed and blocked, by location, cloud applications in use, SaaS security and firewall actions, and the users with the most security incidents. Needs ZIA Insights ticked on the Scope page. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Needs ZIA Insights ticked on the Scope page to read anything.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openSslCoverageTab()\"]": {
    "what": "Lists every SSL inspection exemption, Client Connector and PAC file bypass that leaves traffic uninspected, ranks them by risk and gives a recovery plan with a safe-to-change note. With ZIA Insights in scope it also shows how much HTTPS and HTTP traffic is inspected. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Run in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openDigestTab()\"]": {
    "what": "When you click Run the loop now (the timer is off unless the operator sets DLP_CHECK_CONTINUOUS_EVAL_HOURS), the app re-reads guidance and, for every tenant profile that remembers its secret, only what its Scope page puts in scope: FP/TP detection ratio, the SaaS tenants and the ticked packs' drift. It writes a digest. It does not re-run the assessment. This tab shows the latest one, lets you run the loop now, and shows what is notified where. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openPostureTab()\"]": {
    "what": "From the results on this page and the tenant profile's history: the ten fixes that raise the score most (points, effort, one-click fix), the score after the fixes you tick or have staged in the change queue, the score trend with the checks that started or stopped failing, score-drop alerts, and what could not be checked and why. Reads nothing from the tenant. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Works best after an assessment has run on this page.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openDlpPacksModal()\"]": {
    "what": "Pick a policy pack, see exactly what would be created, approve, deploy. Every rule arrives disabled.",
    "input": "Nothing to type. Just click it. Deploying needs write mode on; looking does not.",
    "effect": "local"
   },
   ".tool-group button[onclick=\"openOperationsTab()\"]": {
    "what": "Enable or disable up to 100 rules, reorder a policy with the fewest moves, add, remove, move or copy URLs on custom URL categories, and move ZPA domains between application segments. Every change is previewed item by item, applied only in write mode after you confirm the plan, checked again before each write, read back and recorded with Undo. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Changes need write mode on and your OK in that tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openTodoTab()\"]": {
    "what": "Every open to-do you or your team wrote on an object in Find anything, across your tenants: filter by tag, tick one when it is done, open the object it is on. Kept on this computer; nothing is written to the tenant. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openToolTab('terraform')\"]": {
    "what": "Same policy pack as a Terraform workspace for teams that manage Zscaler as code. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openVendorMigrateTab()\"]": {
    "what": "Upload another vendor's policy export, review every policy's translation, and get disabled ZIA dictionaries, engines and rules on every channel (web, endpoint, SaaS Security API, email) as Terraform. Symantec, Forcepoint, Netskope and Skyhigh exports, each with its API cross-reference to ZIA. Opens in a new tab.",
    "input": "Nothing to type. Just click it. You upload the other vendor's export in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"_gdGoMigration()\"]": {
    "what": "The migration wizard: reorders web DLP rules so the tenant can switch from first-match-wins to Evaluate All Rules safely. Opens on this page.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".tool-group button[onclick=\"openSelfHealTab()\"]": {
    "what": "The app checks itself and fixes what it safely can (stuck jobs, damaged saved files, file permissions, old locks). For your tenant it lists every setting you approved that changed back, with who and when, and heals it only when you click Heal and confirm. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openEvalAllTab()\"]": {
    "what": "How ZIA decides with Evaluate All Rules: every rule evaluated, the most restrictive action wins, a tie on the action is broken by rule order. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openToolTab('bestpractices')\"]": {
    "what": "Curated Zscaler best-practice articles. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openExportsTab()\"]": {
    "what": "Every export the app has, in one place: the assessment as Excel or Word, the DLP inventory, deployment plans, Export from tenant, and new read-only exports of each ZIA policy (every rule in order with the shadowed-rule findings), every URL the policy names, and which custom-category URLs Zscaler already categorises. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openQueueTab()\"]": {
    "what": "The team change queue: plans someone filed with Request approval in Deploy policy packs or Review and remediate. Another writer approves or rejects each one; an approved request is applied from here after the plan is checked against the tenant again. Export as JSON or Markdown. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openAdvancedTab()\"]": {
    "what": "Add your own policy packs (JSON, Terraform or a ZIP) so they appear in Deploy policy packs, the Data flow map and the Terraform hand-off; see the library and this server's settings. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openToolTab('updates')\"]": {
    "what": "Checks PyPI and help.zscaler.com for SDK and documentation changes since last time. This is about Zscaler's SDK and docs, not this app's own update (see the Update app card in Connect to the tenant). Opens in a new tab.",
    "input": "Nothing to type. Just click it. The check runs only when you click Check now there.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openBeaconTab()\"]": {
    "what": "Watches the Zscaler Python SDK, the ZIA API (service definition, API reference, help-center pages) and the zscaler/zia Terraform provider, runs on a timer while this server runs, and says what changed since the last run. Optionally reads from a tenant, GET only and about one request a second, only the endpoints in scope on the Scope page. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openReferenceTab('data-security-portfolio-framework')\"]": {
    "what": "Zscaler's data-security portfolio as an operating program: pick the coverage a customer needs, build the customer-ready story, and turn it into a testable proof-of-value plan. Works offline inside the tool. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openReferenceTab('ai-security-framework')\"]": {
    "what": "AI security controls as an operating model: coverage by phase, a customer-ready story and a testable proof plan. Works offline inside the tool. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openReferenceTab('genai-security-framework')\"]": {
    "what": "The generative-AI subset of the AI security framework, with the same story builder and proof plan. Works offline inside the tool. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openReferenceTab('framework-machine')\"]": {
    "what": "How the framework pages are built and kept portable: the six components, the assembly line and the setup order. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openReferenceTab('data-security-architect')\"]": {
    "what": "Zscaler's data-security reference architecture: every DLP channel's flow, dictionaries and engines, evidence to Workflow Automation, setup sequences, symptom walkbacks. Works offline inside the tool. Opens in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openAuditTimelineTab()\"]": {
    "what": "Who changed what in the tenant, and what Zscaler Made Easy did, on one timeline: ZIA's admin audit log for a window you choose, Zscaler Made Easy's deployment records and audit log, filters, field-by-field diffs, CSV and JSON. Writes nothing to the tenant. Opens in a new tab.",
    "input": "Nothing to type. Just click it. You pick the time window in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openFleetTab()\"]": {
    "what": "Client Connector profiles, PAC files and enrolled devices together: blind spots, bypass risk, ghost devices, version drift, profile and PAC comparisons and a ranked plan. Read-only, only when ZCC is in scope. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Reads only when ZCC is ticked on the Scope page.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openTrafficLogsTab()\"]": {
    "what": "Upload ZPA LSS and ZIA NSS logs and see sessions, failures and their reasons, connector health, anomalies, blocks, rules hit, DLP, threats and SSL inspection. Read on this computer; only counts are kept. Opens in a new tab.",
    "input": "Nothing to type. Just click it. You drop the log files in the new tab.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openLogAnalyzerTab()\"]": {
    "what": "Drop in the ZIP from Client Connector's Export Logs, single .log files or a PAC file. Analysed on this computer, nothing stored. Says what happened, what it means for the user and what to do next. Opens in a new tab.",
    "input": "Nothing to type. Just click it. You drop the files in the new tab.",
    "effect": "nav"
   },
   "a.skip-link": {
    "what": "Jumps past the menus to the main part of the page.",
    "input": "Nothing to type. Press Enter or click it.",
    "effect": "local"
   },
   "#stepBar button[data-step=\"configure\"]": {
    "what": "Open the sign-in details (cloud, vanity domain, API client). Shows step 1, Connect to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#stepBar button[data-step=\"scope\"]": {
    "what": "Shows step 2, Scope assessment: Channels, what to assess, frameworks, organisation and assessor; run the assessment on this page from there.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#stepBar button[data-step=\"review\"]": {
    "what": "Shows step 3. The Dashboard: score, findings and the exports, on this page.",
    "input": "Nothing to type. Just click it. If no assessment has run in this tab yet, it tells you so.",
    "effect": "local"
   },
   "#org": {
    "what": "The customer's company or agency name. It prints on the report cover.",
    "input": "Required to run the assessment. Plain text, exactly as it should print, like Acme Health System.",
    "effect": "local"
   },
   "#assessor": {
    "what": "Your name and role. The report names you as the person who ran it, and changes to the tenant are logged under it.",
    "input": "Required to run the assessment and for any change to the tenant. Plain text, like Jane Doe, Zscaler DS Engineer.",
    "effect": "local"
   },
   "#cloud": {
    "what": "Picks the Zscaler cloud the customer's tenant lives on.",
    "input": "Required. Pick one. Commercial works for every commercial cloud with OneAPI. Pick zscalergov.net or zscalergov.us for US Government. For the classic ZIA API pick the real cloud, like zscalerten.net for admin.zscalerten.net.",
    "effect": "local"
   },
   "#authMethod": {
    "what": "Picks how the app signs in: OneAPI (a ZIdentity API client) or the classic ZIA API (admin login and API key). The fields below change to match.",
    "input": "Required. Pick OneAPI for most tenants. Pick Classic ZIA API only if the tenant has no ZIdentity; it covers ZIA only.",
    "effect": "local"
   },
   "#vd": {
    "what": "The short name in the customer's ZIdentity login address.",
    "input": "Required for OneAPI. Only the part before .zslogin.net, no web prefix and no dots. For acme.zslogin.net type acme.",
    "effect": "local"
   },
   "#zuser": {
    "what": "The sign-in name of a ZIA admin who may use the API (classic ZIA API only).",
    "input": "Required for the classic ZIA API. Usually an email address, like api-admin@acme.com.",
    "effect": "local"
   },
   "#zpass": {
    "what": "The ZIA admin's password (classic ZIA API only). Kept only in this form unless a saved profile remembers it.",
    "input": "Required for the classic ZIA API, unless the chosen tenant profile remembers it. Hidden as you type.",
    "effect": "local"
   },
   "#zkey": {
    "what": "The tenant's API key from ZIA Administration, API Key Management (classic ZIA API only).",
    "input": "Required for the classic ZIA API, unless the chosen tenant profile remembers it. 12 characters.",
    "effect": "local"
   },
   "#cid": {
    "what": "The Client ID of the API client made in ZIdentity, Integration, API Clients.",
    "input": "Required for OneAPI. Letters and digits only, no spaces, like 3f9c2a1b7d8e4f0a9b6c1d2e3f4a5b6c.",
    "effect": "local"
   },
   "#csec": {
    "what": "The API client's secret. ZIdentity shows it only once, when the client is made. Kept only in this form unless a saved profile remembers it.",
    "input": "Required for OneAPI, unless the chosen tenant profile remembers it. A long random string. Dots like •••••• mean a placeholder: make a new secret.",
    "effect": "local"
   },
   "#togglePass": {
    "what": "Shows or hides the admin password as you type. Click again to hide it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#toggleKey": {
    "what": "Shows or hides the API key as you type. Click again to hide it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#toggleCid": {
    "what": "Shows or hides the API client ID as you type. Click again to hide it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#toggleSecret": {
    "what": "Shows or hides the API client secret as you type. Click again to hide it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#custid": {
    "what": "The ZPA customer ID. The app needs it only to read ZPA.",
    "input": "Optional. Digits only, needed when ZPA is ticked. Copy it from the ZPA admin address, like 216196257331281920.",
    "effect": "local"
   },
   "#scopeField a[href=\"/permissions\"]": {
    "what": "Opens the page that lists the smallest API access each scope needs, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#scopeField button[onclick=\"openToolTab('zcc')\"]": {
    "what": "Probes every ZCC (Client Connector) endpoint on the tenant and shows which ones the API client can read. Opens in a new tab.",
    "input": "Nothing to type here. Needs the sign-in details under Connect to the tenant (or the sample tenant) and ZCC ticked on the Scope page.",
    "effect": "read"
   },
   "#scopeField input.scope-cb[value=\"dlp\"]": {
    "what": "Adds the DLP checks (188): dictionaries, engines and DLP rules.",
    "input": "Tick it to check DLP. Ticked at first.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zia_extras\"]": {
    "what": "Adds the ZIA platform checks (75). They cover threat protection and SaaS Security hygiene, governance and forwarding. Governance is the configuration audit, alerts and NSS log streaming (N/A without NSS). Forwarding is proxy chaining, gateways, GRE tunnels, IPv6, NAT and DNS gateways. Tenant health is in there too. It also lets the Path analyzer read URL filtering, File Type Control, threat protection, Cloud Firewall, DNS Control, Sandbox and forwarding control rules.",
    "input": "Tick it to check the ZIA platform. Ticked at first.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zpa\"]": {
    "what": "Adds the ZPA checks (15) for private app access.",
    "input": "Tick it to check ZPA. Needs the ZPA customer ID; without it the ZPA checks are skipped.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zcc\"]": {
    "what": "Adds the ZCC checks (5) for Client Connector, the app on each device.",
    "input": "Tick it to check Client Connector. Ticked at first.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"genai\"]": {
    "what": "Adds the GenAI and prompt checks (20) for AI apps.",
    "input": "Tick it to check GenAI. Ticked at first.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"automation\"]": {
    "what": "Adds the Automation readiness checks (19). Validates tenant readiness for github.com/zscaler automation projects: SDKs, Terraform providers, Ansible collections, zscaler-terraformer.",
    "input": "Tick it to check automation readiness.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zdx\"]": {
    "what": "Adds the ZDX checks (8). Zscaler Digital Experience — apps, alerts, inventory, reports, troubleshooting.",
    "input": "Tick it to check ZDX. Needs ZDX access for the API client.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zidentity\"]": {
    "what": "Adds the ZIdentity checks (5). ZIdentity directory, groups, resource servers, user entitlements.",
    "input": "Tick it to check ZIdentity.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"rbac\"]": {
    "what": "Adds the RBAC checks (14). Role-Based Access Control hygiene: admin counts, SSO federation, MFA, admin password expiry, Zscaler Support remote access, group-bound policies, stale accounts.",
    "what": "Adds the RBAC checks (23). Role-Based Access Control hygiene: admin counts, SSO federation, MFA, group-bound policies, stale accounts. With ZPA ticked too, it also checks ZPA admins, roles, API keys, break-glass accounts, microtenants, provisioning keys and remote access. It never reads key or password values.",
    "input": "Tick it to check admin and role hygiene.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"insights\"]": {
    "what": "Lets the app read traffic numbers from ZIA Insights: the Traffic insights page, 3 Shadow IT and SaaS checks, and the cloud app sanction change in Bulk changes. It reads traffic data, not configuration.",
    "input": "Tick it to allow Traffic insights. Needs a OneAPI API client with Z-Insights read access.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"aiguard\"]": {
    "what": "Lets the app read Zscaler AI Guard: is it licensed and reachable. The Bulk changes builders use it. Not part of the checks.",
    "input": "Tick it to allow AI Guard. Needs a OneAPI API client with AI Guard access.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"ztw\"]": {
    "what": "Lets the Path analyzer read Cloud & Branch Connector forwarding rules and workload groups, for traffic from a workload.",
    "input": "Tick it to allow it. Needs a OneAPI API client with a Cloud & Branch Connector role.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"ztb\"]": {
    "what": "Lets the app read Zero Trust Branch: sites, templates, alarms, API key names and ages, hubs. Five checks and the Other products page.",
    "input": "Tick it to allow it. Needs a OneAPI API client with Zero Trust Branch read access. Off by default.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"easm\"]": {
    "what": "Lets the app read External Attack Surface Management: organizations, findings and lookalike domains. Four checks and the Other products page.",
    "input": "Tick it to allow it. Needs a OneAPI API client with EASM read access. Off by default.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zbi\"]": {
    "what": "Lets the app read Business Insights: custom applications and scheduled reports. Two checks and the Other products page.",
    "input": "Tick it to allow it. Needs a OneAPI API client with Business Insights read access. Off by default.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zcell\"]": {
    "what": "Lets the app read Zero Trust Cellular: account, regions, anomaly policies and SIM counts. Three checks and the Other products page.",
    "input": "Tick it to allow it. Needs a OneAPI API client with Zero Trust Cellular access and the ZCell customer ID. Off by default.",
    "effect": "local"
   },
   "#scopeField input.scope-cb[value=\"zms\"]": {
    "what": "Lets the app read Microsegmentation: agents, agent groups, provisioning key names, policy and default rules. Six checks and the Other products page.",
    "input": "Tick it to allow it. Needs a OneAPI API client with Microsegmentation access; uses the ZPA customer ID unless you give another. Off by default.",
    "effect": "local"
   },
   "#scopeField a[href*=\"github.com/zscaler\"]": {
    "what": "Opens Zscaler's public code pages (SDKs, Terraform and Ansible) in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#complianceFwField input.fw-cb": {
    "what": "Puts this compliance framework in the report. The compliance card shows only ticked frameworks.",
    "input": "Optional. Tick the ones the customer cares about. With none ticked, every framework is shown.",
    "effect": "local"
   },
   "#complianceFwField button[onclick=\"toggleFrameworks(true)\"]": {
    "what": "Ticks every compliance framework.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#complianceFwField button[onclick=\"toggleFrameworks(false)\"]": {
    "what": "Unticks every compliance framework. Then the compliance card shows them all.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#authBtn": {
    "what": "Signs in to the tenant with these values and nothing else: it reads nothing from the tenant. Run the assessment from the Scope page.",
    "input": "The sign-in fields above must be filled in first: vanity domain, client ID and secret for OneAPI, or username, password and API key for the classic API.",
    "effect": "read"
   },
   "#runBtn": {
    "what": "Starts the assessment: reads the tenant for what is ticked on the Scope page and shows the score and findings. This copy is hidden; use Run assessment on the Scope page.",
    "input": "Needs the organisation, the assessor and the sign-in details filled in, and at least one scope ticked.",
    "effect": "read"
   },
   "#saveBtn": {
    "what": "Save config locally (except secret). Keeps the names, cloud, vanity domain, client ID, customer ID, scopes and frameworks in this browser.",
    "input": "Nothing to type. Just click it. The secret is never saved here.",
    "effect": "local"
   },
   "#clearBtn": {
    "what": "Clear saved config. Also empties the form and puts the scopes back to the defaults.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick=\"exportChecks('all','csv')\"]": {
    "what": "Saves the list of every check the app can run, with its compliance mapping, as a CSV file.",
    "input": "Nothing to type. Just click it. No tenant needed.",
    "effect": "download"
   },
   "button[onclick=\"exportChecks('dlp','csv')\"]": {
    "what": "Saves the list of the DLP checks only, as a CSV file.",
    "input": "Nothing to type. Just click it. No tenant needed.",
    "effect": "download"
   },
   "button[onclick=\"exportChecks('all','md')\"]": {
    "what": "Saves the list of every check the app can run as a Markdown file.",
    "input": "Nothing to type. Just click it. No tenant needed.",
    "effect": "download"
   },
   "button[onclick=\"exportChecks('all','json')\"]": {
    "what": "Saves the list of every check the app can run as a JSON file.",
    "input": "Nothing to type. Just click it. No tenant needed.",
    "effect": "download"
   },
   "#stopBtn": {
    "what": "Stops the running assessment. Checks still waiting are cancelled, and the ones that finished are shown.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#results button[onclick=\"downloadDocx()\"]": {
    "what": "Saves the full report as a Word file.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "download"
   },
   "#results button[onclick=\"downloadXlsx()\"]": {
    "what": "Saves an Excel workbook: Summary, findings (one row each, filterable), compliance mapping and best practices.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "download"
   },
   "#results button[onclick=\"downloadJSON()\"]": {
    "what": "Saves the raw results as a JSON file.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "download"
   },
   "#results button[onclick=\"openRemediationReview()\"]": {
    "what": "Opens a list of the open findings that have a one-click fix, so you can pick which to walk through. Nothing changes yet.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "local"
   },
   "#results button[onclick=\"resetForm()\"]": {
    "what": "Clears these results and goes back to Connect to the tenant; nothing runs until you click Run assessment.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#results button[onclick=\"openToolTab('results', 'view')\"]": {
    "what": "Show these results in their own tab, with a link back to this page.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "nav"
   },
   ".checks-filter button[data-filter=\"all\"]": {
    "what": "Shows every finding. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"FAIL\"]": {
    "what": "Shows only the findings marked Action required. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"REVIEW\"]": {
    "what": "Shows only the findings marked Needs review. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"PASS\"]": {
    "what": "Shows only the checks that are Configured. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"INFO\"]": {
    "what": "Shows only the checks marked Not configured: not licensed, not in use, or nothing to score. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"NOTPERM\"]": {
    "what": "Shows only the checks the API client was Not permitted to read. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".checks-filter button[data-filter=\"ERROR\"]": {
    "what": "Shows only the checks that Could not be checked because the read failed. The number is how many there are.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#checksList button[onclick^=\"openRemediationWizard(\"]": {
    "what": "Opens the one-click fix for this finding. You fill in a few fields and preview the change first.",
    "input": "Nothing to type here. Applying the fix later needs write mode on.",
    "effect": "local"
   },
   "#checksList a.check-tool": {
    "what": "Opens the Bulk changes builder that fixes this finding, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#checksList summary": {
    "what": "Shows or hides the technical detail behind this finding.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#complianceGrid button[onclick^=\"openComplianceTab(\"]": {
    "what": "Opens this framework control by control in a new tab, with the findings behind each control.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "nav"
   },
   "#complianceCard button[onclick=\"openComplianceTab()\"]": {
    "what": "Opens Regulatory and compliance alignment in a new tab, control by control, for the ticked frameworks.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "nav"
   },
   "#benchmarkBody button[onclick=\"downloadBenchmarks('markdown')\"]": {
    "what": "Saves the best-practice and benchmark note as a Markdown file.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "download"
   },
   "#benchmarkBody button[onclick=\"downloadBenchmarks('json')\"]": {
    "what": "Saves the best-practice and benchmark results as a JSON file.",
    "input": "Nothing to type. Needs an assessment run first.",
    "effect": "download"
   },
   "#benchmarkBody a[href]": {
    "what": "Opens the Zscaler article that says what good looks like, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#benchmarkBody summary": {
    "what": "Shows or hides the gaps in this best-practice area.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#permissionsBody summary": {
    "what": "Shows or hides the list of checks the API client was not allowed to run.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#permissionsBody a[href]": {
    "what": "Opens the Required API access page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.card-toggle": {
    "what": "Opens or closes this section. Click to expand or collapse.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.card-popout": {
    "what": "Open this section in a new tab, as a copy you can read or print.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#selfHealBanner button": {
    "what": "Opens Self-healing in a new tab, to see what needs you and which tenant settings drifted.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#themeToggleBtn": {
    "what": "Switches the page between light and dark colors. Your choice is remembered.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#bgIntensityControl input[value=\"subtle\"]": {
    "what": "Makes the background picture faint.",
    "input": "Pick one. Your choice is remembered in this browser.",
    "effect": "local"
   },
   "#bgIntensityControl input[value=\"medium\"]": {
    "what": "Makes the background picture a bit stronger.",
    "input": "Pick one. Your choice is remembered in this browser.",
    "effect": "local"
   },
   "#bgIntensityControl input[value=\"prominent\"]": {
    "what": "Makes the background picture strong.",
    "input": "Pick one. Your choice is remembered in this browser.",
    "effect": "local"
   },
   "#dlpEffModal button[onclick=\"closeDlpEffModal()\"]": {
    "what": "Closes the DLP efficacy window.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#dlpEffRunBtn": {
    "what": "Reads the custom DLP dictionaries, engines and rules and scores each one for false-positive risk.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#dlpEffModal button[onclick=\"toggleDlpEffCorpus()\"]": {
    "what": "Shows or hides the box where you paste sample text to test.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpEffCorpus": {
    "what": "Sample text to test against the dictionaries. It stays on this server.",
    "input": "Required for the corpus test. Plain text up to 256 KB, like a few emails or a spreadsheet row.",
    "effect": "local"
   },
   "#dlpEffModal button[onclick=\"runDlpEfficacyCorpus()\"]": {
    "what": "Reads the tenant's dictionaries and engines, then runs them on your sample text here and shows which would fire.",
    "input": "Paste sample text in the box first. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#dlpEffResult button[onclick=\"exportDlpEfficacy('csv')\"]": {
    "what": "Reads the tenant again and saves the efficacy scores as a CSV file.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#dlpEffResult button[onclick=\"exportDlpEfficacy('markdown')\"]": {
    "what": "Reads the tenant again and saves the efficacy scores as a Markdown file.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#dlpEffResult button[onclick=\"exportDlpEfficacy('docx')\"]": {
    "what": "Reads the tenant again and saves the efficacy scores as a Word file.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#dlpEffResult button[onclick=\"exportDlpEfficacy('json')\"]": {
    "what": "Reads the tenant again and saves the efficacy scores as a JSON file.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#dlpEffResult summary": {
    "what": "Shows or hides this part of the efficacy results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#permissionsModal button[onclick=\"closePermissionsModal()\"]": {
    "what": "Closes the Required API access window.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#permissionsContent summary": {
    "what": "Shows or hides the permissions, endpoints and license for this scope.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#permissionsContent a[href]": {
    "what": "Opens the ZIdentity admin portal in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#bypassModal button[onclick=\"closeBypassModal()\"]": {
    "what": "Closes the bypass report window.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#bypassRunBtn": {
    "what": "Reads ZIA and Client Connector and lists every setting that lets traffic skip inspection.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#bypassExportCsv": {
    "what": "Reads the tenant again and saves the bypass report as a CSV file.",
    "input": "Nothing to type. Works after Generate report. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#bypassExportMd": {
    "what": "Reads the tenant again and saves the bypass report as a Markdown file.",
    "input": "Nothing to type. Works after Generate report. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#bypassExportDocx": {
    "what": "Reads the tenant again and saves the bypass report as a Word file.",
    "input": "Nothing to type. Works after Generate report. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#bypassExportJson": {
    "what": "Reads the tenant again and saves the bypass report as a JSON file.",
    "input": "Nothing to type. Works after Generate report. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#updateModal button[onclick=\"closeUpdateModal()\"]": {
    "what": "Closes the Zscaler update check window.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#updateRunBtn": {
    "what": "Checks PyPI and help.zscaler.com for Zscaler SDK and doc changes since last time. It does not touch your tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#updateModal button[onclick=\"runUpdateCheck(true)\"]": {
    "what": "Clear the cached snapshot so every source is reported as 'new'. Then it checks again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#updateResult button[onclick=\"runUpdateCheck(false, true)\"]": {
    "what": "Checks again without TLS certificate checks. Use it only when company TLS inspection blocks the check.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#updateResult summary": {
    "what": "Shows or hides the proxy and TLS settings this server uses.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#updateResult a[href]": {
    "what": "Opens this SDK page or doc page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#bestPracticesModal button[onclick=\"closeBestPracticesModal()\"]": {
    "what": "Closes the best practices library.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#bpCrawlBtn": {
    "what": "Reads the Zscaler help site, blog and developer pages now and adds new best-practice articles to the library. It does not touch your tenant.",
    "input": "Nothing to type. Takes about 30 to 90 seconds.",
    "effect": "local"
   },
   "#bpSkipTls": {
    "what": "Skips TLS certificate checks for this update only. Enable if corporate TLS inspection is blocking the crawl and no CA bundle is configured in local_settings.bat.",
    "input": "Optional. Tick it only when the update fails because of company TLS inspection.",
    "effect": "local"
   },
   "#bestPracticesContent a[href]": {
    "what": "Opens this best-practice article in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#bestPracticesContent summary": {
    "what": "Shows or hides why some sources could not be reached.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zccDiagModal button[onclick=\"closeZccDiagModal()\"]": {
    "what": "Closes the ZCC endpoint check window.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#remediationModal button[onclick=\"closeRemediationModal()\"]": {
    "what": "Closes the fix window. Nothing is changed.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#remediationModal button[onclick=\"remediationPreview()\"]": {
    "what": "Checks your values and shows the exact change the fix would send. Nothing is sent to the tenant.",
    "input": "Fill in the fields above first; fields with a star are required.",
    "effect": "local"
   },
   "#remediationActivateBtn": {
    "what": "Sends the previewed fix to the tenant now.",
    "input": "Preview the plan first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#remediationFormFields select": {
    "what": "A setting for this fix. Pick the value you want.",
    "input": "Pick one of the listed values. The hint under it says more.",
    "effect": "local"
   },
   "#remediationFormFields textarea": {
    "what": "A setting for this fix.",
    "input": "Type the text the hint asks for. Required when the label has a star.",
    "effect": "local"
   },
   "#remediationFormFields input": {
    "what": "A setting for this fix.",
    "input": "Type the value the hint under it asks for. Lists are comma-separated. Required when the label has a star.",
    "effect": "local"
   },
   "#reviewModal button[onclick=\"closeReviewModal()\"]": {
    "what": "Closes this list. Nothing is changed.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#reviewList button[onclick=\"_reviewSelectAll(true)\"]": {
    "what": "Ticks every finding in the list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#reviewList button[onclick=\"_reviewSelectAll(false)\"]": {
    "what": "Unticks every finding in the list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#reviewList input.reviewCheck": {
    "what": "Puts this finding in the fix walkthrough. Ticking it changes nothing in the tenant.",
    "input": "Tick it to fix this finding, untick it to skip it.",
    "effect": "local"
   },
   "#reviewStartBtn": {
    "what": "Starts the walkthrough: one fix per screen for each ticked finding.",
    "input": "Tick at least one finding first.",
    "effect": "local"
   },
   "#wizardModal button[onclick=\"closeWizard()\"]": {
    "what": "Stops the walkthrough and closes it. Fixes already applied stay applied.",
    "input": "Nothing to type. Click it or press Esc.",
    "effect": "local"
   },
   "#wizardPreviewBtn": {
    "what": "Checks your values and shows the exact change this fix would send. Nothing is sent to the tenant.",
    "input": "Fill in the fields first; fields with a star are required.",
    "effect": "local"
   },
   "#wizardApplyBtn": {
    "what": "Sends the previewed fix to the tenant now.",
    "input": "Preview the plan first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#wizardRequestBtn": {
    "what": "File this fix in the change queue for another writer to approve. Nothing is sent to the tenant now.",
    "input": "Preview the plan first. No write mode needed.",
    "effect": "local"
   },
   "#wizardSkipBtn": {
    "what": "Skips this finding and goes to the next one. Nothing is changed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#wizardNextBtn": {
    "what": "Goes to the next finding. On the last screen it shows the summary, then closes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#wizardResult a[href=\"/report/queue\"]": {
    "what": "Opens the Change queue in a new tab, where another writer approves the fix.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#wizardFormFields select": {
    "what": "A setting for this fix. Pick the value you want.",
    "input": "Pick one of the listed values. The hint under it says more.",
    "effect": "local"
   },
   "#wizardFormFields textarea": {
    "what": "A setting for this fix.",
    "input": "Type the text the hint asks for. Required when the label has a star.",
    "effect": "local"
   },
   "#wizardFormFields input": {
    "what": "A setting for this fix.",
    "input": "Type the value the hint under it asks for. Lists are comma-separated. Required when the label has a star.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"closeMigrateModal()\"]": {
    "what": "Closes the rule migration wizard. Nothing is changed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pendingActivationsBanner button[onclick^=\"activatePending(\"]": {
    "what": "Runs this staged change live on the tenant, the same as its step's Activate button.",
    "input": "Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#pendingActivationsBanner button[onclick^=\"clearPendingAction(\"]": {
    "what": "Removes this staged change from the list. Nothing is sent to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pendingActivationsBanner button[onclick=\"clearAllPendingActions()\"]": {
    "what": "Removes every staged change from the list. Nothing is sent to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step1Assess()\"]": {
    "what": "Step 1. Reads the Inline Web DLP rules and says if the tenant uses Rule Order or Evaluate All Rules.",
    "input": "Nothing to type here. Needs the sign-in details (or the sample tenant) and DLP in scope.",
    "effect": "read"
   },
   "#step1Result input[name=\"manualMode\"][value=\"rule_order\"]": {
    "what": "Says the tenant uses Rule Order, where the first matching rule wins.",
    "input": "Pick it if the ZIA portal shows Evaluate All DLP Rules turned off. Then click Apply.",
    "effect": "local"
   },
   "#step1Result input[name=\"manualMode\"][value=\"evaluate_all_rules\"]": {
    "what": "Says the tenant already uses Evaluate All Rules.",
    "input": "Pick it if the ZIA portal shows Evaluate All DLP Rules turned on. Then click Apply.",
    "effect": "local"
   },
   "#step1Result button[onclick=\"step1SetManual()\"]": {
    "what": "Reads the rules again and uses the mode you picked, for when the API does not show it.",
    "input": "Pick Rule order or Evaluate All Rules first. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#step1Result summary": {
    "what": "Shows or hides the raw API probe results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step2Download()\"]": {
    "what": "Step 2. Reads the live Inline Web DLP rules into this page so the next steps can use them.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#step2SaveBtn": {
    "what": "Saves the rules you read in Step 2 as a JSON backup file. Do this before any change.",
    "input": "Nothing to type. Run Download rules first.",
    "effect": "download"
   },
   "#step2PackBtn": {
    "what": "A zip in the policy pack layout: the Inline Web DLP rules with every engine they use and every dictionary those engines use. Deploy Policy Packs can put it back into this tenant or another one; the pack library accepts it as an upload. Read-only.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "download"
   },
   "#step2UploadFile": {
    "what": "Loads a rules JSON file you saved before, in place of reading the tenant.",
    "input": "Required file: a .json backup with a rules list, like the one Save JSON backup makes.",
    "effect": "local"
   },
   "#step2PackResult summary": {
    "what": "Shows or hides the items that could not go into the pack.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exSkipIds": {
    "what": "Rule IDs to leave where they are when the rules are reordered.",
    "input": "Optional. Rule IDs separated by commas, like 7, 12, 44.",
    "effect": "local"
   },
   "#exPinned": {
    "what": "Pins one rule to a fixed position in the new order.",
    "input": "Optional. Rule ID, a colon, then the position, like 5:1 to put rule 5 first.",
    "effect": "local"
   },
   "#exAuditBlocks": {
    "what": "Turns Block actions into Allow and log (audit only) in the new plan, for a safe test window.",
    "input": "Optional. Tick it to make blocking rules only log during the migration.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step3Optimize()\"]": {
    "what": "Step 3. Works out a new rule order that is safe for Evaluate All Rules. Nothing is sent to the tenant.",
    "input": "Run Step 2 first. The exceptions above are optional.",
    "effect": "local"
   },
   "#step3UploadFile": {
    "what": "Loads your own ordered rules JSON file. Step 5 posts them in that order.",
    "input": "Required file: a .json file with a rules list in the order you want.",
    "effect": "local"
   },
   "#step3SaveBtn": {
    "what": "Saves the new rule order as a JSON file.",
    "input": "Nothing to type. Run Optimize or upload a file first.",
    "effect": "download"
   },
   "#migrateModal button[onclick=\"migrateExport('json')\"]": {
    "what": "Saves the migration plan (the new rule order) as a JSON file.",
    "input": "Nothing to type. Run Step 2 or Step 3 first.",
    "effect": "download"
   },
   "#migrateModal button[onclick=\"migrateExport('csv')\"]": {
    "what": "Saves the migration plan (the new rule order) as a CSV file.",
    "input": "Nothing to type. Run Step 2 or Step 3 first.",
    "effect": "download"
   },
   "#manualReorder button[onclick$=\", -1)\"]": {
    "what": "Moves this rule up one place in the new order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#manualReorder button[onclick$=\", 1)\"]": {
    "what": "Moves this rule down one place in the new order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#manualReorder button[onclick=\"reorderReset()\"]": {
    "what": "Throws away your moves and goes back to the auto-optimized order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#step3bResult button.activate-btn": {
    "what": "Deletes every Inline Web DLP rule from the tenant now. This cannot be undone through the API.",
    "input": "Save the Step 2 backup first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#step3bResult summary": {
    "what": "Shows or hides the rules that could not be deleted.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step3bDeleteAll(true)\"]": {
    "what": "Step 3b dry run. Lists every Inline Web DLP rule that Delete all would remove. Nothing is deleted.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#migrateModal button[onclick=\"step3bDeleteAll(false)\"]": {
    "what": "Deletes every Inline Web DLP rule from the tenant. This cannot be undone through the API.",
    "input": "Save the Step 2 backup and run the dry run first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#step4Result button.activate-btn": {
    "what": "Turns on Evaluate All DLP Rules in the tenant now.",
    "input": "Run Enable (dry run) first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#step4Result summary": {
    "what": "Shows or hides every API attempt made.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step4Check()\"]": {
    "what": "Step 4, part 1. Reads whether Evaluate All Rules is on right now. Nothing is changed.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#migrateModal button[onclick=\"step4EnablePlan()\"]": {
    "what": "Step 4, part 2. Builds the plan to turn on Evaluate All Rules, as a dry run. Nothing is changed.",
    "input": "Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#migrateModal button[onclick=\"step4Activate()\"]": {
    "what": "Step 4, part 3. Turns on Evaluate All DLP Rules in the tenant.",
    "input": "Run Enable (dry run) first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#step5Mode": {
    "what": "Picks how Step 5 posts the rules.",
    "input": "Pick one. auto updates rules that exist and adds new ones. update only reorders existing rules. create only adds them all, for use after Step 3b.",
    "effect": "local"
   },
   "#step5Result button.activate-btn": {
    "what": "Writes the rules to the tenant now, in the new order.",
    "input": "Run the dry run first. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#step5Result summary": {
    "what": "Shows or hides the rules that failed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#migrateModal button[onclick=\"step5Post(true)\"]": {
    "what": "Step 5 dry run. Reads the tenant and lists what Post live would add or change. Nothing is written.",
    "input": "Run Step 2 or Step 3 first and pick a mode. Nothing to type here. The sign-in details under Connect to the tenant must be filled in first (or the sample tenant on).",
    "effect": "read"
   },
   "#migrateModal button[onclick=\"step5Post(false)\"]": {
    "what": "Step 5. Writes the rules to the tenant in the new order.",
    "input": "Run the dry run first and pick a mode. Needs write mode on, a writer role, the assessor name on the Scope page and your yes in the pop-up. Run the dry run first.",
    "effect": "write"
   },
   "#dbTools button.db-item[data-db=\"configure\"]": {
    "what": "Opens Connect to the tenant: the sign-in details, tenant profiles and the sample tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbTools button.db-item[data-db=\"scope\"]": {
    "what": "Opens Scope assessment: the channels the customer owns, what to check and which frameworks to map.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbTools button.db-item[data-db=\"dashboard\"]": {
    "what": "Shows the dashboard: the score, the tiles and the findings of the last assessment.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbMenuBtn": {
    "what": "Opens or closes the sidebar menu on a narrow screen.",
    "input": "Nothing to type. Just click it. Esc closes it.",
    "effect": "local"
   },
   "#sbOrderMenu summary": {
    "what": "Opens the sidebar order menu. Rearrange the sidebar, or put it back as it was",
    "input": "Nothing to type. Drag an item to move it, or use Alt+Up and Alt+Down on a focused item.",
    "effect": "local"
   },
   "#sbOrderReset": {
    "what": "Puts the sidebar back in its first order. The order is kept in this browser only.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdHelpFab": {
    "what": "Opens help and the glossary: how this tool works, every term, and what to do if something goes wrong.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdHelp button[onclick=\"_gdHelp(false)\"]": {
    "what": "Closes help and the glossary.",
    "input": "Nothing to type. Just click it. Esc does the same.",
    "effect": "local"
   },
   "#gdHelp a": {
    "what": "Opens What does everything do? in a new tab: every function explained in plain English.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#simpleBanner a.sbn-go": {
    "what": "Opens Simple mode: seven big tasks in plain words, one question at a time.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#simpleBanner button.sbn-no": {
    "what": "Hides this banner and stays in expert mode. The choice is kept in this browser.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdUpdateBtn": {
    "what": "Updates this app from GitHub and restarts it, or shows how to update it. It does not touch your tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdWhere button[onclick=\"_gdUpdateCheck()\"]": {
    "what": "Checks GitHub again for a newer build of this app.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdUpdBranch": {
    "what": "Picks which branch Update app pulls. Stable (main) is what customers run. QA and Development carry work that has not been through QA yet; use them to try a fix before it is promoted.",
    "input": "Pick one. Stable (main) is the safe choice.",
    "effect": "local"
   },
   "#gdUpdate button": {
    "what": "Copies the update command to the clipboard, to paste in a terminal.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdUpdate a": {
    "what": "Reloads the page on the new build.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#gdPanel input[aria-label=\"Guided mode\"]": {
    "what": "Turns Guided mode on or off. Guided mode keeps the seven steps in focus: it hides the Compliance coverage card and the Reference tools (Best practices, Zscaler update check). The gap-finding and deploy tools stay in the toolbar.",
    "input": "Ticked means Guided mode is on.",
    "effect": "local"
   },
   "#gdPanel button[onclick=\"_gdHelp(true)\"]": {
    "what": "Opens help and the glossary.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdPanel button[onclick=\"_gdGoConfig()\"]": {
    "what": "Opens the tenant details form and jumps to the first empty field.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdPanel button[onclick=\"_gdTest()\"]": {
    "what": "Signs in to the tenant with the details below to check they work. It reads no configuration.",
    "input": "Fill in the cloud, vanity domain, client ID and client secret first.",
    "effect": "read"
   },
   "#gdPanel button[onclick=\"_gdRun()\"]": {
    "what": "Runs the assessment: read-only checks on what is in scope, then the results on this page.",
    "input": "Nothing to type. Authenticate first, and fill in the organization and assessor names.",
    "effect": "read"
   },
   "#gdPanel button[onclick=\"_gdGoResults()\"]": {
    "what": "Scrolls down to the assessment results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdPanel button[onclick=\"openDlpPacksModal()\"]": {
    "what": "Opens Deploy policy packs: preflight, review, approve, deploy. Every rule arrives disabled.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdPanel button[onclick=\"openToolTab('terraform')\"]": {
    "what": "Opens the Terraform hand-off in a new tab: the same pack as a Terraform workspace.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#gdPanel button[onclick=\"_gdGoMigration()\"]": {
    "what": "Opens the Inline DLP rule migration wizard on this page, to move the tenant to Evaluate All Rules.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdTenantDetails summary": {
    "what": "Shows or hides the tenant details form: cloud, vanity domain and API client.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdPanel .gd-conn summary": {
    "what": "Shows or hides the technical detail of the sign-in error.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdProfSelect": {
    "what": "Picks a saved tenant profile. The form fills itself with that customer's details and scope.",
    "input": "Optional. Pick a profile, or no profile to type the details yourself.",
    "effect": "local"
   },
   "#gdProfiles button[onclick=\"_gdProfileSave(true)\"]": {
    "what": "Saves the details in the form as a new tenant profile on this computer.",
    "input": "A box asks for the profile name, usually the customer name.",
    "effect": "local"
   },
   "#gdProfiles button[onclick=\"_gdProfileSave(false)\"]": {
    "what": "Saves your changes to the selected tenant profile on this computer.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdProfiles button[onclick=\"_gdProfileDelete()\"]": {
    "what": "Forgets the selected profile and its assessment history. The tenant itself is not touched.",
    "input": "Nothing to type. A box asks you to confirm.",
    "effect": "local"
   },
   "#gdProfiles summary": {
    "what": "Shows or hides the profile details: industry, policy packs, notes and the remembered client secret.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdProfName": {
    "what": "Names this tenant profile.",
    "input": "Optional. Usually the customer name, like Acme Health.",
    "effect": "local"
   },
   "#gdProfIndustry": {
    "what": "Sets the customer's industry. It ticks that industry's policy packs below. It does not change any check.",
    "input": "Optional. Pick one from the list, like Healthcare.",
    "effect": "local"
   },
   "#gdProfiles input.gd-prof-pack": {
    "what": "Marks a policy pack that applies to this customer. The assessment measures the journey against the ticked packs only.",
    "input": "Ticked means the pack applies.",
    "effect": "local"
   },
   "#gdProfNotes": {
    "what": "Keeps notes about this customer with the profile.",
    "input": "Optional. Free text, like Kickoff 12 May, admin contact Pat Lee.",
    "effect": "local"
   },
   "#gdProfRemember": {
    "what": "Remembers the client secret in this laptop's credential store, so you do not paste it each time.",
    "input": "Ticked means remember it. Leave it unticked on a shared machine.",
    "effect": "local"
   },
   "#gdOffline .zo-row .zo-file + button": {
    "what": "Stops the snapshot save or compare that is running.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdOffline .zo-row button.gd-btn.primary": {
    "what": "Opens the sample tenant, a made-up company, in this browser. When one is open, it leaves the sample or closes the snapshot.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdOffline .zo-row button.gd-btn.quiet": {
    "what": "Saves a snapshot: a copy of the tenant settings in scope, never a secret, to open offline later.",
    "input": "Nothing to type. Sign in to the tenant and set the Scope page first.",
    "effect": "read"
   },
   "#zoFile": {
    "what": "Opens a snapshot file saved earlier, so you can use the app offline on it.",
    "input": "Required. A snapshot file in JSON, saved from this app.",
    "effect": "local"
   },
   "#gdOffline .zo-actions button[aria-label^=\"Open \"]": {
    "what": "Opens this saved snapshot in this browser, offline and read-only.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdOffline .zo-actions button[aria-label^=\"Compare \"]": {
    "what": "Reads the live tenant and shows what changed since this snapshot was saved.",
    "input": "Nothing to type. Sign in to the tenant first.",
    "effect": "read"
   },
   "#gdOffline .zo-actions a[download]": {
    "what": "Saves this snapshot as a file on this computer.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#gdOffline .zo-actions button[aria-label^=\"Delete \"]": {
    "what": "Deletes this saved snapshot from this computer. The tenant is not touched.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#gdJourney summary": {
    "what": "Shows or hides the five stages of the data governance journey, or the objects not yet in place.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbChSelectAll": {
    "what": "Marks every channel as addressed by Zscaler, or clears them all.",
    "input": "Ticked means all channels are in scope.",
    "effect": "local"
   },
   "#dbChAdd": {
    "what": "Adds your own channel or capability to track, like the built-in ones.",
    "input": "A box asks for its name.",
    "effect": "local"
   },
   "#dbChList .db-ch-check input": {
    "what": "Marks this channel as addressed by the customer. Unticked means it is a gap.",
    "input": "Ticked means addressed. Then pick Zscaler or Alternative.",
    "effect": "local"
   },
   "#dbChList input[value=\"zscaler\"]": {
    "what": "Says Zscaler covers this channel, so the assessment reads it.",
    "input": "Pick Zscaler or Alternative.",
    "effect": "local"
   },
   "#dbChList input[value=\"alternative\"]": {
    "what": "Says another product covers this channel, so its checks are not run.",
    "input": "Pick Zscaler or Alternative.",
    "effect": "local"
   },
   "#dbChList button.db-ch-edit": {
    "what": "Note the alternative vendor, or edit a custom channel",
    "input": "A box asks for the note, like the vendor name.",
    "effect": "local"
   },
   "#dbChList button.db-ch-expand": {
    "what": "Shows more about this channel, or less.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbScopeRun": {
    "what": "Runs the assessment on what is in scope here. The results open on the Dashboard.",
    "input": "Nothing to type. Authenticate first.",
    "effect": "read"
   },
   "#dbLastRunGo": {
    "what": "Goes to Scope assessment to run a fresh assessment, or to Connect to the tenant when none ran yet.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbRadarExpand": {
    "what": "Shows the scores by section as a big radar. Radar view, full size (three or more measured sections)",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbRadarClose": {
    "what": "Closes the full-size radar.",
    "input": "Nothing to type. Just click it. Esc does the same.",
    "effect": "local"
   },
   "#dbPillars button.db-pillar": {
    "what": "Jumps to the findings of this section in the results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbActions button[data-i=\"0\"]": {
    "what": "Opens Review and remediate: the findings to fix, with one-click recipes where there are some.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbActions button[data-i=\"1\"]": {
    "what": "Opens Traffic flow and gaps in a new tab: where inspection is lost.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dbActions button[data-i=\"2\"]": {
    "what": "Saves the assessment report as a Word document for the customer.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dbActions button[data-i=\"3\"]": {
    "what": "Opens Deploy policy packs to close the gaps, with a preflight first.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbActions button[data-i=\"4\"]": {
    "what": "Opens the Path analyzer in a new tab: what blocks one destination.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dbActions button[data-i=\"5\"]": {
    "what": "Opens the Flow animator in a new tab: watch the path, DLP and deploy flows.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dbActions button[data-i=\"6\"]": {
    "what": "Starts a new assessment: clears these results so you can run again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dbFootBtn": {
    "what": "Opens Review and remediate when there are gaps. With no gaps, it saves the report as a Word document.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#postureSummary button": {
    "what": "Opens Improve my score in a new tab, at the part this button names.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".tool-group button[onclick=\"openAiGuardTab()\"]": {
    "what": "Opens AI Guard: the detection policies, match rules, LLM applications and credential names, and Test a prompt with made-up prompts. Read-only. Opens in a new tab.",
    "input": "Nothing to type. Just click it. Nothing is read until you click Read in the new tab. Tick AI Guard on the Scope page first.",
    "effect": "nav"
   }
  },
  "/simple": {
   "#smExpertLink": {
    "what": "Back to the assessment page. Switches to expert mode, with all the tools and details. The app remembers this choice.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#smPovLink": {
    "what": "Plan and run a customer proof of value: intake, success criteria, a test runbook, a test kit and a report",
    "input": "Nothing to type. Just click it. Opens the proof of value page.",
    "effect": "nav"
   },
   "a.skip-link[href=\"#smMain\"]": {
    "what": "Skips straight to the big task buttons. Handy if you use the keyboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWords summary": {
    "what": "Shows or hides the list of words to know. Each word has a short meaning.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"connect\"]": {
    "what": "Opens the Connect task. You sign in once, so this app can look at your settings. It only signs in.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"check\"]": {
    "what": "Opens the Check task. We look at your settings and give you a score. It only looks.",
    "input": "Nothing to type. Just click it. Connect your Zscaler first.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"fix\"]": {
    "what": "Opens the Fix task. It shows the three most important things to fix, and how. Nothing changes until you say yes.",
    "input": "Nothing to type. Just click it. Run the check first.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"protect\"]": {
    "what": "Opens the Protect task. It helps you pick ready-made rules for your kind of work. Nothing changes until you say yes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"path\"]": {
    "what": "Opens the Why was something blocked task. Type a website, and we tell you what happens to it. It only looks.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"changes\"]": {
    "what": "Opens the Show what changed task. See how your score moved, and what this app added. It only looks.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smTiles button.sm-tile[data-tile=\"report\"]": {
    "what": "Opens the Report task. You get a Word file or an Excel table of your results. It only looks.",
    "input": "Nothing to type. Just click it. Run the check first.",
    "effect": "local"
   },
   "#smWizard:has(#smRunBar) #smNext": {
    "what": "Start the check. Reads your settings for the ways you picked and gives you a score. It takes a minute or two and changes nothing.",
    "input": "Nothing to type. Just click it. Pick at least one way on the step before.",
    "effect": "read"
   },
   "#smWizard:has(#smRun) #smNext": {
    "what": "Sign in. Signs in to your Zscaler to test the details. It reads nothing and changes nothing. For the sample tenant, it opens the made-up company.",
    "input": "Nothing to type. Just click it. Fill in the steps before first.",
    "effect": "read"
   },
   "#smWizard:has(#smRunText) #smNext": {
    "what": "Find out. Reads the rules you picked and tells you what Zscaler does with this website. It changes nothing.",
    "input": "Nothing to type. Just click it. Type a website and pick where to look first.",
    "effect": "read"
   },
   "#smNext": {
    "what": "Next. Goes on to the next step. If something is missing, it tells you what to fill in.",
    "input": "Answer the question on this step first.",
    "effect": "local"
   },
   "#smBack": {
    "what": "Back. Goes back one step, or to all tasks from the first step. While a check runs, it says Stop and stops it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smDone": {
    "what": "Done. Closes this task and takes you back to all tasks.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smExpertView": {
    "what": "Show me the expert view. Opens the expert page for this task, with all the details.",
    "input": "Nothing to type. Just click it. You may need to type your secret key again there.",
    "effect": "nav"
   },
   "#smWizard input[name=\"smHow\"][value^=\"profile:\"]": {
    "what": "Uses a saved connection on this computer. If the secret key was not kept, we ask for it next.",
    "input": "Pick one. Ticking this uses that saved connection.",
    "effect": "local"
   },
   "#smWizard input[name=\"smHow\"][value=\"new\"]": {
    "what": "Sets up a new connection. You need three things from Zscaler. We show you where to find them.",
    "input": "Pick one. Ticking this asks for your short name, client ID and client secret next.",
    "effect": "local"
   },
   "#smWizard input[name=\"smHow\"][value=\"server\"]": {
    "what": "Uses the details saved on this computer. Pick this if someone set up this computer for you.",
    "input": "Pick one. Ticking this uses the sign-in details the app already has.",
    "effect": "local"
   },
   "#smWizard input[name=\"smHow\"][value=\"sample\"]": {
    "what": "Tries the app with a sample tenant. It is a made-up company, so you can look around first. Nothing here is real.",
    "input": "Pick one. Ticking this opens the made-up company, not your real Zscaler.",
    "effect": "local"
   },
   "#smCloud": {
    "what": "Picks which Zscaler cloud your company uses. Not sure? Keep the first one. It works for most companies.",
    "input": "Required. Pick one from the list, like Most companies or zscalertwo.net.",
    "effect": "local"
   },
   "#smVd": {
    "what": "Your short name. This is your vanity domain, the word before .zslogin.net when you sign in.",
    "input": "Required. One word, like acme for acme.zslogin.net. If you paste the whole address, we keep only the short name.",
    "effect": "local"
   },
   "#smCid": {
    "what": "Client ID. This is the login name of the app's own API client, made in ZIdentity.",
    "input": "Required. A long mix of letters and numbers, copied from ZIdentity, Integration, API Clients.",
    "effect": "local"
   },
   "#smSec": {
    "what": "Client secret. It is like a password for the API client, so keep it safe.",
    "input": "Required. Copied from ZIdentity, Integration, API Clients. Shown as dots.",
    "effect": "local"
   },
   "#smSec2": {
    "what": "Client secret for this saved connection. This computer did not keep it, so we ask again. We keep it only while this page is open.",
    "input": "Required. Copied from ZIdentity, Integration, API Clients. Shown as dots.",
    "effect": "local"
   },
   "#smOrg": {
    "what": "Your company name. We put it on your report.",
    "input": "Required for a new connection, optional otherwise. Plain words, like Acme Bank.",
    "effect": "local"
   },
   "#smWho": {
    "what": "Your name. We put your name on the report, and on any rules you add later.",
    "input": "Optional. Your full name, like Sam Lee.",
    "effect": "local"
   },
   "#smWizard input[name=\"smRemember\"]": {
    "what": "Remembers your secret key on this computer. Leave this off if other people use this computer.",
    "input": "Optional. Ticked means the key is saved in a file on this computer. Unticked means we keep it only while this page is open.",
    "effect": "local"
   },
   "#smWizard input[name=\"smCh\"][value=\"web\"]": {
    "what": "Adds this way data can leave to the check. Web uploads: files and text that people send to websites.",
    "input": "Pick at least one. Ticked means we read the settings for this way. Unticked means we skip it.",
    "effect": "local"
   },
   "#smWizard input[name=\"smCh\"][value=\"endpoint\"]": {
    "what": "Adds this way data can leave to the check. Computers: files copied to USB sticks, printers and shared drives. This is an endpoint check.",
    "input": "Pick at least one. Ticked means we read the settings for this way. Unticked means we skip it.",
    "effect": "local"
   },
   "#smWizard input[name=\"smCh\"][value=\"email\"]": {
    "what": "Adds this way data can leave to the check. Email: mail that goes out of Microsoft 365 or Gmail.",
    "input": "Pick at least one. Ticked means we read the settings for this way. Unticked means we skip it.",
    "effect": "local"
   },
   "#smWizard input[name=\"smCh\"][value=\"saas\"]": {
    "what": "Adds this way data can leave to the check. Cloud apps: files kept in apps like Box or Google Drive.",
    "input": "Pick at least one. Ticked means we read the settings for this way. Unticked means we skip it.",
    "effect": "local"
   },
   "#smWizard a.sm-btn[href*=\"simple=fix\"]": {
    "what": "Fix it step by step. Opens the fix screen in the expert view. It shows the change first. Nothing changes until you say yes there.",
    "input": "Nothing to type. Just click it. You may need to type your secret key again there.",
    "effect": "nav"
   },
   "#smWizard a.sm-btn[href*=\"simple=finding\"]": {
    "what": "Show me this in the expert view. The expert view shows all the details for this one.",
    "input": "Nothing to type. Just click it. You may need to type your secret key again there.",
    "effect": "nav"
   },
   "#smWizard input[name=\"smKind\"]": {
    "what": "Picks the kind of work your company does. We use this to pick the right rules for you.",
    "input": "Pick one. Ticking this shows the rule sets that fit that kind of work.",
    "effect": "local"
   },
   "#smWizard input[name=\"smProfile\"]": {
    "what": "Picks the compliance rules your company must follow, like FedRAMP or HIPAA. It picks the rule sets on the next step.",
    "input": "Pick one, or None of these.",
    "effect": "local"
   },
   "#smWizard input[name=\"smPack\"]": {
    "what": "Picks a ready-made rule set, called a policy pack. The first one is the best first pick.",
    "input": "Pick one. Ticking this shows what that rule set would add, on the next step.",
    "effect": "local"
   },
   "#smDeployGo": {
    "what": "Open the deploy screen. Asks you first, then opens the expert view with this rule set picked. Nothing changes yet.",
    "input": "Nothing to type. Just click it. To really add the rules there, you need write mode on and the safety words.",
    "effect": "nav"
   },
   "#dlpAskGo": {
    "what": "Yes, open it. Opens the deploy screen in the expert view with this rule set picked. Nothing changes yet.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dlpAskCancel": {
    "what": "Cancel. Closes this question and stays here. Nothing changes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smSite": {
    "what": "Website address. The website you want to know about.",
    "input": "Required. A web address or host name, like dropbox.com or drive.google.com.",
    "effect": "local"
   },
   "#smWizard input[name=\"smWhere\"][value=\"web\"]": {
    "what": "Adds these rules to the look. Web rules: rules that stop some websites or apps, like URL filtering, Cloud App Control and SSL inspection.",
    "input": "Pick at least one. Ticked means we read these rules. Unticked means we skip them.",
    "effect": "local"
   },
   "#smWizard input[name=\"smWhere\"][value=\"data\"]": {
    "what": "Adds these rules to the look. Data rules: rules that look for private data. This is DLP.",
    "input": "Pick at least one. Ticked means we read these rules. Unticked means we skip them.",
    "effect": "local"
   },
   "#smWizard input[name=\"smWhere\"][value=\"app\"]": {
    "what": "Adds these rules to the look. The Zscaler app: the Client Connector app on each computer.",
    "input": "Pick at least one. Ticked means we read these rules. Unticked means we skip them.",
    "effect": "local"
   },
   "#smWizard input[name=\"smWhat\"][value=\"score\"]": {
    "what": "How my score changed. Compares your last two check-ups.",
    "input": "Pick one. Ticking this shows your score history. It needs a saved connection.",
    "effect": "local"
   },
   "#smWizard input[name=\"smWhat\"][value=\"added\"]": {
    "what": "What this app added. Shows the rule sets that this app put into your Zscaler.",
    "input": "Pick one. Ticking this lists what this app added, and what was taken out again.",
    "effect": "local"
   },
   "#smWizard input[name=\"smFile\"][value=\"word\"]": {
    "what": "A Word file. A neat report to read or print.",
    "input": "Pick one. Ticking this makes a Word file.",
    "effect": "local"
   },
   "#smWizard input[name=\"smFile\"][value=\"sheet\"]": {
    "what": "A spreadsheet. A table of your results that you can open in Excel.",
    "input": "Pick one. Ticking this makes a CSV table file.",
    "effect": "local"
   },
   "#smMake": {
    "what": "Make my file. Saves your report to this computer. Look in your Downloads folder.",
    "input": "Nothing to type. Just click it. Run the check first.",
    "effect": "download"
   },
   "#smWizard button.sm-btn[data-tile=\"connect\"]": {
    "what": "Connect my Zscaler. Opens the Connect task, so you can sign in first.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWizard button.sm-btn[data-tile=\"check\"]": {
    "what": "Check how safe my data is. Opens the Check task, which gives you a score.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWizard button.sm-btn[data-tile=\"fix\"]": {
    "what": "Fix the top problems. Opens the Fix task with the three most important things to fix.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWizard button.sm-btn[data-tile=\"protect\"]": {
    "what": "Protect sensitive data. Opens the Protect task, to pick ready-made rules.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWizard .nextstep details summary": {
    "what": "What an expert would do next. Shows or hides a tip from the expert view.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#smWizard details.sm-box summary": {
    "what": "Shows or hides more detail. For a website answer, this is the exact answer.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/help": {
   ".rp-bar a[href=\"#glossary\"]": {
    "what": "Jumps to the list of words you will hear.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".rp-bar a[href=\"#trouble\"]": {
    "what": "Jumps to fixes for when something goes wrong.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#hpFirst a": {
    "what": "Jumps to the help for this step on this page.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#hpToc a": {
    "what": "Jumps to the help for this function on this page.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#hpAll a.rp-btn": {
    "what": "Opens that page of the app in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/advanced": {
   "#advUpdNotify": {
    "what": "Sends one notice per new version, by the e-mail or webhook the digests use, when the update check finds a newer version.",
    "input": "Optional. Ticked turns it on. Needs the digests' e-mail or webhook set up; a writer may change it.",
    "effect": "local"
   },
   "#advPlugOn": {
    "what": "Allows approved local plugins to load when the app starts. Off, no plugin loads, approved or not.",
    "input": "Optional. Ticked turns it on. Needs the plugins folder set (DLP_CHECK_PLUGINS_DIR); a writer on this computer may change it.",
    "effect": "local"
   },
   "#advPlugins button[data-approve]": {
    "what": "Puts this exact plugin hash on the allow-list after you have read its code. It loads when the app next starts; a changed file is refused.",
    "input": "Type the plugin's name to confirm, then optionally the people allowed to use it.",
    "effect": "confirm"
   },
   "#advPlugins button[data-revoke]": {
    "what": "Takes this plugin off the allow-list and unloads it at once.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advApiJob": {
    "what": "Shows only the API calls one run made, like a deploy, a builder or a readiness check. Every call shows all of them.",
    "input": "Optional. Pick a run from the list; each says its kind, its id and how many calls it made.",
    "effect": "local"
   },
   "#advApiProduct": {
    "what": "Shows only the API calls made to one Zscaler product, like ZIA or ZPA.",
    "input": "Optional. Pick a product. Every product shows all of them.",
    "effect": "local"
   },
   "#advApiFailed": {
    "what": "Shows only the calls that failed or had to be sent again, for example after a rate limit.",
    "input": "Tick it to show only those. Clear it to show every call.",
    "effect": "local"
   },
   "#advApiReload": {
    "what": "Reads the list of API calls again from this server. It calls nothing at Zscaler.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advApiCsv": {
    "what": "Saves the API calls shown, with the same filters, as a CSV spreadsheet file. No body, token, secret or tenant name is in it.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#advApiJson": {
    "what": "Saves the API calls shown, with the same filters, as a JSON data file. No body, token, secret or tenant name is in it.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#advRefresh": {
    "what": "Re-read the library from disk. The pack list then shows the packs saved on this computer now.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".rp-bar a.rp-btn[href^=\"#\"]": {
    "what": "Jumps to that part of this page.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advGlass": {
    "what": "Turns the glass effect on or off. On, bars, cards and buttons are see-through like frosted glass. Off, they are solid.",
    "input": "Tick it or clear it. The choice is kept in this browser only and every open tab follows it.",
    "effect": "local"
   },
   "#advM365On": {
    "what": "Lets this app fetch Microsoft's list of Microsoft 365 sites and addresses from endpoints.office.com. It sends nothing about your tenant.",
    "input": "Tick it or clear it. Off by default. On, the app checks for a new version at most once a day when you analyze.",
    "effect": "local"
   },
   "#advM365Fetch": {
    "what": "Fetches Microsoft's Microsoft 365 list now. The Path analyzer, Test a list and Shadowed rules then match the OFFICE365 app service group with it.",
    "input": "Nothing to type. Turn on fetching first. A list that fails the checks is refused and the old one stays.",
    "effect": "local"
   },
   "#advM365Remove": {
    "what": "Forgets the Microsoft 365 list. Rules on Microsoft 365 app service groups show as unknown again.",
    "input": "Nothing to type. Just click it, then confirm.",
    "effect": "local"
   },
   "#advM365File": {
    "what": "Picks a saved copy of Microsoft's Microsoft 365 list, for a machine that cannot reach endpoints.office.com.",
    "input": "Required to import. The JSON file that endpoints.office.com/endpoints/worldwide gives, up to 2 MB.",
    "effect": "local"
   },
   "#advM365Ver": {
    "what": "Names the version of the list you import, so results can say which list they used.",
    "input": "Optional. Ten digits, like 2026100100, as endpoints.office.com/version/worldwide gives it.",
    "effect": "local"
   },
   "#advM365Import": {
    "what": "Checks the chosen file and keeps it as the Microsoft 365 list. A file that is not Microsoft's list is refused whole.",
    "input": "Choose the file first. The version is optional. Nothing touches the tenant.",
    "effect": "local"
   },
   "#advAssessor": {
    "what": "Names the assessor in every Terraform download. Each object's description is tagged with this name, never Zscaler Made Easy.",
    "input": "Required for Terraform downloads. A person's name, up to 40 letters, like Alex Morgan. Not the tool's name.",
    "effect": "local"
   },
   "#advPacks a[href$=\"/bundle\"]": {
    "what": "Download this pack as one JSON file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#advPacks a[href$=\"/terraform.zip\"]": {
    "what": "Download this pack as a Terraform workspace for the zscaler/zia provider (static mode).",
    "input": "Fill in the assessor name above first. Without a name the download is refused.",
    "effect": "download"
   },
   "#advPacks button[data-remove]": {
    "what": "Remove this uploaded pack from the library. Nothing is changed in the Zscaler tenant.",
    "input": "Nothing to type. Just click it, then confirm. Needs uploads allowed on this server.",
    "effect": "local"
   },
   "#advFiles": {
    "what": "Picks the pack files to add. The app reads them and checks them right away.",
    "input": "Required. JSON, Terraform (.tf) or ZIP files, up to 8 MB. Example: dlp_policies.json. You can also drop files on the box.",
    "effect": "local"
   },
   "#advName": {
    "what": "Names the new pack.",
    "input": "Optional. Any short name, like Finance PII. Left empty, the name comes from the files.",
    "effect": "local"
   },
   "#advId": {
    "what": "Sets the pack id, which is also its folder name.",
    "input": "Optional. Letters, digits and _ only, like finance_pii. Left empty, it comes from the name.",
    "effect": "local"
   },
   "#advDesc": {
    "what": "Describes the new pack.",
    "input": "Optional. A short sentence on what it protects and for whom.",
    "effect": "local"
   },
   "#advCheck": {
    "what": "Checks the chosen files: patterns must work, and rules must point to engines that exist. Shows what blocks the pack, if anything.",
    "input": "Choose the files first. Nothing is stored and nothing touches the tenant.",
    "effect": "local"
   },
   "#advAdd": {
    "what": "Adds the checked pack to the library on this computer and turns it into Terraform. It then shows up in Deploy policy packs.",
    "input": "Check the files first; the check must pass. Needs uploads allowed on this server. Nothing touches the tenant.",
    "effect": "local"
   },
   "#advPreview summary": {
    "what": "Opens or closes the list of dictionaries, engines or rules found in the files.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advStatus a.rp-btn": {
    "what": "Saves the Terraform made from the pack you just added.",
    "input": "Fill in the assessor name above first. Without a name the download is refused.",
    "effect": "download"
   },
   "#extension a[href=\"/api/browser-extension.zip\"]": {
    "what": "Saves the companion browser extension for Chrome and Edge as a zip file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#advExample": {
    "what": "Saves a complete example pack as one JSON file, to show the format the app accepts.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#advUpdBtn": {
    "what": "Gets the latest release from GitHub, reinstalls what it needs and restarts the app. Your settings and saved packs are kept.",
    "input": "Nothing to type. Just click it. The app restarts, so finish other work first.",
    "effect": "local"
   },
   "#advUpdCheck": {
    "what": "Asks GitHub again if a newer build of the app is out.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#sbd a[target=\"_blank\"]": {
    "what": "Opens CISA's Secure by Design page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#advSbdCheck": {
    "what": "Measures this app against CISA's Secure by Design ideas again. It says nothing about the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#quality a[href=\"/api/quality-score/report.md\"]": {
    "what": "Opens the full quality and security report of this app in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#advQsReload": {
    "what": "Loads this app's quality and security score again, from the last full test run.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advUpCheck": {
    "what": "Runs the offline check now: the installed SDK and Terraform against what the shipped packs send. It takes under a second.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#advUpBeacon": {
    "what": "Opens Beacon in a new tab: the online check on this server, on a timer, with what changed.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#upstream a[href=\"/report/beacon\"]": {
    "what": "Opens Beacon in a new tab: the online check on this server, on a timer, with what changed.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/audit": {
   "#atDays": {
    "what": "Sets how far back the timeline goes. ZIA keeps its audit log for up to 180 days.",
    "input": "Pick a window, like Last 7 days (the default), or Dates… to pick your own dates.",
    "effect": "local"
   },
   "#atStart": {
    "what": "Sets the first day of the timeline.",
    "input": "Required when Dates… is picked. A date, like 2026-10-01.",
    "effect": "local"
   },
   "#atEnd": {
    "what": "Sets the last day of the timeline.",
    "input": "Required when Dates… is picked. A date on or after From, like 2026-10-28.",
    "effect": "local"
   },
   "#atZia": {
    "what": "Adds ZIA's admin audit log to the timeline. Without it, only Zscaler Made Easy's own records are shown.",
    "input": "Tick to read ZIA's audit log. Needs Automation readiness in scope and an API role that may view the audit log.",
    "effect": "local"
   },
   "#atTenant": {
    "what": "Picks which tenant sign-in reads ZIA's audit log. It only shows when there is more than one choice.",
    "input": "Optional. Pick who to sign in as: the assessment tab, a saved tenant profile, or what is saved on this computer.",
    "effect": "local"
   },
   "#atRun": {
    "what": "Asks ZIA for an audit log report for the window, reads it, and adds the app's own records. Then shows one timeline, newest first.",
    "input": "Choose a window first. Asking ZIA for the report changes nothing in the tenant, so no write mode is needed.",
    "effect": "read"
   },
   "#atStop": {
    "what": "Stops building the timeline.",
    "input": "Nothing to type. Just click it while the timeline is built.",
    "effect": "local"
   },
   "#atCsv": {
    "what": "Saves the timeline as a CSV file.",
    "input": "Build the timeline first.",
    "effect": "download"
   },
   "#atJson": {
    "what": "Saves the timeline as a JSON file.",
    "input": "Build the timeline first.",
    "effect": "download"
   },
   "#atFSrc": {
    "what": "Shows only events from one source.",
    "input": "Pick a source, or Every source.",
    "effect": "local"
   },
   "#atFAdmin": {
    "what": "Shows only changes made by one admin.",
    "input": "Pick an admin, or Every admin.",
    "effect": "local"
   },
   "#atFAction": {
    "what": "Shows only events whose action has this text.",
    "input": "Optional. Part of an action, like update or delete.",
    "effect": "local"
   },
   "#atFObject": {
    "what": "Shows only events whose object or category has this text.",
    "input": "Optional. Part of a name, like a rule or dictionary name.",
    "effect": "local"
   },
   "#atFQ": {
    "what": "Shows only events that have this text anywhere.",
    "input": "Optional. Any text, like an admin name or a result.",
    "effect": "local"
   },
   "#atFForeign": {
    "what": "Shows only changes someone else made to objects Zscaler Made Easy created.",
    "input": "Tick to see only those changes.",
    "effect": "local"
   },
   "#atTable button.at-more": {
    "what": "Opens or closes the details of this event: what changed field by field, and the raw audit log entry.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#atMore": {
    "what": "Shows more events in the table.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#atBody details summary": {
    "what": "Opens or closes the log of what was read to build the timeline.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/beacon": {
   "a.rp-btn[href=\"#changes\"]": {
    "what": "Jumps to what changed since the last Beacon run.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"#sdk\"]": {
    "what": "Jumps to the SDK part: the Zscaler Python SDK releases and whether they touch what the app uses.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"#api\"]": {
    "what": "Jumps to the API part: ZIA operations, the API reference, Zscaler help pages and the tenant API watch.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"#terraform\"]": {
    "what": "Jumps to the Terraform part: the zscaler/zia provider version, schema and docs.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"#history\"]": {
    "what": "Jumps to the history of the last 30 Beacon runs on this computer.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#bcOnline": {
    "what": "Ticked: Run now also reads the internet (PyPI, the Terraform registry and Zscaler pages). Unticked: it checks only the SDK and Terraform files on this computer.",
    "input": "Optional. Ticked by default.",
    "effect": "local"
   },
   "#bcRun": {
    "what": "Runs Beacon now: checks the SDK, the API and the Terraform provider for changes since the last run. It does not read your tenant.",
    "input": "Nothing to type. Just click it. Tick Online to read the internet too.",
    "effect": "local"
   },
   "#bcTenant": {
    "what": "Picks which tenant the tenant API watch reads. The line below then says what is in scope.",
    "input": "Pick one: the assessment tab's sign-in, a saved tenant profile, or the one saved on this computer.",
    "effect": "local"
   },
   "#bcRunTenant": {
    "what": "Runs Beacon and also reads, from the tenant, only the endpoints in scope on the Scope page. GET only, about one request a second.",
    "input": "Pick a tenant first. Something must be in scope on the Scope page.",
    "effect": "read"
   },
   "#bcStop": {
    "what": "Stops the tenant API watch. It reads nothing more, and what was read is kept.",
    "input": "Nothing to type. Just click it. It shows while a run is going.",
    "effect": "local"
   },
   "#bcTenantBody summary": {
    "what": "Shows or hides the endpoints that are not in scope or not mapped. They were never read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#bcChanges a": {
    "what": "Opens the page behind this change in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#bcApi a": {
    "what": "Opens this Zscaler help or API page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/other-products": {
   "#opTenant": {
    "what": "Picks which tenant sign-in the read uses.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#opZcell": {
    "what": "The Zero Trust Cellular customer ID. Every Zero Trust Cellular read carries it.",
    "input": "Optional; needed only when Zero Trust Cellular is ticked. Letters, digits, - and _, at most 64, for example gi754cvqb07r0. The ZCell admin portal shows it.",
    "effect": "local"
   },
   "#opZms": {
    "what": "The Microsegmentation customer ID. Every Microsegmentation query carries it.",
    "input": "Optional. Leave it empty to use the ZPA customer ID from Connect to the tenant. Letters, digits, - and _, at most 64.",
    "effect": "local"
   },
   "#opRun": {
    "what": "Reads the other Zscaler products ticked on the Scope page once and checks them: Zero Trust Branch, EASM, Business Insights, Zero Trust Cellular and Microsegmentation.",
    "input": "Nothing to type. Just click it. Tick at least one of these products on the Scope page first.",
    "effect": "read"
   },
   "#opStop": {
    "what": "Stops the read at once. Nothing more is read and nothing is kept.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#expXlsx": {
    "what": "Saves the findings and every table of this read as an Excel workbook.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the findings and every table of this read as a JSON file.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#opBody .op-filter button[data-sev]": {
    "what": "Shows only the findings of this severity. All shows every finding.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opBody details.pa-details > summary": {
    "what": "Shows or hides this list: the assumptions, or the log of what was read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/browser": {
   "#bwTenant": {
    "what": "Picks which tenant sign-in the browser security read uses.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#bwRun": {
    "what": "Reads browser security once: isolation profiles, rules that isolate, Browser Control, Browser Access and Privileged Remote Access.",
    "input": "Nothing to type. Just click it. Tick ZIA platform or ZPA on the Scope page first.",
    "effect": "read"
   },
   "#bwStop": {
    "what": "Stops the read at once. Nothing more is read and nothing is kept.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#expXlsx": {
    "what": "Saves the findings and the tables of this read as an Excel workbook.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the findings and the tables of this read as a JSON file.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#bwBody .bw-filter button[data-sev]": {
    "what": "Shows only the findings of this severity. All shows every finding.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#bwBody details.pa-details > summary": {
    "what": "Shows or hides this list: the assumptions, or the log of what was read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/ztw": {
   "#ztTenant": {
    "what": "Picks which tenant sign-in the Cloud & Branch Connector read uses.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#ztRun": {
    "what": "Reads the Cloud & Branch Connector configuration once and checks it: connector groups, forwarding rules, gateways, locations, activation, admins, roles, API keys and cloud accounts. It never reads an API key value or a provisioning URL.",
    "input": "Nothing to type. Just click it. Tick Cloud & Branch Connector on the Scope page first, and sign in with a OneAPI API client.",
    "effect": "read"
   },
   "#ztStop": {
    "what": "Stops the read at once. Nothing more is read and nothing is kept.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#expXlsx": {
    "what": "Saves the findings and the tables of this read as an Excel workbook. Admins are counted and key values are never in it.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the findings and the tables of this read as a JSON file. Admins are counted and key values are never in it.",
    "input": "Nothing to type. Just click it. Click Read first.",
    "effect": "download"
   },
   "#ztBody .zt-filter button[data-st]": {
    "what": "Shows only the findings with this result. All shows every finding.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#ztBody a.zt-trace": {
    "what": "Opens the Path analyzer for traffic from a workload, with this connector group (and the rule's workload group and destination) filled in, reusing this read. Nothing is read until you click Analyze there.",
    "input": "Nothing to type. Just click it. You can add the workload's source IP and tags there.",
    "effect": "nav"
   },
   "#ztBody details.pa-details > summary": {
    "what": "Shows or hides this list: the assumptions, or the log of what was read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/bypass": {
   "a.rp-btn[href^=\"/reference/data-security-architect\"]": {
    "what": "Data Security Architect: the reference architecture this flow is measured against (inline web module; opens in a new tab)",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#expCsv": {
    "what": "Saves this bypass report as a CSV file. A spreadsheet can open it.",
    "input": "Nothing to type. Just click it. It shows once the report is ready.",
    "effect": "download"
   },
   "#expMd": {
    "what": "Saves this bypass report as a Markdown text file.",
    "input": "Nothing to type. Just click it. It shows once the report is ready.",
    "effect": "download"
   },
   "#expDocx": {
    "what": "Saves this bypass report as a Word document.",
    "input": "Nothing to type. Just click it. It shows once the report is ready.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves this bypass report as a JSON file, with every item in full. Other tools can read it.",
    "input": "Nothing to type. Just click it. It shows once the report is ready.",
    "effect": "download"
   },
   "#bpFlow button.rp-btn": {
    "what": "Pauses or plays the moving packets in the bypass picture. The list under the picture says the same in words.",
    "input": "Nothing to type. Just click it. The label says what a click does now.",
    "effect": "local"
   },
   "#rpBody .bp-card details summary": {
    "what": "Shows or hides the parts of the tenant that could not be read, and the error for each.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody details.bp-sec summary": {
    "what": "Opens or closes this group of bypass items. The number at the right is how many items it holds.",
    "input": "Nothing to type. Just click it. Groups with items start open.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/compliance": {
   "#cpProfilePick": {
    "what": "Reads this assessment's checks against a compliance profile, like FedRAMP High. Each control shows met, partly met, not met or not tested.",
    "input": "Optional. Pick a profile. It reads nothing from the tenant.",
    "effect": "local"
   },
   "#cpProfileCsv": {
    "what": "Saves the assessment read against the picked compliance profile as a CSV file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#cpScope": {
    "what": "Picks which frameworks to show as cards.",
    "input": "Pick Selected in the assessment, or All frameworks.",
    "effect": "local"
   },
   "#expMd": {
    "what": "Saves the compliance mapping as a Markdown text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the compliance mapping as a JSON data file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expCsv": {
    "what": "Saves the compliance mapping as a CSV file for a spreadsheet.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#rpBody .cp-card": {
    "what": "Opens this framework's controls below: met, partly met or not met, with the findings behind each.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#cpDrill [data-filter]": {
    "what": "Shows only the controls with this status, or all of them.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#cpClose": {
    "what": "Closes this framework's list of controls.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody a.rp-btn[href=\"/\"]": {
    "what": "Goes back to the assessment page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/dataflow": {
   "a.rp-btn[href^=\"/reference/data-security-architect\"]": {
    "what": "Data Security Architect: the reference architecture this flow is measured against (inline web module; opens in a new tab)",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dfDest": {
    "what": "Sets the place you want to trace, like a cloud app, a URL category or a host name. Press Enter or Trace to see its path.",
    "input": "Required for Trace. A cloud app, URL category or host name, like Dropbox, Web Mail or drive.google.com. The list suggests names.",
    "effect": "local"
   },
   "#dfNet": {
    "what": "Picks the network the device is on for the next trace. Each network can use a different forwarding action.",
    "input": "Pick one: Off network (remote), On trusted network (office) or On VPN.",
    "effect": "local"
   },
   "#dfPlat": {
    "what": "Picks the device type for the next trace or refresh. Client Connector profiles can differ per device type.",
    "input": "Pick one: windows, macos, ios, android or linux.",
    "effect": "local"
   },
   "#dfTrace": {
    "what": "Traces the path for the place you typed, on the network and device type you picked. It uses the copy of settings already read, so it does not ask the tenant again.",
    "input": "Type a destination first. Network and Platform are optional.",
    "effect": "local"
   },
   "#dfRefresh": {
    "what": "Re-read the tenant. The assessment tab reads the settings again and redraws this map.",
    "input": "Nothing to type. Just click it. The assessment tab must still be open and signed in.",
    "effect": "read"
   },
   "#dfBypass": {
    "what": "The full bypass and non-inspected inventory. Opens the Bypass report in a new tab, which reads the tenant.",
    "input": "Nothing to type. Just click it. The assessment tab must still be open.",
    "effect": "read"
   },
   "#dfSsl": {
    "what": "The full SSL inspection flow diagram. Opens it in a new tab, which reads the tenant.",
    "input": "Nothing to type. Just click it. The assessment tab must still be open.",
    "effect": "read"
   },
   "#expMd": {
    "what": "Saves this data flow map as a Markdown text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves this data flow map as a JSON file, with every traced path in full.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dfMotionPlay": {
    "what": "Pauses or plays the moving packets in the traffic flow picture. The list under it says the same in words.",
    "input": "Nothing to type. Just click it. The label says what a click does now.",
    "effect": "local"
   },
   "#dfMotionStage path.fa-band": {
    "what": "Shows one route the traffic takes, as wide as its share of all traced paths. Hover for its count; click or press Enter to list its paths.",
    "input": "Nothing to type. Hover it, or click it to list the paths.",
    "effect": "local"
   },
   "#dfMotionPick a": {
    "what": "Jumps to this path in the Every destination, every network table and shows its full path.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dfEnforcement g.df-node": {
    "what": "Scrolls to the words for this step of how ZIA handles a web request.",
    "input": "Nothing to type. Click it or press Enter.",
    "effect": "local"
   },
   "#dfTraceBody g.df-node": {
    "what": "Scrolls to the details for this step of the path, with the rule that decided it.",
    "input": "Nothing to type. Click it or press Enter.",
    "effect": "local"
   },
   "#dfTraceBody summary": {
    "what": "Shows or hides every Client Connector app profile, forwarding profile and PAC file read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dfCategories button.df-vis": {
    "what": "Shows the full path for this cloud app category on this network. The cell says how much DLP can see there; click for the path.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dfFishbones button.df-cat-card": {
    "what": "Opens the full path for this cloud app category, with each control in order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dfGaps button.df-gap": {
    "what": "Shows the full path for this place where inspection is lost, and what causes it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody .df-cc summary": {
    "what": "Shows or hides the parts of the tenant that could not be read, and the error for each.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/deploy-flow": {
   "#tabDeploy": {
    "what": "Shows the steps of deploying a pack.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tabRemove": {
    "what": "Shows the steps of removing a pack.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#flow button[onclick=\"toggle(this)\"]": {
    "what": "Opens or closes this step: what happens, what can stop it, and what you see.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick=\"expandAll(true)\"]": {
    "what": "Opens every step at once.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[onclick=\"expandAll(false)\"]": {
    "what": "Closes every step at once.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".df-nav a.rp-btn[href=\"/\"]": {
    "what": "Back to the app: opens the app's main page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/device-posture": {
   "#dvTenant": {
    "what": "Picks which tenant sign-in the device posture read uses.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#dvRun": {
    "what": "Reads the ZPA posture profiles, trusted networks and access rules once. Then it shows the findings.",
    "input": "Nothing to type. Just click it. Tick ZPA on the Scope page and give the ZPA customer ID first.",
    "effect": "read"
   },
   "#dvStop": {
    "what": "Stops the read at once. Nothing more is read and nothing is kept.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#expXlsx": {
    "what": "Profiles, families, usage, findings and every access rule in plain words, as an Excel workbook. Saves it as a file.",
    "input": "Nothing to type. Just click it. Read device posture first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "The whole report as JSON. Saves it as a file.",
    "input": "Nothing to type. Just click it. Read device posture first.",
    "effect": "download"
   },
   "#tab-findings": {
    "what": "Shows the findings: rules that let devices in without a real check. Fix high before medium.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-profiles": {
    "what": "Shows each posture profile (a device check), its family and the rules that use it.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-networks": {
    "what": "Shows each trusted network (where a device is) and the rules that use it.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-rules": {
    "what": "Shows every access rule and its conditions in plain words.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#rSearch": {
    "what": "Narrows the access rules to those that contain your words.",
    "input": "Optional. Any words, like a rule, app, group or profile name. Blank shows all.",
    "effect": "local"
   },
   "#rShow": {
    "what": "Picks which access rules to show.",
    "input": "Pick one: every rule, rules with a posture check, rules with a finding, or allow rules without a posture check.",
    "effect": "local"
   },
   "#rList details.dv-rule > summary": {
    "what": "Opens or closes this access rule. Inside, its conditions are in plain words.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#panel-findings details.pa-details > summary": {
    "what": "Shows or hides the log of what was read, line by line.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/digest": {
   "#dgHealth": {
    "what": "The FP/TP detection ratio report is generated from the assessment page (it reads the tenant); this opens it from there.",
    "input": "Nothing to type. Just click it. Keep the assessment tab open.",
    "effect": "nav"
   },
   "#dgRun": {
    "what": "Runs the loop now: reads the guidance sources and each tenant profile that remembers its secret, writes a digest, and sends it when set up.",
    "input": "Nothing to type. Just click it. Only what each profile's Scope page puts in scope is read. It takes about a minute per tenant.",
    "effect": "read"
   },
   "#dgMd": {
    "what": "Saves the latest digest as a Markdown file.",
    "input": "Nothing to type. Just click it. Works once a digest exists.",
    "effect": "download"
   },
   "section[aria-labelledby=\"dgLatestH\"] summary": {
    "what": "Opens or closes the full text of the latest digest.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "section[aria-labelledby=\"dgSaasH\"] summary": {
    "what": "Opens or closes the list of every SaaS application and what it can do.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dgPrev a.rp-btn": {
    "what": "Saves this past digest as a Markdown file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   }
  },
  "/report/evalall": {
   ".rp-bar a.rp-btn[href*=\"help.zscaler.com\"]": {
    "what": "Opens the Zscaler help page on DLP rules with Evaluate All Rules, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#evalAllFlow summary": {
    "what": "Shows or hides the two lanes: first match wins next to Evaluate All Rules, and how a tie is broken.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#evalAllFlow a[href*=\"help.zscaler.com\"]": {
    "what": "Opens the Zscaler help page this diagram is based on, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/exports": {
   "#exTenant": {
    "what": "Picks which tenant sign-in the exports use. It only shows when there is more than one choice.",
    "input": "Optional. Pick who to sign in as: the assessment tab, a saved tenant profile, or what is saved on this computer.",
    "effect": "local"
   },
   "#exPaper": {
    "what": "Sets the paper size for PDF exports: the policy PDF and the deployment plan PDF.",
    "input": "Pick A4 or Letter. A4 is the default.",
    "effect": "local"
   },
   "input[name=\"exPolicy\"]": {
    "what": "Picks a policy to put in the policy export. Each ticked policy gets its own workbook or PDF.",
    "input": "Tick to include this policy. Tick at least one. Several policies arrive as one zip.",
    "effect": "local"
   },
   "#exPolXlsx": {
    "what": "Reads the ticked policies from the tenant, read-only, and saves one formatted Excel workbook per policy.",
    "input": "Tick at least one policy first. URL filtering and File Type Control need DLP or ZIA platform ticked on the Scope page.",
    "effect": "download"
   },
   "#exPolPdf": {
    "what": "Reads the ticked policies from the tenant, read-only, and saves a PDF review copy of each one.",
    "input": "Tick at least one policy first. The PDF paper box sets the page size.",
    "effect": "download"
   },
   "#exLocations": {
    "what": "Reads every location, sub-location and location group, read-only, and saves them in an Excel file with the rules that use each one.",
    "input": "Nothing to type. Just click it. Needs ZIA platform ticked on the Scope page.",
    "effect": "download"
   },
   "#exZcc": {
    "what": "Reads the Client Connector app profiles, forwarding profiles and PAC files, read-only, and saves them in an Excel file.",
    "input": "Nothing to type. Just click it. Needs ZCC ticked on the Scope page.",
    "effect": "download"
   },
   "#exUrls": {
    "what": "Reads every URL, domain, IP range and keyword the policy names, read-only, and saves them in one Excel file. Each one says where it was found.",
    "input": "Nothing to type. Just click it. Only sources in scope on the Scope page are read.",
    "effect": "download"
   },
   "#exCats": {
    "what": "Names the custom URL categories to check. Leave it empty to check all of them.",
    "input": "Optional. Category names or ids, separated by commas, like Finance Sites, CUSTOM_01.",
    "effect": "local"
   },
   "#exMax": {
    "what": "Sets the most URLs the analyzer looks up in one run. The rest are listed as not looked up.",
    "input": "Optional. A whole number from 1 to 20000. The default is 20000.",
    "effect": "local"
   },
   "#exContinue": {
    "what": "Looks up the URLs the last analyzer run did not reach, keeping what it already looked up, and saves an Excel file that covers everything so far.",
    "input": "Nothing to type. Just click it. It continues the same categories; the lookup changes nothing in the tenant.",
    "effect": "download"
   },
   "#exAnalyze": {
    "what": "Looks up each URL of your custom categories with ZIA's URL lookup and saves an Excel file. It says if Zscaler already sorts it the same way, differently, or not at all.",
    "input": "Fill in Categories and At most first, or leave them as they are. The lookup changes nothing in the tenant. Needs DLP or ZIA platform ticked.",
    "effect": "download"
   },
   "#exInventory": {
    "what": "Reads the tenant's DLP dictionaries, engines and rules on each channel, read-only, and saves them in an Excel file with who uses what.",
    "input": "Nothing to type. Just click it. Needs DLP ticked on the Scope page.",
    "effect": "download"
   },
   "#exPackJson": {
    "what": "Reads the DLP rules on the channels in scope, with the engines and dictionaries they use, and saves them as a policy pack JSON file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#exPackTf": {
    "what": "Reads the DLP rules on the channels in scope, with the engines and dictionaries they use, and saves them as a Terraform workspace (a zip file).",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "input[name=\"exTfProduct\"]": {
    "what": "Picks a product to put in the whole-tenant Terraform export. Each ticked product gets its own workspace.",
    "input": "Tick at least one: ZIA, ZPA, Cloud & Branch Connector or Client Connector. Only what the Scope page ticks is read.",
    "effect": "local"
   },
   "input[name=\"exTfMode\"]": {
    "what": "Picks how the Terraform is meant to be used. Adopt brings this tenant's objects into Terraform as they are, with import blocks. Clone makes new objects for another tenant, every rule disabled.",
    "input": "Pick one. Adopt is the default and changes nothing in the tenant.",
    "effect": "local"
   },
   "#exTfMore summary": {
    "what": "Opens or closes the extra options of the whole-tenant Terraform export.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exTfPrefix": {
    "what": "Puts a short word in front of every resource name in the Terraform files, so they do not clash with names you already use.",
    "input": "Optional. A lowercase letter first, then lowercase letters, digits or _, at most 20, like acme.",
    "effect": "local"
   },
   "#exTfNs": {
    "what": "Sets where Terraform downloads the Zscaler providers from, for a private registry mirror.",
    "input": "Optional. Leave empty for zscaler, or type a mirror like registry.example.com/zscaler.",
    "effect": "local"
   },
   "#exTfMt": {
    "what": "Reads the ZPA objects of one microtenant instead of the parent tenant.",
    "input": "Optional. The microtenant's ID, digits only, like 216196257331285825.",
    "effect": "local"
   },
   "#exTfKeep": {
    "what": "In clone mode, keeps each rule on or off as it is in this tenant, instead of writing every rule disabled.",
    "input": "Optional. Unticked (the default) writes every rule disabled. Has no effect in adopt mode.",
    "effect": "local"
   },
   "#exTfPersonal": {
    "what": "Also exports the objects that hold email addresses: alert subscriptions and PRA approvals.",
    "input": "Optional. Unticked by default. Users are never exported.",
    "effect": "local"
   },
   "#exTfTypes input[type=\"checkbox\"]": {
    "what": "Keeps this object type in the whole-tenant Terraform export. Untick it to leave it out.",
    "input": "Tick to export it. Types that are not in scope on the Scope page are left out anyway.",
    "effect": "local"
   },
   "#exTenantTf": {
    "what": "Reads every object in scope from the tenant, read-only, and saves them as Terraform workspaces for the official Zscaler providers (a zip file). No secret is written.",
    "input": "Tick the products and pick Adopt or Clone first. Needs the products' scope ticked on the Scope page.",
    "effect": "download"
   },
   "#exStop": {
    "what": "Stops the export that is running. No file is made.",
    "input": "Nothing to type. Just click it while an export runs.",
    "effect": "local"
   },
   "#exResult a.rp-btn": {
    "what": "Saves the file of the last export again.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "input[name=\"exLayout\"]": {
    "what": "Sets how a field with several values goes into the Excel file: all in one cell, or one row per value.",
    "input": "Pick one. One row per rule is the default. One row per value makes filtering easier.",
    "effect": "local"
   },
   "#exSep": {
    "what": "Sets what goes between several values in one cell of the Excel file.",
    "input": "Pick New line, Comma or Semicolon. New line is the default.",
    "effect": "local"
   },
   "#exColsBox summary": {
    "what": "Opens or closes the list of columns, so you can pick which columns each export has.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exColsSheet": {
    "what": "Picks the export whose columns are shown below.",
    "input": "Pick an export from the list, like URL filtering or Locations.",
    "effect": "local"
   },
   "#exColsAll": {
    "what": "Ticks every column of the export picked above.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exColsNone": {
    "what": "Unticks every column of the export picked above, except the columns that name the rule or object. Those always stay.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exColsList input[type=\"checkbox\"]": {
    "what": "Keeps this column in the Excel file of the picked export. Columns that name the rule or object (Order, Rule, Name) always stay.",
    "input": "Tick to keep the column. Untick to leave it out.",
    "effect": "local"
   },
   "#exOptReset": {
    "what": "Puts the export options back to the defaults: every column, one row per rule, values on separate lines.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exAssessXlsx": {
    "what": "Saves the assessment results from the assessment tab as an Excel file: summary, findings with fixes, compliance and best practices.",
    "input": "Run the assessment first, then open this page from the assessment tab. Nothing is read from the tenant.",
    "effect": "download"
   },
   "#exAssessDocx": {
    "what": "Saves the assessment results from the assessment tab as a Word file: summary, findings with fixes, compliance and best practices.",
    "input": "Run the assessment first, then open this page from the assessment tab. Nothing is read from the tenant.",
    "effect": "download"
   },
   "#exPlansRefresh": {
    "what": "Lists again the preflights this server keeps, so you can save one as a deployment plan.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#exPlans button[data-fmt=\"pdf\"]": {
    "what": "Saves this kept preflight as a PDF deployment plan, with a sign-off block for change approval.",
    "input": "Nothing to type. Just click it. The PDF paper box sets the page size.",
    "effect": "download"
   },
   "#exPlans button[data-fmt=\"xlsx\"]": {
    "what": "Saves this kept preflight as an Excel deployment plan, with a sign-off block for change approval.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#exRgCloud": {
    "what": "The ZIA cloud whose published ranges to use. It is the cloud in your ZIA admin address.",
    "input": "Pick a cloud, like zscaler.net.",
    "effect": "local"
   },
   "#exRgZpa": {
    "what": "The ZPA cloud for the ZPA allow list. None leaves ZPA out.",
    "input": "Pick a ZPA cloud, like private.zscaler.com, or None.",
    "effect": "local"
   },
   "input[name=\"exRgFeed\"]": {
    "what": "Which of Zscaler's published lists to fetch and use.",
    "input": "Tick one or more feeds. All are ticked to start.",
    "effect": "local"
   },
   "#exRgFetchOn": {
    "what": "Lets this app fetch Zscaler's published ranges from config.zscaler.com. It is off to start.",
    "input": "Ticked allows a fetch, but only when you click Fetch now. Unticked keeps the app offline for this.",
    "effect": "local"
   },
   "#exRgFetch": {
    "what": "Fetches the ticked feeds from config.zscaler.com now and keeps them with today's date.",
    "input": "Nothing to type. Turn on the fetch switch first.",
    "effect": "local"
   },
   "#exRgRemove": {
    "what": "Removes every kept feed from this computer.",
    "input": "Nothing to type. You confirm it first.",
    "effect": "local"
   },
   "#exRgImpFeed": {
    "what": "Which feed the file you import holds.",
    "input": "Pick the feed that matches the file.",
    "effect": "local"
   },
   "#exRgFile": {
    "what": "A feed saved by hand from config.zscaler.com, for a computer without internet access.",
    "input": "A JSON file of at most 4 MB.",
    "effect": "local"
   },
   "#exRgImport": {
    "what": "Checks the chosen file and keeps it as that feed. A file that is not that feed is refused.",
    "input": "Nothing to type. Pick the feed and the file first.",
    "effect": "local"
   },
   "input[name=\"exRgRegion\"]": {
    "what": "Keeps only the ranges of the ticked regions.",
    "input": "Optional. Tick regions. None ticked keeps every region.",
    "effect": "local"
   },
   "#exRgV4": {
    "what": "Puts the IPv4 ranges in the allowlist.",
    "input": "Ticked includes them.",
    "effect": "local"
   },
   "#exRgV6": {
    "what": "Puts the IPv6 ranges in the allowlist.",
    "input": "Ticked includes them.",
    "effect": "local"
   },
   "#exRgExclude": {
    "what": "Ranges to take out of the allowlist. A larger range is split around them.",
    "input": "Optional. One CIDR or address per line, like 165.225.240.0/23.",
    "effect": "local"
   },
   "#exRgExtra": {
    "what": "Ranges to add to the allowlist, such as certificate checks your firewall must allow.",
    "input": "Optional. One CIDR or address per line, like 192.0.2.10/32.",
    "effect": "local"
   },
   "#exRgBuild": {
    "what": "Builds the allowlist from the kept feeds, joined into the fewest ranges. It fetches nothing.",
    "input": "Nothing to type. Fetch or import the feeds first.",
    "effect": "local"
   },
   "#exRgTxt": {
    "what": "Saves the ranges as a plain list, one per line.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   },
   "#exRgCsv": {
    "what": "Saves the ranges per region and the host names as a CSV file.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   },
   "#exRgEdlIp": {
    "what": "Saves the ranges as a Palo Alto external dynamic list of IP addresses.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   },
   "#exRgEdlUrl": {
    "what": "Saves the host names as a Palo Alto external dynamic list of URLs.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   },
   "#exRgJson": {
    "what": "Saves the allowlist, its sources and their dates as a JSON file.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   },
   "#exRgM365": {
    "what": "Saves the allowlist in the shape of Microsoft's 365 endpoint list, one set per region.",
    "input": "Nothing to type. Build the allowlist first.",
    "effect": "download"
   }
  },
  "/report/fleet": {
   "#zfTenant": {
    "what": "Picks which tenant sign-in to use for the read.",
    "input": "Pick the assessment tab sign-in, a saved tenant profile, or the details saved on this computer.",
    "effect": "local"
   },
   "#zfRun": {
    "what": "Reads the Client Connector profiles, PAC files and enrolled devices from the tenant. Read-only; it takes about a minute.",
    "input": "Nothing to type. ZCC must be ticked on the Scope page, and you must be signed in.",
    "effect": "read"
   },
   "#zfStop": {
    "what": "Stops the fleet read at once. Nothing more is read and no partial result is kept.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfExpPlan": {
    "what": "Saves the ranked fix plan as a CSV file.",
    "input": "Nothing to type. Read the fleet first.",
    "effect": "download"
   },
   "#zfExpDevices": {
    "what": "Saves the device table as a CSV file, with user and device names.",
    "input": "Nothing to type. Read the fleet first. It is off while Counts only is ticked.",
    "effect": "download"
   },
   "#zfExpSummary": {
    "what": "Saves the fleet summary as a CSV file.",
    "input": "Nothing to type. Read the fleet first.",
    "effect": "download"
   },
   "#zfExpXlsx": {
    "what": "Summary, versions, operating systems, stale devices, devices, alerts and the plan in one workbook",
    "input": "Nothing to type. Read the fleet first. Saves an Excel file.",
    "effect": "download"
   },
   "#zfCounts": {
    "what": "Leaves every user and device name out of the exports.",
    "input": "Tick it to export counts only. Untick it to include names.",
    "effect": "local"
   },
   "#zfExpPdf": {
    "what": "Saves the page as a PDF report: the tiles, alerts, versions, profiles, last seen, sites, history and the plan. It never names a user or a device.",
    "input": "Nothing to type. Read the fleet or import the files first.",
    "effect": "download"
   },
   "#zfImpDev": {
    "what": "Picks the Device Details file you exported from the Client Connector Portal, under Enrolled Devices.",
    "input": "Optional. A CSV file of up to 48 MB. Pick this one, the Service Status file, or both.",
    "effect": "local"
   },
   "#zfImpSvc": {
    "what": "Picks the Service Status file you exported from the Client Connector Portal. It says if ZIA, ZPA and ZDX are on.",
    "input": "Optional. A CSV file of up to 48 MB. Export it at the same time as Device Details.",
    "effect": "local"
   },
   "#zfImpLabel": {
    "what": "Names this import in the history, so you can follow the same customer over time.",
    "input": "Optional. Up to 80 letters, digits or spaces, like Acme Corp. Empty is Imported CSV.",
    "effect": "local"
   },
   "#zfImpGo": {
    "what": "Reads the files you picked and shows the fleet from them. Nothing is sent to a tenant.",
    "input": "Nothing to type. Pick at least one file first.",
    "effect": "local"
   },
   "#zfSiteMode": {
    "what": "Picks how a host name names its site, so devices are counted per site.",
    "input": "Pick No grouping, First characters, Part before a separator, or A list of site prefixes.",
    "effect": "local"
   },
   "#zfSiteLen": {
    "what": "How many first letters of the host name are the site. With 3, LON-LT-001 is site LON.",
    "input": "A whole number from 1 to 12.",
    "effect": "local"
   },
   "#zfSiteDelim": {
    "what": "The character that ends the site part of a host name. With a hyphen, LON-LT-001 is site LON.",
    "input": "Pick a hyphen, an underscore or a dot.",
    "effect": "local"
   },
   "#zfSiteSeg": {
    "what": "How many parts before the separator make the site. With 2, LON-HQ-001 is site LON-HQ.",
    "input": "A whole number from 1 to 4.",
    "effect": "local"
   },
   "#zfSiteList": {
    "what": "The site prefixes to look for. The longest one a host name starts with is its site. Others go to Other.",
    "input": "Prefixes split by commas or spaces, like LON, NYC, PAR. Letters, digits, dots, hyphens. Up to 200.",
    "effect": "local"
   },
   "#zfSiteApply": {
    "what": "Counts the devices per site with your choice. It uses the fleet already read and keeps the choice in this browser.",
    "input": "Nothing to type. Pick how to group first.",
    "effect": "local"
   },
   "#zfHistSave": {
    "what": "Keeps the counts of this read on this computer, so you can see the trend later. No user or device name is kept.",
    "input": "Nothing to type. Saving the same read twice keeps it once.",
    "effect": "local"
   },
   "#zfHistForget": {
    "what": "Removes every saved read of this tenant from this computer. It asks first.",
    "input": "Nothing to type. Click OK in the question to remove them.",
    "effect": "local"
   },
   "#zfHistA": {
    "what": "Picks the older saved read to compare.",
    "input": "Pick a date from the list.",
    "effect": "local"
   },
   "#zfHistB": {
    "what": "Picks the newer saved read to compare.",
    "input": "Pick a date from the list.",
    "effect": "local"
   },
   "#zfHistCompare": {
    "what": "Shows what changed between the two saved reads: devices, ZIA, ZPA and ZDX, alerts, last seen and versions.",
    "input": "Nothing to type. Pick two different reads first.",
    "effect": "local"
   },
   "#zfA": {
    "what": "Picks the first app profile to compare.",
    "input": "Required. Pick a profile from the list.",
    "effect": "local"
   },
   "#zfB": {
    "what": "Picks the second app profile to compare.",
    "input": "Required. Pick a different profile from Profile A.",
    "effect": "local"
   },
   "#zfCompare": {
    "what": "Shows the settings that differ between the two app profiles. Uses the fleet already read.",
    "input": "Pick two different profiles first.",
    "effect": "local"
   },
   "#zfOnlyDiff": {
    "what": "Shows only the settings that differ, or every setting.",
    "input": "Tick it to hide settings that are the same. Untick it to see all.",
    "effect": "local"
   },
   "#zfFilter": {
    "what": "Filters the device table as you type.",
    "input": "Optional. Part of a user, device, profile or version, like laptop-12 or 4.3.",
    "effect": "local"
   },
   "#zfOut details.zf-alert > summary": {
    "what": "Opens or closes this alert: its exact meaning, the devices in it and what to do.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfOut details.zf-details > summary": {
    "what": "Opens or closes this extra detail.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfOut details.pa-details > summary": {
    "what": "Opens or closes the log of what the read did.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfInstPlat": {
    "what": "Picks the computer type to install on. The other choices change to match.",
    "input": "Pick Windows or macOS.",
    "effect": "local"
   },
   "#zfInstType": {
    "what": "Picks the kind of installer file.",
    "input": "Pick MSI or EXE on Windows, or macOS app on a Mac.",
    "effect": "local"
   },
   "#zfInstName": {
    "what": "Holds the installer's file name for the command.",
    "input": "Optional. The file name, like Zscaler-windows-installer-x64.msi. Up to 200 characters.",
    "effect": "local"
   },
   "#zfInstProfile": {
    "what": "Picks the app profile whose policy token goes in the command. Read the fleet first to pick an app profile.",
    "input": "Optional. Pick a profile, or None (no policy token).",
    "effect": "local"
   },
   "#zfIo_cloudName": {
    "what": "The Zscaler cloud without .net (for example zscalertwo). Needed with strict enforcement.",
    "input": "Optional. Pick a cloud from the list, or leave Not set.",
    "effect": "local"
   },
   "#zfIo_userDomain": {
    "what": "The company's sign-in domain, so users go straight to single sign-on instead of typing it.",
    "input": "Optional. A domain, like example.com.",
    "effect": "local"
   },
   "#zfIo_deviceToken": {
    "what": "Only when the Client Connector Portal is the identity provider (ZIA only). Masked unless you reveal it.",
    "input": "Optional. Paste the device token from the portal.",
    "effect": "local"
   },
   "#zfIo_userName": {
    "what": "The user to enroll, without the domain. Needs the user domain.",
    "input": "Optional. A user name, like jsmith.",
    "effect": "local"
   },
   "#zfIo_strictEnforcement": {
    "what": "Blocks internet access until the user enrolls. Needs the cloud name and the policy token.",
    "input": "Tick it to turn strict enforcement on.",
    "effect": "local"
   },
   "#zfIo_enableAntiTampering": {
    "what": "Stops users from stopping or changing the Zscaler services.",
    "input": "Tick it to turn anti-tampering on. Windows only.",
    "effect": "local"
   },
   "#zfIo_hideAppUIOnLaunch": {
    "what": "Keeps the Client Connector window hidden until the user enrolls.",
    "input": "Tick it to hide the window.",
    "effect": "local"
   },
   "#zfIo_launchTray": {
    "what": "On by default; turn it off to install without starting the app.",
    "input": "Ticked means Client Connector starts after install.",
    "effect": "local"
   },
   "#zfIo_externalRedirect": {
    "what": "Users authenticate in their own browser instead of the embedded window.",
    "input": "Tick it to sign in with the default browser.",
    "effect": "local"
   },
   "#zfIo_vdi": {
    "what": "Marks the install as a virtual desktop.",
    "input": "Tick it for a virtual desktop install. Windows only.",
    "effect": "local"
   },
   "#zfIo_uninstallPassword": {
    "what": "Allows a silent uninstall later; must match the app profile's uninstall password. Masked unless you reveal it.",
    "input": "Optional. The uninstall password set in the app profile.",
    "effect": "local"
   },
   "#zfInstOpts input, #zfInstOpts select": {
    "what": "Sets one install option for the command.",
    "input": "Optional. Fill it in or tick it only if you need that option.",
    "effect": "local"
   },
   "#zfInstBuild": {
    "what": "Builds the install command and a script. With an app profile picked, it reads that profile's policy token from the tenant.",
    "input": "Pick the platform and installer first. The rest is optional.",
    "effect": "read"
   },
   "#zfInstReveal": {
    "what": "Shows or hides tokens and passwords in the command. They show as ******** until you reveal them.",
    "input": "Nothing to type. Just click it. Click again to mask them.",
    "effect": "local"
   },
   "#zfInstCopy": {
    "what": "Copies the install command to the clipboard.",
    "input": "Nothing to type. Build the command first.",
    "effect": "local"
   },
   "#zfInstSave": {
    "what": "Saves the install script as a file. Masked secrets stay masked unless you reveal them first.",
    "input": "Nothing to type. Build the command first.",
    "effect": "download"
   },
   "#zfOtpUser": {
    "what": "The user the device is enrolled to, as the fleet lists it. Used to find the device for its one-time passwords.",
    "input": "Required. The enrolled user name, like jdoe@acme.example.",
    "effect": "local"
   },
   "#zfOtpDevice": {
    "what": "The device whose one-time passwords you need: its host name or its UDID.",
    "input": "Required. A host name, like LT-0042, or the UDID. Type the UDID when the user has two devices with the same name.",
    "effect": "local"
   },
   "#zfOtpAssessor": {
    "what": "Your name, for the audit log entry that records who asked for the one-time passwords.",
    "input": "Required. A person's name, like Jane Doe.",
    "effect": "local"
   },
   "#zfOtpPhrase": {
    "what": "Confirms you mean to show this device's one-time passwords.",
    "input": "Required. Type SHOW OTP and the device exactly as you typed it above, like SHOW OTP LT-0042.",
    "effect": "local"
   },
   "#zfOtpShow": {
    "what": "Reads the device's Client Connector one-time passwords from the tenant and shows them here for 60 seconds. Nothing is changed in the tenant, and the passwords are never kept. Needs ZCC on the Scope page and permission to change the tenant; at most 5 requests in 10 minutes.",
    "input": "Fill in the user, the device, your name and the confirmation first.",
    "effect": "read"
   },
   "#zfOtpHide": {
    "what": "Hides the one-time passwords now. They are not kept anywhere.",
    "input": "Nothing to type. Just click it. They hide on their own after 60 seconds.",
    "effect": "local"
   },
   "#zfOtpOut button[data-otp]": {
    "what": "Copies this one-time password to the clipboard, for the user who needs it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"/help#fleet\"]": {
    "what": "Opens the help for this page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfDnsDomain": {
    "what": "The DNS domain the client names go under. Each device gets the name hostname.domain.",
    "input": "Required. A DNS name, like corp.example.com.",
    "effect": "local"
   },
   "#zfDnsResolvers": {
    "what": "The resolver that answers for the client names, such as a Branch Connector. Every name is sent to it.",
    "input": "Required. One to eight IPv4 or IPv6 addresses, separated by commas, like 10.0.0.12, 10.0.0.13.",
    "effect": "local"
   },
   "input[name=\"zfDnsPlat\"]": {
    "what": "Which kinds of device get a name. Phones are left out unless you tick them.",
    "input": "Tick one or more platforms. Windows, macOS and Linux are ticked to start.",
    "effect": "local"
   },
   "#zfDnsRegistered": {
    "what": "Leaves out devices that are not registered now, such as removed ones.",
    "input": "Ticked uses registered devices only. Unticked uses every device in the read.",
    "effect": "local"
   },
   "#zfDnsSeen": {
    "what": "Leaves out devices not seen for this many days.",
    "input": "Optional. A whole number of days from 1 to 3650, like 30. Empty means any.",
    "effect": "local"
   },
   "#zfDnsMap": {
    "what": "Gives a device a second name under another domain when its user's e-mail domain matches.",
    "input": "Optional. One line per mapping: e-mail domain, a colon, DNS domain. Like subsidiary.com: subsidiary.corp.example.",
    "effect": "local"
   },
   "#zfDnsLocalZone": {
    "what": "Adds a local-zone transparent line for each name in the Unbound file. Keep it when the parent domain is a local zone on that server.",
    "input": "Ticked adds the lines. It does no harm otherwise.",
    "effect": "local"
   },
   "#zfDnsInsecure": {
    "what": "Adds a domain-insecure line for each name in the Unbound file. The resolver's answers are not signed, so DNSSEC would refuse them.",
    "input": "Ticked adds the lines. Untick it when DNSSEC is off on that server.",
    "effect": "local"
   },
   "#zfDnsTtl": {
    "what": "How long other servers may keep the zone file's records.",
    "input": "A whole number of seconds from 30 to 86400. 300 is five minutes.",
    "effect": "local"
   },
   "#zfDnsBuild": {
    "what": "Builds the DNS records from the fleet read. It does not read the tenant again and sends nothing to a DNS server.",
    "input": "Nothing to type. Read the fleet first, then fill in the domain and the resolver addresses.",
    "effect": "local"
   },
   "#zfDnsUnbound": {
    "what": "Saves the Unbound forward zones as a file. You load it on your DNS server yourself.",
    "input": "Nothing to type. Build the records first.",
    "effect": "download"
   },
   "#zfDnsNamed": {
    "what": "Saves the BIND forward zones for named.conf as a file.",
    "input": "Nothing to type. Build the records first.",
    "effect": "download"
   },
   "#zfDnsZone": {
    "what": "Saves a BIND zone file part that hands each name to the resolver.",
    "input": "Nothing to type. Build the records first.",
    "effect": "download"
   },
   "#zfDnsCsv": {
    "what": "Saves every device's hostname, its DNS name and what happened to it as a CSV file.",
    "input": "Nothing to type. Build the records first.",
    "effect": "download"
   },
   "#zfDevUdid": {
    "what": "The device to look at, by its device id (UDID).",
    "input": "Required. The id as the Client Connector Portal shows it: letters, digits and . _ : - { }.",
    "effect": "local"
   },
   "#zfDevShow": {
    "what": "Reads one device's service state: services on and healthy, versions, strict enforcement, anti-tampering and trust. Ids stay hidden.",
    "input": "Type the device id first. It only reads. Needs ZCC ticked on the Scope page.",
    "effect": "read"
   },
   "#zfDisShow": {
    "what": "Reads the disable-reason report and shows how often Client Connector was switched off, per reason. No person is listed.",
    "input": "Nothing to type. It only reads. Needs ZCC ticked on the Scope page.",
    "effect": "read"
   },
   "#zfDisCsv": {
    "what": "Downloads the same counts as a CSV file: reason, device type, service, times and people. No names.",
    "input": "Nothing to type. It reads the report first.",
    "effect": "download"
   }
  },
  "/report/flow": {
   "#flFind": {
    "what": "Finds a box by name. Boxes whose name does not match are dimmed.",
    "input": "Optional. Part of a dictionary, engine or rule name, like PCI.",
    "effect": "local"
   },
   "#flRefresh": {
    "what": "Read the plan currently shown in Deploy policy packs, and draw it again here.",
    "input": "Nothing to type. Just click it. Run a preflight in Deploy policy packs first.",
    "effect": "local"
   },
   "#flSide button.fl-link": {
    "what": "Pins this box in the picture and shows its details, then scrolls to it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/health": {
   "#thWarn": {
    "what": "Sets how many days before expiry a certificate is flagged as needing attention soon.",
    "input": "Optional. A whole number of days from 1 to 365, like 30. Empty uses the server's setting (30 unless changed). It must be more than the critical days.",
    "effect": "local"
   },
   "#thCrit": {
    "what": "Sets how many days before expiry a certificate is flagged as needing attention now.",
    "input": "Optional. A whole number of days from 1 to 365, like 7. Empty uses the server's setting (7 unless changed). It must be fewer than the warning days.",
    "effect": "local"
   },
   "#thRun": {
    "what": "Checks the tenant's health: changes waiting for activation, the SSL inspection rule order, certificates close to expiry and App Connector groups with no connector. It only reads.",
    "input": "Nothing to type. Just click it. Sign in on the assessment page first; only what the Scope page ticks is read.",
    "effect": "read"
   },
   "#thCalls": {
    "what": "Opens the list of API calls this check made, in Advanced settings.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#dhDays": {
    "what": "Picks how many days of incidents the report looks back over. Changing it reads the tenant again.",
    "input": "Pick one: 7, 14, 30, 60 or 90 days. 30 days is the usual choice. Needs the assessment tab that opened this page.",
    "effect": "read"
   },
   "#dhRefresh": {
    "what": "Re-read the tenant. Reads the Workflow Automation incidents and DLP rules again and redraws the report.",
    "input": "Nothing to type. Just click it. The assessment tab that opened this page must still be open.",
    "effect": "read"
   },
   "#expMd": {
    "what": "Saves this report as a Markdown text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves this report as a JSON data file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dhBy": {
    "what": "Holds your name for the audit log next to each decision.",
    "input": "Optional. Your name, like Sam Lee. The server records the signed-in person as the one who decided.",
    "effect": "local"
   },
   "#dhClosed": {
    "what": "Shows or hides proposals that are already closed, like dismissed, applied or rolled back ones.",
    "input": "Tick it to list closed proposals too. Untick it to show only open ones.",
    "effect": "local"
   },
   "#dhProposals a.rp-btn[href^=\"/api/proposals/export\"]": {
    "what": "Saves every proposal for this tenant as a Markdown text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#dhProposals .dh-confirm": {
    "what": "Holds the confirm phrase. This change makes the tenant stricter for users, so you must type it to approve.",
    "input": "Required for this proposal. Type the phrase shown in the box exactly, like I UNDERSTAND.",
    "effect": "local"
   },
   "#dhProposals button[data-act=\"approve\"]": {
    "what": "Marks this proposal as approved and writes it in the audit log. Approving never changes the tenant by itself.",
    "input": "Nothing to type for most proposals. A stricter-for-users proposal needs the confirm phrase typed first.",
    "effect": "local"
   },
   "#dhProposals button[data-act=\"snooze\"]": {
    "what": "Quiet for 14 days. Hides this proposal for now; it comes back after that.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dhProposals button[data-act=\"dismiss\"]": {
    "what": "Not raised again for 30 days. Closes this proposal and asks you why.",
    "input": "Click it, then type a short reason in the box that pops up. The reason is optional.",
    "effect": "local"
   },
   "#dhProposals button[data-act=\"reopen\"]": {
    "what": "Puts this proposal back to open, so you can decide again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dhProposals button[data-flow=\"apply\"]": {
    "what": "Reads the rules in the tenant again and shows exactly what would change. Nothing is written yet.",
    "input": "Nothing to type. Just click it. The proposal must be approved first.",
    "effect": "read"
   },
   "#dhProposals button[data-flow=\"rollback\"]": {
    "what": "Reads the rules in the tenant again and shows what a roll back would put back. Nothing is written yet.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#dhProposals .dh-ok": {
    "what": "Says you checked the change shown above. It unlocks the button that writes it.",
    "input": "Tick it once you have read the preview table and want the change made.",
    "effect": "local"
   },
   "#dhProposals button[data-go]": {
    "what": "Changes each rule in the tenant, then reads it back to check it. ZIA keeps the change pending until an admin activates it.",
    "input": "Tick the I have reviewed box first. Needs write mode on, a writer sign-in and a named assessor.",
    "effect": "write"
   },
   "#dhProposals button[data-cancel]": {
    "what": "Closes this preview without changing anything.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody a.rp-btn[href=\"/\"]": {
    "what": "Goes back to the assessment page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#zwaIncId": {
    "what": "The id of one Workflow Automation incident to read in depth.",
    "input": "Required for Read the incident. The id as Workflow Automation shows it, letters, digits and - _ . : only, up to 80 characters, like 1-152-DFZG-17410647793298599936. Details beside a latest transaction fills it in.",
    "effect": "local"
   },
   "#zwaIncRead": {
    "what": "Reads one incident's details, what triggered it (rule, engine and dictionary names with match counts), its change history and its tickets. Metadata only: the evidence is never fetched, and the user, file name and client IP are not shown.",
    "input": "Nothing to type here. Type the incident id first. Needs DLP ticked on the Scope page and Workflow Automation not marked as another product.",
    "effect": "read"
   },
   "#zwaAuditDays": {
    "what": "Picks how many days of the Workflow Automation audit log to read.",
    "input": "Pick one: 1, 7, 30 or 90 days. 7 days is the usual choice.",
    "effect": "local"
   },
   "#zwaAuditRead": {
    "what": "Reads the Workflow Automation admin audit log: who did what to which incident, workflow or integration, newest first.",
    "input": "Nothing to type. Just click it. Needs DLP ticked on the Scope page and Workflow Automation not marked as another product.",
    "effect": "read"
   },
   "button.dh-inc": {
    "what": "Reads this incident in depth below the report: details, triggers, change history and tickets (metadata only).",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "a.dh-close": {
    "what": "Opens Bulk changes with the open incidents of this rule or destination ready to close as false positives. Nothing is changed until you preview, turn on write mode, name the assessor and type the phrase.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/insights": {
   "#tiLogsLink": {
    "what": "Opens Traffic and session logs, where uploaded NSS logs answer what Insights cannot: per rule, per category, per user and per host.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#tiTenant": {
    "what": "Picks which tenant to read: the one signed in on the assessment tab, a saved tenant profile, or the one saved on this computer.",
    "input": "Pick one from the list. It shows only when there is more than one choice.",
    "effect": "local"
   },
   "#tiWindow": {
    "what": "Picks the time window for the traffic numbers.",
    "input": "Pick one: last 24 hours, 7, 14, 30 or 90 days, or Custom to pick your own dates.",
    "effect": "local"
   },
   "#tiFrom": {
    "what": "Sets the start of your own time window, in your local time.",
    "input": "Required when the window is Custom. A date and time, like 2026-10-01 09:00. Up to 92 days long, within the last 180 days.",
    "effect": "local"
   },
   "#tiTo": {
    "what": "Sets the end of your own time window, in your local time.",
    "input": "Required when the window is Custom. A date and time after the start, like 2026-10-08 09:00.",
    "effect": "local"
   },
   "#tiUnit": {
    "what": "Picks how web traffic is counted: by number of requests or by amount of data.",
    "input": "Pick one: Transactions or Bytes.",
    "effect": "local"
   },
   "#tiUsers": {
    "what": "Ticked: also lists the users with the most security incidents. Names show on this screen only, not in the exports.",
    "input": "Optional. Ticked by default. Untick it to leave users out.",
    "effect": "local"
   },
   "#tiRun": {
    "what": "Reads ZIA Insights for the chosen window: web traffic by action and location, web threats, cloud apps, SaaS security, firewall traffic, incidents by location, IoT device counts and top users. Read-only.",
    "input": "Pick a time window first. ZIA Insights must be ticked on the Scope page.",
    "effect": "read"
   },
   "#tiStop": {
    "what": "Stops the read at once. Nothing more is asked of the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#expCsv": {
    "what": "Saves the Insights tables as a CSV file. It has every table except the per-user one.",
    "input": "Nothing to type. Just click it. It shows after a read.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the Insights tables as a JSON file. It has every table except the per-user one.",
    "input": "Nothing to type. Just click it. It shows after a read.",
    "effect": "download"
   },
   "#tiFlowView": {
    "what": "Picks which numbers the traffic flow picture shows.",
    "input": "Pick one, like web traffic from locations to actions, firewall traffic by action, or cloud apps by sanctioned state.",
    "effect": "local"
   },
   "#tiFlow button.rp-btn": {
    "what": "Pauses or plays the moving packets in the traffic flow picture. The list under it says the same in words.",
    "input": "Nothing to type. Just click it. The label says what a click does now.",
    "effect": "local"
   },
   "#tiGrid th button[data-sec]": {
    "what": "Sorts this table by this column. Click again to flip the order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tiBody details.pa-details summary": {
    "what": "Shows or hides the list of questions sent to ZIA Insights during the read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/live": {
   "#lfTenant": {
    "what": "Picks which tenant sign-in to use: the assessment tab, a saved tenant profile, or the one saved on this computer.",
    "input": "Pick one from the list. It shows only when there is more than one choice.",
    "effect": "local"
   },
   "#lfStart": {
    "what": "Starts the live feed. It reads new DLP incidents from Workflow Automation every 15 seconds.",
    "input": "Nothing to type. Needs Workflow Automation in scope on the Scope page. Nothing is written.",
    "effect": "read"
   },
   "#lfStop": {
    "what": "Stops the live feed. The tally and the rows stay on screen until you reset.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#lfReset": {
    "what": "Clear the feed and the tally and start a fresh session. It also stops the feed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#lfMotion a[href=\"/reference/data-security-architect#chain\"]": {
    "what": "Opens the DLP chain in the reference architecture, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#pmToggle": {
    "what": "Pauses or plays the moving bits in the DLP chain picture.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#lfLanesBody .fp-head button": {
    "what": "Pauses or plays the motion of each incident through its lanes. When paused, each incident lands at once.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/logs": {
   "#laDownload": {
    "what": "Saves the findings as a Markdown text file.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   "#laCopy": {
    "what": "Copies a short summary of the findings to the clipboard.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "local"
   },
   "#laFiles": {
    "what": "Picks the files to analyze. You can also drop them in this box.",
    "input": "Required. The Client Connector log bundle (.zip), .log files, or a PAC file, like ZSATray.log. Keep it under the upload limit shown.",
    "effect": "local"
   },
   "#laRun": {
    "what": "Reads the chosen files on this computer and explains what happened, in plain words. Nothing is sent to Zscaler.",
    "input": "Choose one or more files first.",
    "effect": "local"
   },
   "details.la-find > summary": {
    "what": "Opens or closes this finding: what happened, what it means for the user, and what to do next.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#laPac summary": {
    "what": "Opens or closes this PAC file list: its bypasses, or what it answers for common sites.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#laResults summary": {
    "what": "Opens or closes the list of files that were read, with their lines and dates.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "section[aria-labelledby=\"laCatH\"] summary": {
    "what": "Opens or closes the full list of problems this analyzer can spot.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"/help\"]": {
    "what": "Opens the page that explains every function of the app, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/motion": {
   "#archRef": {
    "what": "Opens this flow in the Data Security Architect reference, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   ".rp-bar a[href=\"/reference/data-security-architect\"]": {
    "what": "Data Security Architect: the reference architecture these flows come from (opens in a new tab).",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#tab-path": {
    "what": "Shows the Test and path view: replay the last analyzed path.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-dlp": {
    "what": "Shows the Detection detail view: which DLP engines fire, and why one does not.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-deploy": {
    "what": "Shows the Deployment view: a policy-pack plan from templates to rules.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-live": {
    "what": "Shows the Live evidence view: DLP incidents as they land.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-arch": {
    "what": "Shows the Architecture flows view: every flow of the reference, step by step.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#faTenant": {
    "what": "Picks which tenant sign-in to use: the assessment tab, a saved tenant profile, or the one saved on this computer.",
    "input": "Pick one from the list. Changing it clears the scenario and the live feed.",
    "effect": "local"
   },
   "#scenarioChannel": {
    "what": "Picks the DLP channel to test. It also sets a matching operation.",
    "input": "Pick one: Inline Web, Endpoint, Email or SaaS API.",
    "effect": "local"
   },
   "#scenarioDestination": {
    "what": "Sets where the test data goes.",
    "input": "Required for Inline Web. A host name or a web address with no user name or password in it, like drive.google.com. Up to 2048 characters.",
    "effect": "local"
   },
   "#scenarioOperation": {
    "what": "Picks what the user does with the data.",
    "input": "Pick one: Upload, Download, Clipboard, USB transfer, Send email or At-rest scan.",
    "effect": "local"
   },
   "#scenarioFileType": {
    "what": "Sets the file type, for context only.",
    "input": "Optional. A short type like txt, pdf or xlsx (letters, numbers, up to 32).",
    "effect": "local"
   },
   "#scenarioNetwork": {
    "what": "Picks the network the device is on.",
    "input": "Pick one: Off network, Trusted network or VPN. Only for Inline Web.",
    "effect": "local"
   },
   "#scenarioPlatform": {
    "what": "Picks the device platform.",
    "input": "Pick one: windows, macos, ios, android or linux.",
    "effect": "local"
   },
   "#scenarioCorpus": {
    "what": "Holds the made-up test text to check against your DLP rules. It stays on this app server.",
    "input": "Required for Simulate test data. Synthetic text only, no real customer records. Up to 256 KB.",
    "effect": "local"
   },
   "#scenarioRun": {
    "what": "Reads your DLP configuration and checks the test text against it on this app server. No traffic is sent through Zscaler.",
    "input": "Fill in the test content first, and a destination for Inline Web. Nothing is written.",
    "effect": "read"
   },
   "#scenarioTrace": {
    "what": "Reads your DLP configuration and shows the path, without testing any content.",
    "input": "Pick a channel first, and a destination for Inline Web. Nothing is written.",
    "effect": "read"
   },
   "#scenarioCancel": {
    "what": "Cancels the test that is running. No result is kept.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#scenarioPlay": {
    "what": "Plays the whole scenario animation from the start.",
    "input": "Nothing to type. Run a test first.",
    "effect": "local"
   },
   "#scenarioNext": {
    "what": "Moves the scenario animation one step forward.",
    "input": "Nothing to type. Run a test first.",
    "effect": "local"
   },
   "#scenarioRestart": {
    "what": "Resets the scenario animation to the first step.",
    "input": "Nothing to type. Run a test first.",
    "effect": "local"
   },
   "#scenarioDetails summary": {
    "what": "Opens or closes every stage of the scenario, with object IDs and evidence.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#v-path a[href=\"/report/dataflow\"]": {
    "what": "Opens the Traffic flow and gaps overview page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#tpView": {
    "what": "Picks the picture to replay.",
    "input": "Pick one: Every step (ZPA, PAC, ZIA) or Hop by hop to Web DLP.",
    "effect": "local"
   },
   "#tpReload": {
    "what": "Read the result the Path analyzer last kept in this browser. It does not read the tenant.",
    "input": "Nothing to type. Analyze a destination on the Path analyzer first, or a sample is shown.",
    "effect": "local"
   },
   "#tpSample": {
    "what": "Shows a sample path instead of your own result.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHost button.tp-back": {
    "what": "Moves the replay one step back.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHost button.tp-play": {
    "what": "Pauses or plays the replay.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHost button.tp-next": {
    "what": "Moves the replay one step forward.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHost button.tp-restart": {
    "what": "Starts the replay again from the first step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHost select.tp-speed-sel": {
    "what": "Sets how fast the replay moves.",
    "input": "Pick one: Slow, Normal or Fast.",
    "effect": "local"
   },
   "#tpHost details.tp-alt > summary": {
    "what": "Opens or closes the path written out in words, step by step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHopPlay": {
    "what": "Plays the hop-by-hop picture from the start.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHopStep": {
    "what": "Moves the hop-by-hop picture one hop forward.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tpHopReset": {
    "what": "Resets the hop-by-hop picture to the first hop.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dlpReplay": {
    "what": "Plays the detection detail again: dictionaries, engines and rules.",
    "input": "Nothing to type. Run Simulate test data above first.",
    "effect": "local"
   },
   "#dlpSample": {
    "what": "Shows a made-up demo of the detection detail. It never joins your tenant results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#deployPause": {
    "what": "Pauses or streams the moving dots in the deployment picture.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#deployReplay": {
    "what": "Replays the order a deploy writes things: dictionaries, engines, app groups, then rules.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#deployRefresh": {
    "what": "Read the plan currently shown in Deploy policy packs. It does not read the tenant.",
    "input": "Nothing to type. Run preflight in Deploy policy packs first, or a sample is shown.",
    "effect": "local"
   },
   "#deploySample": {
    "what": "Shows a sample deployment plan and replays it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#liveStart": {
    "what": "Starts the live feed. It reads new DLP incidents from Workflow Automation every 15 seconds.",
    "input": "Nothing to type. Needs Workflow Automation in scope on the Scope page. No test traffic is sent.",
    "effect": "read"
   },
   "#liveStop": {
    "what": "Stops the live feed. What is shown stays on screen.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#liveSample": {
    "what": "Shows four made-up incidents in a separate demo. They never count in your live totals.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#v-live details > summary": {
    "what": "Opens or closes the isolated demonstration.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#archFlow": {
    "what": "Picks which reference flow to animate.",
    "input": "Pick one flow from the list.",
    "effect": "local"
   },
   "#archPlay": {
    "what": "Plays the chosen flow step by step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#archStep": {
    "what": "Moves the flow one step forward.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#archSlow": {
    "what": "Slows the animation down.",
    "input": "Tick it to play the flow slowly.",
    "effect": "local"
   },
   "#archOverlay": {
    "what": "Colours the flow with your last scenario result.",
    "input": "Ticked: steps take the colour of your result. Unticked: plain flow.",
    "effect": "local"
   }
  },
  "/report/operations": {
   "#fwiFile": {
    "what": "Loads a migration plan saved from Migrate from another vendor (Palo Alto Networks). The server checks it again before the preview.",
    "input": "Optional when the plan was handed over from that page. One .json plan file under 4 MB.",
    "effect": "local"
   },
   "#fwiEnable": {
    "what": "Creates the imported rules enabled instead of disabled, so they decide traffic as soon as ZIA activates. Applying still needs write mode and the typed phrase.",
    "input": "Optional. Leave it unticked to create every rule disabled.",
    "effect": "local"
   },
   "#opPlugJson": {
    "what": "The operation for a local plugin, as JSON. The preview shows exactly what it would change; applying needs write mode and the same gates.",
    "input": "Required. A JSON object with the fields the plugin's documentation names, like {\"name_prefix\": \"tmp-\"}.",
    "effect": "local"
   },
   "#opTenant": {
    "what": "Picks which tenant sign-in this page reads and changes.",
    "input": "Optional. Pick one from the list: the assessment tab, a saved tenant profile, or what is saved on this computer.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"rule_state\"]": {
    "what": "Picks \"Enable or disable rules\". It turns up to 100 rules on or off in one go.",
    "input": "Tick it to pick this operation. Then click Read from the tenant.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"reorder\"]": {
    "what": "Picks \"Reorder a policy\". It puts one policy's rules in the order you want.",
    "input": "Tick it to pick this operation. Default, predefined and read-only rules never move.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"url_categories\"]": {
    "what": "Picks \"URL category change\". It adds, removes, moves or copies URLs on custom URL categories.",
    "input": "Tick it to pick this operation. Then click Read from the tenant.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"zpa_domains\"]": {
    "what": "Picks \"ZPA segment domains\". It moves or copies domains between application segments, or clones a segment.",
    "input": "Tick it to pick this operation. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"list_fix\"]": {
    "what": "Picks \"Fix rows from Test a list\". It turns rows of the Path analyzer's Test a list that did not do what was expected into group, rule and ATP list changes.",
    "input": "Tick it to pick this operation. Fix selected on the Path analyzer picks it for you. Then click Read from the tenant.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"ip_group_edit\"]": {
    "what": "Picks \"IP destination group change\". It adds or removes addresses or host names on one IP destination group, or makes a new group.",
    "input": "Tick it to pick this operation. Then click Read from the tenant.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"atp_list_edit\"]": {
    "what": "Picks \"ATP allow and deny lists\". It adds or removes URLs on the security policy lists Advanced Threat Protection applies to every user.",
    "input": "Tick it to pick this operation. Then click Read from the tenant.",
    "effect": "local"
   },
   "#lfArea": {
    "what": "Picks the area the pasted destinations are fixed in.",
    "input": "Pick one: Cloud Firewall, DNS Control or Advanced Threat Protection lists.",
    "effect": "local"
   },
   "#lfPurpose": {
    "what": "Says whether the pasted destinations should be blocked or allowed.",
    "input": "Pick one: Blocked or Allowed.",
    "effect": "local"
   },
   "#lfDests": {
    "what": "The destinations to fix, when you did not come from Fix selected.",
    "input": "Optional. One per line: an IPv4 address, CIDR block, range (a.b.c.d-e.f.g.h), host name or URL. At most 5,000. Example: 203.0.113.9",
    "effect": "local"
   },
   "#lfUse": {
    "what": "Turns the pasted destinations into a fix section below.",
    "input": "Nothing to type. Paste the destinations first.",
    "effect": "local"
   },
   "input[id^=\"lfInc\"]": {
    "what": "Keeps this fix in the change, or leaves it out.",
    "input": "Ticked includes it. Unticked leaves it out of the preview.",
    "effect": "local"
   },
   "select[id^=\"lfAct\"]": {
    "what": "Says whether the destinations are added, or taken out (of a group, or of the other ATP list).",
    "input": "Pick one. Taking out works on an existing group only and changes no rule.",
    "effect": "local"
   },
   "select[id^=\"lfIp\"]": {
    "what": "Picks the IP destination group the addresses go into or come out of.",
    "input": "Pick a group of type IP, or A new group. The count shows how full it is (at most 8,000 entries, assumed).",
    "effect": "local"
   },
   "input[id^=\"lfIpName\"]": {
    "what": "Names the new group for the addresses.",
    "input": "Required for a new group. At most 128 characters. Over the limit, it is split into numbered groups.",
    "effect": "local"
   },
   "select[id^=\"lfHost\"]": {
    "what": "Picks the IP destination group the host names go into or come out of.",
    "input": "Pick a group of type FQDN or domain, or A new group.",
    "effect": "local"
   },
   "input[id^=\"lfHostName\"]": {
    "what": "Names the new group for the host names.",
    "input": "Required for a new group. At most 128 characters.",
    "effect": "local"
   },
   "select[id^=\"lfRuleId\"]": {
    "what": "Picks the existing rule the group is added to.",
    "input": "Required. Only rules whose action matches (Block for rows to block, Allow for rows to allow) are listed.",
    "effect": "local"
   },
   "input[id^=\"lfRuleName\"]": {
    "what": "Names the new rule.",
    "input": "Required. At most 31 characters, as ZIA allows. It must not be the name of another rule.",
    "effect": "local"
   },
   "select[id^=\"lfRule\"]": {
    "what": "Says which rule uses the group: none, a new rule, or an existing rule.",
    "input": "Pick one. A new rule is created disabled unless you tick it on.",
    "effect": "local"
   },
   "select[id^=\"lfAbove\"]": {
    "what": "Picks where the new rule goes: above this rule. The rule that decided the rows is suggested.",
    "input": "Optional. Leave it to put the rule last, above the Default rule.",
    "effect": "local"
   },
   "input[id^=\"lfOn\"]": {
    "what": "Creates the new rule enabled instead of disabled. It then acts on traffic as soon as ZIA activates the change.",
    "input": "Optional. Off by default. When ticked, applying needs the typed phrase.",
    "effect": "local"
   },
   "select[id^=\"lfSvc\"]": {
    "what": "Adds network services to the rule, so it applies to those ports and protocols only.",
    "input": "Optional. Hold Ctrl or Cmd to pick several. Leave it empty to keep the rule as it is.",
    "effect": "local"
   },
   "#opObjects a[href^=\"#lf-row-\"]": {
    "what": "Jumps to this row in the table of rows this fixes.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#opPlan a[href^=\"#lf-row-\"]": {
    "what": "Jumps to this row in the table of rows this fixes.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#lfProve": {
    "what": "Tests the same rows again, as Test a list did, and says which now do what was expected. It only reads.",
    "input": "Nothing to type. Only what is in scope is read.",
    "effect": "read"
   },
   "#lfProof a[href^=\"#lf-row-\"]": {
    "what": "Jumps to this row in the table of rows this fixes.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#lgGroup": {
    "what": "Picks the IP destination group to change, or A new group.",
    "input": "Pick one. The count shows how full it is (at most 8,000 entries, assumed).",
    "effect": "local"
   },
   "#lgName": {
    "what": "Names the new group.",
    "input": "Required for a new group. At most 128 characters.",
    "effect": "local"
   },
   "#lgType": {
    "what": "Says what the new group holds: IPv4 addresses, CIDR blocks and ranges, or host names.",
    "input": "Pick one.",
    "effect": "local"
   },
   "#lgAdd": {
    "what": "The entries to add to the group.",
    "input": "Optional. One per line: an IPv4 address, CIDR block, range or host name. IPv6 is refused: ZIA has no user-defined IPv6 group.",
    "effect": "local"
   },
   "#lgRemove": {
    "what": "The entries to take out of the group.",
    "input": "Optional. One per line, written as the group lists them.",
    "effect": "local"
   },
   "#laList": {
    "what": "Picks the security policy list to change: the denylist blocks, the allowlist exempts.",
    "input": "Pick one.",
    "effect": "local"
   },
   "#laAdd": {
    "what": "The URLs to add to the list.",
    "input": "Optional. One per line, like example.com or example.com/path, with no scheme in front.",
    "effect": "local"
   },
   "#laRemove": {
    "what": "The URLs to take off the list.",
    "input": "Optional. One per line, written as the list holds them.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"zpa_segment_fields\"]": {
    "what": "Picks \"ZPA segment settings in bulk\". It sets the same fields on many application segments at once, Browser Access, PRA and inspection segments too.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#zfFilter": {
    "what": "Shows only the segments whose name or kind contains what you type.",
    "input": "Optional. Type part of a name, or Browser Access, PRA or inspection.",
    "effect": "local"
   },
   "#zfAll": {
    "what": "Picks every segment the list shows, up to the most one operation takes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zfNone": {
    "what": "Clears the segments you picked.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[data-zf-seg]": {
    "what": "Picks this segment for the change. A read-only segment cannot be picked.",
    "input": "Tick it to pick it.",
    "effect": "local"
   },
   "select[data-zf-field]": {
    "what": "Sets this field on every picked segment, or leaves it as it is.",
    "input": "Optional. Pick a value, or Leave as it is.",
    "effect": "local"
   },
   "#zfSegGroup": {
    "what": "Moves every picked segment to this segment group, or leaves them where they are.",
    "input": "Optional. Pick a segment group, or Leave as it is.",
    "effect": "local"
   },
   "#zfSgMode": {
    "what": "Says what to do with the server groups you tick: add them, remove them, or make them the only ones.",
    "input": "Optional. Pick one, then tick the server groups.",
    "effect": "local"
   },
   "input[data-zf-sg]": {
    "what": "A server group to add, remove or replace with, on every picked segment.",
    "input": "Tick it to use it.",
    "effect": "local"
   },
   "#zfTcpAdd": {
    "what": "TCP ports or ranges to add to every picked segment.",
    "input": "Optional. Ports from 1 to 65535 and ranges, separated by commas, like 443, 8000-8080.",
    "effect": "local"
   },
   "#zfTcpRemove": {
    "what": "TCP ranges to remove from every picked segment. A range is removed whole.",
    "input": "Optional. The ranges as the segment lists them, like 8080 or 8000-8100.",
    "effect": "local"
   },
   "#zfUdpAdd": {
    "what": "UDP ports or ranges to add to every picked segment.",
    "input": "Optional. Ports from 1 to 65535 and ranges, separated by commas, like 53, 5000-5100.",
    "effect": "local"
   },
   "#zfUdpRemove": {
    "what": "UDP ranges to remove from every picked segment. A range is removed whole.",
    "input": "Optional. The ranges as the segment lists them, like 53.",
    "effect": "local"
   },
   "input[name=\"opKind\"][value=\"cloud_app_sanction\"]": {
    "what": "Picks \"Sanction or unsanction cloud apps\". It marks up to 100 cloud apps Sanctioned or Unsanctioned for the whole tenant.",
    "input": "Tick it, then click Read from the tenant to list the apps. Needs ZIA platform and ZIA Insights ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"aiguard_detection_policy\"]": {
    "what": "Picks the AI Guard detection policy builder. It turns a compliance profile into an AI Guard policy for GenAI apps.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs AI Guard ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"aiguard_routing\"]": {
    "what": "Picks the AI Guard routing builder. It sends the GenAI apps you pick through Zscaler AI Guard.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZIA platform and AI Guard ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zcc_profile_build\"]": {
    "what": "Picks the Client Connector profiles builder. It makes a forwarding profile and a Windows or macOS app profile.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zcc_profile_delete\"]": {
    "what": "Picks \"Delete a Client Connector profile\". It removes one app or forwarding profile that is not in use.",
    "input": "Tick it, then click Read from the tenant to list the profiles. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zdx_probes\"]": {
    "what": "Picks \"ZDX probe setup\". It adds ZDX apps with a Web probe and a CloudPath probe each. ZDX is Zscaler Digital Experience.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZDX ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zdx_probe_state\"]": {
    "what": "Picks \"Turn ZDX apps and probes on or off\". It lists every ZDX app and probe with its state.",
    "input": "Tick it, then click Read from the tenant to list them. Needs ZDX ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zdx_probe_delete\"]": {
    "what": "Picks \"Delete ZDX apps and probes\". It deletes custom ZDX apps and custom probes. This cannot be undone.",
    "input": "Tick it, then click Read from the tenant to list them. Needs ZDX ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zia_baseline\"]": {
    "what": "Picks the ZIA security baseline builder. It builds rules from a Strict, Balanced, Permissive or Healthcare tier.",
    "input": "Tick it, then click Read from the tenant to show the form. New rules arrive disabled.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"ssl_certificate_move\"]": {
    "what": "Picks the SSL certificate manager. It shows which certificate each SSL inspection rule uses, and moves rules to another one.",
    "input": "Tick it, then click Read from the tenant to list the rules and certificates.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zpa_connector_group\"]": {
    "what": "Picks the ZPA App Connector group builder. It makes a group (or reuses one) with a provisioning key.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zpa_app_segments\"]": {
    "what": "Picks the ZPA application segments builder. It makes segments from a wildcard, a preset or a CSV.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zpa_policies\"]": {
    "what": "Picks the ZPA policy rules builder. It makes access, timeout, inspection and isolation rules for your prefixed segments.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"zpa_prefix_delete\"]": {
    "what": "Picks \"Delete ZPA objects by prefix\". It deletes only objects named with your prefix.",
    "input": "Tick it, then click Read from the tenant to list what the prefix matches. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zpa_infra_update\"]": {
    "what": "Picks \"Change ZPA App Connectors, Service Edges and portals\". It shows each one's health, then renames, turns on or off, moves App Connectors and sets update schedules. Undo puts it back.",
    "input": "Tick it, then click Read from the tenant. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zpa_infra_delete\"]": {
    "what": "Picks \"Delete ZPA connectors, groups, portals, certificates or keys\". Anything connected or still used is kept. This cannot be undone.",
    "input": "Tick it, then click Read from the tenant. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zpa_provisioning_key_new\"]": {
    "what": "Picks \"New ZPA provisioning key\". It makes a key for an App Connector group or a Service Edge group, shown once.",
    "input": "Tick it, then click Read from the tenant. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zpa_ba_certificate\"]": {
    "what": "Picks \"ZPA Browser Access certificate\". It uploads a certificate with its key, or picks one, and points Browser Access applications at it.",
    "input": "Tick it, then click Read from the tenant. Needs ZPA ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zcc_device_remove\"]": {
    "what": "Picks \"Remove Client Connector devices\". It removes or force removes one user's devices. This cannot be undone.",
    "input": "Tick it, then click Read from the tenant. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zcc_device_bulk_remove\"]": {
    "what": "Picks \"Remove Client Connector devices from a list\". It matches a list of users, host names or device ids and removes them in batches. This cannot be undone.",
    "input": "Tick it, then click Read from the tenant. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zcc_bypass_app\"]": {
    "what": "Picks \"Client Connector custom bypass apps\". It lists, creates, edits or deletes the apps whose traffic skips the Zscaler tunnel.",
    "input": "Tick it, then click Read from the tenant. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zcc_entitlements\"]": {
    "what": "Picks \"ZPA and ZDX entitlements\". It sets who gets ZPA and ZDX in Client Connector.",
    "input": "Tick it, then click Read from the tenant. Needs ZCC ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zdx_deeptrace_start\"]": {
    "what": "Picks \"Start a ZDX deep trace\". It shows application scores, a user's devices and their health, and starts a deep trace on one device.",
    "input": "Tick it, then click Read from the tenant. Needs ZDX ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zdx_deeptrace_stop\"]": {
    "what": "Picks \"Stop a ZDX deep trace\". ZDX deletes the trace and what it collected. This cannot be undone.",
    "input": "Tick it, then click Read from the tenant. Needs ZDX ticked on the Scope page.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"]": {
    "what": "Picks this \"Build new\" builder. Its form shows after you read the tenant.",
    "input": "Tick it, then click Read from the tenant.",
    "effect": "local"
   },
   "#opRead": {
    "what": "Reads from the tenant what the picked operation can change. It reads only what is in scope on the Scope page. Nothing is written.",
    "input": "Pick the operation in step 1 first. Then click it.",
    "effect": "read"
   },
   "#opPreview": {
    "what": "Reads the tenant again and lists every item with its value before and after. Nothing is written.",
    "input": "Read from the tenant and pick the objects first. Then click it.",
    "effect": "read"
   },
   "#opApiCalls": {
    "what": "Opens the API calls this run made, in Advanced settings: each call's path, answer, time taken, retries and waits.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#opPdf": {
    "what": "Saves the previewed plan as a PDF, for a change ticket or the customer.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#opStop": {
    "what": "Stops the job that is running now. Nothing more is read or written after it stops.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[name=\"opState\"][value=\"DISABLED\"]": {
    "what": "Sets the picked rules to Disabled when you apply.",
    "input": "Tick it to turn the picked rules off.",
    "effect": "local"
   },
   "input[name=\"opState\"][value=\"ENABLED\"]": {
    "what": "Sets the picked rules to Enabled when you apply.",
    "input": "Tick it to turn the picked rules on.",
    "effect": "local"
   },
   "#opFilter": {
    "what": "Shows only the rules whose name has this text.",
    "input": "Optional. Part of a rule name, like Block or DLP.",
    "effect": "local"
   },
   "#opPolicy": {
    "what": "Shows the rules of one policy only.",
    "input": "Optional. Pick a policy, or Every policy in scope.",
    "effect": "local"
   },
   "#opAll": {
    "what": "Picks every rule shown in the table, up to 100 rules.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opNone": {
    "what": "Clears every pick, so no rule is picked.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opObjects:has(input[name=\"opState\"]) input[data-k]": {
    "what": "Picks this rule for the change.",
    "input": "Tick it to include the rule. At most 100 rules per operation. A greyed-out box is a rule that cannot change.",
    "effect": "local"
   },
   "#opOrdPol": {
    "what": "Picks the policy whose rules you want to put in a new order.",
    "input": "Required. Pick a policy from the list.",
    "effect": "local"
   },
   "#opOrdType": {
    "what": "Picks the Cloud App Control application type to reorder. Each type has its own order.",
    "input": "Required. Pick a type from the list.",
    "effect": "local"
   },
   "#opOrdReset": {
    "what": "Puts the list back to the tenant's order, so you can start again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-mv=\"-1\"]": {
    "what": "Moves this rule one place up in the new order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-mv=\"1\"]": {
    "what": "Moves this rule one place down in the new order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opUrlAct": {
    "what": "Picks what to do with URLs: add, remove, move or copy them.",
    "input": "Required. Pick Add URLs, Remove URLs, Move URLs or Copy URLs.",
    "effect": "local"
   },
   "#opUrlSrc": {
    "what": "Picks the custom URL category the URLs come from.",
    "input": "Required for remove, move and copy. Pick a category from the list.",
    "effect": "local"
   },
   "#opUrlTgt": {
    "what": "Picks the custom URL category the URLs go to, or a new one.",
    "input": "Required for add, move and copy. Pick a category, or A new category.",
    "effect": "local"
   },
   "#opUrlNew": {
    "what": "Names the new custom URL category the URLs go into.",
    "input": "Required when To is A new category. A name not used yet, like Partner sites.",
    "effect": "local"
   },
   "#opUrls": {
    "what": "Lists the URLs to add to the category.",
    "input": "Required. One URL per line, up to 1000, like www.example.com. .example.com covers its subdomains.",
    "effect": "local"
   },
   "#opUrlAll": {
    "what": "Picks every URL listed in the source category.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opUrlNone": {
    "what": "Clears every URL pick.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[data-u]": {
    "what": "Picks this URL for the change.",
    "input": "Tick it to include the URL. Pick at least one.",
    "effect": "local"
   },
   "#opZAct": {
    "what": "Picks what to do: move domains, copy domains, or clone a segment.",
    "input": "Required. Pick Move domains, Copy domains or Clone a segment.",
    "effect": "local"
   },
   "#opZSrc": {
    "what": "Picks the application segment the domains come from.",
    "input": "Required. Pick a segment from the list.",
    "effect": "local"
   },
   "#opZTgt": {
    "what": "Picks the application segment the domains go to.",
    "input": "Required for move and copy. Pick a segment from the list.",
    "effect": "local"
   },
   "#opZName": {
    "what": "Names the new segment the clone makes.",
    "input": "Required for clone. A name not used yet, like Finance apps copy.",
    "effect": "local"
   },
   "#opZMove": {
    "what": "Takes the picked domains out of the source segment when the clone is made.",
    "input": "Tick it to move the domains. Leave it empty to copy them.",
    "effect": "local"
   },
   "input[data-d]": {
    "what": "Picks this domain for the change.",
    "input": "Tick it to include the domain. At most 500 domains per operation.",
    "effect": "local"
   },
   "#opZNew": {
    "what": "Adds more domains to the clone, besides the ones picked above.",
    "input": "Optional. One domain per line, like app.example.com.",
    "effect": "local"
   },
   "input[data-aig-app]": {
    "what": "Picks this GenAI app for the AI Guard builder.",
    "input": "Tick it to include the app. Pick at least one.",
    "effect": "local"
   },
   "input[name=\"aigCert\"][value=\"existing\"]": {
    "what": "Uses a root certificate that is already in ZIA for proxy chaining.",
    "input": "Tick it, then pick the certificate below.",
    "effect": "local"
   },
   "input[name=\"aigCert\"][value=\"upload\"]": {
    "what": "Uploads the AI Guard root certificate to ZIA for proxy chaining.",
    "input": "Tick it, then pick the .pem file or paste the certificate below.",
    "effect": "local"
   },
   "#aigCertId": {
    "what": "Picks the root certificate already in ZIA to use.",
    "input": "Required for this choice. Pick one from the list.",
    "effect": "local"
   },
   "#aigPemFile": {
    "what": "Loads the Proxy Chain certificate file from the AI Guard portal (Tenant Settings, Integrations).",
    "input": "A .pem, .crt or .cer file, at most 16 KB. It is read in the browser.",
    "effect": "local"
   },
   "#aigPem": {
    "what": "Holds the AI Guard certificate in PEM text.",
    "input": "One certificate from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----, at most 16 KB.",
    "effect": "local"
   },
   "input[data-aig-opt=\"block_quic\"]": {
    "what": "Adds a rule that blocks QUIC, so the apps use TCP 443 that ZIA can inspect.",
    "input": "Tick it to add the rule. On by default.",
    "effect": "local"
   },
   "input[data-aig-opt=\"ssl_inspect\"]": {
    "what": "Adds an SSL Inspect rule for the apps at the top, above every Do Not Decrypt bypass.",
    "input": "Tick it to add the rule. Needs SSL/TLS Inspection in scope.",
    "effect": "local"
   },
   "input[data-aig-opt=\"prompt_capture\"]": {
    "what": "Turns on GenAI prompt capture for the picked apps.",
    "input": "Tick it to turn it on. Needs the Gen AI Security subscription.",
    "effect": "local"
   },
   "input[data-aig-opt=\"allow_in_zia\"]": {
    "what": "Allows the apps in ZIA above any Block, Caution or Isolate rule, so they reach AI Guard.",
    "input": "Tick it to add the Allow rules.",
    "effect": "local"
   },
   "#aigPrefix": {
    "what": "Adds your text to the front of every object name this builder makes.",
    "input": "Optional. Up to 12 letters, digits, - or _, starting with a letter or digit, like ACME.",
    "effect": "local"
   },
   "#zsbHashes": {
    "what": "The files to block in Cloud Sandbox, by their MD5 hash. A blocked hash stops that file for every user once the change is activated.",
    "input": "Required. One MD5 hash per line (32 characters, 0-9 and a-f), up to 100; anything after the hash on the line is its comment. SHA-256 is not accepted.",
    "effect": "local"
   },
   "#aigProfile": {
    "what": "Picks the compliance profile the detection policy looks for. It follows the compliance profile picked in the ZIA security baseline, until you change it here.",
    "input": "Required. HIPAA, HITRUST, PCI DSS, GDPR, CJIS, FERPA, SOX, NIST SP 800-53, NIST SP 800-171 / CMMC, IRS Publication 1075 or General.",
    "effect": "local"
   },
   "input[name=\"aigMode\"][value=\"monitor\"]": {
    "what": "Sets the policy to Monitor: it detects and logs only. Recommended first.",
    "input": "Tick it for detect only.",
    "effect": "local"
   },
   "input[name=\"aigMode\"][value=\"block\"]": {
    "what": "Sets the policy to Block: it stops prompts with the profile's identifiers and prompt attacks.",
    "input": "Tick it to block.",
    "effect": "local"
   },
   "input[name=\"rcPolicy\"]": {
    "what": "Picks the policy whose rules you export and import: Cloud Firewall, URL filtering or the ZPA access policy.",
    "input": "Tick one. Only policies in scope on the Scope page are offered.",
    "effect": "local"
   },
   "#rcExport": {
    "what": "Saves the policy's rules as a CSV file: names, not ids, with the order and the admin rank. Every cell is safe to open in a spreadsheet.",
    "input": "Nothing to type. Just click it. Read from the tenant first.",
    "effect": "download"
   },
   "#rcCols > summary": {
    "what": "Shows or hides the columns a file for this policy may have and what each holds.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rcFile": {
    "what": "Chooses the edited CSV file. Choosing it only checks the file; nothing is read from or written to the tenant.",
    "input": "Required to preview. A UTF-8 CSV with a header row, at most 1000 kB and 2000 rules; lists separated by a semicolon, like QUIC; DNS.",
    "effect": "local"
   },
   "#rcRemove": {
    "what": "Deletes every rule of the policy that is not in the file (never the Default, predefined or read-only rules). Applying then needs DELETE and the count typed, like DELETE 3 RULES.",
    "input": "Optional. Off by default. Tick it only when the file lists every rule you want to keep.",
    "effect": "local"
   },
   "#rcEnabled": {
    "what": "Creates new rules from the file enabled. Off, new ZIA rules are created disabled; new ZPA access rules are left out, because ZPA cannot create them disabled.",
    "input": "Optional. Off by default.",
    "effect": "local"
   },
   "#opObjects details.pa-details > summary": {
    "what": "Shows or hides what the app assumes for this builder.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[name=\"zcPlat\"]": {
    "what": "Picks the platform of the app profile: Windows or macOS.",
    "input": "Tick one. The settings list changes to match.",
    "effect": "local"
   },
   "input[name=\"zcFwdTpl\"][value=\"existing\"]": {
    "what": "Links the new app profile to a forwarding profile the tenant already has. Nothing is made for it.",
    "input": "Tick it, then pick the profile below.",
    "effect": "local"
   },
   "input[name=\"zcFwdTpl\"]": {
    "what": "Picks the template for the new forwarding profile: Best practice or Portal default.",
    "input": "Tick one. The settings below change to match.",
    "effect": "local"
   },
   "#zcFwdId": {
    "what": "Picks the existing forwarding profile to link to.",
    "input": "Required for this choice. Pick one from the list.",
    "effect": "local"
   },
   "#zcFwdName": {
    "what": "Names the new forwarding profile.",
    "input": "Required. Up to 64 letters, digits, spaces and . _ ( ) -, starting with a letter or digit, like Best practice forwarding.",
    "effect": "local"
   },
   "input[name=\"zcAppTpl\"]": {
    "what": "Picks the template for the new app profile: Best practice or Portal default.",
    "input": "Tick one. The settings below change to match.",
    "effect": "local"
   },
   "#zcAppName": {
    "what": "Names the new app profile.",
    "input": "Required. Up to 64 letters, digits, spaces and . _ ( ) -, starting with a letter or digit, like Best practice Windows.",
    "effect": "local"
   },
   "input[data-zk^=\"fwd:\"]": {
    "what": "Uses this setting in the new forwarding profile.",
    "input": "Tick it to keep the setting. Untick it to leave the portal default.",
    "effect": "local"
   },
   "input[data-zk^=\"app:\"]": {
    "what": "Uses this setting in the new app profile.",
    "input": "Tick it to keep the setting. Untick it to leave the portal default.",
    "effect": "local"
   },
   "#zcEnable": {
    "what": "Turns the profiles on when they are made. They are off by default, so you can review them first.",
    "input": "Tick it to make them on.",
    "effect": "local"
   },
   "input[data-zpw]": {
    "what": "A tamper protection password for the new app profile: users need it to uninstall Client Connector, turn off Internet security or log out. It is sent once, when the profile is made, and never kept; the preview shows set (hidden).",
    "input": "Optional. Up to 128 characters. Leave it empty to set no password. You type it again before you apply.",
    "effect": "local"
   },
   "input[name=\"zcDel\"]": {
    "what": "Picks this profile to delete. A profile in use cannot be picked.",
    "input": "Pick one. You type the profile's name to confirm when you apply.",
    "effect": "local"
   },
   "#reType": {
    "what": "Picks the kind of rule to create, edit, copy or delete. The form below shows only the fields that kind of rule has.",
    "input": "Pick one. The number is how many rules of that kind the tenant has.",
    "effect": "local"
   },
   "input[name=\"reMode\"]": {
    "what": "Picks what to do: create a new rule, edit one, make a copy of one, or delete one.",
    "input": "Tick one. Nothing is written until you preview and apply.",
    "effect": "local"
   },
   "#reFilter": {
    "what": "Narrows the rule list below to rules whose name has these words.",
    "input": "Optional. Type part of a rule's name.",
    "effect": "local"
   },
   "#reRule": {
    "what": "Picks the rule to edit, copy or delete. The Default rule, predefined rules and read-only rules are listed but not changed here.",
    "input": "Pick one rule from the list.",
    "effect": "local"
   },
   "#reCacType": {
    "what": "Picks the Cloud App Control application type the new rule belongs to, such as Webmail or File sharing.",
    "input": "Required for Cloud App Control. Pick one.",
    "effect": "local"
   },
   "#rePlace": {
    "what": "Picks where the new rule goes in the policy: the top, the bottom (above the Default rule), an order number, or right below a rule. The preview shows the order and the admin rank it gets.",
    "input": "Pick one.",
    "effect": "local"
   },
   "#rePlaceOrder": {
    "what": "The order number the new rule takes; 1 is the top. A number past the end puts it last.",
    "input": "A whole number from 1.",
    "effect": "local"
   },
   "#rePlaceBelow": {
    "what": "Picks the rule the new rule goes right below.",
    "input": "Pick one rule from the list.",
    "effect": "local"
   },
   "#reEnabled": {
    "what": "Creates the rule enabled, so it applies to users as soon as ZIA activates. It is off by default: the rule then changes nothing until you enable it.",
    "input": "Tick it to create the rule enabled; you then type a confirmation when you apply.",
    "effect": "local"
   },
   "#reState": {
    "what": "Keeps the rule's state, or enables or disables it with the edit.",
    "input": "Pick one. Enabling needs a typed confirmation when you apply.",
    "effect": "local"
   },
   "#reDupName": {
    "what": "Names the copy. The copy keeps every other setting, sits right below the rule and is created disabled.",
    "input": "Required. Up to 31 characters (127 for Web DLP), no angle brackets or control characters.",
    "effect": "local"
   },
   "input[name=\"reObj\"]": {
    "what": "Picks which objects to list and change: cloud application instances or tenancy restriction profiles.",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[name=\"reObjMode\"]": {
    "what": "Picks whether to create a new object or edit one the tenant has.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#reObjPick": {
    "what": "Picks the object to edit. Its current values fill the form below.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "[data-re-kind=\"text\"]": {
    "what": "Names the rule or object (the label in the first column says which).",
    "input": "Required. Up to the length the third column gives, no angle brackets or control characters.",
    "effect": "local"
   },
   "[data-re-kind=\"longtext\"]": {
    "what": "A description kept with the rule or object, shown in the ZIA Admin Portal.",
    "input": "Optional. Up to 255 bytes of plain text.",
    "effect": "local"
   },
   "[data-re-kind=\"enum\"]": {
    "what": "Picks one value for the field named in the first column, such as the rule's action.",
    "input": "Pick one. The values are the ones the Zscaler SDK accepts.",
    "effect": "local"
   },
   "[data-re-kind=\"ssl_action\"]": {
    "what": "Picks what SSL inspection does: inspect (decrypt), do not inspect, or block.",
    "input": "Pick one. Inspect uses TLS 1.2 or later; an edit that keeps the action keeps its other settings.",
    "effect": "local"
   },
   "[data-re-kind=\"enums\"]": {
    "what": "Ticks the values the rule applies to for the field named in the first column; none ticked means every one.",
    "input": "Tick any.",
    "effect": "local"
   },
   "[data-re-kind=\"refs\"]": {
    "what": "Picks, by name, the tenant's objects the rule applies to for the field named in the first column; none picked means any.",
    "input": "Optional unless marked required. Ctrl or Cmd picks several.",
    "effect": "local"
   },
   "[data-re-kind=\"names\"]": {
    "what": "Picks, by name, the categories or applications the rule applies to for the field named in the first column.",
    "input": "Optional unless marked required. Ctrl or Cmd picks several.",
    "effect": "local"
   },
   "[data-re-kind=\"ref\"]": {
    "what": "Picks one of the tenant's objects by name, such as the gateway a forwarding rule uses.",
    "input": "Pick one, or none.",
    "effect": "local"
   },
   "[data-re-kind=\"addrs\"]": {
    "what": "Lists the addresses the rule applies to: IP addresses, ranges, CIDR blocks or (for destinations) domains.",
    "input": "One per line, such as 10.0.0.0/8, 10.0.0.1-10.0.0.9 or *.example.com.",
    "effect": "local"
   },
   "[data-re-kind=\"countries\"]": {
    "what": "Lists the destination countries the rule applies to.",
    "input": "One per line: a two-letter code such as US, or COUNTRY_US.",
    "effect": "local"
   },
   "[data-re-kind=\"enums_free\"]": {
    "what": "Lists the Zscaler file types the rule applies to.",
    "input": "One per line, such as FTCATEGORY_ZIP.",
    "effect": "local"
   },
   "[data-re-kind=\"cac_actions\"]": {
    "what": "Lists the Cloud App Control actions the rule takes, such as blocking uploads.",
    "input": "One per line, such as BLOCK_FILE_SHARE_UPLOAD. ZIA refuses an action the application does not support.",
    "effect": "local"
   },
   "[data-re-kind=\"bool\"]": {
    "what": "Turns the setting named in the first column on or off.",
    "input": "Tick for yes.",
    "effect": "local"
   },
   "[data-re-kind=\"flag01\"]": {
    "what": "Turns the setting named in the first column on or off.",
    "input": "Tick for yes.",
    "effect": "local"
   },
   "[data-re-kind=\"int\"]": {
    "what": "A number for the field named in the first column, such as a port or a size.",
    "input": "A whole number in the range the third column gives.",
    "effect": "local"
   },
   "[data-re-kind=\"ports\"]": {
    "what": "The segment's ports for this protocol. A port taken away cuts access on it.",
    "input": "Ports and ranges, separated by commas, such as 443, 8000-8080.",
    "effect": "local"
   },
   "[data-re-kind=\"lines\"]": {
    "what": "Lists the items of the tenancy restriction, such as tenant IDs or domains.",
    "input": "One per line, no spaces.",
    "effect": "local"
   },
   "[data-re-kind=\"identifiers\"]": {
    "what": "Lists what identifies this cloud application instance: a URL, a referring URL or a keyword.",
    "input": "One per line: URL, REFURL or KEYWORD, a space, then the value.",
    "effect": "local"
   },
   "[data-re-kind=\"host\"]": {
    "what": "The proxy's address: where ZIA forwards the traffic it chains.",
    "input": "An IP address or a host name such as proxy.example.com.",
    "effect": "local"
   },
   "input[name=\"zdxTier\"]": {
    "what": "Picks how closely ZDX watches: Strict monitors the most apps every 5 minutes, Balanced the Microsoft 365 core every 10, Permissive sign-in only every 15, Healthcare adds Zoom every 5. It fills in the apps, the interval and the CloudPath probes below.",
    "input": "Tick one: Strict, Balanced, Permissive or Healthcare. It starts on the tier picked for the ZIA security baseline, else Balanced.",
    "effect": "local"
   },
   "input[name=\"zdxTpl\"]": {
    "what": "Picks a ZDX template. It fills in the apps and probes below.",
    "input": "Tick one: Best practice, Microsoft 365 or Start empty.",
    "effect": "local"
   },
   "input[data-pre][data-f=\"on\"]": {
    "what": "Sets up this predefined app in ZDX.",
    "input": "Tick it to include the app. At most 20 predefined apps.",
    "effect": "local"
   },
   "input[data-pre][data-f=\"web\"]": {
    "what": "Turns on the Web probe of this app. It checks the page is reachable and how fast.",
    "input": "Tick it to turn the probe on.",
    "effect": "local"
   },
   "input[data-pre][data-f=\"cloudpath\"]": {
    "what": "Turns on the CloudPath probe of this app. It checks the network path to it.",
    "input": "Tick it to turn the probe on.",
    "effect": "local"
   },
   "input[data-pre][data-f=\"prefix\"]": {
    "what": "Gives the customer's tenant prefix this app needs in its web address.",
    "input": "Required for this app. Letters, digits and hyphens, like acme.",
    "effect": "local"
   },
   "input[data-cus][data-f=\"name\"]": {
    "what": "Names this custom app.",
    "input": "Required. Up to 64 letters, digits, spaces or - _ . ( ) : / & +, like Intranet portal.",
    "effect": "local"
   },
   "input[data-cus][data-f=\"url\"]": {
    "what": "Gives the web address the custom app probes.",
    "input": "Required. A full web address with https or http in front, like portal.example.com with https in front.",
    "effect": "local"
   },
   "input[data-cus][data-f=\"cloudpath\"]": {
    "what": "Adds a CloudPath probe to this custom app.",
    "input": "Tick it to add the probe.",
    "effect": "local"
   },
   "button[data-rm]": {
    "what": "Removes this custom app from the setup.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zdxAdd": {
    "what": "Adds a row for a new custom app.",
    "input": "Nothing to type. Just click it. At most 20 custom apps.",
    "effect": "local"
   },
   "#zdxInterval": {
    "what": "Picks how often the custom apps' probes run.",
    "input": "Required. Every 5, 10, 15 or 30 minutes.",
    "effect": "local"
   },
   "#zdxProto": {
    "what": "Picks the protocol of the custom apps' CloudPath probes.",
    "input": "Required. Adaptive, ICMP, TCP or UDP.",
    "effect": "local"
   },
   "input[name=\"zdxTo\"][value=\"off\"]": {
    "what": "Turns the picked apps and probes off when you apply.",
    "input": "Tick it to turn them off.",
    "effect": "local"
   },
   "input[name=\"zdxTo\"][value=\"on\"]": {
    "what": "Turns the picked apps and probes on when you apply.",
    "input": "Tick it to turn them on.",
    "effect": "local"
   },
   "#zdxNone": {
    "what": "Clears every pick.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[name=\"sanTo\"][value=\"unsanctioned\"]": {
    "what": "Marks the picked cloud apps Unsanctioned when you apply. That labels them for the whole tenant; it does not block them.",
    "input": "Tick it to mark them Unsanctioned. Block or isolate them in Cloud App Control too.",
    "effect": "local"
   },
   "input[name=\"sanTo\"][value=\"sanctioned\"]": {
    "what": "Marks the picked cloud apps Sanctioned when you apply: approved for business use, for the whole tenant.",
    "input": "Tick it to mark them Sanctioned.",
    "effect": "local"
   },
   "#sanFilter": {
    "what": "Shows only the cloud apps whose name or category contains these words.",
    "input": "Optional. Some words, like box or file share. Up to 80 characters.",
    "effect": "local"
   },
   "#sanRisky": {
    "what": "Ticked: shows only the cloud apps with a risk index of 4 or 5 (high risk).",
    "input": "Optional. Tick it to see the high-risk apps only.",
    "effect": "local"
   },
   "#sanNone": {
    "what": "Clears every pick.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opObjects:has(input[name=\"sanTo\"]) input[data-id]": {
    "what": "Picks this cloud app to change. Its state now, risk and traffic come from ZIA Insights.",
    "input": "Tick it to include it. At most 100 per change.",
    "effect": "local"
   },
   "#opObjects:has(input[name=\"zdxTo\"]) input[data-k]": {
    "what": "Picks this ZDX app or probe to turn on or off.",
    "input": "Tick it to include it. At most 100 per change.",
    "effect": "local"
   },
   "input[data-k][data-name]": {
    "what": "Picks this custom ZDX app or probe to delete. Deleting cannot be undone.",
    "input": "Tick it, then type its name below to confirm.",
    "effect": "local"
   },
   "#zdxNames input[data-nk]": {
    "what": "Confirms that you want to delete this app or probe.",
    "input": "Required. Type its name exactly as shown.",
    "effect": "local"
   },
   "input[name=\"zbTier\"]": {
    "what": "Picks the tier the baseline is built from.",
    "input": "Tick one: Strict, Balanced, Permissive or Healthcare zero trust.",
    "effect": "local"
   },
   "#zbCompliance": {
    "what": "Picks the one compliance profile, like FedRAMP High or CMMC Level 2. It sets the tier and the rules its source asks for. It also picks the policy packs, the AI Guard profile and the compliance pack.",
    "input": "Optional. Pick a profile, or None. With a saved tenant profile picked above, the choice is remembered for that tenant.",
    "effect": "local"
   },
   "button[data-zb-cp-file]": {
    "what": "Saves one file of the compliance pack, made from the build on screen. Pick the control mapping, the policy export, the test plan, or all of them with the DLP test files.",
    "input": "Nothing to type. Pick a compliance profile first. Local files only: nothing is written to the tenant.",
    "effect": "download"
   },
   "#zbCpCheck": {
    "what": "Checks that every rule of the build maps to a control of the profile, or has a reason code.",
    "input": "Nothing to type. Pick a compliance profile first. It reads nothing from the tenant.",
    "effect": "local"
   },
   "#zbCpSummary a.rp-btn[href*=\"simple=deploy\"]": {
    "what": "Opens Deploy policy packs with this policy pack picked. Nothing is deployed until you preview and confirm there.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#zbFile": {
    "what": "Loads a framework file saved from another tenant, instead of a tier.",
    "input": "Optional. A .json file from Export from tenant, ZIA policy framework, at most 2 MB.",
    "effect": "local"
   },
   "#zbClearFw": {
    "what": "Drops the loaded framework file and goes back to a tier.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[data-zb-ov]": {
    "what": "Adds the controls of this compliance framework to each rule it fits. It does not change the rules.",
    "input": "Tick it to add the overlay.",
    "effect": "local"
   },
   "input[data-zb-area]": {
    "what": "Includes this area, like URL filtering or Cloud Firewall, in the baseline.",
    "input": "Tick it to include it. A greyed-out area is not in scope on the Scope page.",
    "effect": "local"
   },
   "#zbPrefix[data-f=\"prefix\"]": {
    "what": "Every object is named with it (pov1-server-group, ...), so running the same build again updates them instead of making copies.",
    "input": "Required. 1 to 20 letters, digits, - or _, like pov1.",
    "effect": "local"
   },
   "#zbEnable[data-f=\"enable\"]": {
    "what": "Makes the applications enabled. Off: they are made disabled and decide nothing until you enable them.",
    "input": "Tick it to make them enabled.",
    "effect": "local"
   },
   "#zbPrefix": {
    "what": "Starts every rule name the baseline makes.",
    "input": "Required. 1 to 10 letters, digits, - or _, starting with a letter or digit, like BL.",
    "effect": "local"
   },
   "select#zbMode": {
    "what": "Sets Allow or Block for the whole baseline, or keeps each tier default.",
    "input": "Pick Tier default, Allow all or Block all.",
    "effect": "local"
   },
   "#zbProfile": {
    "what": "Picks the Cloud Browser Isolation profile the Isolate rules use.",
    "input": "Optional. Pick one, or keep the tenant's default profile.",
    "effect": "local"
   },
   "#zbCert": {
    "what": "Picks the intermediate certificate the Inspect rules use.",
    "input": "Optional. Pick one, or keep the tenant's default certificate.",
    "effect": "local"
   },
   "#zbEnable": {
    "what": "Makes the new rules enabled. Off: every new rule arrives disabled, to turn on after review.",
    "input": "Tick it to make them enabled.",
    "effect": "local"
   },
   "input[data-zb-on]": {
    "what": "Includes this rule in the baseline.",
    "input": "Tick it to include the rule. A locked rule is always included.",
    "effect": "local"
   },
   "select[data-zb-act]": {
    "what": "Picks the action of this rule.",
    "input": "Pick Tier default, Allow, Block or Isolate.",
    "effect": "local"
   },
   "input[data-zb-atp]": {
    "what": "Turns this Advanced Threat Protection setting on.",
    "input": "Tick it to turn it on. It takes effect when ZIA activates the change.",
    "effect": "local"
   },
   "#opObjects a[target=\"_blank\"]": {
    "what": "Opens the source document of this rule or control in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "input[data-zc]": {
    "what": "Picks this Inspect rule to move to another certificate.",
    "input": "Tick it to include the rule. Pick at least one.",
    "effect": "local"
   },
   "#zcTarget": {
    "what": "Picks the certificate to move the picked rules to.",
    "input": "Required. Pick a certificate, or the tenant's default certificate.",
    "effect": "local"
   },
   "#zbModeNew": {
    "what": "Makes a new App Connector group named with the prefix.",
    "input": "Tick it to make one.",
    "effect": "local"
   },
   "#zbModeOld": {
    "what": "Reuses an App Connector group the tenant already has.",
    "input": "Tick it, then pick the group below.",
    "effect": "local"
   },
   "#zbCg": {
    "what": "Picks the existing App Connector group to reuse.",
    "input": "Required for this choice. Pick one from the list.",
    "effect": "local"
   },
   "#zbLoc": {
    "what": "Picks the location of the new App Connector group.",
    "input": "Required. Pick a city from the list, like San Jose, US.",
    "effect": "local"
   },
   "#zbMax": {
    "what": "Sets how many App Connectors may enroll with the provisioning key.",
    "input": "Required. A whole number from 1 to 500, like 5.",
    "effect": "local"
   },
   "#zbSegCg": {
    "what": "Picks the App Connector group the segments use.",
    "input": "Optional. Pick one, or keep the prefix's own group.",
    "effect": "local"
   },
   "#zbWDom": {
    "what": "Makes one segment for every host under this domain. *. is added for you.",
    "input": "Optional. A domain name, like corp.example.com.",
    "effect": "local"
   },
   "#zbWTcp": {
    "what": "Sets the TCP ports of the wildcard segment.",
    "input": "Ports or ranges from 1 to 65535, split by commas, like 443, 8000-8100. 1-65535 means all.",
    "effect": "local"
   },
   "#zbWUdp": {
    "what": "Sets the UDP ports of the wildcard segment.",
    "input": "Optional. Ports or ranges from 1 to 65535, like 53. Leave it empty for none.",
    "effect": "local"
   },
   "#zbVert": {
    "what": "Picks a preset of applications for the customer's sector.",
    "input": "Optional. None, Healthcare, Finance, Education or General.",
    "effect": "local"
   },
   "#zbPDom": {
    "what": "Gives the base domain the preset's applications go under.",
    "input": "Required with a preset. A domain name, not an IP address, like hospital.org.",
    "effect": "local"
   },
   "#zbCsvFile": {
    "what": "Loads a CSV file of applications.",
    "input": "Optional. A .csv file, at most 256 KB and 500 rows.",
    "effect": "local"
   },
   "#zbCsv": {
    "what": "Holds the CSV of applications to make.",
    "input": "Optional. Columns name,domains,tcp_ports,udp_ports,description. Domains split by ; and ports like 443;8000-8100.",
    "effect": "local"
   },
   "#zbBaDom": {
    "what": "Gives the web server for a Browser Access application.",
    "input": "Optional. One server name, not a wildcard, like ehr.hospital.org.",
    "effect": "local"
   },
   "#zbBaPort": {
    "what": "Sets the port of the Browser Access web server.",
    "input": "One port from 1 to 65535, like 443.",
    "effect": "local"
   },
   "#zbBaCert": {
    "what": "Picks the web server certificate for Browser Access.",
    "input": "Required with Browser Access. Pick one from the list.",
    "effect": "local"
   },
   "#zbRdp": {
    "what": "Gives an RDP server for Privileged Remote Access.",
    "input": "Optional. One server name or IP address, like rdp01.corp.example.com.",
    "effect": "local"
   },
   "#zbSsh": {
    "what": "Gives an SSH server for Privileged Remote Access.",
    "input": "Optional. One server name or IP address, like 10.0.0.12.",
    "effect": "local"
   },
   "#zbPortal": {
    "what": "Picks the PRA portal for the remote access consoles.",
    "input": "Optional. Pick a portal, or No console.",
    "effect": "local"
   },
   "#zbAccess": {
    "what": "Adds an access rule that allows the prefixed applications.",
    "input": "Tick it to add the rule.",
    "effect": "local"
   },
   "#zbTimeout": {
    "what": "Adds a timeout rule that makes users sign in again.",
    "input": "Tick it to add the rule, then pick the times.",
    "effect": "local"
   },
   "#zbRt": {
    "what": "Sets how often users must sign in again.",
    "input": "Pick 1 hour, 8 hours, 1 day or 7 days.",
    "effect": "local"
   },
   "#zbIt": {
    "what": "Sets how long idle time is allowed before users sign in again.",
    "input": "Pick 15 minutes, 1 hour or 8 hours.",
    "effect": "local"
   },
   "#zbInsp": {
    "what": "Adds an inspection profile of Zscaler's predefined OWASP controls, with its rule. Needs AppProtection.",
    "input": "Tick it to add them.",
    "effect": "local"
   },
   "#zbIso": {
    "what": "Picks an isolation profile for an isolation rule.",
    "input": "Optional. Pick a profile, or No isolation rule.",
    "effect": "local"
   },
   "#zbWhoAll": {
    "what": "Lets the access rule allow every user of the applications.",
    "input": "Nothing to type. Just pick it.",
    "effect": "local"
   },
   "#zbWhoSome": {
    "what": "Limits the access rule to users in the SCIM groups or with the SAML values you pick from the tenant.",
    "input": "Nothing to type. Pick it, then pick SCIM groups or add SAML values below.",
    "effect": "local"
   },
   "#zbScimFind": {
    "what": "Narrows the SCIM group list to names that contain what you type.",
    "input": "Optional. Part of a group name, like Fin.",
    "effect": "local"
   },
   "#zbScimList input[data-scim]": {
    "what": "Picks this SCIM group for the access rule. A user in any picked group matches.",
    "input": "Nothing to type. Tick it. At most 20 groups.",
    "effect": "local"
   },
   "#zbSamlAttr": {
    "what": "Picks a SAML attribute the tenant has, for a value the access rule requires.",
    "input": "Pick an attribute, then type its value.",
    "effect": "local"
   },
   "#zbSamlVal": {
    "what": "Sets the SAML attribute value a user must have.",
    "input": "Required to add. 1 to 200 characters, like Finance.",
    "effect": "local"
   },
   "#zbSamlAdd": {
    "what": "Adds this SAML attribute and value to the access rule. A user with any added value matches.",
    "input": "Pick the attribute and type the value first. At most 20.",
    "effect": "local"
   },
   "#zbSamlList button[data-saml-del]": {
    "what": "Removes this SAML value from the access rule.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zbAll": {
    "what": "Deletes everything named with the prefix, not only the picked objects.",
    "input": "Tick it to pick all of them.",
    "effect": "local"
   },
   "#zbShow": {
    "what": "Lists the objects the prefix matches, from the last read.",
    "input": "Enter the prefix first. Then click it.",
    "effect": "local"
   },
   "#opObjects .op-checks input[data-k]": {
    "what": "Picks this ZPA object to delete.",
    "input": "Tick it to include the object.",
    "effect": "local"
   },
   "#zbKey": {
    "what": "Shows the new provisioning key once. This app never keeps, logs or exports it.",
    "input": "Nothing to type. Copy it now.",
    "effect": "local"
   },
   "#zbCopy": {
    "what": "Copies the provisioning key to the clipboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#opAssessor": {
    "what": "Gives the assessor's name. The change record names who made it.",
    "input": "Required. A name, like Jane Doe, Zscaler DS Engineer.",
    "effect": "local"
   },
   "#opPhrase": {
    "what": "Confirms the change by typing the phrase shown.",
    "input": "Required when shown. Type the phrase exactly, like APPLY 12 CHANGES. Case does not matter.",
    "effect": "local"
   },
   "#opAgree": {
    "what": "Confirms you reviewed this plan and the customer agreed to it.",
    "input": "Tick it before you apply.",
    "effect": "local"
   },
   "#opGo": {
    "what": "Applies the previewed change to the tenant. Each item is read again right before its write.",
    "input": "Needs write mode on, your permission to change the tenant, the assessor's name, the box ticked and any phrase typed.",
    "effect": "write"
   },
   "#opResult details.pa-details > summary": {
    "what": "Shows or hides the log of what was done.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-undo]": {
    "what": "Starts an Undo of this change. It previews the Undo first. Nothing is written until you apply it.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"config_restore_zia\"]": {
    "what": "Picks restore or clone for ZIA. It restores this tenant from a backup, clones another tenant's backup into it, or applies a template.",
    "input": "Tick it, then click Read from the tenant to show the form. It lists the saved backups and reads nothing from the tenant.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"config_restore_zpa\"]": {
    "what": "Picks restore or clone for ZPA. It restores this tenant from a backup, clones another tenant's backup into it, or applies a template.",
    "input": "Tick it, then click Read from the tenant to show the form. It lists the saved backups and reads nothing from the tenant.",
    "effect": "local"
   },
   "#opBuildKinds input[name=\"opKind\"][value=\"config_restore_zcc\"]": {
    "what": "Picks restore or clone for Client Connector. It restores this tenant from a backup, clones another tenant's backup into it, or applies a template.",
    "input": "Tick it, then click Read from the tenant to show the form. It lists the saved backups and reads nothing from the tenant.",
    "effect": "local"
   },
   "input[name=\"crSrc\"]": {
    "what": "Picks where the objects come from: a saved backup or a template.",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[name=\"crBackup\"]": {
    "what": "Picks the backup to restore or clone from.",
    "input": "Tick one row. Each row says when it was saved and which tenant it is of.",
    "effect": "local"
   },
   "button[data-crdel]": {
    "what": "Deletes this backup file from this computer. The tenant is not changed.",
    "input": "Click it, then confirm. This cannot be undone.",
    "effect": "local"
   },
   "#opObjects a[href^=\"/api/config-backups/\"]": {
    "what": "Downloads this backup as a file. It holds no secret.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#crTemplate": {
    "what": "Picks the template to apply.",
    "input": "Pick one from the list. Make or import one under the tools below.",
    "effect": "local"
   },
   "#crPrefix": {
    "what": "Sets the text put in front of the name of each object the template makes.",
    "input": "Optional. Up to 20 letters, digits, spaces and . _ -, like ACME-.",
    "effect": "local"
   },
   "input[name=\"crTarget\"]": {
    "what": "Says whether this tenant is the backup's own tenant or another one. Another tenant means a clone: objects are matched by name.",
    "input": "Tick one. A clone works only on the saved profile picked in the Tenant list.",
    "effect": "local"
   },
   "input[name=\"crMode\"]": {
    "what": "Picks how far the plan goes: add what is missing, also update what differs, or match the source exactly. Matching exactly also deletes.",
    "input": "Tick one. Deletes need DELETE and the count typed to confirm.",
    "effect": "local"
   },
   "input[data-crtype]": {
    "what": "Includes this kind of object in the restore.",
    "input": "Tick or untick it. All are ticked to start with.",
    "effect": "local"
   },
   "input[data-crkeys]": {
    "what": "Limits a settings restore to the keys you name. The other keys keep the target's value.",
    "input": "Optional. Key names split by commas, like enable_office365. Blank means all keys.",
    "effect": "local"
   },
   "#crKeep": {
    "what": "Keeps each rule on or off as it is in the source. When it is off, new rules are made turned off.",
    "input": "Tick it to keep the source's state.",
    "effect": "local"
   },
   "#crActivate": {
    "what": "Activates the ZIA changes as the last step of the plan. When it is off, they wait in ZIA.",
    "input": "Untick it to activate later in the portal.",
    "effect": "local"
   },
   "#crAck": {
    "what": "Says you checked the licences. A clone is blocked while the target lacks a subscription the source has.",
    "input": "Tick it only after you checked the two tenants' licences.",
    "effect": "local"
   },
   "#crRollback": {
    "what": "Undoes what a run applied at once if the run stops or fails. Without it, Undo is offered.",
    "input": "Tick it before you apply.",
    "effect": "local"
   },
   "#crPskName": {
    "what": "Names the VPN credential whose key you type next.",
    "input": "Its FQDN or IP address, like branch@corp.example.",
    "effect": "local"
   },
   "#crPskValue": {
    "what": "Takes the pre-shared key of that VPN credential. No backup holds one. It is sent with the apply only and never kept.",
    "input": "The key, as the branch device has it.",
    "effect": "local"
   },
   "#crPskAdd": {
    "what": "Keeps the typed key in this page until the apply.",
    "input": "Type the name and the key first. Then click it.",
    "effect": "local"
   },
   "#crSave": {
    "what": "Saves a backup of this tenant now. It reads only what is in scope on the Scope page. Nothing is written to the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#crFromSample": {
    "what": "Keeps the made-up sample tenant as a backup, to rehearse with. No tenant is read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#crCache": {
    "what": "Reads this tenant into its local cache and says what changed since the last time. Nothing is written to the tenant.",
    "input": "Pick a saved profile in the Tenant list first. Then click it.",
    "effect": "read"
   },
   "#crDiffOld": {
    "what": "Picks the older side of the compare.",
    "input": "Pick a backup from the list.",
    "effect": "local"
   },
   "#crDiffNew": {
    "what": "Picks the newer side of the compare: another backup or the live tenant.",
    "input": "Pick one from the list. The live tenant is read when you compare.",
    "effect": "local"
   },
   "#crIgnore": {
    "what": "Leaves more fields out of the compare. Ids, change times and counters are always left out.",
    "input": "Optional. Field names split by commas. A * matches any text.",
    "effect": "local"
   },
   "#crDiff": {
    "what": "Compares the two sides field by field. With the live tenant, it reads only what is in scope.",
    "input": "Pick both sides first. Then click it.",
    "effect": "read"
   },
   "#crEvery": {
    "what": "Sets how often the scheduled backup runs.",
    "input": "A whole number of hours from 1 to 168, like 24.",
    "effect": "local"
   },
   "#crKeepN": {
    "what": "Sets how many backups of this profile are kept. Older ones are deleted.",
    "input": "A whole number from 1 to 100, like 10.",
    "effect": "local"
   },
   "#crSchedOn": {
    "what": "Turns the scheduled backup on or off. It only reads, so it may run on its own.",
    "input": "Tick it to turn it on.",
    "effect": "local"
   },
   "#crSched": {
    "what": "Saves the schedule for the saved profile picked in the Tenant list.",
    "input": "Set the hours and the count first. Then click it.",
    "effect": "local"
   },
   "#crTplType": {
    "what": "Picks the kind of object to put in the template.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#crTplNames": {
    "what": "Names the objects of that kind to put in the template. What they use comes with them.",
    "input": "One name per line, as in the backup.",
    "effect": "local"
   },
   "#crTplName": {
    "what": "Names the template.",
    "input": "Required. Up to 80 characters, like Starter policy.",
    "effect": "local"
   },
   "#crTplStrip": {
    "what": "Replaces this text at the start of names with the template's prefix.",
    "input": "Optional. Up to 20 letters, digits, spaces and . _ -, like OLD-.",
    "effect": "local"
   },
   "#crTplMake": {
    "what": "Makes a template from the picked backup. Ids are removed and no secret is kept.",
    "input": "Pick the backup in step 1 and name the objects first. Then click it.",
    "effect": "local"
   },
   "#crTplFile": {
    "what": "Imports a template file. It is checked before it is kept.",
    "input": "Choose a template JSON file of at most 2 MB.",
    "effect": "local"
   },
   "#crRehearseOn": {
    "what": "Picks what the rehearsal plans against: the sample tenant or a saved backup.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#crRehearse": {
    "what": "Makes the plan against a saved copy instead of a tenant. Nothing can be applied from it.",
    "input": "Fill in the form above first. Then click it.",
    "effect": "local"
   },
   "#crRepush": {
    "what": "Previews a new plan for what did not arrive in the tenant. It writes nothing until you apply it.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#admFilter": {
    "what": "Shows only the objects whose name, group or health has these words.",
    "input": "Optional. Any words, like disconnected.",
    "effect": "local"
   },
   "input[data-admpick]": {
    "what": "Picks this object to change.",
    "input": "Tick it to include it. At most 50 per change.",
    "effect": "local"
   },
   "input[name=\"admOn\"]": {
    "what": "Turns the picked objects on or off, or leaves them as they are.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admName": {
    "what": "Renames the one picked object.",
    "input": "Optional. 1 to 128 characters, like hq-connector-1. Pick only one object.",
    "effect": "local"
   },
   "#admMoveTo": {
    "what": "Moves the picked App Connectors to this App Connector group.",
    "input": "Optional. Pick a group, or Do not move.",
    "effect": "local"
   },
   "#admDay": {
    "what": "Sets the day the picked groups take software updates.",
    "input": "Optional. A day of the week.",
    "effect": "local"
   },
   "#admHour": {
    "what": "Sets the hour the picked groups take software updates.",
    "input": "Optional. A whole hour, 00:00 to 23:00.",
    "effect": "local"
   },
   "#admVer": {
    "what": "Sets the software version profile of the picked groups.",
    "input": "Optional. Default, Previous default or New release.",
    "effect": "local"
   },
   "input[data-admdel]": {
    "what": "Picks this object to delete. Deleting cannot be undone.",
    "input": "Tick it. You type the confirmation when you apply.",
    "effect": "local"
   },
   "input[name=\"admKeyType\"]": {
    "what": "Picks whether the key enrolls App Connectors or Service Edges.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admKeyGroup": {
    "what": "Picks the group the new key enrolls into.",
    "input": "Required. Pick one from the list.",
    "effect": "local"
   },
   "#admKeyName": {
    "what": "Names the new provisioning key.",
    "input": "Required. 1 to 128 characters, like branch-key.",
    "effect": "local"
   },
   "#admKeyMax": {
    "what": "Sets how many App Connectors or Service Edges may enroll with the key.",
    "input": "Required. A number from 1 to 500.",
    "effect": "local"
   },
   "#admKeyOn": {
    "what": "Turns the new key on. Off: nothing can enroll with it until it is on.",
    "input": "Tick it to turn it on.",
    "effect": "local"
   },
   "#admKeyValue": {
    "what": "Shows the new provisioning key, this once.",
    "input": "Nothing to type. Copy it now: it is not kept.",
    "effect": "local"
   },
   "#admKeyCopy": {
    "what": "Copies the new provisioning key.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "input[name=\"admCertMode\"]": {
    "what": "Picks whether to upload a new certificate or use one ZPA has.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admCertName": {
    "what": "Names the uploaded certificate in ZPA.",
    "input": "Required for an upload. 1 to 128 characters, like wiki-2027.",
    "effect": "local"
   },
   "#admCertDesc": {
    "what": "Describes the uploaded certificate in ZPA.",
    "input": "Optional. Up to 255 characters.",
    "effect": "local"
   },
   "#admCertPem": {
    "what": "Takes the certificate, the server certificate first, then its chain.",
    "input": "Required for an upload. PEM text starting -----BEGIN CERTIFICATE-----.",
    "effect": "local"
   },
   "#admCertFile": {
    "what": "Loads the certificate from a file.",
    "input": "Optional. A .pem, .crt or .cer file, at most 64 KB.",
    "effect": "local"
   },
   "#admKeyPem": {
    "what": "Takes the certificate's private key. It is sent to this app once and never kept, logged or shown.",
    "input": "Required for an upload. An unencrypted PEM key.",
    "effect": "local"
   },
   "#admKeyFile": {
    "what": "Loads the private key from a file.",
    "input": "Optional. A .pem or .key file, at most 16 KB.",
    "effect": "local"
   },
   "#admCertUpload": {
    "what": "Checks the certificate and its key and holds them for ten minutes for your change. It does not touch the tenant.",
    "input": "Nothing to type. Needs write mode on.",
    "effect": "local"
   },
   "#admCertPick": {
    "what": "Picks a certificate ZPA already has.",
    "input": "Required. Pick one from the list.",
    "effect": "local"
   },
   "input[data-admba]": {
    "what": "Picks this Browser Access application to point at the certificate.",
    "input": "Tick it to include it. At most 20.",
    "effect": "local"
   },
   "#admUser": {
    "what": "Gives the user whose Client Connector devices to list.",
    "input": "Required. The user's email, like jdoe@acme.com.",
    "effect": "local"
   },
   "#admFind": {
    "what": "Lists the user's enrolled devices. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "input[name=\"admMode\"]": {
    "what": "Picks Remove (unenrolls at its next check-in) or Force remove (dropped at once).",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[data-admdev]": {
    "what": "Picks this device to remove. This cannot be undone.",
    "input": "Tick it. At most 25; use the list removal for more.",
    "effect": "local"
   },
   "#admList": {
    "what": "Takes the users, host names, device ids or @domains to remove, one a line.",
    "input": "Required. Like jdoe@acme.com, LAPTOP-12, or @old-domain.com. At most 5000 lines.",
    "effect": "local"
   },
   "#admListFile": {
    "what": "Loads the list from a file.",
    "input": "Optional. A .txt or .csv file, at most 1 MB.",
    "effect": "local"
   },
   "#admListDomain": {
    "what": "Keeps only devices of users in this domain.",
    "input": "Optional. A domain, like acme.com.",
    "effect": "local"
   },
   "#admBatch": {
    "what": "Sets how many devices go in one call to Client Connector.",
    "input": "Required. 1 to 100. Larger batches use fewer of the 100 calls an hour.",
    "effect": "local"
   },
   "input[name=\"admBulkMode\"]": {
    "what": "Picks Remove or Force remove for the whole list.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admMatch": {
    "what": "Matches the list against the enrolled devices. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "select[data-admamb]": {
    "what": "Picks which device this ambiguous entry means.",
    "input": "Optional. Pick one, or leave it out.",
    "effect": "local"
   },
   "a[data-admcsv=\"full\"]": {
    "what": "Downloads the plan or the result as a CSV file. It holds user and host names.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "a[data-admcsv=\"counts\"]": {
    "what": "Downloads only the counts per status and user domain, without names.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "input[name=\"admApp\"]": {
    "what": "Picks this custom bypass app to edit or delete.",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[name=\"admAppAct\"]": {
    "what": "Picks whether to create, edit or delete a custom bypass app.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admAppName": {
    "what": "Names the custom bypass app.",
    "input": "Required. 1 to 64 letters, digits, spaces or . _ ( ) -, like Teams media.",
    "effect": "local"
   },
   "#admAppOn": {
    "what": "Turns the app on. New apps start off.",
    "input": "Tick it to turn it on.",
    "effect": "local"
   },
   "#admAppEntries": {
    "what": "Lists what the app bypasses: protocol, port and address, one a line.",
    "input": "Required. Like TCP 443 10.0.0.0/8 or UDP 3478-3481 52.112.0.0/14. At most 100.",
    "effect": "local"
   },
   "input[name=\"admSvc\"]": {
    "what": "Picks the ZPA or the ZDX entitlement to change.",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[name=\"admAll\"]": {
    "what": "Turns the service on for every user, or only for the listed groups.",
    "input": "Tick one. Off narrows who gets it.",
    "effect": "local"
   },
   "#admAddGroups": {
    "what": "Adds these groups to the entitlement.",
    "input": "Optional. One group name a line, like Engineering.",
    "effect": "local"
   },
   "input[data-admgrp]": {
    "what": "Takes this group out of the entitlement.",
    "input": "Tick it to take it out.",
    "effect": "local"
   },
   "button[data-admscore]": {
    "what": "Shows this application's ZDX score over the last day. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#admZUser": {
    "what": "Gives the user whose ZDX devices to find.",
    "input": "Required. An email, like jdoe@acme.com, or part of a name.",
    "effect": "local"
   },
   "#admZFind": {
    "what": "Finds the user's ZDX devices. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#admZDev": {
    "what": "Picks the device to look at or trace.",
    "input": "Required. Pick one from the list.",
    "effect": "local"
   },
   "#admZHealthView": {
    "what": "Shows the device's details and health metrics. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "button[data-admperf]": {
    "what": "Shows how this application performs on this device. It only reads.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "button[data-admfollow]": {
    "what": "Follows this deep trace until it ends, a limited number of reads, then shows its results.",
    "input": "Nothing to type. Stop ends it.",
    "effect": "read"
   },
   "input[name=\"admTrace\"]": {
    "what": "Picks the deep trace to stop. Stopping deletes it and its results.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#admZName": {
    "what": "Names the deep trace session.",
    "input": "Required. 1 to 64 letters, digits, spaces or _ . -, like slow teams.",
    "effect": "local"
   },
   "#admZLen": {
    "what": "Sets how long the deep trace runs.",
    "input": "Required. 5, 15, 30 or 60 minutes.",
    "effect": "local"
   },
   "#admZApp": {
    "what": "Picks the application the deep trace measures.",
    "input": "Optional. Pick one, or None.",
    "effect": "local"
   },
   "#admZWeb": {
    "what": "Picks the application's Web probe the trace runs.",
    "input": "Optional. Pick one, or None.",
    "effect": "local"
   },
   "#admZPath": {
    "what": "Picks the application's CloudPath probe the trace runs.",
    "input": "Optional. Pick one, or None.",
    "effect": "local"
   },
   "#admZHealth": {
    "what": "Collects the device's own health (CPU, memory, network) during the trace.",
    "input": "Tick it to collect it.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zia_directory\"]": {
    "what": "Picks \"ZIA users, groups and departments\". It finds users and adds, changes or deletes users, groups and departments.",
    "input": "Tick it, then click Read from the tenant to show the form. Needs ZIA platform ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zia_pac\"]": {
    "what": "Picks \"ZIA PAC files\". It shows each hosted PAC file and its versions, validates a PAC and adds, clones, switches or deletes versions and files.",
    "input": "Tick it, then click Read from the tenant to list the PAC files. Needs ZIA platform ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zid_users\"]": {
    "what": "Picks \"ZIdentity users\". It finds users and adds, disables, enables or deletes them.",
    "input": "Tick it, then click Read from the tenant to list the users. Needs ZIdentity ticked on the Scope page.",
    "effect": "local"
   },
   "#opAdminKinds input[name=\"opKind\"][value=\"zid_api_clients\"]": {
    "what": "Picks \"ZIdentity API clients\". It lists the API clients and their scopes, and creates, rotates, disables, enables or deletes one.",
    "input": "Tick it, then click Read from the tenant to list them. Needs ZIdentity ticked on the Scope page.",
    "effect": "local"
   },
   "input[name=\"zdMode\"]": {
    "what": "Picks what to do: change or delete users, add a user, or change groups and departments.",
    "input": "Tick one. The form below changes to match.",
    "effect": "local"
   },
   "#zdSearch": {
    "what": "Finds ZIA users whose name starts with what you type.",
    "input": "Optional. Up to 100 characters, like Sam. Empty lists the first users. Then click Search.",
    "effect": "local"
   },
   "#zdSearchGo": {
    "what": "Reads the users whose name starts with the search from the tenant. It only reads.",
    "input": "Nothing to type here. Type the name in the box first.",
    "effect": "read"
   },
   "input[data-zu]": {
    "what": "Picks this user for the change below. Admin accounts cannot be picked.",
    "input": "Tick it. Up to 100 changes per plan.",
    "effect": "local"
   },
   "input[name=\"zdUserAct\"]": {
    "what": "Picks what happens to the picked users: change their department or groups, or delete them.",
    "input": "Tick one. A delete asks its name typed when you apply and cannot be undone.",
    "effect": "local"
   },
   "#zdDept": {
    "what": "Moves the picked users to this department.",
    "input": "Optional. Pick one from the list, or leave No change.",
    "effect": "local"
   },
   "#zdAdd": {
    "what": "Adds the picked users to these groups.",
    "input": "Optional. Pick one or more; hold Ctrl or Cmd to pick several.",
    "effect": "local"
   },
   "#zdRemove": {
    "what": "Takes the picked users out of these groups.",
    "input": "Optional. Pick one or more; hold Ctrl or Cmd to pick several.",
    "effect": "local"
   },
   "#zdNewName": {
    "what": "Names the new ZIA user.",
    "input": "Required. Up to 255 characters, like Sam Lee.",
    "effect": "local"
   },
   "#zdNewEmail": {
    "what": "The new user's email. It must be unique and its domain must belong to the organisation.",
    "input": "Required. An address like sam.lee@example.com.",
    "effect": "local"
   },
   "#zdNewDept": {
    "what": "Puts the new user in this department.",
    "input": "Required. Pick one from the list.",
    "effect": "local"
   },
   "#zdNewGroups": {
    "what": "Puts the new user in these groups.",
    "input": "Optional. Pick one or more; hold Ctrl or Cmd to pick several.",
    "effect": "local"
   },
   "input[name=\"zdGKind\"]": {
    "what": "Picks whether to change groups or departments.",
    "input": "Tick one. The list below changes to match.",
    "effect": "local"
   },
   "#zdGName": {
    "what": "Names a new group or department to add.",
    "input": "Optional. Up to 255 characters, like Contractors.",
    "effect": "local"
   },
   "#zdRename": {
    "what": "Picks a group or department to rename.",
    "input": "Optional. Pick one, then type its new name.",
    "effect": "local"
   },
   "#zdRenameTo": {
    "what": "The new name for the group or department picked to rename.",
    "input": "Required when you pick one to rename. Up to 255 characters.",
    "effect": "local"
   },
   "input[data-zg]": {
    "what": "Deletes this group or department. It cannot be undone.",
    "input": "Tick it. You type its name to confirm when you apply.",
    "effect": "local"
   },
   "input[name=\"zpPick\"]": {
    "what": "Picks this PAC file for the change below.",
    "input": "Tick one.",
    "effect": "local"
   },
   "input[name=\"zpAct\"]": {
    "what": "Picks what to do with the PAC file: validate, add a staged version, switch the active version, clone, add a new file or delete it.",
    "input": "Tick one. The fields below change to match.",
    "effect": "local"
   },
   "#zpVer": {
    "what": "Picks the PAC version to start from, or the one to make active.",
    "input": "Required for this choice. Pick one from the list.",
    "effect": "local"
   },
   "#zpText": {
    "what": "The PAC text to check or save. It is parsed and checked, never run.",
    "input": "Required for this choice. A PAC with FindProxyForURL(url, host), up to 256 KB.",
    "effect": "local"
   },
   "#zpLoad": {
    "what": "Copies the active version's text into the box, to edit it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpName": {
    "what": "Names the new PAC file.",
    "input": "Required for this choice. Up to 63 letters, digits, spaces and . _ ( ) -, like branch.pac.",
    "effect": "local"
   },
   "#zpDomain": {
    "what": "The organisation's domain the new PAC file applies to.",
    "input": "Required for this choice. A domain like example.com.",
    "effect": "local"
   },
   "#zpDesc": {
    "what": "Describes the new PAC file.",
    "input": "Optional. Up to 1024 characters.",
    "effect": "local"
   },
   "#zpMsg": {
    "what": "The commit message saved with the new version.",
    "input": "Optional. Up to 255 characters, like Partner portal goes direct.",
    "effect": "local"
   },
   "#opPlan .op-diff": {
    "what": "The lines the change adds (+) and removes (-) in the PAC text.",
    "input": "Nothing to type. Scroll it with the arrow keys.",
    "effect": "local"
   },
   "input[name=\"zuMode\"]": {
    "what": "Picks what to do: disable, enable or delete users, or add a user.",
    "input": "Tick one. The form below changes to match.",
    "effect": "local"
   },
   "#zuSearch": {
    "what": "Finds ZIdentity users whose login name contains what you type.",
    "input": "Optional. Up to 100 characters, like sam. Then click Search.",
    "effect": "local"
   },
   "#zuSearchGo": {
    "what": "Reads the users whose login name contains the search from the tenant. It only reads.",
    "input": "Nothing to type here. Type the name in the box first.",
    "effect": "read"
   },
   "input[data-zid-u]": {
    "what": "Picks this user for the change below. Administrators and users from SCIM cannot be picked.",
    "input": "Tick it. Up to 50 changes per plan.",
    "effect": "local"
   },
   "input[name=\"zuAct\"]": {
    "what": "Picks what happens to the picked users: disable, enable or delete.",
    "input": "Tick one. A delete asks its name typed when you apply and cannot be undone.",
    "effect": "local"
   },
   "#zuLogin": {
    "what": "The new user's login name.",
    "input": "Required. An address like sam.lee@example.com.",
    "effect": "local"
   },
   "#zuDisplay": {
    "what": "The new user's display name.",
    "input": "Required. Up to 255 characters, like Sam Lee.",
    "effect": "local"
   },
   "#zuFirst": {
    "what": "The new user's first name.",
    "input": "Optional. Up to 255 characters.",
    "effect": "local"
   },
   "#zuLast": {
    "what": "The new user's last name.",
    "input": "Optional. Up to 255 characters.",
    "effect": "local"
   },
   "#zuEnable": {
    "what": "Turns the new user on when it is made. Off by default, so the user is created disabled.",
    "input": "Tick it to enable the user at once.",
    "effect": "local"
   },
   "input[name=\"zkAct\"]": {
    "what": "Picks what to do: rotate a secret, disable, enable or delete an API client, or make a new one.",
    "input": "Tick one. The form below changes to match.",
    "effect": "local"
   },
   "input[name=\"zkPick\"]": {
    "what": "Picks this API client. The client this app signs in with cannot be picked.",
    "input": "Tick one.",
    "effect": "local"
   },
   "#zkKeepOld": {
    "what": "Keeps the old secrets when the new one is made, so tools keep working until you delete them.",
    "input": "Tick it to keep them. Off by default: the old secrets are deleted once the new one exists.",
    "effect": "local"
   },
   "#zkName": {
    "what": "Names the new API client.",
    "input": "Required. Up to 128 letters, digits, spaces and . _ ( ) -, like Reporting export.",
    "effect": "local"
   },
   "#zkDesc": {
    "what": "Describes the new API client.",
    "input": "Optional. Up to 500 characters.",
    "effect": "local"
   },
   "#zkLife": {
    "what": "How long each access token of the new client lasts, in seconds.",
    "input": "Required. 300 to 86400 seconds; 3600 is one hour.",
    "effect": "local"
   },
   "input[data-zk-scope]": {
    "what": "Gives the new API client this scope. Tick only what the tool needs.",
    "input": "Tick one or more. A full-access scope is flagged.",
    "effect": "local"
   },
   "#zkEnable": {
    "what": "Turns the new API client on when it is made. Off by default.",
    "input": "Tick it to enable the client at once.",
    "effect": "local"
   },
   ".zk-secret": {
    "what": "Shows the new secret once. This app never keeps, logs or exports it.",
    "input": "Nothing to type. Copy it now.",
    "effect": "local"
   },
   ".zk-copy": {
    "what": "Copies the new secret to the clipboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "input[name=\"zwaMode\"]": {
    "what": "Chooses which incidents to close: every open incident of the rule or destination Detection health sent, or the ones you pick below.",
    "input": "Pick one. The first choice shows only when you came from Detection health.",
    "effect": "local"
   },
   "input[data-zwa]": {
    "what": "Picks this open incident to close as a false positive.",
    "input": "Tick it to include the incident, untick it to leave it out. At most 100 incidents per change.",
    "effect": "local"
   },
   "#zwaNote": {
    "what": "A reason added to the note on each closed incident, after your name as the assessor.",
    "input": "Optional. Plain words, up to 300 characters, like Telemetry upload, not customer data.",
    "effect": "local"
   },
   "#zidGroup": {
    "what": "Picks the ZIdentity group to add people to or remove them from. A dynamic group cannot be picked.",
    "input": "Pick one. Each shows its member count, never its members.",
    "effect": "local"
   },
   "#zidAdd": {
    "what": "The people to add to the group, by sign-in name.",
    "input": "Optional. One per line or comma separated, at most 50, like jane.doe@example.com.",
    "effect": "local"
   },
   "#zidRemove": {
    "what": "The people to remove from the group, by sign-in name.",
    "input": "Optional. One per line or comma separated, at most 50, like jane.doe@example.com.",
    "effect": "local"
   },
   "select[data-zl]": {
    "what": "Says whether to turn this app profile on or off. Devices get the change at once.",
    "input": "Pick on, off, or leave as it is. You type the profile's name to confirm.",
    "effect": "local"
   },
   "#zlProfile": {
    "what": "Picks the app profile whose DNS and tunnel settings to change.",
    "input": "Pick one.",
    "effect": "local"
   },
   "select[data-zs]": {
    "what": "Sets this DNS or tunnel setting of the app profile.",
    "input": "Pick on, off, or leave as it is.",
    "effect": "local"
   },
   "input[data-zs]": {
    "what": "The packet tunnel exclusions: addresses that leave the device outside the tunnel, uninspected.",
    "input": "Optional. Addresses, ranges or host names, comma separated, like 10.0.0.0/8. Leave empty to keep it.",
    "effect": "local"
   }
  },
  "/report/path": {
   "a[href=\"/reference/data-security-architect#inline\"]": {
    "what": "Data Security Architect: the reference architecture this flow is measured against (inline web module; opens in a new tab).",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "a[href=\"/report/motion#path\"]": {
    "what": "Flow animator: replay this result hop by hop, with what happens inside DLP (opens in a new tab).",
    "input": "Nothing to type. Analyze a destination first to replay your own result; otherwise it shows a sample.",
    "effect": "nav"
   },
   "#paDest": {
    "what": "Sets the place the traffic goes to. The analyzer walks the path to it step by step.",
    "input": "Required. A URL, a host name or an IP address, like drive.google.com/drive, dropbox.com or 203.0.113.10. Press Enter to analyze.",
    "effect": "local"
   },
   "#paSource": {
    "what": "Picks where the traffic comes from: a user device or a workload (a server behind a Cloud or Branch Connector).",
    "input": "Pick one: A user device or A workload. A workload shows its own fields (source IP, tags, groups).",
    "effect": "local"
   },
   "#paNet": {
    "what": "Picks the network the device is on. This changes which forwarding rules apply.",
    "input": "Pick one: Off network (remote), On trusted network (office) or On VPN. Also used by Test a list.",
    "effect": "local"
   },
   "#paPlat": {
    "what": "Picks the device platform. This picks the Client Connector app profile to use.",
    "input": "Pick one: windows, macos, ios, android or linux. Also used by Test a list.",
    "effect": "local"
   },
   "#paProto": {
    "what": "Picks the protocol of the traffic. Use it to trace traffic that is not web, like QUIC or SSH.",
    "input": "Optional. From the URL (default), TCP or UDP.",
    "effect": "local"
   },
   "#paPort": {
    "what": "Sets the destination port. The hint beside it names well-known ports, like 22 for SSH.",
    "input": "Optional. A number from 1 to 65535, like 443. Leave it empty to take the port from the URL.",
    "effect": "local"
   },
   "#paTenant": {
    "what": "Picks which tenant sign-in to use: the assessment tab, a saved tenant profile, or the one saved on this computer.",
    "input": "Pick one from the list. It shows only when there is more than one choice.",
    "effect": "local"
   },
   "#paRun": {
    "what": "Reads the tenant and walks the traffic to the destination step by step. It shows where the traffic stops and why.",
    "input": "Type a destination first. The first run reads the tenant (about a minute); later runs reuse that read. Nothing is written.",
    "effect": "read"
   },
   "#paFresh": {
    "what": "Read the tenant again before analyzing (otherwise the last read is reused). Click again to turn it off.",
    "input": "Nothing to type. Click it, then click Analyze.",
    "effect": "local"
   },
   "#expJson": {
    "what": "Saves the whole result of this analysis as a JSON file.",
    "input": "Nothing to type. Analyze a destination first.",
    "effect": "download"
   },
   "#paHarBtn": {
    "what": "Analyze every host a browser HAR file names. The file is read in this browser. Only host names, request counts, HTTP methods, schemes and upload amounts are sent. Cookies, headers, URL paths and bodies stay in this browser.",
    "input": "Nothing to type. Click it and choose a .har or .json file, up to 100 MB. Up to 200 hosts per run.",
    "effect": "local"
   },
   "#paHar": {
    "what": "Chooses the HAR file to read. The file stays in this browser.",
    "input": "A HAR file (.har or .json) saved from the browser developer tools, Network tab. Up to 100 MB.",
    "effect": "local"
   },
   "#paWlIp": {
    "what": "Sets the source IP address of the workload.",
    "input": "Required for a workload. An IP address, like 10.1.2.3.",
    "effect": "local"
   },
   "#paWlTags": {
    "what": "Sets the tags of the workload. Tags can put it in a workload group.",
    "input": "Optional. key=value pairs, comma separated, optionally with a type, like VPC: Vpc-id=vpc-123, Env=prod. Up to 2000 characters.",
    "effect": "local"
   },
   "#paWlGroup": {
    "what": "Sets the workload group, if you know it.",
    "input": "Optional. A workload group name, up to 200 characters.",
    "effect": "local"
   },
   "#paWlEc": {
    "what": "Sets the Cloud or Branch Connector group the workload sits behind.",
    "input": "Optional. A connector group name, up to 200 characters.",
    "effect": "local"
   },
   "#tab-one": {
    "what": "Shows the view for one destination or a HAR file.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-list": {
    "what": "Shows the Test a list view. Test many destinations at once.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#tab-cat": {
    "what": "Shows the Category lookup view. See a destination's ZIA categories and every rule that names them.",
    "input": "Nothing to type. Just click it. Arrow keys move between the tabs.",
    "effect": "local"
   },
   "#clText": {
    "what": "Sets what to look up: destinations or categories, one per line.",
    "input": "Required. Up to 25 lines: a URL, host name or IP address (dropbox.com, 203.0.113.10), a category id (GAMBLING, CUSTOM_01) or category: and its name (category:Partner portals). Ctrl+Enter looks up.",
    "effect": "local"
   },
   "#clRun": {
    "what": "Asks ZIA's URL lookup for each destination's categories and lists every rule that names each category, in evaluation order, with order, rank and action.",
    "input": "Type at least one entry first. The first lookup reads the policies in scope (a few seconds to a minute); later ones reuse that read. Nothing is written.",
    "effect": "read"
   },
   "#clFresh": {
    "what": "Read the tenant again before the next lookup (otherwise the last read is reused). Click again to turn it off.",
    "input": "Nothing to type. Click it, then click Look up.",
    "effect": "local"
   },
   "#paWhatIf > summary": {
    "what": "Opens or closes the what-if fields. Use them to check rules for one user, group, department or location, or a ZPA identity.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paWi_user": {
    "what": "Sets the user to check rules for. Rules for this user apply; rules for others are skipped.",
    "input": "Optional. An email or display name, like jane@acme.com. Up to 200 characters.",
    "effect": "local"
   },
   "#paWi_group": {
    "what": "Sets the groups to check rules for. They are taken as the user's only groups.",
    "input": "Optional. One or more group names, separated by commas. Up to 200 characters.",
    "effect": "local"
   },
   "#paWi_department": {
    "what": "Sets the department to check rules for.",
    "input": "Optional. A department name, like Finance. Up to 200 characters.",
    "effect": "local"
   },
   "#paWi_location": {
    "what": "Sets the location to check rules for.",
    "input": "Optional. A location name, like HQ office. Up to 200 characters.",
    "effect": "local"
   },
   "#paWhatIf button[data-wi-find]": {
    "what": "Searches ZIA for names that match what you typed. One search of at most 20 names; nothing else is read.",
    "input": "Type at least 2 characters in the field beside it first. Needs ZIA platform ticked on the Scope page.",
    "effect": "read"
   },
   "#paWhatIf button[data-wi-pick]": {
    "what": "Picks this match and fills it in. A user also brings their department and groups.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paWiZ_idp": {
    "what": "Picks the IdP the user signs in with, for ZPA's access policy. Conditions of other IdPs are then not met.",
    "input": "Optional. Click Load IdPs from ZPA first, then pick one, or leave Not given.",
    "effect": "local"
   },
   "#paWiZ_load": {
    "what": "Reads the tenant's IdPs and SAML attribute names from ZPA, to pick from. It only reads.",
    "input": "Nothing to type. Needs ZPA ticked on the Scope page.",
    "effect": "read"
   },
   "#paWiZ_user": {
    "what": "Sets the SCIM user name whose SCIM groups ZPA looks up during the analysis. They are kept only for that analysis.",
    "input": "Optional. Usually the email, like jane@acme.com. Up to 128 characters. Needs the IdP.",
    "effect": "local"
   },
   "#paWiZ_find": {
    "what": "Shows the SCIM groups ZPA lists for this user in the IdP you picked, before you analyze. It only reads.",
    "input": "Pick the IdP and type the SCIM user name first. Needs ZPA ticked on the Scope page.",
    "effect": "read"
   },
   "#paWiZ_attrs": {
    "what": "Sets SAML or SCIM attribute values for ZPA's access policy, matched by attribute name. Attributes you leave out stay unknown.",
    "input": "Optional. One Name=value per line, like Department=Finance. At most 20.",
    "effect": "local"
   },
   "#paDevice > summary": {
    "what": "Opens or closes the device fields. Use them to trace one user's enrolled device instead of a platform.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paDevQ": {
    "what": "Sets the user whose enrolled devices to look up in the Client Connector Portal.",
    "input": "Optional. The user's sign-in name or part of it, like jane@acme.com or jane. 2 to 128 characters. Press Enter to find devices.",
    "effect": "local"
   },
   "#paDevFind": {
    "what": "Asks the Client Connector Portal once for this user's enrolled devices, at most 20. Nothing else is read.",
    "input": "Type at least 2 characters in the field beside it first. Needs Client Connector (ZCC) ticked on the Scope page and a OneAPI sign-in.",
    "effect": "read"
   },
   "#paDevice button[data-dev-pick]": {
    "what": "Uses this device for the trace: its platform, the app profile the Portal reports for it and its details. Reads this one device's details.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#paDevClear": {
    "what": "Stops using the picked device. The Platform you choose applies again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paCompare > summary": {
    "what": "Opens or closes Compare two identities: the same destination for A and B, step by step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paCmp_user": {
    "what": "Sets the user of identity B. Rules for this user apply to B; rules for others are skipped.",
    "input": "Optional. An email or display name, like sam@acme.com. Up to 200 characters.",
    "effect": "local"
   },
   "#paCmp_group": {
    "what": "Sets the groups of identity B. They are taken as B's only groups.",
    "input": "Optional. One or more group names, separated by commas. Up to 200 characters.",
    "effect": "local"
   },
   "#paCmp_department": {
    "what": "Sets the department of identity B.",
    "input": "Optional. A department name, like Engineering. Up to 200 characters.",
    "effect": "local"
   },
   "#paCmp_location": {
    "what": "Sets the location of identity B.",
    "input": "Optional. A location name, like Branch office. Up to 200 characters.",
    "effect": "local"
   },
   "#paCmpDevQ": {
    "what": "Sets the user whose enrolled devices to look up for identity B.",
    "input": "Optional. The user's sign-in name or part of it. 2 to 128 characters. Press Enter to find devices.",
    "effect": "local"
   },
   "#paCmpDevFind": {
    "what": "Asks the Client Connector Portal once for this user's enrolled devices, for identity B. At most 20; nothing else is read.",
    "input": "Type at least 2 characters in the field beside it first. Needs Client Connector (ZCC) ticked on the Scope page and a OneAPI sign-in.",
    "effect": "read"
   },
   "#paCompare button[data-dev-pick]": {
    "what": "Uses this device for identity B. Reads this one device's details.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#paCmpDevClear": {
    "what": "Stops using the picked device for identity B.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paCmpRun": {
    "what": "Analyzes the destination for A (the what-if and device above) and B (this panel) on one tenant read and shows each step side by side. Nothing is written.",
    "input": "Type a destination in the bar above first. Give B at least one name or a device to see a difference.",
    "effect": "read"
   },
   "#paCmpStop": {
    "what": "Stops the comparison. Nothing more is read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paCmpCsv": {
    "what": "Saves the comparison, step by step for A and B, as a CSV file.",
    "input": "Nothing to type. Compare first.",
    "effect": "download"
   },
   "#paCmpJson": {
    "what": "Saves the comparison, step by step for A and B, as a JSON file.",
    "input": "Nothing to type. Compare first.",
    "effect": "download"
   },
   "#paProbePort": {
    "what": "Picks the port Test from here connects to. Only web and TLS ports are allowed.",
    "input": "Pick one: From the URL (443, or 80 for http://), 443, 80 (connect only), 8443 or 8080.",
    "effect": "local"
   },
   "#paProbeRun": {
    "what": "Tests this destination from the computer running this app (in Docker, from the container). It looks the name up, connects and shakes hands over TLS. Then it compares the certificate with the prediction. It sends no request, data or credentials and keeps nothing.",
    "input": "Nothing to type. Analyze a destination first. At most 6 tests a minute.",
    "effect": "read"
   },
   "#paFramework > summary": {
    "what": "Opens or closes the framework: the order Zscaler checks a policy in, from the device to the incident.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paFrameworkBody g.df-node": {
    "what": "Jumps to the text for this stage of the framework, below the picture.",
    "input": "Nothing to type. Click it, or press Enter on it.",
    "effect": "local"
   },
   "#paFlowRef button.tp-play": {
    "what": "Pauses or plays the moving packets in the picture.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paFlowRef details.tp-alt > summary": {
    "what": "Opens or closes the reference path written out in words, step by step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paStop": {
    "what": "Stops the analysis that is running. Nothing more is read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paFlowHost [role=\"button\"]": {
    "what": "Opens the card for this step of the path, further down the page.",
    "input": "Nothing to type. Click it, or press Enter on it.",
    "effect": "local"
   },
   "#paFlowHost button.tp-play": {
    "what": "Pauses or plays the packets moving along this path.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paFlowHost details.tp-alt > summary": {
    "what": "Opens or closes this path written out in words, step by step.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-flow-view=\"path\"]": {
    "what": "Shows the picture with every step: ZPA, the PAC file and every ZIA module.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-flow-view=\"hops\"]": {
    "what": "Shows the picture hop by hop, up to Web DLP.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paHopPlay": {
    "what": "Plays the hop-by-hop picture from the start.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paHopStep": {
    "what": "Moves the hop-by-hop picture one hop forward.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paWiMore": {
    "what": "Shows or hides more rules that could change the policy action.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paBody details.pm-more > summary": {
    "what": "Opens or closes more detail about the rules of this step: rules that also match, or rules that could apply first.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paBody g.df-node": {
    "what": "Jumps to the card for this control in The path, hop by hop.",
    "input": "Nothing to type. Click it, or press Enter on it.",
    "effect": "local"
   },
   "#paBody a[href=\"/report/insights\"]": {
    "what": "Opens the Traffic insights page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#paBody details.pa-details > summary": {
    "what": "Opens or closes the log of what was read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paHarGo": {
    "what": "Reads the tenant once and traces every host from the HAR file. Only host names, request counts, HTTP methods, schemes and upload amounts are sent. Cookies, headers, URL paths and bodies stay in this browser.",
    "input": "Nothing to type. Choose a HAR file first. Nothing is written to the tenant.",
    "effect": "read"
   },
   ".pa-har-cap summary": {
    "what": "Opens or closes the list of hosts left out of this run.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paHarQ": {
    "what": "Filters the host table as you type.",
    "input": "Optional. Any text from a host, rule or stop, like dropbox.",
    "effect": "local"
   },
   "#paHarO": {
    "what": "Shows only hosts with one outcome.",
    "input": "Pick one outcome, or Every outcome.",
    "effect": "local"
   },
   "#paHarU": {
    "what": "Shows only hosts that received uploads.",
    "input": "Tick it to hide hosts with no uploads.",
    "effect": "local"
   },
   "#paHarCsv": {
    "what": "Saves the HAR results as a CSV file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#paHarJson": {
    "what": "Saves the HAR results as a JSON file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "button.pa-har-sort": {
    "what": "Sorts the host table by this column. Click again to flip the order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.pa-har-host": {
    "what": "Shows the full analysis for this host.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paHarBack": {
    "what": "Goes back to the table of HAR results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#plFile": {
    "what": "Chooses a CSV file with the list to test. The file is read in this browser.",
    "input": "Optional. A .csv or .txt file up to 8 MB and 250,000 rows. One destination per line. While a file is chosen, the pasted text is ignored.",
    "effect": "local"
   },
   "#plText": {
    "what": "Holds the list to test, if you paste it instead of choosing a file.",
    "input": "Optional. One destination per line: an IP, a CIDR block (up to a /16), a range, a host name or a URL. A first line with column names lets you add port, protocol, expected and more.",
    "effect": "local"
   },
   "#plLookup": {
    "what": "Asks ZIA which categories each destination is in.",
    "input": "Ticked: ZIA looks the destinations up. Unticked: only the tenant's own custom categories and your file are used.",
    "effect": "local"
   },
   "#plMax": {
    "what": "Sets the most lookup requests to send to ZIA. Each request holds 100 destinations.",
    "input": "Required. A whole number from 1 to 2500. Default 400. ZIA allows about 400 an hour.",
    "effect": "local"
   },
   "#plRun": {
    "what": "Reads the tenant and tests every destination in the list. It shows which are blocked, allowed or sent around Zscaler.",
    "input": "Choose a CSV file or paste the list first. Network, Platform and Tenant from the bar apply. Nothing is written.",
    "effect": "read"
   },
   "#plStop": {
    "what": "Stops the list test that is running.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#plFlowHost button.lf-play": {
    "what": "Pauses or plays the moving rows in the picture.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#plBody a[href*=\"/export?format=\"]": {
    "what": "Saves the tested rows as a file: all rows, the flagged rows or the rows not as expected, as CSV or Excel.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#plBody input.pl-pick": {
    "what": "Picks this row for Fix selected.",
    "input": "Tick it to include this row.",
    "effect": "local"
   },
   "#plPurpose": {
    "what": "Sets what the picked rows should be when the list has no expected column. A row with an expected result is fixed for that.",
    "input": "Pick one: Blocked or Allowed.",
    "effect": "local"
   },
   "#plFix": {
    "what": "Opens Bulk changes in a new tab with the picked rows filled in. Each row is fixed for what it was expected to do: in a URL category, an IP destination group with a rule, or an ATP list. Nothing is written until you preview it and apply it there in write mode.",
    "input": "Pick at least one row first. Needs what each row's fix changes in scope on the Scope page.",
    "effect": "nav"
   },
   "#plBody button.pl-cat": {
    "what": "Opens Category lookup with this row's destination and looks it up: its ZIA categories and every rule that names them, in evaluation order.",
    "input": "Nothing to type. Just click it. The first lookup reads the policies in scope; later ones reuse that read. Nothing is written.",
    "effect": "read"
   },
   "#plBody button[data-list]": {
    "what": "Shows or hides this list of destinations, one per line, ready to copy.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#plBody a[href*=\"/list?area=\"]": {
    "what": "Saves this list of destinations as a text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#plBody button[data-fixarea]": {
    "what": "Opens Bulk changes in a new tab with this list filled in. It goes into a URL category, an IP destination group with a rule, or an ATP list. Nothing is written there until you apply it.",
    "input": "Nothing to type. Needs that area in scope on the Scope page.",
    "effect": "nav"
   },
   "#plBody textarea[id^=\"plList\"]": {
    "what": "Shows the destinations of this list, one per line. Copy them into the place named beside it.",
    "input": "Read-only. Select the text and copy it.",
    "effect": "local"
   },
   "#plFixInfo a": {
    "what": "Opens Bulk changes in a new tab. Use it when your browser blocked the tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#plBody details.pa-details > summary": {
    "what": "Opens or closes the assumptions or the log of what was done.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#paBody > details > summary": {
    "what": "Opens or closes the list of every app profile, forwarding profile and PAC file read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zdxCp > summary": {
    "what": "Opens the ZDX panel: the cloud path ZDX measured to an application, and a score analysis that finds why it is slow.",
    "input": "Nothing to type. Click it to open or close the panel.",
    "effect": "local"
   },
   "#zdxCpLoad": {
    "what": "Reads the applications ZDX monitored in the last day and picks the one that matches the destination. It only reads.",
    "input": "Nothing to type. Needs ZDX ticked on the Scope page.",
    "effect": "read"
   },
   "#zdxCpApp": {
    "what": "Picks the ZDX application whose measured path to show or to analyse.",
    "input": "Pick one. Load the applications first.",
    "effect": "local"
   },
   "#zdxCpShow": {
    "what": "Reads the cloud path ZDX measured to the application, leg by leg: time, loss, hops and tunnel. No device or person is named.",
    "input": "Pick an application first. It only reads.",
    "effect": "read"
   },
   "#zdxRcaDev": {
    "what": "The ZDX device to analyse. Leave it empty and the app picks a device that probes the application.",
    "input": "Optional. Digits only, as the ZDX Admin Portal shows them, like 132559212.",
    "effect": "local"
   },
   "#zdxRcaHours": {
    "what": "How far back the score analysis looks.",
    "input": "Pick 1, 2, 4, 8 or 24 hours. 2 hours is the default.",
    "effect": "local"
   },
   "#zdxRcaWho": {
    "what": "The assessor's name, kept with the start in the audit log.",
    "input": "Required to start or stop. Your name, like Jane Doe.",
    "effect": "local"
   },
   "#zdxRcaPhrase": {
    "what": "Confirms that you mean to start a score analysis on the tenant.",
    "input": "Required. Type START ANALYSIS.",
    "effect": "local"
   },
   "#zdxRcaStart": {
    "what": "Asks ZDX to analyse the application on one device. It changes no setting, but it is an action on the tenant.",
    "input": "Needs write mode, your permission to change the tenant, the assessor's name and START ANALYSIS. One start per tenant every 5 minutes.",
    "effect": "write"
   },
   "#zdxRcaStatus": {
    "what": "Reads what ZDX found in the analysis so far.",
    "input": "Nothing to type. Start an analysis first. It only reads.",
    "effect": "read"
   },
   "#zdxRcaStop": {
    "what": "Stops the running score analysis in ZDX.",
    "input": "Needs write mode, your permission to change the tenant and the assessor's name.",
    "effect": "write"
   }
  },
  "/report/posture": {
   "#ppRefresh": {
    "what": "Takes the latest results from the assessment tab again and redraws this page. Nothing is read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#ppJson": {
    "what": "Saves everything on this page as a JSON file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#ppFixes input[data-pick]": {
    "what": "Counts this fix in the projected score below.",
    "input": "Tick it to add the fix to the projection. Untick it to take it out.",
    "effect": "local"
   },
   "#ppFixes button[data-fix]": {
    "what": "Opens the one-click fix for this check in Review & remediate, on the assessment tab.",
    "input": "Nothing to type. Open this page from the assessment tab to use the one-click fix.",
    "effect": "nav"
   },
   "#ppFixes a.rp-btn[target=\"_blank\"]": {
    "what": "Opens Zscaler's guidance for this fix in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#ppFixes summary": {
    "what": "Opens or closes the steps to fix this check.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#ppQueue": {
    "what": "Counts fixes already waiting in the change queue in the projected score.",
    "input": "Ticked counts them. Untick it to leave the queue out.",
    "effect": "local"
   },
   "#ppQueueTenant": {
    "what": "Picks whose change queue requests to count.",
    "input": "Pick a tenant when the queue holds requests for more than one.",
    "effect": "local"
   },
   "#ppTrend summary": {
    "what": "Opens or closes a table of every saved run.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#ppPoints": {
    "what": "Sets how big a score drop raises an alert.",
    "input": "Required. A whole number of points from 1 to 100, like 5.",
    "effect": "local"
   },
   "#ppNotify": {
    "what": "Also sends a score-drop alert by e-mail or webhook through the digest.",
    "input": "Tick it to send alerts. It works only if digest notifications are set up.",
    "effect": "local"
   },
   "#ppSettings button[type=\"submit\"]": {
    "what": "Saves the alert settings in this app.",
    "input": "Set the points first.",
    "effect": "local"
   },
   ".pp-words summary": {
    "what": "Opens or closes short meanings of the words on this page.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/plugin": {
   "a.rp-btn[href=\"/report/advanced#plugins\"]": {
    "what": "Opens Advanced settings at Local plugins, where plugins are switched on, approved and revoked.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/pov": {
   "a.skip-link[href=\"#main-content\"]": {
    "what": "Skips straight to the POV planner. Handy if you use the keyboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvProfile": {
    "what": "Picks the tenant profile the POV belongs to. Each tenant profile has its own POV.",
    "input": "Required. Pick a saved tenant profile from the list.",
    "effect": "local"
   },
   "#pvReload": {
    "what": "Loads the POV of this tenant profile again from this computer. Use it if another tab saved changes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tab-plan": {
    "what": "Shows the plan: the intake, the status, the success criteria and the timeline.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-build": {
    "what": "Shows the Build tab: one plan of the builders this POV needs, one dry run and one confirmed apply.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-runbook": {
    "what": "Shows the tests for each product in scope. Mark each one pass or fail, with notes and evidence.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-kit": {
    "what": "Shows the test kit: safe test files and test links to run the tests with.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-notes": {
    "what": "Shows the follow-ups and your notes for this POV.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-report": {
    "what": "Shows the customer report, export, import, templates and delete.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#pvBuild form.pv-form input[maxlength=\"120\"]": {
    "what": "Sets the customer name for the rehearsal. It is kept in this page only.",
    "input": "Required. Up to 120 characters, like Contoso Health.",
    "effect": "local"
   },
   "#pvBuild form.pv-form input[placeholder=\"corp.example.com\"]": {
    "what": "Sets the internal domain the ZPA segments and the ZDX intranet probe are made under.",
    "input": "Optional. A domain name, like corp.example.com.",
    "effect": "local"
   },
   "#pvBuild form.pv-form input[placeholder=\"Made from the name\"]": {
    "what": "Sets the short prefix every built object is named with.",
    "input": "Optional. 2 to 8 letters or digits, like CH.",
    "effect": "local"
   },
   "#pvBuild form.pv-form select:has(+ p.pv-meta)": {
    "what": "Picks the vertical preset. It decides the builders' defaults, like the ZIA tier and the compliance overlays.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#pvBuild form.pv-form select": {
    "what": "Starts the rehearsal from a saved template's vertical and products.",
    "input": "Optional. Pick a template, or No template.",
    "effect": "local"
   },
   "#pvBuild form.pv-form fieldset.pv-checks input[type=\"checkbox\"]": {
    "what": "Puts this product in the rehearsal. The build suggests the parts for the products ticked.",
    "input": "Tick it to include the product.",
    "effect": "local"
   },
   "#pvBuild form.pv-form button[type=\"submit\"]": {
    "what": "Uses this intake for the rehearsal and lists the parts it suggests. Nothing is read or written yet.",
    "input": "Fill in the customer name first.",
    "effect": "local"
   },
   "#pvBuild input.pb-on": {
    "what": "Puts this part in the build. A part whose product is not ticked on the Scope page cannot be picked.",
    "input": "Tick it to build the part. Untick it to leave it out.",
    "effect": "local"
   },
   "#pvBuild select.pb-tier": {
    "what": "Picks the ZIA security baseline tier: Strict, Balanced, Permissive or Healthcare zero trust.",
    "input": "Pick one from the list. The vertical preset picks it first.",
    "effect": "local"
   },
   "#pvBuild input.pb-enable": {
    "what": "Creates the new rules or segments enabled instead of disabled. Off by default: nothing changes for users until you turn them on.",
    "input": "Tick it only if the customer agreed to enforce now.",
    "effect": "local"
   },
   "#pvBuild select.pb-platform": {
    "what": "Picks the platform the Client Connector app profile is for.",
    "input": "Pick Windows or macOS.",
    "effect": "local"
   },
   "#pvBuild select.pb-mode": {
    "what": "Picks what the AI Guard detection policy does: Monitor only detects, Block stops the prompt.",
    "input": "Pick Monitor (the default) or Block.",
    "effect": "local"
   },
   "#pvBuild button.pb-choices": {
    "what": "Reads the certificates and rules this part can pick from. It changes nothing.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#pvBuild select.pb-cert": {
    "what": "Picks the certificate this part uses.",
    "input": "Pick one from the list. Load the choices from the tenant first.",
    "effect": "local"
   },
   "#pvBuild input.pb-rule": {
    "what": "Picks an SSL Inspect rule to move to the picked certificate.",
    "input": "Tick each rule to move.",
    "effect": "local"
   },
   "#pvBuild details.pb-json > summary": {
    "what": "Shows the part exactly as it is sent, to change any option the form does not show.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvBuild textarea.pb-json-text": {
    "what": "The part as it is sent to its builder. Every builder checks it again when it plans.",
    "input": "Optional. A JSON object; leave it as it is unless you know the option.",
    "effect": "local"
   },
   "#pbPreview": {
    "what": "Plans every ticked part as one dry run: a section per product, every object before and after, one plan hash. Nothing is written.",
    "input": "Tick at least one part first.",
    "effect": "read"
   },
   "#pvBuild details.pb-prev-part > summary": {
    "what": "Shows or hides every object this part changes, with its value before and after.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pbAssessor": {
    "what": "Names the assessor. Every change record and every object the build creates names them.",
    "input": "Required to apply. A name, like Jane Doe, Zscaler DS Engineer.",
    "effect": "local"
   },
   "#pbPhrase": {
    "what": "Confirms the whole build with one phrase.",
    "input": "Type the phrase shown, like APPLY 12 POV CHANGES.",
    "effect": "confirm"
   },
   "#pbAgree": {
    "what": "Says you reviewed the dry run and the customer agreed to it.",
    "input": "Tick it to allow Apply.",
    "effect": "local"
   },
   "#pbGo": {
    "what": "Applies every part in order, each read again right before it is written, read back and recorded with its Undo. Stops at the first part that does not apply.",
    "input": "Needs write mode on, a named assessor, the review box and the typed phrase.",
    "effect": "write"
   },
   "#pvBuild button.pb-key": {
    "what": "Shows the provisioning key the build just created for the App Connectors. It is shown once and never kept by this app.",
    "input": "Nothing to type. Just click it, then copy the key.",
    "effect": "local"
   },
   "#pvBuild input.pb-key-value": {
    "what": "The new provisioning key, to enroll the App Connectors with. Copy it now: it is not shown again.",
    "input": "Read only. Select it and copy it.",
    "effect": "local"
   },
   "#pvBuild button.pb-undo-build": {
    "what": "Plans the Undo of what this build applied, latest part first, as one dry run. Nothing is written until you confirm it.",
    "input": "Nothing to type. Just click it.",
    "effect": "read"
   },
   "#pvPlan details.pv-sec > summary": {
    "what": "Shows or hides the intake form, so you can change it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvPlan form.pv-form input[maxlength=\"120\"]": {
    "what": "Sets the customer name. The report and the file names use it.",
    "input": "Required. Up to 120 characters, like Contoso Health.",
    "effect": "local"
   },
   "#pvPlan form.pv-form input[placeholder=\"corp.example.com\"]": {
    "what": "Sets the customer's internal domain.",
    "input": "Optional. A domain name, like corp.example.com.",
    "effect": "local"
   },
   "#pvPlan form.pv-form input[placeholder=\"Made from the name\"]": {
    "what": "Sets a short prefix that names the POV objects. It is made from the customer name until you change it.",
    "input": "Optional. 2 to 8 letters or digits, like CH.",
    "effect": "local"
   },
   "#pvPlan form.pv-form select[data-pv-compliance]": {
    "what": "Picks the POV's compliance profile, like FedRAMP Moderate. The vertical preset picks one. It drives the compliance pack on the Test kit tab.",
    "input": "Optional. Pick a profile, or None.",
    "effect": "local"
   },
   "#pvPlan form.pv-form select:has(+ p.pv-meta)": {
    "what": "Picks the vertical preset, like Healthcare. It fills in the products and suggested success criteria.",
    "input": "Pick one from the list. You can change the products after.",
    "effect": "local"
   },
   "#pvPlan form.pv-form select": {
    "what": "Starts the new POV from a saved template: its vertical, products and success criteria.",
    "input": "Optional. Pick a template, or No template.",
    "effect": "local"
   },
   "#pvPlan form.pv-form fieldset.pv-checks input[type=\"checkbox\"]": {
    "what": "Puts this product in the POV. Its tests show on the Runbook tab.",
    "input": "Tick it to test this product. Untick it to leave it out.",
    "effect": "local"
   },
   "#pvPlan details.pv-sec form.pv-form button[type=\"submit\"]": {
    "what": "Saves the changed intake to the POV on this computer.",
    "input": "Fill in the customer name first.",
    "effect": "local"
   },
   "#pvPlan form.pv-form button[type=\"submit\"]": {
    "what": "Starts the POV for this tenant profile from the intake. It is kept on this computer.",
    "input": "Fill in the customer name first. The rest is optional.",
    "effect": "local"
   },
   "#pvPlan select[aria-label=\"POV status\"]": {
    "what": "Sets where the POV stands: planning, testing, wrapping up or closed. It saves at once.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#pvPlan select[aria-label^=\"Status of: \"]": {
    "what": "Sets whether this success criterion is met. It saves at once.",
    "input": "Pick Pending, Met or Not met.",
    "effect": "local"
   },
   "#pvPlan .pv-list summary.pv-meta": {
    "what": "Shows or hides the tests that prove this success criterion.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvPlan .pv-list fieldset.pv-checks input[type=\"checkbox\"]": {
    "what": "Links this test to the success criterion. The report shows the test's result under it.",
    "input": "Tick it to link the test. Untick it to unlink.",
    "effect": "local"
   },
   "#pvPlan button[aria-label^=\"Remove the criterion\"]": {
    "what": "Removes this success criterion from the POV.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvPlan input[placeholder^=\"For example: card numbers\"]": {
    "what": "Holds a new success criterion: what the customer needs to see.",
    "input": "Required to add one. Up to 300 characters, like: card numbers uploaded to webmail are blocked.",
    "effect": "local"
   },
   "#pvPlan div.pv-form label:has(+ label) input[type=\"date\"]": {
    "what": "Sets the kickoff date of the POV. It saves at once.",
    "input": "Optional. A date.",
    "effect": "local"
   },
   "#pvPlan div.pv-form label + label input[type=\"date\"]": {
    "what": "Sets the date the POV ends. It saves at once.",
    "input": "Optional. A date.",
    "effect": "local"
   },
   "#pvPlan button[aria-label^=\"Remove the check-in\"]": {
    "what": "Removes this check-in from the timeline.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvPlan form.pv-row input[type=\"date\"]": {
    "what": "Sets the date of a new check-in.",
    "input": "Required to add one. A date.",
    "effect": "local"
   },
   "#pvPlan form.pv-row input[placeholder=\"Weekly check-in\"]": {
    "what": "Says what the new check-in is.",
    "input": "Optional. Up to 80 characters, like Weekly check-in.",
    "effect": "local"
   },
   "#pvPlan form.pv-row:has(input[type=\"date\"]) button[type=\"submit\"]": {
    "what": "Adds the check-in to the timeline.",
    "input": "Pick a check-in date first.",
    "effect": "local"
   },
   "#pvPlan form.pv-row button[type=\"submit\"]": {
    "what": "Adds the new success criterion to the POV.",
    "input": "Type the success criterion first.",
    "effect": "local"
   },
   "#pvRunbook select[aria-label=\"Insights time window\"]": {
    "what": "Picks how far back the Insights counts look.",
    "input": "Pick one: last 24 hours, 7 days, 14 days or 30 days.",
    "effect": "local"
   },
   "#pvRunbook .pv-live button": {
    "what": "Stops the read at once. Nothing is recorded.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#pvRunbook .pv-sec > .pv-row > button": {
    "what": "Reads the ZIA Insights counts for the tests and records them on the POV. It changes nothing.",
    "input": "Nothing to type. Just click it. Needs ZIA Insights ticked on the Scope page and a OneAPI API client.",
    "effect": "read"
   },
   "#pvRunbook details.pv-test > summary": {
    "what": "Opens or closes this test: its steps, the expected result, Prove it, the result and the evidence.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvRunbook .pv-test-body > div > .pv-row input[type=\"text\"]": {
    "what": "Sets the place Prove it checks. It starts with the test's own destination.",
    "input": "Required. A web address or host name, like www.example.com.",
    "effect": "local"
   },
   "#pvRunbook .pv-test-body > div > .pv-row button.primary": {
    "what": "Asks the Path analyzer what the tenant's setup does with this destination. The verdict is added as evidence.",
    "input": "Check the destination first. Only what is ticked on the Scope page is read.",
    "effect": "read"
   },
   "#pvRunbook .pv-test-body .pv-form select": {
    "what": "Sets the result of this test. It saves at once.",
    "input": "Pick Not run, Pass, Fail or Skipped.",
    "effect": "local"
   },
   "#pvRunbook .pv-test-body .pv-form textarea": {
    "what": "Holds your notes on this test. They save when you leave the box.",
    "input": "Optional. Up to 2000 characters.",
    "effect": "local"
   },
   "#pvRunbook button[aria-label^=\"Remove the evidence\"]": {
    "what": "Removes this piece of evidence from the test.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvRunbook input[placeholder^=\"Block page named rule\"]": {
    "what": "Holds new evidence: what you saw when you ran the test.",
    "input": "Required to add one. Up to 300 characters, like: Block page named rule \"Block gambling\".",
    "effect": "local"
   },
   "#pvRunbook .pv-test-body > form.pv-row button[type=\"submit\"]": {
    "what": "Adds the evidence to this test.",
    "input": "Type the evidence first.",
    "effect": "local"
   },
   "#pvKit a.rp-btn[href^=\"/api/compliance-pack/\"]": {
    "what": "Saves a file of the compliance pack for this POV's compliance profile. Pick the control mapping, the test plan, the policy export, or all of them.",
    "input": "Nothing to type. Just click it. Local files only: nothing is written to the tenant.",
    "effect": "download"
   },
   "#pvKit a.rp-btn[download]": {
    "what": "Saves this test file on this computer. It is synthetic test data or a harmless test file, never real data.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#pvKit a.pv-ext[href*=\"eicar\"]": {
    "what": "Opens an EICAR antivirus test page or file in a new tab. Open it through ZIA to see it blocked.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#pvKit a.pv-ext": {
    "what": "Opens an AMTSO security features check page in a new tab. Open it through ZIA to test the protection.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#pvNotes .pv-list input[type=\"checkbox\"]": {
    "what": "Marks this follow-up as done. It saves at once.",
    "input": "Tick it when it is done. Untick it to open it again.",
    "effect": "local"
   },
   "#pvNotes button[aria-label^=\"Remove the follow-up\"]": {
    "what": "Removes this follow-up.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvNotes button[aria-label=\"Remove this note\"]": {
    "what": "Removes this note.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvNotes form.pv-row input[maxlength=\"300\"]": {
    "what": "Holds a new follow-up: what you or the customer promised to do.",
    "input": "Required to add one. Up to 300 characters.",
    "effect": "local"
   },
   "#pvNotes form.pv-row input[type=\"date\"]": {
    "what": "Sets when the new follow-up is due.",
    "input": "Optional. A date.",
    "effect": "local"
   },
   "#pvNotes form.pv-row input[maxlength=\"80\"]": {
    "what": "Sets who owns the new follow-up.",
    "input": "Optional. A name, up to 80 characters.",
    "effect": "local"
   },
   "#pvNotes form.pv-row button[type=\"submit\"]": {
    "what": "Adds the follow-up to the POV.",
    "input": "Type the follow-up first.",
    "effect": "local"
   },
   "#pvNotes textarea": {
    "what": "Holds a new note. Notes stay with the POV and are not put in the customer report.",
    "input": "Required to add one. Up to 2000 characters.",
    "effect": "local"
   },
   "#pvNotes form button[type=\"submit\"]": {
    "what": "Adds the note to the POV.",
    "input": "Type the note first.",
    "effect": "local"
   },
   "#pvReport .pv-row > button.primary:has(+ button.primary)": {
    "what": "Saves the customer report as a Word file. It is built from what actually ran. It reads no tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#pvReport .pv-row > button.primary + button.primary": {
    "what": "Saves the customer report as a PDF file. It is built from what actually ran. It reads no tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#pvReport p.pv-meta + .pv-row > button:only-child": {
    "what": "Saves the whole POV as a JSON file, to keep or move to another computer. It holds no secret.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#pvReport input[type=\"file\"]": {
    "what": "Picks an exported POV file to import.",
    "input": "Required to import. A .json file exported from this planner for this same tenant.",
    "effect": "local"
   },
   "#pvReport input[type=\"checkbox\"]": {
    "what": "Lets the import replace this tenant's POV.",
    "input": "Tick it to overwrite the POV that is here now. Leave it off to keep it.",
    "effect": "local"
   },
   "#pvReport .pv-row:has(input[type=\"file\"]) > button": {
    "what": "Imports the chosen POV file. A file made for another tenant is refused.",
    "input": "Choose an exported POV file first.",
    "effect": "local"
   },
   "#pvReport button[aria-label^=\"Delete the template\"]": {
    "what": "Deletes this template from this computer.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#pvReport form.pv-row input[maxlength=\"80\"]": {
    "what": "Sets the name of the new template.",
    "input": "Required. Up to 80 characters, like Healthcare DLP POV.",
    "effect": "local"
   },
   "#pvReport form.pv-row input[maxlength=\"300\"]": {
    "what": "Says what the new template is for.",
    "input": "Optional. Up to 300 characters.",
    "effect": "local"
   },
   "#pvReport form.pv-row button[type=\"submit\"]": {
    "what": "Saves this POV's plan as a template: the vertical, the products and the success criteria. Never the customer or results.",
    "input": "Type a template name first.",
    "effect": "local"
   },
   "#pvReport h2 + .pv-row > button:only-child": {
    "what": "Deletes this POV and everything in it from this computer. The tenant is not changed.",
    "input": "Nothing to type. Click it, then confirm. Export it first to keep a copy.",
    "effect": "local"
   }
  },
  "/report/queue": {
   "#cqTenant": {
    "what": "Shows only the requests of this tenant.",
    "input": "Optional. Pick a tenant, or All tenants.",
    "effect": "local"
   },
   "#cqRefresh": {
    "what": "Loads the change queue again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#cqJson": {
    "what": "Saves the change queue as a JSON file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#cqMd": {
    "what": "Saves the change queue as a Markdown file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#cqXlsx": {
    "what": "Saves the change queue as an Excel file. Requests, items, approvals, comments and history in one workbook.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#cqApplyTenant": {
    "what": "Picks the tenant sign-in Apply uses. Nothing is read until you click Apply.",
    "input": "Pick one: the assessment tab, a saved tenant profile, or what is saved on this computer.",
    "effect": "local"
   },
   "#tab-pending": {
    "what": "Shows the requests waiting for approval.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tab-approved": {
    "what": "Shows the approved requests waiting to be applied.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tab-history": {
    "what": "Shows requests that were rejected, applied, failed, stale or withdrawn.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".cq-req > summary": {
    "what": "Opens or closes the details of this request.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   ".cq-body details > summary": {
    "what": "Shows or hides the history of this request.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "textarea.cq-ta": {
    "what": "Holds your comment on this request.",
    "input": "Optional, but needed to reject. Plain text, up to 1000 characters.",
    "effect": "local"
   },
   "button[data-act=\"approve\"]": {
    "what": "Approves this request, so it can be applied. Another writer approves it when four-eyes is on.",
    "input": "Needs writer rights. Optional comment.",
    "effect": "local"
   },
   "button[data-act=\"reject\"]": {
    "what": "Rejects this request. It moves to History.",
    "input": "Needs writer rights. Type why in the comment box first.",
    "effect": "local"
   },
   "button[data-act=\"apply\"]": {
    "what": "Applies this approved request to the tenant. The plan is checked against the tenant first.",
    "input": "Needs write mode on, writer rights and a named assessor. You type the confirmation phrase.",
    "effect": "write"
   },
   "button[data-act=\"withdraw\"]": {
    "what": "Withdraws your own request. It moves to History and can no longer be approved or applied.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-act=\"comment\"]": {
    "what": "Adds your comment to this request.",
    "input": "Type a comment in the box first.",
    "effect": "local"
   },
   ".cq-job button": {
    "what": "Stops the apply that is running now.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#syNew > summary": {
    "what": "Opens or closes the form for a new sync job.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#syName": {
    "what": "Names the sync job.",
    "input": "Required. Up to 80 characters, like Firewall baseline.",
    "effect": "local"
   },
   "#sySource": {
    "what": "Picks what the targets are kept in step with: a saved tenant profile (with its secret) or a saved snapshot.",
    "input": "Required. Pick one.",
    "effect": "local"
   },
   "#syTargets input": {
    "what": "Adds this tenant profile as a target. Each run plans the change for it and files the plan for approval.",
    "input": "Tick 1 to 10 profiles that remember their secret.",
    "effect": "local"
   },
   "#syGroups input": {
    "what": "Keeps these rules in step: ZIA Cloud Firewall, ZIA URL filtering or the ZPA access policy.",
    "input": "Tick at least one. Each must be in scope on the Scope page.",
    "effect": "local"
   },
   "#syLabel": {
    "what": "Keeps only rules carrying this ZIA rule label in step.",
    "input": "Optional. A rule label name, like Baseline. Not for ZPA.",
    "effect": "local"
   },
   "#syPrefix": {
    "what": "Keeps only rules whose name starts with this text in step.",
    "input": "Optional. Up to 128 characters, like BASE-.",
    "effect": "local"
   },
   "#syInterval": {
    "what": "Sets how often the job runs on its own. Each run only reads and files plans; nothing is applied.",
    "input": "Pick one: only when you click Run now, or every 1, 4, 12, 24 or 168 hours.",
    "effect": "local"
   },
   "#syDeletes": {
    "what": "Also plans deletes of target rules in the selection that the source does not have. Applying such a plan needs DELETE and the count typed, like DELETE 3 RULES.",
    "input": "Optional. Off by default.",
    "effect": "local"
   },
   "#syEnabled": {
    "what": "Creates new rules in the targets enabled. Off, new ZIA rules arrive disabled and new ZPA rules are left out.",
    "input": "Optional. Off by default.",
    "effect": "local"
   },
   "#sySave": {
    "what": "Saves the sync job. Nothing is read until it runs.",
    "input": "Needs writer rights, a name, a source, targets and what to keep in step.",
    "effect": "local"
   },
   "button[data-sy=\"run\"]": {
    "what": "Runs the job now: reads the source and the targets and files one plan per target here for approval. Nothing is written to any tenant.",
    "input": "Needs writer rights. Just click it.",
    "effect": "read"
   },
   "button[data-sy=\"toggle\"]": {
    "what": "Pauses or resumes the job's schedule.",
    "input": "Needs writer rights. Just click it.",
    "effect": "local"
   },
   "button[data-sy=\"delete\"]": {
    "what": "Deletes the job and its history. Requests it filed stay in the queue.",
    "input": "Needs writer rights. You confirm it.",
    "effect": "local"
   },
   ".sy-job details > summary": {
    "what": "Shows or hides the job's runs: when, who started them, each target and what was filed.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/self-heal": {
   "#shRunNow": {
    "what": "Runs the app self-checks now. It fixes what it safely can. It never changes your Zscaler.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#shRefresh": {
    "what": "Loads the app checks and the tenant drift list again. Nothing is read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#appChecks button[data-fix]": {
    "what": "Restarts the app to fix this problem. This page reloads when it is back. Nothing in your Zscaler changes.",
    "input": "Nothing to type. You confirm in a dialog.",
    "effect": "local"
   },
   "#shTenant": {
    "what": "Picks the tenant to look at for drift.",
    "input": "Pick one: the assessment tab, a saved tenant profile, or what is saved on this computer.",
    "effect": "local"
   },
   "#shWho": {
    "what": "Who changed it (reads ZIA's admin audit log; needs Automation readiness on the Scope page)",
    "input": "Tick it to add who changed each setting and when.",
    "effect": "local"
   },
   "#shScan": {
    "what": "Reads the tenant and lists settings that changed since you approved them. Nothing is changed.",
    "input": "Needs DLP in scope on the Scope page. Just click it.",
    "effect": "read"
   },
   "#shStop": {
    "what": "Stops the drift scan. Nothing more is read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#shAll": {
    "what": "Selects every drift that Heal can fix in one click.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#shHealSel": {
    "what": "Heals every selected drift: puts each setting back to what you approved.",
    "input": "Select drifts first. Needs write mode on, writer rights and a named assessor. You type the confirmation phrase.",
    "effect": "write"
   },
   "input.shSel": {
    "what": "Selects this drift for Heal selected.",
    "input": "Tick it to include it.",
    "effect": "local"
   },
   "button[data-act=\"heal\"]": {
    "what": "Puts this setting back to what you approved. It is read again first, and left alone if it moved again.",
    "input": "Needs write mode on, writer rights and a named assessor. You type the confirmation phrase.",
    "effect": "write"
   },
   "button[data-act=\"accept\"]": {
    "what": "Makes the current value the approved one, so the app stops proposing to change it back. Nothing in your Zscaler changes.",
    "input": "Nothing to type. You confirm in a dialog.",
    "effect": "local"
   },
   "button[data-act=\"undo\"]": {
    "what": "Undoes this heal: puts the setting back to the value it had before, then checks it.",
    "input": "Needs write mode on, writer rights and a named assessor. Nothing to type. You confirm in a dialog.",
    "effect": "write"
   },
   "#tenBody details > summary": {
    "what": "Shows or hides earlier drifts that were healed, accepted or back to normal.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a[href=\"/report/queue\"]": {
    "what": "Opens the change queue in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "a[href=\"/report/health\"]": {
    "what": "Opens the proposal queue (FP/TP detection ratio) in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/shadow": {
   "#shMode": {
    "what": "Says how Inline Web DLP picks a rule: first match by rule order, or evaluate all rules.",
    "input": "Pick Read it from the tenant (usual), By rule order, or Evaluate all rules.",
    "effect": "local"
   },
   "#shTenant": {
    "what": "Picks which tenant sign-in to use for the read.",
    "input": "Pick the assessment tab sign-in, a saved tenant profile, or the details saved on this computer.",
    "effect": "local"
   },
   "#shRun": {
    "what": "Reads the rules of every policy in scope and finds rules that can never match or never act. Nothing is written.",
    "input": "Nothing to type. Sign in first, and set the Scope page on the assessment tab.",
    "effect": "read"
   },
   "#shStop": {
    "what": "Stops the read at once.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#expCsv": {
    "what": "Saves the findings as a CSV file for a change request.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves the findings as a JSON data file.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   ".sh-filter button": {
    "what": "Shows only the findings of this severity, or all of them.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#shBody details.pa-details > summary": {
    "what": "Opens or closes the log of what the analysis read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/sslcoverage": {
   "#scTenant": {
    "what": "Picks which tenant to read: the one signed in on the assessment tab, a saved tenant profile, or the one saved on this computer.",
    "input": "Pick one from the list. It shows only when there is more than one choice.",
    "effect": "local"
   },
   "#scWindow": {
    "what": "Picks the time window for the traffic numbers.",
    "input": "Pick one: Last 7 days or Last 30 days.",
    "effect": "local"
   },
   "#scVolume": {
    "what": "Ticked: also asks ZIA Insights how much HTTPS and HTTP traffic was inspected. Unticked: only the rules and bypasses are read.",
    "input": "Optional. Ticked by default. Needs ZIA Insights in scope on the Scope page.",
    "effect": "local"
   },
   "#scRun": {
    "what": "Checks SSL coverage: reads the SSL inspection rules, and Client Connector profiles and PAC files when in scope. Shows the causes and a recovery plan. Read-only.",
    "input": "Nothing to type. Just click it. What it reads follows the Scope page.",
    "effect": "read"
   },
   "#scStop": {
    "what": "Stops the check at once. Nothing more is read from the tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#expXlsx": {
    "what": "Saves this SSL coverage result as an Excel file.",
    "input": "Nothing to type. Just click it. It shows after a check.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves this SSL coverage result as a JSON file.",
    "input": "Nothing to type. Just click it. It shows after a check.",
    "effect": "download"
   },
   "#scRiverPlay": {
    "what": "Pauses or plays the moving packets in the traffic river.",
    "input": "Nothing to type. Just click it. The label says what a click does now.",
    "effect": "local"
   },
   "#scRiverTraffic path.fa-band": {
    "what": "Shows one stream of web traffic, as wide as its share. Hover or click it to see its numbers.",
    "input": "Nothing to type. Hover it or click it.",
    "effect": "local"
   },
   "#scRiverCauses path.fa-band": {
    "what": "Shows one cause of traffic that is not inspected, as wide as its share of the causes found. Hover or click it to see it.",
    "input": "Nothing to type. Hover it or click it.",
    "effect": "local"
   },
   "#scTraffic button[data-unit=\"BYTES\"]": {
    "what": "Shows the percentages by amount of data (bytes).",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#scTraffic button[data-unit=\"TRANSACTIONS\"]": {
    "what": "Shows the percentages by number of requests (transactions).",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#scTraffic a[href=\"#hCauses\"]": {
    "what": "Jumps down to the list of causes.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#scBody details.pa-details summary": {
    "what": "Shows or hides the list of what was read from the tenant during the check.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/sslflow": {
   "a.rp-btn[href^=\"/reference/data-security-architect\"]": {
    "what": "Data Security Architect: the reference architecture this flow is measured against (inline web module; opens in a new tab)",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#sfAuto": {
    "what": "Ticked: reads the tenant again every 2 minutes and redraws this page.",
    "input": "Optional. Off by default. The assessment tab must stay open.",
    "effect": "read"
   },
   "#sfRefresh": {
    "what": "Reads the tenant again now and redraws the SSL inspection flow.",
    "input": "Nothing to type. Just click it. The assessment tab must still be open and signed in.",
    "effect": "read"
   },
   "#expCsv": {
    "what": "Saves this SSL inspection flow as a CSV file. A spreadsheet can open it.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expMd": {
    "what": "Saves this SSL inspection flow as a Markdown text file.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#expJson": {
    "what": "Saves this SSL inspection flow as a JSON file, with every rule in full.",
    "input": "Nothing to type. Just click it.",
    "effect": "download"
   },
   "#sfMotionPlay": {
    "what": "Pauses or plays the moving packets in the diagram and the rule walk.",
    "input": "Nothing to type. Just click it. The label says what a click does now.",
    "effect": "local"
   },
   "#sfFlowWrap g.sf-node[data-key=\"zcc\"]": {
    "what": "Shows the Client Connector bypasses: traffic sent around Zscaler that no SSL or DLP rule ever sees.",
    "input": "Nothing to type. Click it or press Enter.",
    "effect": "local"
   },
   "#sfFlowWrap g.sf-node": {
    "what": "Shows this kind of traffic: which SSL rule decides it, who is left out, which DLP rules apply and how to close the gap. It also walks its rules.",
    "input": "Nothing to type. Click it or press Enter.",
    "effect": "local"
   },
   "#sfOpenBypass": {
    "what": "Opens the full Bypass and Non-Inspected report in a new tab. It reads the tenant to build it.",
    "input": "Nothing to type. Just click it. The assessment tab must still be open.",
    "effect": "read"
   },
   "#rpBody a.sf-gap-link": {
    "what": "Shows the details for this gap in the box above: the rule behind it and how to fix it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody details.bp-sec summary": {
    "what": "Opens or closes this list of rules, in the order they are checked. The number is how many rules it has.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/todo": {
   "a.skip-link": {
    "what": "Jumps to the to-do list, past the page header.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tdTenant": {
    "what": "Shows only the to-dos of this tenant.",
    "input": "Optional. Pick a tenant, or All tenants.",
    "effect": "local"
   },
   "#tdTag": {
    "what": "Shows only the to-dos on objects with this tag.",
    "input": "Optional. Pick a tag, or All tags.",
    "effect": "local"
   },
   "#tdShowDone": {
    "what": "Shows done to-dos too, not only open ones.",
    "input": "Tick it to show done to-dos.",
    "effect": "local"
   },
   "#tdRefresh": {
    "what": "Loads the to-do list again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tdBody input[type=\"checkbox\"]": {
    "what": "Marks this to-do done, or open again. It is saved on this computer.",
    "input": "Tick it when the to-do is done. Untick it to open it again.",
    "effect": "local"
   },
   "#tdBody button.td-link": {
    "what": "Opens the object this to-do is on in Find anything.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tdBody .td-kind a": {
    "what": "Opens the page of the object this to-do is on.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/traffic-logs": {
   "#tlFiles": {
    "what": "Picks the ZPA LSS or ZIA NSS log files to analyze. You can also drop them in this box.",
    "input": "Required. JSON lines, a CSV or TSV with its header row, or the default NSS tab-separated feed, as .json, .log, .txt, .csv or .tsv, or packed in a .gz or .zip. Keep it under the upload limit shown.",
    "effect": "local"
   },
   "#tlFormatBox > summary": {
    "what": "Opens or closes the box for a custom NSS feed's output format.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlFormat": {
    "what": "The feed output format of a custom NSS feed, so lines that are not JSON can be split into fields.",
    "input": "Optional. Paste it from the NSS feed in the ZIA Admin Portal, like %s{time}\\t%s{login}\\t%s{url}\\t%s{action}. Up to 4,000 characters. Leave it empty for JSON, a CSV with a header or the default format.",
    "effect": "local"
   },
   "#tlRun": {
    "what": "Reads the chosen files on this computer and shows what the logs say. Nothing is sent to Zscaler and the lines are not kept.",
    "input": "Choose one or more files first.",
    "effect": "local"
   },
   "#tlSavedBox > summary": {
    "what": "Opens or closes the list of reports saved on this computer.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlSaved button.tl-act": {
    "what": "Opens this saved report on the page, or deletes it from this computer after you confirm.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlCsv": {
    "what": "Downloads the analysis as one CSV file, table by table. User names are replaced by user 1, user 2 unless you tick Include user names and addresses.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   "#tlXlsx": {
    "what": "Downloads the analysis as an Excel workbook, one sheet per table. User names are replaced unless you tick Include user names and addresses.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   "#tlPdf": {
    "what": "Downloads the analysis as a PDF report with the top rows of each table. User names are replaced unless you tick Include user names and addresses.",
    "input": "Nothing to type. Run Analyze first.",
    "effect": "download"
   },
   "#tlNames": {
    "what": "Keeps user names, IP addresses, devices and the session list in downloads and in a saved report.",
    "input": "Unticked: counts only, with users shown as user 1, user 2. Ticked: the names as they are in the logs.",
    "effect": "local"
   },
   "#tlSave": {
    "what": "Saves the analysis as a file only you can read on this computer, so you can open it again later. Counts only unless Include user names and addresses is ticked.",
    "input": "Run Analyze first. You are asked for a name, up to 80 characters.",
    "effect": "local"
   },
   "#tlForget": {
    "what": "Forgets the analysis: it is removed from this page and from the server's memory. Saved reports stay.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlNav a": {
    "what": "Jumps to that part of the results.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlResults a.tl-link[href^=\"/report/path\"]": {
    "what": "Opens the Path analyzer in a new tab with this destination filled in. It reads the tenant only when you click Analyze there.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#tlInsights": {
    "what": "Opens Traffic insights in a new tab with the same time window as these logs filled in. It reads the tenant only when you click Read Insights there.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#tlResults button.tl-act": {
    "what": "Puts this user or destination in the SIEM query below, so the query asks only about it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlSessFilter": {
    "what": "Shows only the sessions whose user, device, address, country, platform or version contains what you type.",
    "input": "Optional. A few letters, like a user name or a country code.",
    "effect": "local"
   },
   "#tlResults details > summary": {
    "what": "Opens or closes the extra detail: the values as a table, or the lines that could not be read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlSiem": {
    "what": "Picks the SIEM whose query language the query is written in.",
    "input": "Pick Splunk (SPL), Microsoft Sentinel (KQL) or Elastic (ES|QL).",
    "effect": "local"
   },
   "#tlQuestion": {
    "what": "Picks the question the query asks, the same questions this page answers from the uploaded logs.",
    "input": "Pick one from the list, grouped by ZPA and ZIA log type.",
    "effect": "local"
   },
   "#tlHours": {
    "what": "How far back the query looks.",
    "input": "A whole number of hours from 1 to 2208 (92 days). Default 24.",
    "effect": "local"
   },
   "#tlQUser": {
    "what": "Limits the query to one user.",
    "input": "Optional. A user name as it appears in the logs, like jdoe@example.com. It is escaped for the query language.",
    "effect": "local"
   },
   "#tlQDest": {
    "what": "Limits the query to one destination: a host, or for DNS a queried name.",
    "input": "Optional. A host name or address, like intranet.example.com. It is escaped for the query language.",
    "effect": "local"
   },
   "#tlSiemSec details > summary": {
    "what": "Opens or closes where the logs are kept in your SIEM.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tlSrcZpa": {
    "what": "Where the ZPA LSS logs are in your SIEM.",
    "input": "Optional. Splunk: the index name. Sentinel: the table name. Elastic: the index pattern. Letters, digits, _ and - (Elastic also . * , :). Empty uses the placeholder shown.",
    "effect": "local"
   },
   "#tlSrcWeb": {
    "what": "Where the ZIA NSS web logs are in your SIEM.",
    "input": "Optional. Splunk: the index name. Sentinel: the table name. Elastic: the index pattern. Empty uses the placeholder shown.",
    "effect": "local"
   },
   "#tlSrcFw": {
    "what": "Where the ZIA NSS firewall logs are in your SIEM.",
    "input": "Optional. Splunk: the index name. Sentinel: the table name. Elastic: the index pattern. Empty uses the placeholder shown.",
    "effect": "local"
   },
   "#tlSrcDns": {
    "what": "Where the ZIA NSS DNS logs are in your SIEM.",
    "input": "Optional. Splunk: the index name. Sentinel: the table name. Elastic: the index pattern. Empty uses the placeholder shown.",
    "effect": "local"
   },
   "#tlQuery": {
    "what": "The query text to copy into your SIEM. It only reads your SIEM's data; nothing here runs it.",
    "input": "Nothing to type: it is written from your choices above.",
    "effect": "local"
   },
   "#tlCopyQuery": {
    "what": "Copies the query text to the clipboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "section[aria-labelledby=\"tlReadsH\"] summary": {
    "what": "Opens or closes the list of log formats this page reads and the rules it uses to decide.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"/help\"]": {
    "what": "Opens the page that explains every function of the app, in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "a.rp-btn[href=\"/\"]": {
    "what": "Goes back to the assessment page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/report/vendor": {
   "a[href=\"#panos\"]": {
    "what": "Jumps to the Firewall and private access section, which maps a Palo Alto Networks configuration export to Cloud Firewall rules and ZPA segments.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#panExport": {
    "what": "Picks the Palo Alto Networks configuration export (the firewall's or Panorama's). It is read on this computer with a hardened XML reader.",
    "input": "Required. One .xml configuration export, under the upload limit shown.",
    "effect": "local"
   },
   "#panPrefix": {
    "what": "Sets the prefix every object the import makes starts with, so a re-run finds them and Undo deletes only them.",
    "input": "Optional. 1 to 10 letters, digits, - or _, like pan. The default is pan.",
    "effect": "local"
   },
   "#panZones": {
    "what": "Names the zones GlobalProtect users arrive in. Allow rules from these zones to internal addresses become ZPA application segments.",
    "input": "Optional. Zone names separated by commas, like gp-users. Empty means zone names that say globalprotect, gp, vpn or remote access.",
    "effect": "local"
   },
   "#panDisabled": {
    "what": "Also carries rules that are disabled on the firewall. They still arrive disabled in ZIA.",
    "input": "Optional. Ticked carries them; unticked lists them as not mapped.",
    "effect": "local"
   },
   "#panBuild": {
    "what": "Maps the export to Cloud Firewall rules, IP groups, network services and ZPA segments, and lists what cannot be carried and why. Nothing is written to the tenant.",
    "input": "Choose the export file first.",
    "effect": "local"
   },
   "#panDlPlan": {
    "what": "Saves the migration plan as a JSON file, to load in Bulk changes or the terminal UI.",
    "input": "Nothing to type. Build the plan first.",
    "effect": "download"
   },
   "#panDlCsv": {
    "what": "Saves the ZPA application segments as the CSV the ZPA application segments builder reads.",
    "input": "Nothing to type. Build the plan first; it works when some rules went to ZPA.",
    "effect": "download"
   },
   "#panOpen": {
    "what": "Opens Bulk changes with this plan in the firewall import form. You still read the tenant, preview and confirm there; nothing is written here.",
    "input": "Nothing to type. Build the plan first; it works when some rules went to ZIA.",
    "effect": "nav"
   },
   "#panXref summary": {
    "what": "Opens or closes where each Palo Alto Networks object lands in Zscaler, with the API call.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#vmTemplate": {
    "what": "Saves a decisions file to fill in. It lists every policy with nothing approved yet.",
    "input": "Nothing to type. Run Inventory the export first.",
    "effect": "download"
   },
   "#vmDlReport": {
    "what": "Saves the migration report as a JSON file.",
    "input": "Nothing to type. Run Compile first.",
    "effect": "download"
   },
   "#vmDlWs": {
    "what": "The same file layout as the pack hand-off: terraform.tf, providers.tf, variables.tf, dictionaries.tf, engines.tf, rules.tf, locals.tf, outputs.tf, README, .gitignore, tfvars example and the migration report",
    "input": "Nothing to type. Run Compile first; it works only when the compile is ready. Saves a .zip file.",
    "effect": "download"
   },
   "#vmDlTf": {
    "what": "The same configuration as one machine-readable Terraform JSON file",
    "input": "Nothing to type. Run Compile first; it works only when the compile is ready.",
    "effect": "download"
   },
   "#vmVendor button.vm-vendor": {
    "what": "Picks the DLP product the customer is leaving. The upload box then takes that product's export files.",
    "input": "Nothing to type. Click a card marked adapter ready. Planned ones cannot be picked yet.",
    "effect": "local"
   },
   "#vmXref summary": {
    "what": "Opens or closes the export file types and the field-by-field map from the old product to ZIA.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#vmExport": {
    "what": "Picks the policy export file. You can also drop it in this box.",
    "input": "Required. One export file from the chosen product, like policies.xml (.xml, .json, .zip or .csv). Keep it under the upload limit shown.",
    "effect": "local"
   },
   "#vmInventory": {
    "what": "Reads the export on this computer and lists every policy in it. Nothing is written to the tenant.",
    "input": "Pick the product and choose the export file first.",
    "effect": "local"
   },
   "#vmDecisions": {
    "what": "Picks your reviewed decisions file. You can also drop it in this box.",
    "input": "Required. The decisions template (.json) you downloaded and filled in. It must belong to the same export.",
    "effect": "local"
   },
   "#vmCompile": {
    "what": "Turns the export and your decisions into disabled ZIA dictionaries, engines and rules, and a report. Nothing is written to the tenant.",
    "input": "Choose the reviewed decisions file first.",
    "effect": "local"
   },
   "#vmEfficacy details.vm-pol > summary": {
    "what": "Opens or closes how much of this policy's detection the translation carries, facet by facet.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#vmEfficacy summary": {
    "what": "Opens or closes how the efficacy number is worked out.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#vmReport details.vm-xref > summary": {
    "what": "Opens or closes the field map from the old product to ZIA used for this compile.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "a.rp-btn[href=\"/help#vendormigrate\"]": {
    "what": "Opens the help for this page in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "button.rp-more": {
    "what": "Shows or hides the rest of the page introduction.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "/report/view": {
   "#rpBody [data-call]": {
    "what": "Does what this button does in the assessment tab. This tab is a live copy of that tool.",
    "input": "Nothing to type. Just click it. Keep the assessment tab open.",
    "effect": "local"
   },
   "#rpBody a[href]": {
    "what": "Opens the page or file this link points to.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#rpBody summary": {
    "what": "Opens or closes this part of the report.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#rpBody input, #rpBody select, #rpBody textarea": {
    "what": "Fills in the same field in the assessment tab. This tab is a live copy of that tool.",
    "input": "Type or pick a value, as the same field on the assessment tab asks.",
    "effect": "local"
   },
   "#rpBody button": {
    "what": "A copy of a button in the assessment tab. Use the button there if this one does nothing.",
    "input": "Nothing to type. Keep the assessment tab open.",
    "effect": "local"
   }
  },
  "/report/zpa": {
   "#zpTenant": {
    "what": "Picks which tenant sign-in the ZPA read uses.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#zpRun": {
    "what": "Reads the ZPA setup once and runs every ZPA analysis template on it. Then it shows the overview and the findings.",
    "input": "Nothing to type. Just click it. Tick ZPA on the Scope page and give the ZPA customer ID first.",
    "effect": "read"
   },
   "#zpStop": {
    "what": "Stops the read at once. Nothing more is read and nothing is kept.",
    "input": "Nothing to type. Just click it while a read is running.",
    "effect": "local"
   },
   "#expCsv": {
    "what": "The findings shown (severity filter applied) as CSV. Saves them as a file.",
    "input": "Nothing to type. Just click it. Run Read ZPA and analyze first.",
    "effect": "download"
   },
   "#expJson": {
    "what": "The findings shown, the catalog and the counts as JSON. Saves them as a file.",
    "input": "Nothing to type. Just click it. Run Read ZPA and analyze first.",
    "effect": "download"
   },
   "#expXlsx": {
    "what": "The overview sentences, every table, the findings shown and the map connections as one Excel workbook. Saves it as a file.",
    "input": "Nothing to type. Just click it. Run Read ZPA and analyze first.",
    "effect": "download"
   },
   "#zpBuild": {
    "what": "Build an App Connector group, application segments and policy rules named with a prefix, or delete them, in Bulk changes: previewed, applied in write mode, reversible",
    "input": "Nothing to type. Just click it. It opens the Bulk changes page in a new tab.",
    "effect": "nav"
   },
   "#tab-overview": {
    "what": "Shows the overview: plain sentences, the live picture, the map and every object in tables.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-findings": {
    "what": "Shows the findings, grouped by analysis template, with a severity filter.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-diagnose": {
    "what": "Shows the Diagnose form. It says which app segment, server group and access rule decide for one user and one place.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#zpOverview a[data-kpi]": {
    "what": "Shows the objects behind this sentence in the tables below. It scrolls down to that table.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zoMap .zo-node": {
    "what": "Shows only what is connected to this box in the tables below. Click it again to show everything.",
    "input": "Nothing to type. Click it, or press Enter. Arrow keys move between boxes. Escape shows everything again.",
    "effect": "local"
   },
   "#zpOverview .zo-lbtn": {
    "what": "Shows only what is connected to this object in the tables below. It works like a box in the map.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zoClear": {
    "what": "Clears the filter. The tables show every object again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpOverview details.zo-list > summary": {
    "what": "Shows or hides the map as a written list. Each object says what leads to it and where it leads.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpOverview details.pa-details > summary": {
    "what": "Shows or hides how the map is drawn.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zoTables details.zo-t > summary": {
    "what": "Opens or closes this table of objects. Each row has a status and its flags and findings.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zoFlow .fp-head button": {
    "what": "Pauses or plays the moving packets in the live picture. Your choice is kept for the next read.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpFindings .zp-sev button[data-sev]": {
    "what": "Shows or hides the findings of this severity. The exports follow this filter.",
    "input": "Nothing to type. Click it to switch it on or off.",
    "effect": "local"
   },
   "#zpFindings details.zp-tpl > summary": {
    "what": "Opens or closes the findings of this analysis template. Each finding says what is wrong and what to do.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpFindings details.pa-details > summary": {
    "what": "Shows or hides the log of what was read, line by line.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#dDest": {
    "what": "Sets the place to check: the app the user wants to reach.",
    "input": "Required. A host name, an IP address or a web address, like git.corp.example, 10.20.30.7 or wiki.corp.example.",
    "effect": "local"
   },
   "#dPort": {
    "what": "Sets the port the user connects to.",
    "input": "Optional. A whole number from 1 to 65535, like 22. Blank means 443.",
    "effect": "local"
   },
   "#dProto": {
    "what": "Sets the protocol of the connection.",
    "input": "Pick TCP or UDP. TCP is the usual choice.",
    "effect": "local"
   },
   "#dIdp": {
    "what": "Sets the IdP (the sign-in service) the user comes from.",
    "input": "Optional. Pick one IdP from the list. Any means every IdP.",
    "effect": "local"
   },
   "#dScim": {
    "what": "Sets the SCIM groups (user groups sent by the IdP) the user is in.",
    "input": "Optional. Group names split by commas, like Engineering, Contractors. Blank means any. Type none for no group.",
    "effect": "local"
   },
   "#dSaml": {
    "what": "Sets the SAML or SCIM attributes of the user.",
    "input": "Optional. One attribute=value per line, like Department=Sales. Blank means any.",
    "effect": "local"
   },
   "#dClient": {
    "what": "Sets the client type the user connects with, like Client Connector or a browser.",
    "input": "Optional. Pick one from the list. Any means every client type.",
    "effect": "local"
   },
   "#dPlatform": {
    "what": "Sets the device platform, like Windows or macOS.",
    "input": "Optional. Pick one from the list. Any means every platform.",
    "effect": "local"
   },
   "#dPosture": {
    "what": "Sets the posture profiles (device checks) the device passes.",
    "input": "Optional. Profile names split by commas, like Corp device. Blank means any. Type none if it passes none.",
    "effect": "local"
   },
   "#dTrusted": {
    "what": "Sets the trusted networks the device is on, like the office network.",
    "input": "Optional. Network names split by commas, like HQ. Blank means any. Type none if it is on none.",
    "effect": "local"
   },
   "#dCountry": {
    "what": "Sets the country the user connects from.",
    "input": "Optional. A two-letter country code, like US or DE.",
    "effect": "local"
   },
   "#dMachine": {
    "what": "Sets the machine group of the device.",
    "input": "Optional. One machine group name from the list. Blank means any.",
    "effect": "local"
   },
   "#dRun": {
    "what": "Finds which app segment matches, what serves it and which access rule decides. The first diagnosis reads ZPA, or reuses the analysis you ran.",
    "input": "Type a destination first. The other fields are optional.",
    "effect": "read"
   },
   "#zpWalk .fp-head button:has(+ button + button)": {
    "what": "Plays the walk again. A packet goes through the app segment, its segment group and each access rule in order.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpWalk .fp-head button:has(+ button + span.fp-note)": {
    "what": "Moves the walk one step forward.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#zpWalk .fp-head button:has(+ span.fp-note)": {
    "what": "Stops the walk and goes back to the start.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "ext:options": {
   "#app": {
    "what": "Holds the address of the Zscaler Made Easy app on this computer.",
    "input": "Required. An address on this computer only, like 127.0.0.1:8000 or localhost:8001. Press Enter to save.",
    "effect": "local"
   },
   "#save": {
    "what": "Saves the address in the browser, then checks that the app answers there.",
    "input": "Type the app address first.",
    "effect": "local"
   },
   "#reset": {
    "what": "Puts back the default address, 127.0.0.1:8000, saves it and tests it.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#badgesOn": {
    "what": "Turns on badges next to DLP objects in the ZIA admin console. The browser asks you to allow it.",
    "input": "Nothing to type. Click it, then allow it in the browser prompt.",
    "effect": "local"
   },
   "#badgesOff": {
    "what": "Turns the console badges off and gives back the browser permission.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   }
  },
  "ext:panel": {
   "#tenant": {
    "what": "Picks which saved tenant the app reads for this panel.",
    "input": "Pick a saved tenant profile, or the details saved on this computer.",
    "effect": "local"
   },
   "#read": {
    "what": "Asks the app to read the tenant's DLP objects, rules and the objects they use. Read-only.",
    "input": "Nothing to type. The app must be running and the tenant picked.",
    "effect": "read"
   },
   "#tab-page": {
    "what": "Shows the objects on the console page you are looking at.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-search": {
    "what": "Shows a search over everything the app read.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#tab-stage": {
    "what": "Shows the DLP objects you staged for export.",
    "input": "Nothing to type. Just click it. Arrow keys move between tabs.",
    "effect": "local"
   },
   "#kindFilter": {
    "what": "Shows only objects of one kind, like DLP rules or URL categories.",
    "input": "Pick a kind, or All kinds.",
    "effect": "local"
   },
   "#view input[type=\"search\"]": {
    "what": "Finds objects by name as you type.",
    "input": "Optional. Part of a name, like Finance or PCI.",
    "effect": "local"
   },
   "#view button.obj": {
    "what": "Opens the details of this object: what it uses, what uses it and its findings.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view .detail > button": {
    "what": "Goes back to the list.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view .refs button": {
    "what": "Opens the details of the object with this name.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view button[aria-label=\"Copy the expression with dictionary ids\"]": {
    "what": "Copies the engine's expression, with dictionary ids, to the clipboard.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view .detail > .row button": {
    "what": "Stages this object for export, takes it off the stage, or opens it in the app.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view .list button[aria-label^=\"Remove \"]": {
    "what": "Takes this object off the export stage.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#view input[name=\"fmt\"][value=\"json\"]": {
    "what": "Exports the stage as a JSON pack.",
    "input": "Pick it to get a JSON pack.",
    "effect": "local"
   },
   "#view input[name=\"fmt\"][value=\"terraform\"]": {
    "what": "Exports the stage as Terraform files.",
    "input": "Pick it to get Terraform.",
    "effect": "local"
   },
   "#view input[name=\"fmt\"][value=\"both\"]": {
    "what": "Exports the stage as a JSON pack and as Terraform.",
    "input": "Pick it to get both.",
    "effect": "local"
   },
   "#view .opts input[type=\"checkbox\"]": {
    "what": "Adds what the staged objects use, like the dictionaries an engine needs.",
    "input": "Ticked adds them. Untick it to export only what you staged.",
    "effect": "local"
   },
   "#exportGo": {
    "what": "Has the app read the staged objects from the tenant and saves them as a file. Nothing is written to the tenant.",
    "input": "Stage at least one DLP object and pick a format first.",
    "effect": "download"
   },
   "#view > div > .row > button:not(#exportGo)": {
    "what": "Empties the export stage.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#openApp": {
    "what": "Opens the Zscaler Made Easy app in a new tab.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#settings": {
    "what": "Opens the extension settings: the app address and the console badges.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "ext:popup": {
   "#analyze": {
    "what": "Opens the Path analyzer with this site filled in. It shows what Zscaler does to traffic to this site.",
    "input": "Nothing to type. The app must be running. Nothing runs until you click Analyze there.",
    "effect": "nav"
   },
   "#panel": {
    "what": "Opens the side panel. It shows what the app knows about objects on the admin console page.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#links button": {
    "what": "Opens that page of the Zscaler Made Easy app in a new tab.",
    "input": "Nothing to type. The app must be running.",
    "effect": "nav"
   },
   "#opts": {
    "what": "Opens the extension settings, where you set the app address.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   },
   "#settings": {
    "what": "Opens the extension settings: the app address and the console badges.",
    "input": "Nothing to type. Just click it.",
    "effect": "nav"
   }
  },
  "/login": {
   "#lgUser": {
    "what": "Your user name on this team server.",
    "input": "Required. The name an administrator gave you, often your email address.",
    "effect": "local"
   },
   "#lgPass": {
    "what": "Your password on this team server. It is sent once to this server and never kept in the page.",
    "input": "Required. At least 12 characters. Too many wrong ones lock the account for a while.",
    "effect": "local"
   },
   "#lgGo": {
    "what": "Signs you in to this team server with your user name and password. It does not touch any tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#lgSsoBtn": {
    "what": "Signs you in through your organisation's identity provider instead of a password.",
    "input": "Nothing to type. Just click it. Your identity provider may ask you to sign in there.",
    "effect": "nav"
   }
  },
  "/report/team": {
   "#tmRefresh": {
    "what": "Loads the accounts, access and settings again.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmSignOut": {
    "what": "Signs you out of this team server and ends your session.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmPwCur": {
    "what": "Your current password, to prove it is you.",
    "input": "Required to change your password.",
    "effect": "local"
   },
   "#tmPwNew": {
    "what": "The password you want from now on. Every session of yours ends, so you sign in again.",
    "input": "Required. At least 12 characters; a few words work well. Not your user name.",
    "effect": "local"
   },
   "#tmPwGo": {
    "what": "Changes your own password on this server. It changes nothing in any tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "select[data-role]": {
    "what": "This person's role: the most they may ever do. Their sessions end so the new role applies at once.",
    "input": "Pick one: viewer (read), operator (read, plan, apply), approver (read, approve) or administrator. You cannot demote yourself.",
    "effect": "local"
   },
   "button[data-act=\"off\"]": {
    "what": "Turns this account off: it cannot sign in, and its sessions end. Nothing is deleted.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-act=\"on\"]": {
    "what": "Turns this account back on.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-act=\"unlock\"]": {
    "what": "Unlocks an account locked after too many wrong passwords.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "button[data-act=\"pw\"]": {
    "what": "Sets a new password for this account. Its sessions end; tell the person the new password in person.",
    "input": "At least 12 characters.",
    "effect": "local"
   },
   "button[data-act=\"del\"]": {
    "what": "Deletes this account and the access it was given. Its sessions end. The audit log keeps what it did.",
    "input": "Nothing to type. Just click it. You are asked to confirm.",
    "effect": "local"
   },
   "#tmNuName": {
    "what": "The new account's user name.",
    "input": "Required. Letters, digits and . _ @ + -, up to 100 characters; an email address works and matches an SSO sign-in.",
    "effect": "local"
   },
   "#tmNuEmail": {
    "what": "The new account's email, used to match an SSO sign-in.",
    "input": "Optional. An email address.",
    "effect": "local"
   },
   "#tmNuRole": {
    "what": "The new account's role: the most it may ever do.",
    "input": "Pick one: viewer, operator, approver or administrator.",
    "effect": "local"
   },
   "#tmNuPass": {
    "what": "The new account's first password.",
    "input": "Optional. At least 12 characters. Leave blank for someone who signs in through SSO only.",
    "effect": "local"
   },
   "#tmNuGo": {
    "what": "Adds the account. It may do nothing until you give it access below.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmGrWho": {
    "what": "Who gets the access: one account, or a group (groups come from SCIM provisioning).",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#tmGrProf": {
    "what": "Which tenant profile the access is for, or every tenant profile.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#tmGrActs input": {
    "what": "What they may do there. Read sees the tenant and its reports; plan prepares changes; apply changes the tenant; approve decides on someone else's change. Their role still caps it.",
    "input": "Tick any. Untick all to take the access away.",
    "effect": "local"
   },
   "#tmGrGo": {
    "what": "Saves this access. It takes effect on their next click.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmScimNew": {
    "what": "Makes a new SCIM bearer token for your identity provider to add, change and remove accounts and groups. It is shown once; the one before stops working.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmScimRevoke": {
    "what": "Revokes the SCIM token, so provisioning stops until you make a new one.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmShKind": {
    "what": "Picks what to share: one of your POV templates or one of your saved deploy plans.",
    "input": "Pick one.",
    "effect": "local"
   },
   "#tmShItem": {
    "what": "Picks which template or saved plan to share. Only its owner or an administrator may change who it is shared with.",
    "input": "Pick one from the list.",
    "effect": "local"
   },
   "#tmShWho input": {
    "what": "Ticks the people and groups it is shared with. A shared plan still opens only for people who may read its tenant profile.",
    "input": "Tick any. Untick all to keep it to yourself.",
    "effect": "local"
   },
   "#tmShGo": {
    "what": "Saves who this template or plan is shared with. It changes nothing in any tenant.",
    "input": "Nothing to type. Just click it.",
    "effect": "local"
   },
   "#tmStoreRotate": {
    "what": "Makes a new key for the app's encrypted stores, encrypts every store again with it, then forgets the old key. Only when store encryption is on.",
    "input": "Nothing to type. You are asked to confirm.",
    "effect": "local"
   }
  },
  "/report/aiguard": {
   "#agTenant": {
    "what": "Picks which tenant sign-in the AI Guard read and the prompt test use.",
    "input": "Optional. Pick where the sign-in comes from: the assessment tab, a saved tenant profile, or what is saved on this computer. It only shows when there is more than one choice.",
    "effect": "local"
   },
   "#agRun": {
    "what": "Reads AI Guard once: detection policies, policy match rules, LLM providers, LLM applications and credential names (never a key).",
    "input": "Nothing to type. Just click it. Tick AI Guard on the Scope page first; it needs a OneAPI (ZIdentity) API client.",
    "effect": "read"
   },
   "a.rp-btn[href=\"/report/operations?build=aiguard_detection_policy\"]": {
    "what": "Opens Bulk changes with the AI Guard detection policy builder picked, to build a policy from a compliance profile.",
    "input": "Nothing to type. Just click it. Nothing is changed until you preview and apply with write mode on.",
    "effect": "nav"
   },
   "#agPrompt": {
    "what": "Picks the made-up prompt to send. Only these prompts can be sent; nothing you type is ever sent.",
    "input": "Pick one: an ordinary question, a prompt injection, a reserved test SSN, a published test card number, a link to a made-up malicious site, or internal source code.",
    "effect": "local"
   },
   "#agDir": {
    "what": "Says whether the text is checked as a prompt to the model or as the model's answer.",
    "input": "Pick one: Prompt to the model (IN) or Model's answer (OUT). IN is the usual choice.",
    "effect": "local"
   },
   "#agPolicy": {
    "what": "Picks the detection policy to test against, or lets AI Guard pick it by its match rules.",
    "input": "Optional. Click Read first to list the policies.",
    "effect": "local"
   },
   "#agTest": {
    "what": "Sends the made-up prompt to AI Guard's policy detection and shows the overall action and what each detector did. Changes no configuration.",
    "input": "Nothing to type. Just click it. On a live tenant it needs the server's AI Guard API key (AIGUARD_API_KEY); the sample tenant answers with a made-up detector.",
    "effect": "read"
   }
  }
 }
};
