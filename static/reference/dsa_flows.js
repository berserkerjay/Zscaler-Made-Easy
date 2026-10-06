/* Offline reference snapshot, 2026-09-29. No tenant reads or actions. */
(function (root, factory) {
  var value = factory();
  if (typeof module === 'object' && module.exports) module.exports = value;
  else root.DSAFlows = value;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  var flows = [
  {
    "id": "chains-1",
    "lane": "Shared DLP detection and evidence",
    "stages": [
      {
        "id": "dictionary",
        "label": "Dictionary",
        "detail": "Content is captured by its own channel. Dictionaries report match counts, never a verdict.",
        "gate": false
      },
      {
        "id": "engine",
        "label": "Engine",
        "detail": "Boolean expressions and strict count thresholds turn dictionary results into a verdict.",
        "gate": false
      },
      {
        "id": "channel_rule",
        "label": "Channel rule",
        "detail": "The channel gate and matching criteria choose which rule can act.",
        "gate": false
      },
      {
        "id": "action_and_log",
        "label": "Action and log",
        "detail": "The rule acts. Logs and notification delivery are separate from evidence forwarding.",
        "gate": false
      },
      {
        "id": "evidence_forwarding",
        "label": "Evidence forwarding",
        "detail": "The rule must select Incident Receiver or cloud-to-cloud forwarding.",
        "gate": true
      },
      {
        "id": "customer_storage_event",
        "label": "Customer storage event",
        "detail": "Evidence and metadata reach the configured storage; its event triggers processing.",
        "gate": false
      },
      {
        "id": "workflow_automation",
        "label": "Workflow Automation",
        "detail": "Workflow Automation reads metadata to create the incident. NSS and SIEM logs do not feed this lane.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "No rule forwarding",
        "stopAt": 4,
        "note": "No evidence forwarding is selected: storage and Workflow Automation are not reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "The DLP chain from dictionaries through engines, channel rules, evidence forwarding and Workflow Automation",
    "section": "chain",
    "kind": "figure",
    "image": "/static/reference/dsa/chains-1.webp",
    "sourceCaption": "Dictionaries feed engines; engines gate per channel; each rule forwards logs, notifications and evidence on its own. The telemetry lane (NSS, SIEM) never feeds Workflow Automation; only the evidence lane does."
  },
  {
    "id": "chains-2",
    "lane": "Detection building blocks",
    "stages": [
      {
        "id": "dictionary_type",
        "label": "Dictionary type",
        "detail": "Choose Patterns & Phrases, EDM, IDM or MIP for the data being recognised.",
        "gate": false
      },
      {
        "id": "confidence",
        "label": "Confidence",
        "detail": "Dictionary settings determine detector confidence and the resulting match count.",
        "gate": false
      },
      {
        "id": "engine_expression",
        "label": "Engine expression",
        "detail": "All / Any / Sum applies the expression and strict more-than thresholds.",
        "gate": false
      },
      {
        "id": "channels_gate",
        "label": "Channels gate",
        "detail": "Select the channels that may use this engine.",
        "gate": true
      },
      {
        "id": "rule_attachment",
        "label": "Rule attachment",
        "detail": "A channel rule may attach at most four engines. Each channel enforces through its own path.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Channel not enabled",
        "stopAt": 3,
        "note": "The engine is unavailable to that channel rule; no rule attachment is demonstrated."
      }
    ],
    "web": false,
    "note": "",
    "title": "Dictionary to engine to the five channel rule types",
    "section": "chain",
    "kind": "figure",
    "image": "/static/reference/dsa/chains-2.webp",
    "sourceCaption": "Dictionaries are typed and carry the confidence; the engine holds the Boolean expression, the match counts and the Channels gate; at most four engines per rule."
  },
  {
    "id": "chains-3",
    "lane": "Evidence lane",
    "stages": [
      {
        "id": "source_channel_rule",
        "label": "Source channel rule",
        "detail": "An applicable rule has produced a DLP event.",
        "gate": false
      },
      {
        "id": "forwarding_selection",
        "label": "Forwarding selection",
        "detail": "Select ZIR or cloud-to-cloud on this rule.",
        "gate": true
      },
      {
        "id": "customer_storage",
        "label": "Customer storage",
        "detail": "Forwarder writes evidence and metadata to the same customer storage as the integration.",
        "gate": false
      },
      {
        "id": "storage_event",
        "label": "Storage event",
        "detail": "Cloud storage event signals new metadata.",
        "gate": true
      },
      {
        "id": "metadata_ingestion",
        "label": "Metadata ingestion",
        "detail": "Workflow Automation reads metadata, not the entire file.",
        "gate": false
      },
      {
        "id": "incident",
        "label": "Incident",
        "detail": "The incident is routed through Workflow Automation. NSS, auditor email and third-party ICAP remain parallel outputs.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Forwarding absent",
        "stopAt": 1,
        "note": "No evidence lane is configured; later storage and incident stages are not reached."
      },
      {
        "id": "stop_1",
        "label": "Storage event missing",
        "stopAt": 3,
        "note": "Without the storage event, metadata ingestion is not reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "Evidence chain from a channel rule to Workflow Automation",
    "section": "chain",
    "kind": "figure",
    "image": "/static/reference/dsa/chains-3.webp",
    "sourceCaption": "The evidence chain: the rule's forwarding setting (Incident Receiver or cloud-to-cloud) writes evidence and metadata to customer-owned storage, a storage event wakes Workflow Automation, and it reads metadata only. NSS, auditor email and third-party ICAP are parallel paths that never feed it."
  },
  {
    "id": "dictionary-1",
    "lane": "Dictionary design",
    "stages": [
      {
        "id": "choose_data_target",
        "label": "Choose data target",
        "detail": "This is a type-selection walkthrough, not a transaction with every detector enabled.",
        "gate": false
      },
      {
        "id": "predefined_catalogue",
        "label": "Predefined catalogue",
        "detail": "Check the predefined dictionaries for a recognised data type first.",
        "gate": false
      },
      {
        "id": "custom_shape",
        "label": "Custom shape",
        "detail": "Patterns & Phrases recognises a pattern or phrase when predefined detectors are insufficient.",
        "gate": false
      },
      {
        "id": "owned_records",
        "label": "Owned records",
        "detail": "EDM recognises indexed records; its template must be Completed.",
        "gate": false
      },
      {
        "id": "owned_documents",
        "label": "Owned documents",
        "detail": "IDM recognises overlap with indexed documents.",
        "gate": false
      },
      {
        "id": "microsoft_labels",
        "label": "Microsoft labels",
        "detail": "MIP recognises existing Microsoft labels.",
        "gate": false
      },
      {
        "id": "match_count",
        "label": "Match count",
        "detail": "The selected dictionary type supplies a count to an engine, not an enforcement verdict.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "Alternative detector types are explained in order; they are not all mandatory hops.",
    "title": "Dictionary type decision tree",
    "section": "dictionaries",
    "kind": "figure",
    "image": "/static/reference/dsa/dictionary-1.webp",
    "sourceCaption": "What must this dictionary recognise? Check the ~120 predefined dictionaries first; Patterns & Phrases for a kind of data Zscaler does not ship; EDM for your records; IDM for your documents; MIP for files Microsoft already labelled."
  },
  {
    "id": "dictionary-2",
    "lane": "Patterns and Phrases",
    "stages": [
      {
        "id": "content_input",
        "label": "Content input",
        "detail": "A channel provides inspectable content.",
        "gate": false
      },
      {
        "id": "ocr_gate",
        "label": "OCR gate",
        "detail": "Image text requires OCR enabled for this channel.",
        "gate": true
      },
      {
        "id": "patterns_and_phrases",
        "label": "Patterns and phrases",
        "detail": "Scan text for the configured patterns and phrases.",
        "gate": false
      },
      {
        "id": "match_type",
        "label": "Match type",
        "detail": "Apply the configured Match Type logic.",
        "gate": false
      },
      {
        "id": "proximity",
        "label": "Proximity",
        "detail": "Apply the configured proximity window.",
        "gate": false
      },
      {
        "id": "dictionary_count",
        "label": "Dictionary count",
        "detail": "Return the resulting match count.",
        "gate": false
      },
      {
        "id": "engine_threshold",
        "label": "Engine threshold",
        "detail": "The engine applies strict more than N; a count equal to N does not trigger.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Image with OCR off",
        "stopAt": 1,
        "note": "Image text is skipped: the remaining scan and engine stages are not reached for this sample."
      }
    ],
    "web": false,
    "note": "",
    "title": "Patterns and Phrases scan pipeline",
    "section": "dictionaries",
    "kind": "figure",
    "image": "/static/reference/dsa/dictionary-2.webp",
    "sourceCaption": "Patterns & Phrases pipeline: content, the OCR gate (images are silently skipped when OCR is off for the channel), pattern and phrase scan, Match Type logic, the proximity window, the count, then the DLP Engine's strict \"more than N\" threshold."
  },
  {
    "id": "dictionary-5",
    "lane": "Dictionary confidence",
    "stages": [
      {
        "id": "low_confidence",
        "label": "Low confidence",
        "detail": "Broad matching catches more possible matches and more false positives.",
        "gate": false
      },
      {
        "id": "medium_confidence",
        "label": "Medium confidence",
        "detail": "Additional verification narrows candidate matches.",
        "gate": false
      },
      {
        "id": "high_confidence",
        "label": "High confidence",
        "detail": "Strict format and verification checks reduce matches.",
        "gate": false
      },
      {
        "id": "high_confidence_phrases",
        "label": "High confidence phrases",
        "detail": "Up to 256 custom phrases and proximity can corroborate the high-confidence match.",
        "gate": false
      },
      {
        "id": "dictionary_count",
        "label": "Dictionary count",
        "detail": "Only qualifying matches contribute to the count sent to the engine.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "Comparison of confidence settings; the chosen setting does not change automatically.",
    "title": "Confidence slider from Low to High",
    "section": "dictionaries",
    "kind": "figure",
    "image": "/static/reference/dsa/dictionary-5.webp",
    "sourceCaption": "Confidence: Low catches more with more false positives; High adds strict format and verification checks and unlocks High Confidence Phrases, up to 256 custom phrases and a proximity window."
  },
  {
    "id": "dictionary-3",
    "lane": "EDM dictionary",
    "stages": [
      {
        "id": "indexed_record",
        "label": "Indexed record",
        "detail": "Use a record from the completed EDM template.",
        "gate": false
      },
      {
        "id": "primary_match",
        "label": "Primary match",
        "detail": "The primary field must match.",
        "gate": true
      },
      {
        "id": "secondary_match",
        "label": "Secondary match",
        "detail": "Secondary Match On sets how many corroborating fields must match.",
        "gate": true
      },
      {
        "id": "required_cell",
        "label": "Required cell",
        "detail": "A required-but-blank CSV cell blocks the match.",
        "gate": true
      },
      {
        "id": "dictionary_count",
        "label": "Dictionary count",
        "detail": "A qualifying record contributes a match count to the engine.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Primary missing",
        "stopAt": 1,
        "note": "Secondaries alone cannot match; later stages are not reached."
      },
      {
        "id": "stop_1",
        "label": "Required cell blank",
        "stopAt": 3,
        "note": "The record cannot contribute a match; the count stage is not reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "EDM primary and secondary field matching",
    "section": "dictionaries",
    "kind": "figure",
    "image": "/static/reference/dsa/dictionary-3.webp",
    "sourceCaption": "EDM secondary match: the primary must always match; Secondary Match On decides how many secondaries must corroborate it. A required-but-blank cell in the CSV blocks the match."
  },
  {
    "id": "dictionary-4",
    "lane": "IDM dictionary",
    "stages": [
      {
        "id": "indexed_document",
        "label": "Indexed document",
        "detail": "Compare content with your indexed document.",
        "gate": false
      },
      {
        "id": "overlap_level",
        "label": "Overlap level",
        "detail": "Low requires 25%, Medium 50%, High 75% overlap in this reference snapshot.",
        "gate": false
      },
      {
        "id": "exclude_exact_copy",
        "label": "Exclude exact copy",
        "detail": "Exclude 100% ignores a complete exact copy when enabled.",
        "gate": true
      },
      {
        "id": "dictionary_count",
        "label": "Dictionary count",
        "detail": "Eligible overlap contributes a count for engine evaluation.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Exact copy excluded",
        "stopAt": 2,
        "note": "The configured exact-copy exclusion prevents this sample from reaching the count stage."
      }
    ],
    "web": false,
    "note": "",
    "title": "IDM accuracy levels",
    "section": "dictionaries",
    "kind": "figure",
    "image": "/static/reference/dsa/dictionary-4.webp",
    "sourceCaption": "IDM accuracy: the fill is the overlap required before the dictionary triggers (Low 25 %, Medium 50 %, High 75 %); Exclude 100 % ignores an exact copy."
  },
  {
    "id": "engine-1",
    "lane": "Engine design",
    "stages": [
      {
        "id": "root_operator",
        "label": "Root operator",
        "detail": "Choose All, Any or Sum; Exclude cannot be the root.",
        "gate": true
      },
      {
        "id": "subexpressions",
        "label": "Subexpressions",
        "detail": "Use at most four subexpressions and four operators per level.",
        "gate": false
      },
      {
        "id": "dictionaries",
        "label": "Dictionaries",
        "detail": "Each operator supports at most sixteen dictionaries.",
        "gate": false
      },
      {
        "id": "sum_constraints",
        "label": "Sum constraints",
        "detail": "Sum needs at least two count dictionaries; nothing may nest below it.",
        "gate": true
      },
      {
        "id": "engine_expression",
        "label": "Engine expression",
        "detail": "The valid expression combines dictionary results into a verdict.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Invalid Exclude root",
        "stopAt": 0,
        "note": "Invalid root: no valid expression is built."
      },
      {
        "id": "stop_1",
        "label": "Invalid Sum nesting",
        "stopAt": 3,
        "note": "Invalid Sum subtree: the completed expression is not reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "Engine builder expression tree",
    "section": "engines",
    "kind": "figure",
    "image": "/static/reference/dsa/engine-1.webp",
    "sourceCaption": "The builder tree: root is All / Any / Sum (Exclude cannot be the root); per level ≤ 4 subexpressions, ≤ 4 operators, ≤ 16 dictionaries per operator; Sum needs ≥ 2 count dictionaries and nothing nests beneath it."
  },
  {
    "id": "engine-2",
    "lane": "Engine evaluation",
    "stages": [
      {
        "id": "dictionary_counts",
        "label": "Dictionary counts",
        "detail": "Sample counts are 4 and 2.",
        "gate": false
      },
      {
        "id": "strict_threshold",
        "label": "Strict threshold",
        "detail": "More than 3 is true at 4, but false at 3.",
        "gate": false
      },
      {
        "id": "all_operator",
        "label": "All operator",
        "detail": "All requires every dictionary predicate to be true.",
        "gate": false
      },
      {
        "id": "any_operator",
        "label": "Any operator",
        "detail": "Any requires at least one dictionary predicate to be true.",
        "gate": false
      },
      {
        "id": "sum_operator",
        "label": "Sum operator",
        "detail": "4 + 2 = 6 does not satisfy more than 6.",
        "gate": false
      },
      {
        "id": "verdict",
        "label": "Verdict",
        "detail": "The selected expression, not the count alone, decides the engine result.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "All, Any and Sum are alternative expression examples, not three sequential enforcement policies.",
    "title": "How All, Any and Sum evaluate match counts",
    "section": "engines",
    "kind": "figure",
    "image": "/static/reference/dsa/engine-2.webp",
    "sourceCaption": "Match counts are strict: \"more than 3\" fires at 4. All / Any combine each dictionary's own answer; Sum adds the counts and applies one threshold to the total, so 4 + 2 = 6 stays silent against \"more than 6\"."
  },
  {
    "id": "engine-3",
    "lane": "Channel eligibility",
    "stages": [
      {
        "id": "engine_definition",
        "label": "Engine definition",
        "detail": "Create or edit a DLP engine.",
        "gate": false
      },
      {
        "id": "select_channels",
        "label": "Select Channels",
        "detail": "The Channels selection is mandatory.",
        "gate": true
      },
      {
        "id": "eligible_rule_builders",
        "label": "Eligible rule builders",
        "detail": "Only selected channels can select this engine.",
        "gate": false
      },
      {
        "id": "active_dependency",
        "label": "Active dependency",
        "detail": "A channel cannot be removed while an active policy uses this engine.",
        "gate": true
      },
      {
        "id": "channel_specific_rule",
        "label": "Channel-specific rule",
        "detail": "Attach the engine in the eligible rule builder.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Channel unchecked",
        "stopAt": 1,
        "note": "The requested rule builder cannot use this engine."
      },
      {
        "id": "stop_1",
        "label": "Active policy dependency",
        "stopAt": 3,
        "note": "The existing policy blocks removal; no replacement attachment is implied."
      }
    ],
    "web": false,
    "note": "",
    "title": "Engine Channels gate",
    "section": "engines",
    "kind": "figure",
    "image": "/static/reference/dsa/engine-3.webp",
    "sourceCaption": "The Channels gate: an engine is selectable only in the rule builders of the channels ticked on it; the gate is mandatory at create/edit and a channel cannot be removed while an active policy uses the engine."
  },
  {
    "id": "access",
    "lane": "Inline web",
    "stages": [
      {
        "id": "capture",
        "label": "Capture",
        "detail": "Forward the sample transaction to ZIA.",
        "gate": false
      },
      {
        "id": "ssl_tls_inspection",
        "label": "SSL/TLS Inspection",
        "detail": "HTTPS content must actually be decrypted; Do Not Inspect leaves it encrypted.",
        "gate": true
      },
      {
        "id": "cloud_app_control",
        "label": "Cloud App Control",
        "detail": "An earlier application block ends this sample before DLP.",
        "gate": true
      },
      {
        "id": "url_filtering",
        "label": "URL Filtering",
        "detail": "A URL Filtering block ends evaluation before DLP.",
        "gate": true
      },
      {
        "id": "threat_checks",
        "label": "Threat checks",
        "detail": "The transaction must survive applicable threat checks.",
        "gate": true
      },
      {
        "id": "file_type_control",
        "label": "File Type Control",
        "detail": "File Type Control can block the upload before DLP.",
        "gate": true
      },
      {
        "id": "content_extraction",
        "label": "Content extraction",
        "detail": "Extract the inspectable content after the earlier gates.",
        "gate": false
      },
      {
        "id": "dictionary_matching",
        "label": "Dictionary matching",
        "detail": "Dictionary detectors produce match counts.",
        "gate": false
      },
      {
        "id": "engine_evaluation",
        "label": "Engine evaluation",
        "detail": "Engine expressions and thresholds produce a verdict.",
        "gate": false
      },
      {
        "id": "dlp_rule_action",
        "label": "DLP rule action",
        "detail": "Matching rule acts; a DLP block is different from an earlier-policy block.",
        "gate": false
      },
      {
        "id": "logs_and_user_notice",
        "label": "Logs and user notice",
        "detail": "Write the event and show the configured notification.",
        "gate": false
      },
      {
        "id": "evidence_and_workflow_automation",
        "label": "Evidence and Workflow Automation",
        "detail": "A configured evidence path can deliver metadata and an incident; logging alone cannot.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "SSL bypass / not decrypted",
        "stopAt": 1,
        "note": "HTTPS payload cannot reach content inspection in this sample."
      },
      {
        "id": "stop_1",
        "label": "URL Filtering blocks",
        "stopAt": 3,
        "note": "URL Filtering stops the transaction. Later stages, including DLP, are not_reached."
      },
      {
        "id": "stop_2",
        "label": "File Type Control blocks",
        "stopAt": 5,
        "note": "File Type Control stops the upload. Dictionaries, engines and evidence are not_reached."
      }
    ],
    "web": true,
    "note": "",
    "title": "The inline web gauntlet from end user to Internet with the DLP inspection phases",
    "section": "inline",
    "kind": "figure",
    "image": "/static/reference/dsa/access.webp",
    "sourceCaption": "Phase 1 capture and decryption (SNI, Do-Not-Inspect stays encrypted); Phase 2 the gauntlet in strict order (Cloud App Control, URL Filtering, threat checks, File Type Control, content inspection, bandwidth); Phase 3 a block anywhere means DLP never runs; Phases 4–6 content inspection, what a verdict produces and what the user sees."
  },
  {
    "id": "channels-1",
    "lane": "Inline web",
    "stages": [
      {
        "id": "capture",
        "label": "Capture",
        "detail": "Forward the sample transaction to ZIA.",
        "gate": false
      },
      {
        "id": "ssl_tls_inspection",
        "label": "SSL/TLS Inspection",
        "detail": "HTTPS content must actually be decrypted; Do Not Inspect leaves it encrypted.",
        "gate": true
      },
      {
        "id": "cloud_app_control",
        "label": "Cloud App Control",
        "detail": "An earlier application block ends this sample before DLP.",
        "gate": true
      },
      {
        "id": "url_filtering",
        "label": "URL Filtering",
        "detail": "A URL Filtering block ends evaluation before DLP.",
        "gate": true
      },
      {
        "id": "threat_checks",
        "label": "Threat checks",
        "detail": "The transaction must survive applicable threat checks.",
        "gate": true
      },
      {
        "id": "file_type_control",
        "label": "File Type Control",
        "detail": "File Type Control can block the upload before DLP.",
        "gate": true
      },
      {
        "id": "rule_criteria",
        "label": "Rule criteria",
        "detail": "Applicable rule criteria combine with AND; user/group/department selections combine with OR.",
        "gate": false
      },
      {
        "id": "content_extraction",
        "label": "Content extraction",
        "detail": "Extract content. Scan timeout fails open and is not a successful DLP inspection.",
        "gate": true
      },
      {
        "id": "dictionary_matching",
        "label": "Dictionary matching",
        "detail": "Configured dictionaries produce counts.",
        "gate": false
      },
      {
        "id": "engine_inspection",
        "label": "Engine inspection",
        "detail": "An eligible engine evaluates counts and Boolean expressions.",
        "gate": false
      },
      {
        "id": "action_and_log",
        "label": "Action and log",
        "detail": "Apply the action and write the configured log.",
        "gate": false
      },
      {
        "id": "evidence_and_incident",
        "label": "Evidence and incident",
        "detail": "Explicit per-rule forwarding is required for the storage-to-WA path.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "SSL bypass / not decrypted",
        "stopAt": 1,
        "note": "HTTPS payload cannot reach content inspection in this sample."
      },
      {
        "id": "stop_1",
        "label": "URL Filtering blocks",
        "stopAt": 3,
        "note": "URL Filtering stops the transaction. Later stages, including DLP, are not_reached."
      },
      {
        "id": "stop_2",
        "label": "File Type Control blocks",
        "stopAt": 5,
        "note": "File Type Control stops the upload. Dictionaries, engines and evidence are not_reached."
      },
      {
        "id": "stop_3",
        "label": "Scan timeout",
        "stopAt": 7,
        "note": "This sample times out and fails open; no successful dictionary, engine or evidence evaluation is claimed."
      }
    ],
    "web": true,
    "note": "",
    "title": "Inline web DLP eight-step flow",
    "section": "inline",
    "kind": "figure",
    "image": "/static/reference/dsa/channels-1.webp",
    "sourceCaption": "The eight steps of an inline web transaction: captured and decrypted, survives the policy chain, rule criteria match, content extracted, engine inspection, action taken, log written, evidence and incident. Scan timeout fails open."
  },
  {
    "id": "endpoint",
    "lane": "Endpoint DLP",
    "stages": [
      {
        "id": "detection_deployment",
        "label": "Detection deployment",
        "detail": "Push detection content to the device through the Endpoint DLP module.",
        "gate": false
      },
      {
        "id": "discovery",
        "label": "Discovery",
        "detail": "Classification scans maintain a local cache and inventory.",
        "gate": false
      },
      {
        "id": "sensitive_activity",
        "label": "Sensitive activity",
        "detail": "Intercept relevant local data activity.",
        "gate": false
      },
      {
        "id": "device_control",
        "label": "Device Control",
        "detail": "At plug-in, Device Control applies before Endpoint DLP.",
        "gate": true
      },
      {
        "id": "dictionary_inspection",
        "label": "Dictionary inspection",
        "detail": "Supported dictionaries inspect on-device content.",
        "gate": false
      },
      {
        "id": "engine_and_rules",
        "label": "Engine and rules",
        "detail": "Evaluate all applicable endpoint rules; most restrictive wins.",
        "gate": false
      },
      {
        "id": "evidence_forwarding",
        "label": "Evidence forwarding",
        "detail": "Configured evidence forwarding sends the incident evidence.",
        "gate": false
      },
      {
        "id": "user_self_service",
        "label": "User self-service",
        "detail": "The configured user experience can provide confirmation or exemption workflows.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Device Control block",
        "stopAt": 3,
        "note": "The device activity is blocked before Endpoint DLP inspection."
      }
    ],
    "web": false,
    "note": "",
    "title": "Endpoint DLP architecture",
    "section": "endpoint",
    "kind": "figure",
    "image": "/static/reference/dsa/endpoint.webp",
    "sourceCaption": "Endpoint architecture: detection content pushed to the device, discovery (classification scans, local cache, inventories), activities with sensitive data, Device Control at plug-in before Endpoint DLP rules, evidence forwarding, and user self-service."
  },
  {
    "id": "channels-2",
    "lane": "Endpoint DLP",
    "stages": [
      {
        "id": "activity_intercepted",
        "label": "Activity intercepted",
        "detail": "Endpoint activity can be intercepted while offline.",
        "gate": false
      },
      {
        "id": "exemption_gate",
        "label": "Exemption gate",
        "detail": "An active 12-hour OTP exemption makes enforcement monitor-only.",
        "gate": true
      },
      {
        "id": "all_rules_evaluated",
        "label": "All rules evaluated",
        "detail": "Endpoint evaluates ALL applicable rules.",
        "gate": false
      },
      {
        "id": "dictionary_inspection",
        "label": "Dictionary inspection",
        "detail": "Content is inspected on-device using supported dictionaries.",
        "gate": false
      },
      {
        "id": "engine_verdict",
        "label": "Engine verdict",
        "detail": "Engine thresholds evaluate the dictionary results.",
        "gate": false
      },
      {
        "id": "most_restrictive_action",
        "label": "Most restrictive action",
        "detail": "The most restrictive matching rule wins.",
        "gate": false
      },
      {
        "id": "notify_and_local_log",
        "label": "Notify and local log",
        "detail": "Notify the user and write the local event.",
        "gate": false
      },
      {
        "id": "evidence_and_incident",
        "label": "Evidence and incident",
        "detail": "Forward configured evidence when connectivity permits.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "OTP monitor-only exemption",
        "stopAt": 1,
        "note": "This sample is monitor-only; enforcement-path stages below are not_reached, not proof that telemetry ceases."
      }
    ],
    "web": false,
    "note": "",
    "title": "Endpoint DLP seven-step flow",
    "section": "endpoint",
    "kind": "figure",
    "image": "/static/reference/dsa/channels-2.webp",
    "sourceCaption": "The seven endpoint steps: activity intercepted (works offline), ALL rules evaluated, inspected on-device, most restrictive wins, user notified, logged locally, evidence and incident. A 12-hour OTP exemption makes it monitor only."
  },
  {
    "id": "email",
    "lane": "Email DLP",
    "stages": [
      {
        "id": "outbound_mailbox",
        "label": "Outbound mailbox",
        "detail": "An outbound message enters the platform transport.",
        "gate": false
      },
      {
        "id": "smart_host_redirect",
        "label": "Smart host redirect",
        "detail": "The platform redirects the message to Zscaler.",
        "gate": false
      },
      {
        "id": "tenant_header",
        "label": "Tenant header",
        "detail": "The transport header identifies the tenant.",
        "gate": true
      },
      {
        "id": "per_recipient_dictionaries",
        "label": "Per-recipient dictionaries",
        "detail": "Inspect recipient-scoped content and dictionary counts.",
        "gate": false
      },
      {
        "id": "engine_and_rule_verdict",
        "label": "Engine and rule verdict",
        "detail": "Most restrictive applicable rule decides each recipient outcome.",
        "gate": false
      },
      {
        "id": "verdict_headers",
        "label": "Verdict headers",
        "detail": "Zscaler inserts verdict headers; this is not platform enforcement.",
        "gate": false
      },
      {
        "id": "platform_enforcement",
        "label": "Platform enforcement",
        "detail": "On the return leg, platform transport rules enforce the headers.",
        "gate": true
      },
      {
        "id": "logs_evidence_and_wa",
        "label": "Logs evidence and WA",
        "detail": "Configured event logging and evidence forwarding deliver their separate outputs.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Tenant header absent",
        "stopAt": 2,
        "note": "Tenant attribution is missing; later sample inspection is not reached."
      },
      {
        "id": "stop_1",
        "label": "Platform enforcement rule missing",
        "stopAt": 6,
        "note": "Tagged mail may still be delivered; successful blocking and downstream incident delivery are not asserted."
      }
    ],
    "web": false,
    "note": "",
    "title": "Email DLP architecture",
    "section": "email",
    "kind": "figure",
    "image": "/static/reference/dsa/email.webp",
    "sourceCaption": "Email architecture: leg 1 out (outbound mailbox, redirect to Zscaler, tenant identity header), Zscaler email DLP rules evaluated per recipient, verdict as headers only, leg 2 return where the platform's transport rules enforce, then logs, evidence and Workflow Automation."
  },
  {
    "id": "channels-3",
    "lane": "Email DLP",
    "stages": [
      {
        "id": "smart_host",
        "label": "Smart host",
        "detail": "Mail must be redirected to the correct smart host.",
        "gate": false
      },
      {
        "id": "tenant_identity",
        "label": "Tenant identity",
        "detail": "The Key for Transport Rules identifies the tenant.",
        "gate": false
      },
      {
        "id": "dictionary_scan",
        "label": "Dictionary scan",
        "detail": "Scan the content per recipient.",
        "gate": false
      },
      {
        "id": "engine_evaluation",
        "label": "Engine evaluation",
        "detail": "Engines turn dictionary counts into verdicts.",
        "gate": false
      },
      {
        "id": "most_restrictive_rule",
        "label": "Most restrictive rule",
        "detail": "Block beats Quarantine; Quarantine is Exchange-only.",
        "gate": false
      },
      {
        "id": "verdict_headers",
        "label": "Verdict headers",
        "detail": "Insert the verdict headers for the platform.",
        "gate": false
      },
      {
        "id": "platform_enforces",
        "label": "Platform enforces",
        "detail": "The mail platform must have matching enforcement rules.",
        "gate": true
      },
      {
        "id": "log_and_evidence",
        "label": "Log and evidence",
        "detail": "Log separately from per-rule evidence forwarding to Workflow Automation.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Headers not enforced",
        "stopAt": 6,
        "note": "Without platform enforcement, tagged mail can be delivered. This is not proof of a DLP block."
      }
    ],
    "web": false,
    "note": "",
    "title": "Email DLP seven-step flow",
    "section": "email",
    "kind": "figure",
    "image": "/static/reference/dsa/channels-3.webp",
    "sourceCaption": "The seven email steps: redirected to the smart host, tenant identified, scanned per recipient, most restrictive rule, headers inserted, the PLATFORM enforces, log and evidence. Block always beats Quarantine; Quarantine is Exchange-only."
  },
  {
    "id": "saas",
    "lane": "SaaS API data at rest",
    "stages": [
      {
        "id": "sanctioned_tenant",
        "label": "Sanctioned tenant",
        "detail": "Onboard the tenant for DLP/Malware and grant appropriate scopes.",
        "gate": false
      },
      {
        "id": "policy_and_quarantine",
        "label": "Policy and quarantine",
        "detail": "Configure data-at-rest rules and the required quarantine location.",
        "gate": false
      },
      {
        "id": "start_scan",
        "label": "Start scan",
        "detail": "A scan configuration must reference a policy and be started.",
        "gate": true
      },
      {
        "id": "data_window",
        "label": "Data window",
        "detail": "Initialised is not running. Rule edits can reset the active/historical cutoff.",
        "gate": false
      },
      {
        "id": "dictionary_and_engine",
        "label": "Dictionary and engine",
        "detail": "Inspect each eligible file with dictionaries and DLP engines.",
        "gate": false
      },
      {
        "id": "file_verdict",
        "label": "File verdict",
        "detail": "Apply the configured per-file rule and app-supported remediation.",
        "gate": false
      },
      {
        "id": "analytics",
        "label": "Analytics",
        "detail": "Review scan analytics; readiness/posture is a separate assessment.",
        "gate": false
      },
      {
        "id": "evidence_and_wa",
        "label": "Evidence and WA",
        "detail": "Configured evidence forwarding can feed Workflow Automation.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Scan never started",
        "stopAt": 2,
        "note": "Policies alone do not scan data; the remaining inspection path is not_reached."
      }
    ],
    "web": false,
    "note": "DSPM posture and Copilot readiness are separate assessments, not inline enforcement stages.",
    "title": "SaaS Security API architecture",
    "section": "saas",
    "kind": "figure",
    "image": "/static/reference/dsa/saas.webp",
    "sourceCaption": "SaaS Security API architecture: sanctioned tenants and onboarding, policy rules and the scan configuration lifecycle (initialised, running, stopped, the cutoff-date trap), verdict per file, remediation vocabulary by app family, the Copilot readiness assessment, analytics, forwarding and Workflow Automation."
  },
  {
    "id": "sspm",
    "lane": "SSPM posture",
    "stages": [
      {
        "id": "onboard_sspm",
        "label": "Onboard SSPM",
        "detail": "Select the platform-specific SSPM onboarding path.",
        "gate": false
      },
      {
        "id": "grant_scopes",
        "label": "Grant scopes",
        "detail": "An administrator grants the supported posture scopes.",
        "gate": true
      },
      {
        "id": "poll_and_ingest",
        "label": "Poll and ingest",
        "detail": "Collect supported SaaS configuration posture.",
        "gate": false
      },
      {
        "id": "assess_posture",
        "label": "Assess posture",
        "detail": "Evaluate predefined controls and severity.",
        "gate": false
      },
      {
        "id": "app_governance",
        "label": "App governance",
        "detail": "Assess third-party application access.",
        "gate": false
      },
      {
        "id": "outputs",
        "label": "Outputs",
        "detail": "Publish compliance roll-ups, tickets, workflows and notification channels.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Scopes missing",
        "stopAt": 1,
        "note": "Posture ingestion is unavailable; no assessment result is inferred."
      }
    ],
    "web": false,
    "note": "SSPM posture telemetry is separate from content DLP. It does not feed a DLP evidence incident by assumption.",
    "title": "SSPM architecture",
    "section": "saas",
    "kind": "figure",
    "image": "/static/reference/dsa/sspm.webp",
    "sourceCaption": "SSPM: onboarding (the platform decides the path), the scopes admins grant, poll and ingest, posture assessment (predefined controls, severity, guided remediation), third-party app governance, and the outputs: compliance roll-ups, tickets, workflows, notification channels."
  },
  {
    "id": "edmidm-1",
    "lane": "Detection comparison",
    "stages": [
      {
        "id": "patterns_and_phrases",
        "label": "Patterns and Phrases",
        "detail": "Recognises shapes, such as an SSN-shaped string, without knowing your records.",
        "gate": false
      },
      {
        "id": "exact_data_match",
        "label": "Exact Data Match",
        "detail": "Recognises only records in your completed EDM index.",
        "gate": false
      },
      {
        "id": "indexed_document_match",
        "label": "Indexed Document Match",
        "detail": "Recognises copies or overlap with your indexed documents.",
        "gate": false
      },
      {
        "id": "dictionary_count",
        "label": "Dictionary count",
        "detail": "Each chosen detector returns its own match count.",
        "gate": false
      },
      {
        "id": "engine_verdict",
        "label": "Engine verdict",
        "detail": "An engine applies configured thresholds and Boolean logic.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "These are alternative detection techniques; the animation compares them rather than asserting all three run.",
    "title": "Patterns and Phrases versus EDM versus IDM",
    "section": "edmidm",
    "kind": "figure",
    "image": "/static/reference/dsa/edmidm-1.webp",
    "sourceCaption": "Patterns & Phrases recognise a shape (any SSN-shaped string fires); EDM fires only on your indexed records; IDM fires on copies of your documents. All three end as a match count handed to the engine."
  },
  {
    "id": "edmidm-2",
    "lane": "Index distribution",
    "stages": [
      {
        "id": "index_tool_vm",
        "label": "Index Tool VM",
        "detail": "On premises, the Index Tool prepares templates and hashes.",
        "gate": false
      },
      {
        "id": "completed_template",
        "label": "Completed template",
        "detail": "The template must reach Completed before use.",
        "gate": true
      },
      {
        "id": "dictionary_creation",
        "label": "Dictionary creation",
        "detail": "Completed templates become EDM or IDM dictionaries.",
        "gate": false
      },
      {
        "id": "engine_channels",
        "label": "Engine Channels",
        "detail": "The engine selects eligible inline, SaaS API and email channels.",
        "gate": false
      },
      {
        "id": "endpoint_edm",
        "label": "Endpoint EDM",
        "detail": "Endpoint EDM uses the same index with a pre-filter.",
        "gate": false
      },
      {
        "id": "endpoint_idm",
        "label": "Endpoint IDM",
        "detail": "Endpoint IDM uses a separately built endpoint index.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Template incomplete",
        "stopAt": 1,
        "note": "The dictionary cannot yet be created; no engine or distribution is reached."
      }
    ],
    "web": false,
    "note": "Endpoint branches are distinct distributions; web inspection prerequisites apply only in the consuming inline channel.",
    "title": "EDM and IDM architecture from the Index Tool VM to the channels",
    "section": "edmidm",
    "kind": "figure",
    "image": "/static/reference/dsa/edmidm-2.webp",
    "sourceCaption": "Your premises: the Index Tool VM builds EDM and IDM templates and makes the hashes. Zscaler cloud: templates become dictionaries, the engine's Channels gate distributes them to inline, SaaS API and email. Endpoint is the special case: EDM uses the same index plus a pre-filter; IDM is built separately for endpoints."
  },
  {
    "id": "edmidm-3",
    "lane": "EDM models",
    "stages": [
      {
        "id": "anchor_model",
        "label": "Anchor model",
        "detail": "Default anchor matching requires the one primary identifying field.",
        "gate": true
      },
      {
        "id": "corroboration",
        "label": "Corroboration",
        "detail": "Secondary fields alone never trigger the anchor model.",
        "gate": false
      },
      {
        "id": "composite_alternative",
        "label": "Composite alternative",
        "detail": "Without primary keys, all mandatory fields and at least N optional fields must match.",
        "gate": false
      },
      {
        "id": "migration_warning",
        "label": "Migration warning",
        "detail": "The org-wide model switch requires deleting existing EDM objects. This reference demo makes no changes.",
        "gate": false
      },
      {
        "id": "dictionary_result",
        "label": "Dictionary result",
        "detail": "The configured model returns qualifying match counts.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Anchor absent",
        "stopAt": 0,
        "note": "Secondaries alone are insufficient; the successful-match path is not_reached."
      }
    ],
    "web": false,
    "note": "Anchor and composite are alternative models. The demo does not perform the destructive migration.",
    "title": "EDM anchor model versus composite model",
    "section": "edmidm",
    "kind": "figure",
    "image": "/static/reference/dsa/edmidm-3.webp",
    "sourceCaption": "With primary keys (the anchor model, default): a match must contain the one field that identifies the record; secondaries alone never fire. Without primary keys (the composite model): all mandatory fields and at least N optional fields; an org-wide switch that requires deleting every existing EDM object first."
  },
  {
    "id": "aisec",
    "lane": "AI endpoint / inline / AI Guard",
    "stages": [
      {
        "id": "endpoint_discovery",
        "label": "Endpoint discovery",
        "detail": "Identify and group agents, then apply endpoint clipboard and file-access controls.",
        "gate": false
      },
      {
        "id": "web_capture",
        "label": "Web capture",
        "detail": "The supported AI destination is captured in the separate inline branch.",
        "gate": false
      },
      {
        "id": "ssl_tls_inspection",
        "label": "SSL/TLS Inspection",
        "detail": "The web branch must decrypt relevant traffic.",
        "gate": true
      },
      {
        "id": "cloud_app_control",
        "label": "Cloud App Control",
        "detail": "An applicable application block ends the web path.",
        "gate": true
      },
      {
        "id": "url_filtering",
        "label": "URL Filtering",
        "detail": "URL policy may stop the AI destination before content inspection.",
        "gate": true
      },
      {
        "id": "file_type_control",
        "label": "File Type Control",
        "detail": "File policy can block a file before DLP.",
        "gate": true
      },
      {
        "id": "zia_dictionary_and_engine",
        "label": "ZIA dictionary and engine",
        "detail": "ZIA dictionaries and engines inspect supported file/content traffic.",
        "gate": false
      },
      {
        "id": "forwarding_control",
        "label": "Forwarding Control",
        "detail": "Proxy-chain supported AI domains to AI Guard.",
        "gate": false
      },
      {
        "id": "ai_guard_prompt_detectors",
        "label": "AI Guard prompt detectors",
        "detail": "AI Guard uses its own prompt detectors, policies and tenancy context.",
        "gate": false
      },
      {
        "id": "ai_guard_response_detectors",
        "label": "AI Guard response detectors",
        "detail": "AI Guard uses its own response detectors; allowed files pass through without documented file inspection.",
        "gate": false
      },
      {
        "id": "separate_telemetry",
        "label": "Separate telemetry",
        "detail": "ZIA file incidents can use WA. AI Guard exports and its own portal are separate; no NSS or WA integration is documented.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "URL blocks AI destination",
        "stopAt": 4,
        "note": "The inline branch stops before DLP and AI Guard."
      },
      {
        "id": "stop_1",
        "label": "File type blocked",
        "stopAt": 5,
        "note": "The file does not reach ZIA DLP or AI Guard in this sample."
      }
    ],
    "web": true,
    "note": "Endpoint, ZIA and AI Guard are separate enforcement domains; this walkthrough follows one sample and labels their boundaries.",
    "title": "AI security architecture across endpoint, inline and AI Guard",
    "section": "aisec",
    "kind": "figure",
    "image": "/static/reference/dsa/aisec.webp",
    "sourceCaption": "Part 1 on the endpoint: find the agents, group them, control clipboard and application file access. Part 2 inline: the gauntlet, then Forwarding Control proxy-chains AI domains to AI Guard. Part 3 AI Guard: policy controls, prompt detectors, response detectors, its own dashboard and log exports. Supported AI destinations below."
  },
  {
    "id": "workflow-1",
    "lane": "Evidence plumbing",
    "stages": [
      {
        "id": "forwarding_option",
        "label": "Forwarding option",
        "detail": "Choose cloud-to-cloud or a ZIR VM; options are alternatives.",
        "gate": false
      },
      {
        "id": "cloud_storage_gate",
        "label": "Cloud storage gate",
        "detail": "Workflow Automation requires supported cloud buckets and storage events.",
        "gate": true
      },
      {
        "id": "rule_forwarding",
        "label": "Rule forwarding",
        "detail": "The rule must target the forwarder that writes to this storage.",
        "gate": false
      },
      {
        "id": "storage_event",
        "label": "Storage event",
        "detail": "Cloud-specific event plumbing signals metadata creation.",
        "gate": true
      },
      {
        "id": "validate_integration",
        "label": "Validate integration",
        "detail": "Validate and enable the DLP Application Integration.",
        "gate": false
      },
      {
        "id": "wa_metadata",
        "label": "WA metadata",
        "detail": "Workflow Automation reads metadata to create incidents.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "On-prem storage only",
        "stopAt": 1,
        "note": "On-prem-only storage does not supply the required cloud event lane for WA."
      },
      {
        "id": "stop_1",
        "label": "Event plumbing broken",
        "stopAt": 3,
        "note": "No storage notification reaches Workflow Automation."
      }
    ],
    "web": false,
    "note": "",
    "title": "Evidence forwarding options and plumbing",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-1.webp",
    "sourceCaption": "Three ways to get evidence to Workflow Automation: cloud-to-cloud (no VM), a ZIR VM in your cloud, or a ZIR VM on-prem (no Workflow Automation: it needs a cloud bucket and storage events). The usual plumbing failure points per cloud."
  },
  {
    "id": "workflow-2",
    "lane": "Incident lifecycle",
    "stages": [
      {
        "id": "received",
        "label": "Received",
        "detail": "A configured evidence integration creates the incident.",
        "gate": false
      },
      {
        "id": "investigating",
        "label": "Investigating",
        "detail": "An analyst investigates the incident.",
        "gate": false
      },
      {
        "id": "validating_with_user",
        "label": "Validating with User",
        "detail": "Request the user justification.",
        "gate": false
      },
      {
        "id": "received_justification_response",
        "label": "Received Justification Response",
        "detail": "Receive a response; escalation is available from this state.",
        "gate": true
      },
      {
        "id": "escalated",
        "label": "Escalated",
        "detail": "The selected sample escalates after the response.",
        "gate": false
      },
      {
        "id": "resolved",
        "label": "Resolved",
        "detail": "Resolve the incident. Reopen is the only route back; Delete is irreversible and is not performed here.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Awaiting response",
        "stopAt": 3,
        "note": "The response gate is not satisfied in this sample; escalation and resolution are not reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "Workflow Automation incident lifecycle",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-2.webp",
    "sourceCaption": "Incident lifecycle: Received, Investigating, Validating with User, Received Justification Response, Escalated, Resolved. Escalate is allowed only from Received Justification Response; Reopen is the only way back from Resolved; Delete is irreversible."
  },
  {
    "id": "workflow-3",
    "lane": "Workflow builder",
    "stages": [
      {
        "id": "published_workflow",
        "label": "Published workflow",
        "detail": "Only published workflows can run.",
        "gate": true
      },
      {
        "id": "notify_and_survey",
        "label": "Notify and survey",
        "detail": "Notify the user and collect justification.",
        "gate": false
      },
      {
        "id": "justification_condition",
        "label": "Justification condition",
        "detail": "Select the appropriate branch for the answer.",
        "gate": false
      },
      {
        "id": "selected_escalation_branch",
        "label": "Selected escalation branch",
        "detail": "This sample escalates and creates a ticket.",
        "gate": false
      },
      {
        "id": "close_incident",
        "label": "Close incident",
        "detail": "Close after the selected branch finishes. Use one Close per branch and never escalate after Close.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Unpublished workflow",
        "stopAt": 0,
        "note": "An unpublished workflow does not run; all action stages remain not_reached."
      }
    ],
    "web": false,
    "note": "The alternative false-positive branch closes directly; the animation follows the escalation example only.",
    "title": "Workflow builder tiles and an example flow",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-3.webp",
    "sourceCaption": "The action tile palette (Notify, Escalate, Create Ticket, Close Incident, Create Policy Exception) and an example published flow: notify and survey, a justification condition, then close as false positive or escalate with a ticket. One Close per branch; no escalate after Close."
  },
  {
    "id": "workflow-4",
    "lane": "False-positive workflow",
    "stages": [
      {
        "id": "incident_attributes",
        "label": "Incident attributes",
        "detail": "Read the rule, application and severity from the incident.",
        "gate": false
      },
      {
        "id": "group_mapping",
        "label": "Group mapping",
        "detail": "Map known-noisy patterns to the false-positive queue.",
        "gate": false
      },
      {
        "id": "auto_close",
        "label": "Auto-close",
        "detail": "Close with the configured false-positive resolution label.",
        "gate": false
      },
      {
        "id": "tuning_feedback",
        "label": "Tuning feedback",
        "detail": "False-positive flags provide evidence for later tuning, not automatic tenant changes.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "",
    "title": "Auto-close false positives use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-4.webp",
    "sourceCaption": "Use case: known-noisy patterns. Group mapping (rule + app + severity) routes them to an FP queue group that auto-closes with a resolution label; the FP flags become ground truth for tuning."
  },
  {
    "id": "workflow-5",
    "lane": "User justification workflow",
    "stages": [
      {
        "id": "notify_user",
        "label": "Notify user",
        "detail": "Send the configured notification and survey in the real workflow; this demo sends nothing.",
        "gate": false
      },
      {
        "id": "await_justification",
        "label": "Await justification",
        "detail": "The real workflow can send reminders until the user responds.",
        "gate": true
      },
      {
        "id": "evaluate_answer",
        "label": "Evaluate answer",
        "detail": "The selected sample has a valid justification.",
        "gate": false
      },
      {
        "id": "close_justified",
        "label": "Close justified",
        "detail": "Close with the configured justified resolution label.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "No response yet",
        "stopAt": 1,
        "note": "The sample is waiting; evaluation and close are not reached."
      }
    ],
    "web": false,
    "note": "A bad answer follows the separate escalation path rather than this justified-close sample.",
    "title": "Notify user and close use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-5.webp",
    "sourceCaption": "Use case: notify and survey. The user justifies (reminders until answered); auto-close \"justified\" with a resolution label, or a bad answer goes to the escalation path."
  },
  {
    "id": "workflow-6",
    "lane": "Manager escalation",
    "stages": [
      {
        "id": "justification_response",
        "label": "Justification response",
        "detail": "Escalation is available only from Received Justification Response.",
        "gate": true
      },
      {
        "id": "manager_attributes",
        "label": "Manager attributes",
        "detail": "SCIM or CSV-imported attributes must provide the manager.",
        "gate": true
      },
      {
        "id": "escalate_manager",
        "label": "Escalate manager",
        "detail": "Route the escalation to the manager.",
        "gate": false
      },
      {
        "id": "create_ticket",
        "label": "Create ticket",
        "detail": "Create the configured downstream ticket.",
        "gate": false
      },
      {
        "id": "ticket_closes_incident",
        "label": "Ticket closes incident",
        "detail": "The configured workflow closes the incident when the ticket closes.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "No justification response",
        "stopAt": 0,
        "note": "Escalation is not available before a response."
      },
      {
        "id": "stop_1",
        "label": "Manager not imported",
        "stopAt": 1,
        "note": "No manager lookup is available; escalation and ticket stages are not_reached."
      }
    ],
    "web": false,
    "note": "",
    "title": "Escalation to manager use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-6.webp",
    "sourceCaption": "Use case: escalation. Only from Received Justification Response: escalate to the manager (found via imported user attributes), create a ticket, close on ticket close. No SCIM / CSV import means no manager lookup and the path is silently unavailable."
  },
  {
    "id": "workflow-7",
    "lane": "Policy exception workflow",
    "stages": [
      {
        "id": "supported_source",
        "label": "Supported source",
        "detail": "The blocked transfer must be inline web or email.",
        "gate": true
      },
      {
        "id": "user_justification",
        "label": "User justification",
        "detail": "The user explains the legitimate transfer.",
        "gate": false
      },
      {
        "id": "independent_approver",
        "label": "Independent approver",
        "detail": "An approver outside the DLP admin team reviews.",
        "gate": false
      },
      {
        "id": "time_limited_exception",
        "label": "Time-limited exception",
        "detail": "Approved workflow creates a per-user subrule under the violated rule.",
        "gate": false
      },
      {
        "id": "expiry",
        "label": "Expiry",
        "detail": "The exception is time-limited; this reference player never creates a real exception.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Unsupported source channel",
        "stopAt": 0,
        "note": "Endpoint and SaaS source incidents are not eligible for this exception workflow."
      }
    ],
    "web": false,
    "note": "",
    "title": "Policy exception use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-7.webp",
    "sourceCaption": "Use case: policy exception. A legitimate transfer blocked by an inline web or email rule, the user justifies, an approver outside the DLP admin team reviews, and a time-limited per-user subrule is created under the violated rule. Inline and Email only."
  },
  {
    "id": "workflow-8",
    "lane": "Email quarantine workflow",
    "stages": [
      {
        "id": "exchange_online",
        "label": "Exchange Online",
        "detail": "Quarantine release applies to Exchange Online.",
        "gate": true
      },
      {
        "id": "transport_hold",
        "label": "Transport hold",
        "detail": "An Exchange transport rule holds the message.",
        "gate": false
      },
      {
        "id": "wa_incident",
        "label": "WA incident",
        "detail": "Configured evidence creates the Workflow Automation incident.",
        "gate": false
      },
      {
        "id": "review_release",
        "label": "Review release",
        "detail": "An analyst or the end user chooses the permitted disposition.",
        "gate": false
      },
      {
        "id": "sample_release",
        "label": "Sample release",
        "detail": "This sample describes release; delete is an alternative, never executed by this demo.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Non-Exchange platform",
        "stopAt": 0,
        "note": "This quarantine-release path is not applicable to other email platforms."
      }
    ],
    "web": false,
    "note": "",
    "title": "Email quarantine release use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-8.webp",
    "sourceCaption": "Use case: email quarantine release. Exchange holds the mail via a transport rule; the incident lands in Workflow Automation; the analyst (or the end user) releases or deletes. Exchange Online only."
  },
  {
    "id": "workflow-9",
    "lane": "Restricted administration",
    "stages": [
      {
        "id": "incident_attributes",
        "label": "Incident attributes",
        "detail": "Use business unit, region and source type.",
        "gate": false
      },
      {
        "id": "group_mapping",
        "label": "Group mapping",
        "detail": "Apply the configured mappings and default group.",
        "gate": false
      },
      {
        "id": "admin_assignment",
        "label": "Admin assignment",
        "detail": "Assign each restricted administrator to permitted incident groups.",
        "gate": true
      },
      {
        "id": "restricted_view",
        "label": "Restricted view",
        "detail": "The administrator sees only assigned groups; hidden incidents are not proof of failed ingestion.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Group not assigned",
        "stopAt": 2,
        "note": "That restricted administrator cannot reach the incident view for this group."
      }
    ],
    "web": false,
    "note": "",
    "title": "Restricted admins by incident group use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-9.webp",
    "sourceCaption": "Use case: restricted admins. Group mappings by BU, region and source type; each desk's restricted admin sees only its group via Admin Assignments."
  },
  {
    "id": "workflow-10",
    "lane": "Incident privacy",
    "stages": [
      {
        "id": "obfuscate_attributes",
        "label": "Obfuscate attributes",
        "detail": "Account Settings chooses which identity attributes are obfuscated.",
        "gate": false
      },
      {
        "id": "content_triage",
        "label": "Content triage",
        "detail": "Triage using available content and severity.",
        "gate": false
      },
      {
        "id": "mapping_constraint",
        "label": "Mapping constraint",
        "detail": "Obfuscated attributes cannot drive group mappings.",
        "gate": false
      },
      {
        "id": "escalation_justification",
        "label": "Escalation justification",
        "detail": "Only justified escalation exposes permitted identity to the approver.",
        "gate": false
      },
      {
        "id": "quarantine_constraint",
        "label": "Quarantine constraint",
        "detail": "An obfuscated recipient prevents quarantine release; the player does not expose identity.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      }
    ],
    "web": false,
    "note": "",
    "title": "Identity obfuscation use case",
    "section": "workflow",
    "kind": "figure",
    "image": "/static/reference/dsa/workflow-10.webp",
    "sourceCaption": "Use case: privacy. Identity obfuscated per attribute in Account Settings; triage on content and severity; the approver sees identity only when escalation is justified. Obfuscated attributes cannot drive group mappings and quarantine release breaks on an obfuscated recipient."
  },
  {
    "id": "setup-detection",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "index_template",
        "label": "Index template",
        "detail": "EDM / IDM only: Index Tool config in Admin Console → deploy Index Tool VM → template reaches Completed. Skipped → the dictionary type can't even be created.",
        "gate": true
      },
      {
        "id": "dictionaries",
        "label": "Dictionaries",
        "detail": "Create DLP dictionaries (Patterns & Phrases / EDM / IDM / MIP) — confidence thresholds live here.",
        "gate": false
      },
      {
        "id": "engines_and_channels",
        "label": "Engines and Channels",
        "detail": "Build DLP engines (Boolean expression, match counts are strict \"> N\") and set each engine's Channels.",
        "gate": false
      },
      {
        "id": "notification_pair",
        "label": "Notification pair",
        "detail": "Create notification templates; create auditors. A rule needs BOTH auditor and template or no email is ever sent.",
        "gate": true
      },
      {
        "id": "evidence_forwarder",
        "label": "Evidence forwarder",
        "detail": "Deploy Zscaler Incident Receiver or configure Cloud-to-Cloud Forwarding before building rules that should feed Workflow Automation.",
        "gate": false
      },
      {
        "id": "advanced_settings",
        "label": "Advanced settings",
        "detail": "Check DLP Advanced Settings: OCR per channel, exemption lists (they override rules), evaluation mode.",
        "gate": false
      },
      {
        "id": "activate",
        "label": "Activate",
        "detail": "Activate. Saved ≠ active.",
        "gate": true
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: Index template",
        "stopAt": 0,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      },
      {
        "id": "stop_1",
        "label": "Missing: Notification pair",
        "stopAt": 3,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      },
      {
        "id": "stop_2",
        "label": "Missing: Activate",
        "stopAt": 6,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Universal first: detection building blocks",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "Universal first: detection building blocks"
  },
  {
    "id": "setup-inline",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "traffic_forwarding",
        "label": "Traffic forwarding",
        "detail": "Traffic forwarding + user provisioning (ZCC / tunnels / PAC).",
        "gate": false
      },
      {
        "id": "ssl_tls_inspection",
        "label": "SSL/TLS Inspection",
        "detail": "Enable SSL/TLS inspection and confirm target traffic is actually decrypted. Skipped → DLP never sees HTTPS payloads.",
        "gate": true
      },
      {
        "id": "build_inline_rule",
        "label": "Build inline rule",
        "detail": "Build the DLP rule (engines ≤ 4, criteria are AND-ed; users / groups / departments OR-ed).",
        "gate": false
      },
      {
        "id": "evidence_selection",
        "label": "Evidence selection",
        "detail": "Select Incident Receiver / C2C on the rule if incidents should reach Workflow Automation. The most-missed link.",
        "gate": true
      },
      {
        "id": "notify_and_activate",
        "label": "Notify and activate",
        "detail": "Set auditor + template; EUN show / hide; activate.",
        "gate": false
      },
      {
        "id": "upstream_policy_order",
        "label": "Upstream policy order",
        "detail": "Remember policy order: File Type Control and Cloud App Control run before DLP on POSTs.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: SSL/TLS Inspection",
        "stopAt": 1,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      },
      {
        "id": "stop_1",
        "label": "Missing: Evidence selection",
        "stopAt": 3,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": true,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Inline Web DLP",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "Inline Web DLP"
  },
  {
    "id": "setup-endpoint",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "supported_platform",
        "label": "Supported platform",
        "detail": "Verify platforms (Win 10 2004+ / 11 64-bit, no ARM; macOS 14+; ZCC 4.3 / 4.2+); allowlist ZDP in AV / EDR.",
        "gate": false
      },
      {
        "id": "macos_full_disk_access",
        "label": "macOS Full Disk Access",
        "detail": "macOS: push Full Disk Access via MDM before Endpoint DLP installs.",
        "gate": false
      },
      {
        "id": "endpoint_resources",
        "label": "Endpoint resources",
        "detail": "Create Endpoint Resources (printers, USB by VID / PID / serial, shares) + tags — required for per-device targeting and exceptions.",
        "gate": false
      },
      {
        "id": "endpoint_rules",
        "label": "Endpoint rules",
        "detail": "Build endpoint rules (channel, engines ≤ 4, actions Allow / Block / Confirm / Protect; ≤ 32 exceptions).",
        "gate": false
      },
      {
        "id": "install_endpoint_dlp",
        "label": "Install Endpoint DLP",
        "detail": "Enable \"Install Endpoint DLP\" in the ZCC app profile. Skipped → cloud policy, zero enforcement.",
        "gate": true
      },
      {
        "id": "policy_sync_and_nss",
        "label": "Policy sync and NSS",
        "detail": "Wait for the 15-min policy pull (or force update); configure NSS feeds if SIEM export is wanted.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: Install Endpoint DLP",
        "stopAt": 4,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Endpoint DLP",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "Endpoint DLP"
  },
  {
    "id": "setup-email",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "company_domains",
        "label": "Company domains",
        "detail": "Domains in Company Profile (feeds the tenant's domain dropdown).",
        "gate": false
      },
      {
        "id": "email_tenant",
        "label": "Email tenant",
        "detail": "Add Email Tenant → copy Smart Host FQDN + Key for Transport Rules; set per-domain next hop.",
        "gate": false
      },
      {
        "id": "platform_transport",
        "label": "Platform transport",
        "detail": "Platform side: connectors / route to smart host + tenant-ID header + loop prevention + header-enforcement rules. No enforcement rule → silent monitor-only. No loop guard → mail loop.",
        "gate": true
      },
      {
        "id": "recipient_profiles",
        "label": "Recipient profiles",
        "detail": "Domain / recipient profiles for recipient scoping.",
        "gate": false
      },
      {
        "id": "email_policies",
        "label": "Email policies",
        "detail": "Outbound Email Policy rules (per-recipient, most restrictive; Quarantine = Exchange only).",
        "gate": false
      },
      {
        "id": "enforce_last",
        "label": "Enforce last",
        "detail": "Flip platform rules from test to Enforce last. Gmail changes propagate up to 24 h.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: Platform transport",
        "stopAt": 2,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Email DLP",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "Email DLP"
  },
  {
    "id": "setup-saas",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "onboard_purposes",
        "label": "Onboard purposes",
        "detail": "Onboard the SaaS tenant — the \"Onboard for\" checkboxes (DLP / Malware vs SSPM vs Workflow Automation) fork everything downstream; file apps need a quarantine location at onboarding.",
        "gate": false
      },
      {
        "id": "platform_authorization",
        "label": "Platform authorization",
        "detail": "Per-platform authorization (M365 Global Reader on the connector ID; Google Cloud Identity licence; S3 IAM role + CloudTrail + quarantine bucket…).",
        "gate": false
      },
      {
        "id": "data_at_rest_rules",
        "label": "Data-at-rest rules",
        "detail": "Create Data-at-Rest DLP and / or Malware rules (tombstone template required for quarantine actions).",
        "gate": false
      },
      {
        "id": "start_scan",
        "label": "Start scan",
        "detail": "Create a Scan Configuration (1 per tenant, ≥ 1 policy) and press Start. No scan → policies do literally nothing.",
        "gate": true
      },
      {
        "id": "cutoff_and_queue",
        "label": "Cutoff and queue",
        "detail": "Watch the cutoff quirk: editing any rule mid-scan resets the active / historical cutoff date; stopping a scan flushes its queue.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: Start scan",
        "stopAt": 3,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "SaaS Security API / SSPM",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "SaaS Security API / SSPM"
  },
  {
    "id": "setup-workflow",
    "lane": "Setup checklist",
    "stages": [
      {
        "id": "workflow_access",
        "label": "Workflow Access",
        "detail": "Grant ZIA admins the Workflow Access permission.",
        "gate": false
      },
      {
        "id": "storage_integration",
        "label": "Storage integration",
        "detail": "Build the DLP Application Integration: storage buckets (-data / -metadata, same region as SNS topic, names without dots) + notification topic + cross-account role → Validate → Enable.",
        "gate": false
      },
      {
        "id": "every_rule_forwarding",
        "label": "Every rule forwarding",
        "detail": "Point every channel rule at the ZIR / C2C config that writes to that storage. The #1 cause of the empty console.",
        "gate": true
      },
      {
        "id": "groups_and_assignments",
        "label": "Groups and assignments",
        "detail": "Incident groups + mappings + default group; priorities; approvers; admin assignments.",
        "gate": false
      },
      {
        "id": "user_attributes",
        "label": "User attributes",
        "detail": "Import user attributes (SCIM / CSV) — manager escalation depends on it.",
        "gate": false
      },
      {
        "id": "publish_workflows",
        "label": "Publish workflows",
        "detail": "Build workflows from templates and publish them (unpublished workflows never fire); map to incident attributes.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Missing: Every rule forwarding",
        "stopAt": 2,
        "note": "This reference check identifies an unmet dependency. Later walkthrough stages are not_reached; no tenant condition is claimed."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Workflow Automation",
    "section": "setup",
    "kind": "setup",
    "sourceCaption": "Workflow Automation"
  },
  {
    "id": "walkback-workflow",
    "lane": "Diagnostic walkback",
    "stages": [
      {
        "id": "integration_health",
        "label": "Integration health",
        "detail": "Integration health: does the DLP Application Integration exist and show Enabled (not Failed)?",
        "gate": false
      },
      {
        "id": "rule_forwarding",
        "label": "Rule forwarding",
        "detail": "Rule forwarding: do source-channel rules actually select a ZIR or C2C config? NSS feeds, auditor email, and third-party ICAP never feed WA.",
        "gate": false
      },
      {
        "id": "same_storage",
        "label": "Same storage",
        "detail": "Same storage? The rules' forwarding target must write to the buckets the integration was validated against.",
        "gate": false
      },
      {
        "id": "storage_event_plumbing",
        "label": "Storage event plumbing",
        "detail": "Storage plumbing: AWS — metadata bucket + SNS topic same region, ObjectCreated wired; names ≤ 40 chars, no dots. Azure — Event Grid topic, NAT IPs allowlisted.",
        "gate": false
      },
      {
        "id": "zir_health",
        "label": "ZIR health",
        "detail": "ZIR health (if used): VM up, cert installed, ICAP port open to Zscaler's FCC cloud, SFTP / S3 storage writable (ZIR stores nothing locally).",
        "gate": false
      },
      {
        "id": "missing_channel",
        "label": "Missing channel",
        "detail": "One channel missing? Forwarding is selected per rule — normal for endpoint incidents to arrive while email doesn't.",
        "gate": false
      },
      {
        "id": "restricted_view",
        "label": "Restricted view",
        "detail": "Not ingestion at all: restricted admins only see their assigned incident groups.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Cause found: Integration health",
        "stopAt": 0,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_1",
        "label": "Cause found: Rule forwarding",
        "stopAt": 1,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_2",
        "label": "Cause found: Same storage",
        "stopAt": 2,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_3",
        "label": "Cause found: Storage event plumbing",
        "stopAt": 3,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_4",
        "label": "Cause found: ZIR health",
        "stopAt": 4,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_5",
        "label": "Cause found: Missing channel",
        "stopAt": 5,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Workflow Automation shows no incidents",
    "section": "walkbacks",
    "kind": "walkback",
    "sourceCaption": "Workflow Automation shows no incidents"
  },
  {
    "id": "walkback-inline",
    "lane": "Diagnostic walkback",
    "stages": [
      {
        "id": "ssl_tls_inspection",
        "label": "SSL/TLS Inspection",
        "detail": "SSL inspection on, and this traffic actually decrypted (not exempted)? — cause #1.",
        "gate": false
      },
      {
        "id": "dlp_exemptions",
        "label": "DLP exemptions",
        "detail": "DLP Advanced Settings exemptions (apps / URLs / categories) override every rule.",
        "gate": false
      },
      {
        "id": "upstream_policy_order",
        "label": "Upstream policy order",
        "detail": "Policy-order pre-emption: File Type Control / Cloud App Control / URL Filtering block ends evaluation before DLP.",
        "gate": false
      },
      {
        "id": "criteria_logic",
        "label": "Criteria logic",
        "detail": "Criteria AND-logic: engines ∧ file type ∧ users ∧ location ∧ protocol… Downloads need Inspect Downloads (excludes EDM / IDM).",
        "gate": false
      },
      {
        "id": "engine_internals",
        "label": "Engine internals",
        "detail": "Engine internals: match count is \"> N\"; All-operator needs every dictionary; dictionary confidence too high.",
        "gate": false
      },
      {
        "id": "content_scan",
        "label": "Content scan",
        "detail": "Content: OCR off → images never scanned; size limits; scan timeout fails open (check Exempted DLP Identifier in Web Insights).",
        "gate": false
      },
      {
        "id": "rule_shadowing_and_activation",
        "label": "Rule shadowing and activation",
        "detail": "First-match shadowing by an earlier rule (even an Allow). And: activated, not just saved?",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Cause found: SSL/TLS Inspection",
        "stopAt": 0,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_1",
        "label": "Cause found: DLP exemptions",
        "stopAt": 1,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_2",
        "label": "Cause found: Upstream policy order",
        "stopAt": 2,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_3",
        "label": "Cause found: Criteria logic",
        "stopAt": 3,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_4",
        "label": "Cause found: Engine internals",
        "stopAt": 4,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_5",
        "label": "Cause found: Content scan",
        "stopAt": 5,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      }
    ],
    "web": true,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Inline web rule never fires",
    "section": "walkbacks",
    "kind": "walkback",
    "sourceCaption": "Inline web rule never fires"
  },
  {
    "id": "walkback-endpoint",
    "lane": "Diagnostic walkback",
    "stages": [
      {
        "id": "module_installed",
        "label": "Module installed",
        "detail": "ZDP module installed? (\"Install Endpoint DLP\" in the ZCC app profile — check the device's Data Protection window.)",
        "gate": false
      },
      {
        "id": "platform_support",
        "label": "Platform support",
        "detail": "Platform support: no Windows ARM; macOS Full Disk Access pushed before install; minimum ZCC versions.",
        "gate": false
      },
      {
        "id": "policy_sync",
        "label": "Policy sync",
        "detail": "Policy sync: 15-minute pull; force with Update DLP Policy.",
        "gate": false
      },
      {
        "id": "otp_exemption",
        "label": "OTP exemption",
        "detail": "Active 12-hour OTP exemption on the device (works offline).",
        "gate": false
      },
      {
        "id": "resource_targeting",
        "label": "Resource targeting",
        "detail": "Resource targeting mismatch (USB VID / PID / serial, printer identity).",
        "gate": false
      },
      {
        "id": "engine_channel",
        "label": "Engine channel",
        "detail": "Engine missing the Endpoint DLP channel; parent / sub dictionaries unsupported on endpoint.",
        "gate": false
      },
      {
        "id": "all_rule_evaluation",
        "label": "All-rule evaluation",
        "detail": "Evaluation surprise: ALL rules evaluated, most restrictive wins — an Allow exception on one rule doesn't stop another rule.",
        "gate": false
      },
      {
        "id": "av_and_edr",
        "label": "AV and EDR",
        "detail": "AV / EDR quarantined the ZDP module (allowlist paths).",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Cause found: Module installed",
        "stopAt": 0,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_1",
        "label": "Cause found: Platform support",
        "stopAt": 1,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_2",
        "label": "Cause found: Policy sync",
        "stopAt": 2,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_3",
        "label": "Cause found: OTP exemption",
        "stopAt": 3,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_4",
        "label": "Cause found: Resource targeting",
        "stopAt": 4,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_5",
        "label": "Cause found: Engine channel",
        "stopAt": 5,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_6",
        "label": "Cause found: All-rule evaluation",
        "stopAt": 6,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Endpoint DLP not enforcing on a device",
    "section": "walkbacks",
    "kind": "walkback",
    "sourceCaption": "Endpoint DLP not enforcing on a device"
  },
  {
    "id": "walkback-email",
    "lane": "Diagnostic walkback",
    "stages": [
      {
        "id": "platform_enforcement",
        "label": "Platform enforcement",
        "detail": "Enforcement is delegated: is there a platform rule matching X-Zscaler-Block: 1? Without it: silent monitor-only.",
        "gate": false
      },
      {
        "id": "smart_host_routing",
        "label": "Smart host routing",
        "detail": "Is mail reaching the smart host at all (connector / route present and enforced; Gmail propagation up to 24 h)?",
        "gate": false
      },
      {
        "id": "tenant_header",
        "label": "Tenant header",
        "detail": "Tenant-ID header stamped with the Key for Transport Rules?",
        "gate": false
      },
      {
        "id": "return_path",
        "label": "Return path",
        "detail": "Return path accepted (Exchange receive connector / Gmail SMTP-relay IP allowlist from config.zscaler.com)?",
        "gate": false
      },
      {
        "id": "loop_prevention",
        "label": "Loop prevention",
        "detail": "Loop prevention present (Except-if on X-Zscaler-Block / source-IP-not-in-range)?",
        "gate": false
      },
      {
        "id": "quarantine_support",
        "label": "Quarantine support",
        "detail": "Quarantine is Exchange-only and its header must be mapped; Block always beats Quarantine.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Cause found: Platform enforcement",
        "stopAt": 0,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_1",
        "label": "Cause found: Smart host routing",
        "stopAt": 1,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_2",
        "label": "Cause found: Tenant header",
        "stopAt": 2,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_3",
        "label": "Cause found: Return path",
        "stopAt": 3,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_4",
        "label": "Cause found: Loop prevention",
        "stopAt": 4,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "Email DLP blocks nothing (tagged but delivered)",
    "section": "walkbacks",
    "kind": "walkback",
    "sourceCaption": "Email DLP blocks nothing (tagged but delivered)"
  },
  {
    "id": "walkback-saas",
    "lane": "Diagnostic walkback",
    "stages": [
      {
        "id": "scan_started",
        "label": "Scan started",
        "detail": "Does a scan exist, reference ≥ 1 policy, and was it started? \"Scan Initialized\" is still prereq-checking.",
        "gate": false
      },
      {
        "id": "tenant_status",
        "label": "Tenant status",
        "detail": "Tenant status Active? Validation Failed / Reauthorization Required = scanning silently stopped.",
        "gate": false
      },
      {
        "id": "data_window",
        "label": "Data window",
        "detail": "Data window: \"New Data Only\" scans nothing historical; per-app caveats (Webex 15-day cap, Zoom features).",
        "gate": false
      },
      {
        "id": "rule_targeting",
        "label": "Rule targeting",
        "detail": "Rule targeting: one provider per rule; trusted users / domains suppress matches as \"internal\".",
        "gate": false
      },
      {
        "id": "cutoff_reset",
        "label": "Cutoff reset",
        "detail": "Cutoff reset: any rule edit mid-scan moves the active / historical cutoff to the edit date.",
        "gate": false
      },
      {
        "id": "malware_schedule",
        "label": "Malware schedule",
        "detail": "Public-cloud malware circularity: save rule → create schedule → reopen rule to pick buckets.",
        "gate": false
      }
    ],
    "scenarios": [
      {
        "id": "reference",
        "label": "Reference sample path",
        "note": "Illustrative reference sequence; no tenant configuration or live traffic was read."
      },
      {
        "id": "stop_0",
        "label": "Cause found: Scan started",
        "stopAt": 0,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_1",
        "label": "Cause found: Tenant status",
        "stopAt": 1,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_2",
        "label": "Cause found: Data window",
        "stopAt": 2,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_3",
        "label": "Cause found: Rule targeting",
        "stopAt": 3,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      },
      {
        "id": "stop_4",
        "label": "Cause found: Cutoff reset",
        "stopAt": 4,
        "note": "The selected sample finds the cause at this check. Remaining checks are not_reached, not verified healthy."
      }
    ],
    "web": false,
    "note": "Instructional checklist only: controls never install, activate, modify, query or send anything to a tenant.",
    "title": "SaaS API scan finds nothing",
    "section": "walkbacks",
    "kind": "walkback",
    "sourceCaption": "SaaS API scan finds nothing"
  }
];
  function freeze(value) {
    Object.keys(value).forEach(function (key) { if (value[key] && typeof value[key] === 'object') freeze(value[key]); });
    return Object.freeze(value);
  }
  var byId = {};
  flows.forEach(function (flow) { byId[flow.id] = flow; });
  return freeze({ snapshot: '2026-09-29', flows: flows, byId: byId });
}));
