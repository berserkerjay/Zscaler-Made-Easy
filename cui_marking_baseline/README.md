# CUI Marking Baseline — dictionary notes

Build metadata from the original design (tier, intended action, minimum match count, notes). The pack files carry the API fields only.

| Dictionary | Tier | Intended action | Min matches | Notes |
|---|---|---|---|---|
| CUI-Banner-Structural | 1 | Block | 1 | Single pattern covers both Basic (CUI//PRVCY) and Specified (CUI//SP-CTI). Do not add a separate SP- pattern - it double-counts the same marking. |
| CUI-Banner-LDC | 1 | Block | 1 |  |
| CUI-PortionMark-Structural | 1 | Block | 2 | Min count 2 at rule level - a single parenthetical is FP-prone. |
| CUI-Basic-Bare | 1 | Caution | 3 | Highest-volume / lowest-precision dictionary in the set. UNIQUE counting plus min count 3 at rule level. Never wire this one to Block. |
| CUI-LDC-Standalone | 1 | Caution | 1 | Standalone value: LDCs survive in footers after banner stripping. |
| CUI-Code-CTI | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-PRVCY | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-PROPIN | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-SSEL | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-ISVI | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-OPSEC | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-NNPI | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-PCII | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Code-CVI | 2 | Block | 1 | Token has no plain-English collision - no CUI anchor needed. |
| CUI-Prox-EXPT | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-TAX | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-LEI | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-CRIT | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-NUC | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-INTEL | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-LEGAL | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| CUI-Prox-PROCURE | 3 | Caution | 1 | MATCH_ALL + proximity: both patterns must fall inside the window. Window is bidirectional and byte-measured over extracted text. |
| Legacy-FOUO | 4 | Block | 1 |  |
| Legacy-LES | 4 | Block | 1 | Bare LES is deliberately excluded - collides with French text, surnames, and unrelated acronyms. Spelled form or banner context only. |
| Legacy-SBU | 4 | Block | 1 |  |
| Legacy-Distribution-Statements | 4 | Block | 1 | Very high signal on CTI-bearing engineering documents. |
| CUI-Designation-Indicator | 5 | Caution | 3 | MATCH_ANY with min count 3 enforced at the engine - a single field label is meaningless, three co-located is a designation block. |
| CUI-Decontrol-Context | 6 | Exclude | 1 | DOCUMENT-SCOPED exclusion. A genuine CUI document that cites its own marking guide will suppress. Record this in the residual-risk statement. |

## Engines

- **CUI-Detect-All**: the full surface, as designed (two nested OR groups for the 16-dictionary ceiling, decontrol excluded).
- **CUI-Detect-Block-Grade**: only dictionaries whose intended action is Block, with their minimum counts.
- **CUI-Detect-Caution-Grade**: only dictionaries whose intended action is Caution, with their minimum counts.

## Rules

| Rule | Engine | Action | Purpose |
|---|---|---|---|
| CUI-Monitor-All | CUI-Detect-All | ALLOW | Size incident volume first |
| CUI-Block-Marked-Documents | CUI-Detect-Block-Grade | BLOCK | High-precision markings |
| CUI-Caution-Weak-Markings | CUI-Detect-Caution-Grade | CONFIRM | Low-precision signals; user confirms |
| CUI-SSL-Decrypt-File-Share-Webmail-AI | — | DECRYPT | Make HTTPS uploads inspectable |
| CUI-CAC-AI-No-Upload | — | Cloud App Control | Block uploads to AI apps outright |

All rules ship DISABLED at INFO severity.
