# Fed Policy Pack: CUI markings (tiers 1-7) — dictionary notes

Build metadata from the design file (tier, intended action, minimum match count, notes). The pack configs carry the API fields only; regenerate with `python tools/pack_from_design.py <pack_dir>`.

**Documented ZIA limits:** 8 patterns per dictionary; 256 bytes per pattern; proximity 0-10000 bytes; PCRE syntax minus lookaround; phrases fuzzy-match unless quoted; Count Unique collapses repeated matches to a single count. Engine builder: 4 subexpressions / 4 operators / 16 dictionaries per operator per level; root accepts All, Any, Sum only. Proximity requires BOTH the proximity integer AND proximityEnabledForCustomDictionary = true on custom dictionaries. Engine match counts accept any value under 1000.

**Proximity semantics:** Proximity measures between a PATTERN and a PHRASE within a custom dictionary. Pattern-to-pattern proximity is not available - any design needing a window must place one term in the pattern slot and the other in a phrase.

**Phrase semantics:** Phrase matching is case-insensitive and ignores punctuation - always, and quotes do not change this (quotes only force exact word order and disable noise-word tolerance). A phrase of SP-EXPT therefore also matches lowercase and hyphen-absent variants. Patterns are case-sensitive by default with (?i)/(?-i) tokens available. Phrases: 3-128 bytes, up to 256 per dictionary.

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
| CUI-Prox-EXPT | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-TAX | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-LEI | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-CRIT | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-NUC | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-INTEL | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-LEGAL | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| CUI-Prox-PROCURE | 3 | Caution | 1 | Proximity anchors on the pattern (CUI) and measures to the phrase (category code). Window is bidirectional and byte-measured over extracted text, so OOXML part boundaries inflate distance. |
| Legacy-FOUO | 4 | Block | 1 |  |
| Legacy-LES | 4 | Block | 1 | Bare LES is deliberately excluded - collides with French text, surnames, and unrelated acronyms. Spelled form or banner context only. |
| Legacy-SBU | 4 | Block | 1 |  |
| Legacy-Distribution-Statements | 4 | Block | 1 | Very high signal on CTI-bearing engineering documents. |
| CUI-Designation-Indicator | 5 | Caution | 3 | Rebuilt with a CUI pattern anchor - a phrases-only dictionary has nothing for proximity to measure from. ANY_PATTERN_WITH_ANY_PHRASE gives anchor + at least one label; the 3-of-6 requirement is enforced by the engine threshold (> 2), not the dictionary. |
| CUI-Decontrol-Context | 6 | Exclude | 1 | DOCUMENT-SCOPED exclusion. A genuine CUI document that cites its own marking guide will suppress. Record this in the residual-risk statement. |
| CUI-Declassify-Date | 5 | Caution | 1 | From Zscaler Fed Policy Pack V1.1 (Declassify Date Pattern High + Medium). A decontrol date alone is a caution-grade signal; it sits with the designation block. |
| CUI-Contextual-Phrases | 7 |  |  | From Zscaler Fed Policy Pack V1.1 (CUI Contextual Phrases). No intended action: only the CUI-Detect-Contextual engine uses it, with a minimum of three distinct phrases. |
| CUI-Category-Phrases | 7 |  |  | From Zscaler Fed Policy Pack V1.1 (CUI Category Phrase). Ordinary words on their own; only meaningful next to contextual phrases, never wired to block or caution. |

## Engines

- **CUI-Detect-All**: Full CUI detection surface: banner grammar, category tokens, legacy markings, malformed-marking proximity, and designation blocks.
- **CUI-Detect-Contextual**: Content-based CUI signal: three or more distinct marking-guide phrases together with a Registry category name, minus the decontrol exclusion. Monitor only.
- **CUI-Detect-Block-Grade**: High-precision signals intended to BLOCK (16 dictionaries with their minimum counts), minus the exclusion dictionaries.
- **CUI-Detect-Caution-Grade**: Lower-precision signals intended to CAUTION (12 dictionaries with their minimum counts), minus the exclusion dictionaries. Never wire to BLOCK.

CUI-Detect-All design note: Split into two nested Any groups solely because of the 16-dictionary-per-operator ceiling, not for logical reasons - the two groups are ORed and behave as one set. Validate the three-level nesting renders in Engine Builder before relying on it; if the builder rejects the depth, restructure as root Any(OR) over the two groups and move the decontrol exclusion into each group.

CUI-Detect-Contextual design note: Replaces the Fed Policy Pack V1.1 'CUI Engine (Low Confidence)'. It catches documents that discuss controlled categories without carrying a well-formed marking; expect it to be the noisiest CUI engine, which is why only CUI-Monitor-All carries it.
