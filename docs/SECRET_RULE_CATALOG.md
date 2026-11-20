# Local credential and sanitization policy

All inspection is local. The application does not verify tokens, fetch rule
updates, honor inline `gitleaks:allow`/Secretlint disable comments, fetch URLs,
or execute decoded content.

## Pinned sources and coverage

The catalog was reviewed against **Gitleaks v8.24.2** (annotated tag object
`9c72c5f9f05200fdc06e3f1b16e9aaa89fbe9f75`, target commit
`d5c275d6b2140fcb59bc3f58b8dd5350f5b19df6`) and **Secretlint v9.3.4**
(`1b0bebd91380d94ee0a756900ce9b39c8b3cfd1b`). Both upstream projects are MIT
licensed. Patterns are locally adapted to Python and deliberately do not load
either project at runtime.

The current prefix/structure catalog contains 38 offline detectors: AWS,
GitHub, GitLab, Azure DevOps, Slack, Google, Stripe, PyPI, npm, SendGrid,
Twilio, Mailgun, DigitalOcean PAT/OAuth access/OAuth refresh, Shopify, Square, Telegram, Discord, OpenAI,
Anthropic, Hugging Face, Postman, Vault, age secret keys, Clojars, Cloudflare
Origin CA, Databricks, Doppler, Grafana cloud/service-account, Harness, Linear,
PlanetScale API/OAuth/password, Pulumi, and JWTs. General
detectors additionally cover complete private-key blocks, authorization and
cookie headers, credential URLs/query parameters, assignments/connection
strings, command arguments, and contextual user/password pairs. Every finding
keeps its exact source span; no provider verification is performed.

This is an adapted applicable union, not a claim to implement every upstream
rule. Duplicates are represented once. The inventory's `audit_disposition`
separates inapplicable public identifiers/non-credential policy, deferred
validation, and unreviewed backlog. Skipped does not mean technically impossible.
Generic assignments cover credential-named fields, not every provider-specific
context rule. No regex is claimed equivalent without capture/boundary fixtures.

To update, compare upstream catalogs at the pinned commits, add positive and
negative fixtures for each adopted format, review capture offsets and false
positives, then advance both hashes in this document. Never import upstream
allow comments from input data.

## Custom regex controls

Settings → **Custom rules** holds every rule in one list. A rule matches by
**regex** or by **JSON field**. Regex rules can **Hide as a credential**,
**Hide as a privacy value** (restored locally), **Review before sending** or
**Keep**; field rules always **Keep** (they stop entropy review at that field
or path, which is stored as `heuristic_field_exclusions`). Regex rules include a stable ID/name, enabled state, Python-compatible
pattern, `i/m/s/x` flags, capture group, match mode and scope. The Settings
test calls the same backend engine used for outbound enforcement. Patterns are
limited in size and run with the `regex` module's native timeout; syntax,
unsupported flags, zero-length matches and timeouts fail closed.

Example hide rule: pattern `customer-(\d+)`, capture group `1`, action
`hide_secret`, substring mode. Example false-positive policy: pattern
`[0-9a-f]{64}`, action `exclude`, full-value mode, scope `heuristics`. The
second rule can keep an uncertain hash but cannot override an assignment,
Authorization header, manual Hide, or explicit custom hide.

Precedence is: manual Hide; custom Hide; strong credential evidence; exact
request-local Keep or scoped exclusion for eligible uncertain findings; then
mask all remaining findings. Keep is exact and case-sensitive. It is not saved
as global policy.

## Entropy, decoding, and limitations

UUID/GUID, MD5-, SHA-1-, and SHA-256-shaped values are reviewable uncertain
findings even when their entropy is low. Generic tokens default to 10 characters
and 3.5 Shannon bits/character; lowercase-only tokens default to 14 characters
and 3.15 bits/character. Configurable minimum length is bounded below by eight.
Lowercase structural evidence can trigger review below the entropy threshold;
it is not Shannon entropy or proof of a password. Shape and entropy never
downgrade stronger credential context. The local UI requires Continue with
Keep checked by default; the backend masks uncertain findings without an
explicit request-local Keep decision.

Bounded URL-percent, Base64/base64url, and hex candidates are decoded in memory. If
decoded content has strong credential evidence, the original encoded source
span is masked. Inspection is capped at 100 unique candidates per text (one per
250 characters for texts longer than 25,000 characters, because the final check
before the AI reads a whole batch as one text), 8 KiB decoded bytes per
candidate, at most two decoding layers, and the global 2-million-character
input limit. The decoded-byte limit is checked cumulatively before rescanning.
Arbitrary nested archives and compressed/encrypted content are not decoded.

No detector can promise all arbitrary secrets or zero leakage. Prefix rules
can become stale and entropy produces review load. The regex timeout is the
primary ReDoS boundary; deployments should also retain the server request
timeout and process isolation appropriate to their threat model. Request-wide
literal propagation uses the local Aho-Corasick matcher implemented in
`secret_detection.py`. BPE scoring is not implemented.

Sensitive findings and restoration mappings are request-local. Credential
originals are not returned or persisted in feedback. The Mapping section does
list each `SECRET` placeholder with a non-sensitive "original withheld" label
so analysts can audit every replacement without making credentials restorable.
Privacy mappings may include their originals for local restoration. Reset clears extension storage, including
custom rules and transient analysis state; connector/API settings are also
cleared by that explicit full reset.

## Synthetic evaluation

`tests/test_complete_sanitization.py` is the labeled mixed-format regression
corpus. Its 24 provider positives were all detected at the exact labeled span;
the credential subset therefore measured 24/24 recall and 24/24 precision.
Four bare GUID/hash samples were classified separately as uncertain (not
counted as credential true positives), for a 100% review rate on that small
shape-focused subset. Contextual password, encoded, JSON, command-line and
conflict cases are assertions rather than a statistically representative
population. These figures describe this synthetic corpus only and must not be
generalized to real SOC traffic.

A CPython 3.14 development run over a repeated 460,000-character mixed log
batch produced 10,000 findings in 2.45 seconds. A separate tracemalloc run over
900,000 characters produced 19,564 findings in 27.63 seconds with 9.01 MiB
peak traced allocation; tracemalloc materially increases runtime, so the two
timings are not directly comparable. Production retains the 2,000,000
character input cap and 10-second local-work deadline. These historical numbers
predate the Aho-Corasick and indexed source-span changes; representative SIEM
corpora remain necessary to evaluate production latency.

## Windows commands, field provenance, and review defaults

The command detector recognizes `net use` and `net.exe use` (including an
executable path or `cmd.exe /c` wrapper). It tokenizes Windows-style quoted
arguments without executing them and treats the single explicit positional
argument associated with a UNC mapping as a strong password. Drive mappings,
UNC paths, `/user:` accounts (domain, dotted-domain, and UPN forms), option
ordering, quoted spaces and punctuation are retained. `*`, `/delete`, and
`/smartcard` are not passwords; `net user` is unrelated and is ignored.
Decoded JSON strings are inspected independently and findings are mapped back
to the encoded source span. More complex shell composition, caret expansion,
environment-variable expansion, and PowerShell-specific parsing are not
implemented.

Generic heuristics now evaluate tokens from 10 characters and lowercase-only
tokens from 14 characters. Defaults are 3.5 and 3.15 Shannon bits/character,
respectively, and Settings exposes all four thresholds. This makes synthetic
lowercase candidates such as `testpassabcabcxyz` reviewable without relying on
the Windows detector, while ordinary language can still be indistinguishable
from a password. Entropy remains uncertain evidence, never proof.

Structured provider/channel values, processing tags, SIEM index names and
document IDs suppress only generic entropy noise. UUID/hash shapes remain
reviewable unless an analyst configures an explicit JSON field exclusion.
Field exclusions accept a simple key (matching at any depth) or dotted exact
path (including arrays), and affect only entropy/uncertain findings. Strong
credential detectors and explicit manual, regex, keyword, or JSON-key hides
still run. Thus excluding `_index` does not prevent `bluebird -> ⟦x7q2⟧` inside
`logs-bluebird-windows-2026.08.02`.

The Settings selector makes dotted-name intent explicit: **Literal key at any
depth** treats `event.hash` as one actual JSON key, while **Exact nested path**
selects `{ "event": { "hash": ... } }`. These scopes are occurrence-local.

Uncertain review checkboxes are now **Keep, checked by default**. Continue is
still mandatory. Unchecking records a request-local force-hide decision;
checked values remain eligible for unrelated privacy masking. Strong findings
never enter this Keep list. Reusable exceptions remain explicit Settings
rules, rather than being inferred from a request decision.

Custom regex modes are: `substring` (any captured occurrence), `token`
(alphanumeric token boundaries), and `full_value` (the complete extracted
word-like value, so `acme` does not match inside `soc_acme_id`). Optional
capture groups that do not participate are skipped. `hide_privacy` is applied
in the restorable privacy stage; prior strong credential replacement wins and
is never restored. Privacy-scoped exclusions apply to automatic privacy
findings, while custom/manual/selected-field hides remain stronger.

Decoding work is charged once per unique plausible candidate. Repeated ordinary
metadata does not consume the candidate budget, and failed decoding is cached.
Base64/base64url and percent forms are supported beside assignment delimiters
such as `payload=`. Limits still fail closed when genuinely unique work exceeds
the documented budget; arbitrary compression, encryption, and shell expansion
remain unsupported.

On the correction corpus, 1,000 ordinary JSON events (162,000 characters)
with repeated provider/tag/index metadata and unique document IDs completed in
0.231 seconds on CPython 3.14 and produced zero review findings. This synthetic
measurement validates duplicate-work accounting, not universal SIEM latency or
false-positive performance.

## Privacy rule spans and command arguments

Explicit `hide_privacy` rules are now applied by their actual source spans
before generic privacy replacement. Substring mode therefore edits embedded
text, and a full-value match on a JSON number replaces that number with a
placeholder **string**, preserving valid JSON and all unrelated types. Only
edits actually applied receive mapping entries. Privacy hides are also applied
before manual and automatic TI extraction; their locally restorable originals
are never considered eligible external IOCs.

The Windows tokenizer joins adjacent quoted/unquoted pieces of one argument,
so `/user:"DOMAIN\\name"` is one option rather than a password candidate.
Quoted password punctuation is retained, and quote-aware `&&`, `||`, and `&`
bound the inspected command segment. Structured JSON scanning now maintains a
decoded-character-to-source-span map rather than searching the document for
the password spelling. This prevents short passwords from changing JSON keys,
filenames, or unrelated substrings. Environment expansion, caret escaping,
PowerShell expressions, and pipelines remain unsupported.

Heuristic extraction now uses the configured minimum down to eight characters.
Lowercase candidates below the entropy threshold can enter review when local
alphabet diversity, vowel ratio, and character transitions look unusual; the
reason explicitly reports structural evidence rather than calling it high
entropy. This intentionally increases uncertain review coverage, not confirmed
credential classification. English-like strings can still be false positives
or passwords, so Keep remains checked by default.

Generic heuristics ignore JSON property-name spans and recognize `SourceName`
and `event_prog` as metadata locations. Strong detectors and GUID/hash review
remain active for their values. Review snapshots exclude decisions produced by
the review itself, preventing an unchecked value from reopening an otherwise
unchanged dialog. Settings edits are transactional: the old regex/field rule
remains until Save, while Cancel leaves its stable ID, enabled state, and order
unchanged.

The adapted provider catalog at that point contained 24 formats; the
2026-10-04 update below expands it, but it is still not full
Gitleaks/Secretlint parity. Runtime downloads, remote token verification, and
attacker-controlled bypass comments remain prohibited.

Ordinary `/sanitize` and `/analyze` responses now replace finding values with
the protected label after local review; `/secrets/scan` necessarily returns
candidate originals to the local review UI. Raw input, restorable privacy maps,
and review state still exist in process/browser memory for the active workflow.
This is reduced retention, not a claim that all local sensitive copies have
been eliminated.

## Typed privacy and request context

Eight prefix/structure rules were added from the pinned catalogs: Gitleaks
`clojars-api-token`, `cloudflare-origin-ca-key`, `databricks-api-token`,
`doppler-api-token`, `grafana-cloud-api-token`,
`grafana-service-account-token`, and `harness-api-key`, plus Secretlint's
`@secretlint/secretlint-rule-linear` (adapted to its documented 32–128
character range). Context-only Cloudflare/Datadog/Linear client-secret rules
remain covered by the generic assignment detector rather than unsafe bare
hex matching. The Secretlint 1Password rule is skipped because it requires
decoded JSON validation; public IDs and non-secret policy rules are skipped;
provider verification/checksum rules are skipped where equivalent offline
validation is not implemented. These statuses are deliberate inventory items,
not claims of complete upstream parity.

Custom privacy matching is performed against logical JSON **values**, never
property names or raw JSON punctuation. `full_value` anchors to an entire
structured scalar, `token` uses alphanumeric boundaries, and `substring`
selects the captured portion of a string. For numbers, booleans, and `null`,
any eligible match replaces the complete scalar with a JSON placeholder
string. This prevents partial edits such as inserting a quoted marker into the
middle of `12345`. Unchanged number lexemes are copied byte-for-byte, avoiding
rounding or exponent-format changes. The restoration entry records the whole
replaced scalar; its internal type identity remains distinct from a JSON string
with the same spelling.

Each explicit privacy edit retains its occurrence and rule semantics. Its
restoration map is not reused as a global search-and-replace instruction, so a
`full_value` match for `"acme"` does not hide `acme` inside another value.
Overlaps resolve by source position, rule order, then widest span. Only markers
allocated by this request are protection evidence. Raw and JSON-decoded input
markers are reserved before allocation; explicit field/rule hides still apply
to untrusted marker-shaped text.

One in-memory allocator/restoration context is shared by all components of an
analysis request, including logs, notes, statistics, custom prompts, TI text,
and saved feedback. Different values and different scalar types cannot receive
the same marker; the same compatible value may reuse one. The context is not a
process-global store and is discarded after the request. Credential markers
remain outside this restorable mapping.

The popup's automatic privacy toggle now controls automatic entity and keyword
features only. An enabled explicit `hide_privacy` or `hide_secret` rule is
enforced before AI and TI traffic regardless of that toggle. Privacy markers
may be restored only in local AI output; this eligibility never permits the
original to be submitted as a threat-intelligence indicator.

A CPython 3.14 tracemalloc check on a 1,000-event JSON array (149,890 bytes)
containing repeated Sysmon provider/tag/index metadata completed in 0.776
seconds, peaked at 11.85 MiB traced allocation, and produced zero findings.
This is a synthetic regression workload, not a production latency guarantee;
newline-concatenated objects are treated as unstructured text unless callers
submit them as separate logs or a valid JSON array.

## Protection order across request sources

The request pipeline now classifies current logs, notes, statistics, custom
prompts, and the complete relevant saved-feedback corrections before allocating
privacy identities. Prompt-length truncation happens only after protection.
Consequently, a strong `password=value` occurrence in feedback makes an equal
current value non-restorable even if a custom privacy rule also matches it.
Decoded JSON spellings (for example `a\u0063me`) participate in this request-wide
strong-value propagation without global substring replacement.

Secret and review regex actions now use the same decoded scalar matching
contract as privacy actions. `full_value` eligibility belongs to the enclosing
regex match; a selected capture may occupy only part of that match. Source
offsets are mapped through JSON escapes, value rules never scan property names,
and number/Boolean/null secret edits replace the complete scalar with a quoted,
non-restorable marker. Inputs that were valid JSON are validated again after
credential and privacy transformations; a structural regression stops sending.
Whole-token boundaries treat letters, digits, and underscores as identifier
characters consistently for secret and privacy actions.

Automatic privacy replacement now edits JSON string/scalar source spans rather
than parsing and serializing the whole document. Untouched large integers,
long decimals, and exponent spellings therefore remain byte-for-byte intact.
AI responses that are complete JSON values or recognized JSON code fences are
restored structurally: complete typed markers regain their eligible scalar type,
embedded markers remain string content, and keys are never restored. A
JSON-looking malformed response is left with unresolved markers rather than
being corrupted by blind substitution.

Historical placeholders are reserved from all available request sources before
allocation. A marker persisted without its old restoration map remains an
unknown, non-restorable historical marker and can never acquire a new request's
meaning. Late TI-derived strong evidence also revokes a matching privacy map and
upgrades already-created request markers to non-restorable secret markers.

`SECRET_RULE_INVENTORY.csv` inventories all 206 Gitleaks rules and all 24
Secretlint rule packages at the pinned commits. It records the upstream ID,
local detector ID, status, and a per-row reason. The current totals include
adapted and duplicate coverage plus explicit remaining gaps; the inventory is
not a parity claim. In particular, many context/entropy/checksum rules and the
Secretlint 1Password/secp256k1 executable validators remain unported until their
validation and capture behavior can be reproduced safely offline.

## Structured records and restoration

The structured scalar record is now the shared contract for built-in decoded
credential detection, custom Secret/Privacy/Review rules, explicit JSON-field
hiding, manual substring Hide, automatic complete-occurrence propagation, and
structured restoration. A successful parse with zero scalar records is tracked
separately from parse failure, so `{}`, `[]`, and nested empty containers remain
valid in mixed batches.

Explicit JSON-field Hide allocates and edits from the same source record. The
stored restoration original for a number is its exact lexeme (`1e3`, `-0`, or a
long decimal), not Python's float spelling. Automatic privacy and supported
response restoration likewise perform source-span edits, preserving unrelated
numeric lexemes. Complete JSON string roots and JSON fences are restored with
proper escaping; production callers pass the request's type context. Calling
the low-level restoration helper without that context intentionally provides
string-only restoration and cannot infer numeric types safely.

Strong credential identities are logical decoded values while their edits keep
the original encoded spans. This lets `password="a\u0063me"` override a privacy
decision for `acme`, and lets known provider prefixes or manual substring Hide
work through JSON escapes. Later evidence also revokes a larger privacy original
when a bounded complete credential occurrence appears inside it; the unsafe
privacy original is never published or restored.

Request-wide literal propagation now uses a local Aho-Corasick automaton built
once per protection phase rather than sorting and compiling every known value
inside every scalar loop. On CPython 3.14.4 x86-64 in the development container,
with only assignment detection enabled and tracemalloc active, distinct-secret
JSON arrays measured: 200/6,200 characters in 0.137 s (2.19 MiB peak),
600/18,600 in 0.437 s (5.41 MiB), 800/24,800 in 0.636 s (8.69 MiB), and
1,000/31,000 in 0.841 s (11.01 MiB). A larger 5,000-event/155,000-character run
took 7.90 s without tracemalloc. These are synthetic local measurements, not
portable latency guarantees. Cooperative deadline/cancellation checks run while
building and scanning literal automata; other bounded regex/decoder stages keep
their existing independent limits.

DigitalOcean coverage is no longer conflated: `dop_v1_` is the PAT rule,
`doo_v1_` is OAuth access, and `dor_v1_` is OAuth refresh. All three retain the
upstream 64-hex payload and boundaries. The inventory now records the Gitleaks
target commit rather than incorrectly calling the annotated tag object a commit.
At that snapshot inventory totals were 36 adapted, 5 duplicate, and 165 skipped Gitleaks rows;
13 adapted, 2 duplicate, and 9 skipped Secretlint package rows. Skipped entries
remain explicit work gaps, not claims that every one is technically impossible.

## Shared scan entry point and cancellation

`scan_secrets` is the common entry point for preflight, analysis/sanitize/feedback
protection, and direct TI screening. It normalizes raw and decoded reports to
logical identities with exact original spans and paths, resolves duplicate
reports of one occurrence, and preserves separate repeated occurrences.
Decoded credential keys include Authorization/Proxy-Authorization and
Cookie/Set-Cookie, as well as credential assignments. Numeric, Boolean, and
null credentials retain the existing plain-field policy: the entire scalar is
replaced with a quoted secret marker. No document is rewritten through floats.
Header schemes remain visible; cookie header values remain wholly protected.

Input marker syntax is not proof of protection. Both raw and decoded source
markers are reserved, including keyword marker collisions, and genuine secret
markers are tracked separately from eligible privacy mappings. Composed privacy
originals are flattened at allocation using one pass over request-owned mappings.
Restoration performs one substitution pass, never rescans its own output, and
never follows arbitrary marker chains. Thus marker-shaped originals and unknown
model-returned markers remain literal. Complete typed markers in valid JSON or
JSON fences restore the original scalar lexeme/type; embedded markers restore
string content with JSON escaping. Malformed JSON-looking replies stay unresolved.
The helper without type context intentionally restores strings only.

Strong decoded evidence is case-sensitive and propagates under existing complete
value/token boundaries. Later TI/final-boundary evidence revokes direct and
flattened enclosing privacy originals before response restoration/public mapping.
The escaped Authorization reproduction was a local response/mapping disclosure,
not observed plaintext model egress. TI result objects are protected before being
returned too. Strong credentials are never offered as Keep; explicit hides retain
precedence over uncertain Keep/exclusions. Scanning remains entirely offline.

Scalar/key spans now use ordered binary lookup rather than scanning all fields
for each finding. Parsing is cached only within one worker call (four documents
maximum) and discarded when it exits. Source edits are joined once rather than
rebuilding the document per field; empty custom-rule passes avoid parsing work.
All endpoint local-work calls carry a cancellation event and the unchanged
10-second deadline, with a 95% cooperative work budget. Parser, detector,
literal-matcher, normalization, and edit loops check cancellation. Individual
regex calls retain their bounds; this is cooperative cancellation, not arbitrary
thread termination.

Four additional Gitleaks formats were audited against the
[pinned upstream config](https://github.com/gitleaks/gitleaks/blob/d5c275d6b2140fcb59bc3f58b8dd5350f5b19df6/config/gitleaks.toml):
`planetscale-api-token`, `planetscale-oauth-token`, `planetscale-password`, and
`pulumi-api-token`. Payload lengths/alphabets and prefix case policy are retained;
PlanetScale word payloads use ASCII. Python boundaries reject adjacent identifier
characters and allow JSON punctuation. Prefix evidence deliberately does not
require upstream entropy or allowlist exemptions. Exact capture, truncation,
overlength, invalid alphabet, casing, public controls, and escaped outbound
fixtures are in `tests/test_provider_token_rules.py`.

Current Gitleaks inventory: **40 adapted, 5 duplicate, 161 skipped** (8 inapplicable,
1 deferred, 152 unreviewed). Secretlint: **13 adapted, 2 duplicate, 9 skipped**
(7 inapplicable, 2 deferred). The Gitleaks 1Password row now correctly describes
its upstream prefix/entropy matcher separately from Secretlint's executable
validator. Inventory dispositions are not recall percentages or complete coverage.
