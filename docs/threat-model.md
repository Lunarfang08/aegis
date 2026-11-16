# Aegis MVP threat model

## Trust boundary

Evidence, filenames, JSON, ZIP metadata, and DSSE key IDs are untrusted. Only explicitly imported public keys are trust roots. The browser UI and compiled binaries must themselves come from a trusted source. An attacker controlling the local machine, browser extensions, application source, or imported trust store is outside the protection of this verifier.

## Implemented controls

- Duplicate JSON members and excessive JSON nesting are rejected. DSSE envelopes are parsed once; verification consumes the same decoded bytes that were interpreted by the adapter. Standard and URL-safe base64 are supported.
- Original DSSE payload bytes and payload type are authenticated using the protocol's pre-authentication encoding; Ed25519 strict verification uses ed25519-dalek. No JSON reserialization occurs before signature verification.
- SHA-256 subjects are checked against exactly named supplied files. Missing artifacts and unsupported digest algorithms are unverifiable. Matched source bytes inherit a trusted attestation's digest result; conflicting authenticated digest results fail.
- Unknown keys do not become trusted. Keys embedded in evidence are not imported. Key IDs are hints; all imported keys are tried. One valid trusted signature meets the MVP's trust policy. If no trusted key validates, the result remains Unverifiable: unknown and altered signatures cannot be distinguished without an independent signer binding. Structurally invalid Ed25519 signatures are Invalid. Key IDs never change the outcome.
- Untrusted text is rendered through React escaping. Standalone HTML exports escape all evidence-derived strings, permit no scripts or external assets, and set a restrictive CSP. Markdown escapes HTML and Markdown punctuation. Original source is shown as text, never executed.
- Runtime assets and fonts are bundled. Evidence processing makes no external calls. The production service worker caches only a fixed asset manifest, never imported evidence, trust, results, or downloads.
- Inputs are bounded to 10 MiB per file, 100 MiB expanded, 1,000 files, and 10,000 normalized items. Trust stores are capped at 100 keys (64 KiB on the browser picker). ZIP paths must be safe relative paths; symlinks, duplicate paths, nested archives, encrypted/unsupported ZIPs, and excessive expansions are rejected. CLI file discovery rejects symlinks.
- Every discovered file is accounted for as accepted evidence, a referenced artifact, or rejected. Raw inputs and SHA-256 digests are preserved in JSON reports. Reports can still be exported when verification fails.

## Limitations

A valid signature proves authentication of bytes under an imported public key. It does not prove statement truth, authorization, completeness, legal compliance, system behavior, event ordering, replay absence, artifact safety, or absence of malicious model content. Digest verification never executes artifacts.

No revocation, key rotation policy, transparency log, externally anchored time, receipt chain, freshness, or predicate semantic verification is implemented. Timestamps are assertions. The user supplies a single-system label; Aegis does not establish that all imported sources belong to it.

Structural adapters validate required MVP shapes and versions, rather than every upstream schema field. Resource limits reduce but do not eliminate denial-of-service risk. All processing and exports are in-memory, so maximum-sized inputs can use several times their raw size. Private evidence can appear in JSON exports; there is no automatic secret scanner or redaction in this MVP.

Draft mappings have not received independent practitioner review. An Evidenced outcome applies to the named technical subset and its explicit requirements, never the full framework control. No regulatory deadline calculations are included.

The application is not independently security reviewed, a certification product, or a released service. See SECURITY.md before public disclosure or release.
