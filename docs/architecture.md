# Architecture and interfaces

The pipeline is: bounded input expansion → content detection and structural adaptation → signature and digest verification → source integrity propagation → draft rule evaluation → deterministic reports.

`aegis-adapters` parses CycloneDX 1.6, SARIF 2.1.0, and DSSE-wrapped in-toto v1 statements. Unknown fields remain in original source bytes; normalized items preserve the full component, finding, or statement. `aegis-core` owns the public request/report types, bounded ZIP extraction, trust, crypto, mappings, and rendering. `aegis-cli` handles local file discovery and command exit behavior. `aegis-wasm` exposes `analyze(request_json)` and `render(report_json, format)` with the same core. No networking is available in the core pipeline.

The React client sends base64-encoded original bytes to a module Web Worker, which initializes the Rust WASM engine once. It renders returned results without reimplementing cryptography or mapping. Original evidence is read with FileReader and is never sent in an HTTP request. Browser downloads are generated from in-memory blobs. UI source previews cap displayed text at 100,000 characters; JSON export preserves original inputs.

The request includes `files: [{name, data}]`, `trust_store: {keys: [{id, label, public_key}]}`, `framework`, and `system`. All bytes and keys use standard base64. `system` is an operator-provided label for this single-system review, not an inferred identity. Relative subject paths must match exactly. Generic JSON input is not itself an accepted evidence format.

The version 1.0.0 report includes engine and schema versions, deterministic report ID, system label, the complete mapping and source metadata, input accounting (raw text or base64, encoding, bytes, digest, rejection reasons), normalized evidence, checks, control requirement matches, and limitations. Original binary sources are represented as base64. Evidence outcomes are Valid, Invalid, Unverifiable, or Asserted. Control outcomes are Evidenced, Partial, Not evidenced, or Broken; Out of scope is reserved for later explicit applicability handling. The UI labels Valid as Verified.

A control is Evidenced only when all requirements have an eligible matching item. Partial means there are candidates but incomplete required support. Invalid candidate evidence makes a control Broken. Unsupported evidence kinds are explicit missing requirements. An asserted scan or inventory may satisfy a requirement only if its minimum strength is Asserted. No rule interprets an arbitrary attestation predicate as oversight, approval, or logging evidence.

Rules are bundled JSON in `mappings/`; changing them requires rebuilding native and WASM targets. They are validated by typed deserialization and tests, and exposed through the mapping JSON Schema. The Python mapping generator is a development convenience; edit it if regenerating the bundled rule files. External runtime mapping/plugin loading is outside this MVP.

The offline production build contains a content-versioned service worker caching only its fixed asset allowlist. Cache updates remove previous Aegis app versions. Reset/reload clears evidence and trust. Development runs should use port 5173 and production previews port 4173 to avoid a production service worker masking development changes. The service worker requires HTTPS or localhost.

Tests cover native/WASM parity, signature and digest attacks, input bounds, ZIP traversal and nesting, deterministic rendering, user flows, offline reload, accessible controls, and viewport overflow. Independent crypto review, extended fuzzing, cross-platform release binaries, and public launch remain separate milestones.

The restrictive document CSP applies to production builds. Vite development mode removes that meta policy to permit its own hot-reload preamble; it is not the offline or hardened distribution. The production bundle allows only local scripts/WASM, local or embedded fonts/images, and local workers. External source links open only when a reviewer requests them.
