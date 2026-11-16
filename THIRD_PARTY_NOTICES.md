# Third-party notices

Aegis source is Apache-2.0. Dependencies retain their own licenses; complete dependency versions are pinned in Cargo.lock and web/verifier/package-lock.json. This document is not a substitute for each package's included license.

- Rust: serde, serde_json, sha2, base64, schemars, clap, walkdir, wasm-bindgen, zip, and their dependencies generally use MIT and/or Apache-2.0 terms; ed25519-dalek and curve25519-dalek use BSD-3-Clause. Consult crate package notices for exact terms.
- React and React DOM: MIT, Meta Platforms, Inc. and affiliates.
- Vite and TypeScript: MIT and Apache-2.0 respectively.
- Lucide: ISC license, Lucide contributors; includes portions derived from Feather icons (MIT).
- Inter variable font: SIL Open Font License 1.1, the Inter Project Authors.
- Manrope variable font: SIL Open Font License 1.1, the Manrope Project Authors.
- Playwright: Apache-2.0; axe-core: MPL-2.0 (development/test tooling, not included in the browser runtime).

Local font files are distributed through @fontsource-variable packages. Their OFL license files are included in docs/licenses/. The favicon and import illustration were authored for Aegis using SVG/CSS.

Demo evidence and deterministic signing fixtures are Aegis-authored under Apache-2.0. Example builder URLs use example.invalid. Framework names and references identify external standards; no endorsement is implied and normative source text is not redistributed.
