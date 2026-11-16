# Local validation — 16 November 2026

Validated on macOS (x86_64) with Rust 1.96.0, Node.js 24.14.1, Vite 6.4.6, and installed Chromium.

| Check | Result |
| --- | --- |
| Rust workspace tests | 24 passed: 20 core integration cases, 3 CLI contract cases, 1 strict-JSON parser case |
| Rust formatting | Passed |
| Clippy, all workspace targets, warnings denied | Passed |
| Full production Rust/WASM + TypeScript/Vite build | Passed |
| Browser acceptance tests | 9 passed |
| Native CLI / browser WASM result parity | Full exported clean-demo JSON identical |
| Offline reload and verification | Passed with browser network disabled |
| Accessibility | No axe WCAG 2 A/AA or WCAG 2.1 AA violations in tested empty desktop/mobile layouts, populated workbench views, expanded control, and evidence dialog |
| Responsive overflow | No page overflow at 390, 768, and 1440 pixel viewport widths |
| Production / development browser console | No runtime page or console errors in final visual review |
| HTML, JSON, Markdown downloads | Passed |
| CLI report export with gaps | Report generated; exit code 1 as documented |

Browser cases exercise real cryptography through WASM, tampered and partial samples, file/trust-store imports, framework changes, filtering, raw-source inspection, control links, exports, reset, invalid-input recovery, keyboard tabs, accessibility, and offline reload. Cryptographic tests include DSSE's published PAE vector, URL-safe base64, unknown and wrong keys, modified payloads, malformed signatures, subject digest mismatches, and missing artifacts. Input checks cover duplicate JSON members, path traversal, nested ZIPs, duplicate paths, unsupported versions, resource limits, and raw-byte preservation.

Screenshots in `docs/screenshots/` show the import screen, verified sample overview, mobile overview, and report preview. They are manual visual-review artifacts, not a claim of a maintained pixel-diff baseline.

The CI workflow defines Linux/macOS/Windows native checks and a Linux browser job; remote CI has not run because this workspace has no configured repository host. Firefox and Safari were not exercised. `cargo-audit` was unavailable locally, so a Rust advisory audit was not run. npm dependency installation reported zero known vulnerabilities at installation time. No independent security, legal, or practitioner mapping review is claimed.
