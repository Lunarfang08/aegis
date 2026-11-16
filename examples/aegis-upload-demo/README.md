# Aegis upload demo

This folder contains a complete, signed example for testing the Aegis browser workbench.

## Test it

1. In Aegis, click **Import evidence**.
2. Upload **only** `aegis-example-evidence.zip`.
3. Open **Trust store** in the sidebar.
4. Import `trust-store.json` from this folder.

Before the trust store is imported, the two signatures will appear as **Unverifiable**. After importing it, all 10 evidence items should show **Verified**, with 4 accepted source files and 0 rejected files.

The ZIP contains:

- `inventory.cdx.json` — CycloneDX 1.6 inventory
- `security.sarif` — SARIF 2.1.0 scan results
- `inventory.attestation.json` — signed in-toto/DSSE attestation
- `scan.attestation.json` — signed in-toto/DSSE attestation

The included key is a public deterministic test key. Never use it for real attestations.
