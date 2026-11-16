# Security policy

Aegis v0.1 is a local MVP. It has not undergone an independent security review. Do not treat its results as certification or legal advice.

Do not put private keys into a trust store: only Ed25519 public keys are accepted. Do not use the deliberately public demo signing key for real evidence.

For a suspected vulnerability, contact the repository maintainer privately through the repository hosting provider's private vulnerability reporting channel when available. If no private channel is configured, request a private contact method without posting exploit details or sensitive evidence. No repository host or security contact address is configured in this local workspace yet.

Include the engine version, input format, minimal non-sensitive reproduction, and impact. Keep real evidence out of public reports. Coordinated disclosure and a dedicated contact address must be established before a public release.

See docs/threat-model.md for implemented boundaries and known limitations.
