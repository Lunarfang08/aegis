# Mapping sources and review record

Checked on 16 November 2026. All bundled mappings remain **draft**, without independent practitioner review. These are conservative technical evidence checklists rather than authoritative crosswalks.

- EU AI Act: [consolidated Regulation (EU) 2024/1689, 27 July 2026](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:02024R1689-20260727), Articles 12 (record-keeping), 14 (human oversight), and 50 (transparency). Mappings require unsupported log, oversight, or disclosure records explicitly; none can claim full evidence in this MVP. Source dates are metadata, not an assertion that the mapping has been legally reviewed.
- NIST: [AI RMF Core, 1.0 (2023)](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/). Selected rules: GOVERN 1.6 (inventory), MAP 1.1 (context), MEASURE 2.1 (evaluation), GOVERN 4.3 (testing/incident practices), and MANAGE 1.1 (risk decisions). A structured inventory can satisfy the narrowed inventory evidence rule; organizational implementation and resourcing remain unproven. Other rules contain explicit unsupported requirements.

No applicability, enforcement deadline, conformity assessment, or certification inference is made. NIST's site indicates that a framework revision is in progress; the MVP intentionally pins 1.0.

Adapter references:

- [CycloneDX 1.6 JSON reference](https://cyclonedx.org/docs/1.6/json/)
- [SARIF 2.1.0 plus Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
- [DSSE protocol](https://github.com/dsse-lf/dsse/blob/master/protocol.md), [envelope](https://github.com/dsse-lf/dsse/blob/master/envelope.md)

Runtime supported versions are fixed in the adapters and tested with Aegis-authored fixtures. No upstream fixture corpus is redistributed. Full upstream conformance certification is not claimed.
