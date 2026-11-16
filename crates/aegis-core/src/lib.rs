#![forbid(unsafe_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

pub const MAX_FILE: usize = 10 * 1024 * 1024;
pub const MAX_TOTAL: usize = 100 * 1024 * 1024;
pub const MAX_FILES: usize = 1000;
pub const LIMITATIONS: &str = "Aegis verifies supplied bytes and evaluates draft technical evidence rules. It does not establish completeness, truth of claims, real-world operation, legal applicability, compliance, or certification. Timestamps are asserted. Revocation, timestamp authorities, receipt chains, replay detection, and unsupported predicates are not verified. No legal advice.";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InputFile {
    pub name: String,
    pub data: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    pub public_key: String,
    pub label: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Request {
    pub files: Vec<InputFile>,
    #[serde(default)]
    pub trust_store: TrustStore,
    #[serde(default = "default_framework")]
    pub framework: String,
    #[serde(default = "default_system")]
    pub system: String,
}
fn default_framework() -> String {
    "nist-ai-rmf".into()
}
fn default_system() -> String {
    "Untitled AI system".into()
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Check {
    pub name: String,
    pub status: String,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub format: String,
    pub source: String,
    pub pointer: String,
    pub status: String,
    pub signer: Option<String>,
    pub checks: Vec<Check>,
    pub normalized: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InputRecord {
    pub name: String,
    pub sha256: String,
    pub bytes: usize,
    pub format: String,
    pub accepted: bool,
    pub reason: Option<String>,
    pub raw: String,
    pub encoding: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Requirement {
    pub label: String,
    pub kind: String,
    pub min_strength: String,
    #[serde(default)]
    pub field: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ControlRule {
    pub id: String,
    pub title: String,
    pub description: String,
    pub requirements: Vec<Requirement>,
    pub limitation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Framework {
    pub id: String,
    pub title: String,
    pub version: String,
    pub status: String,
    pub source: String,
    pub source_text_version: String,
    pub verified_on: String,
    pub controls: Vec<ControlRule>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RequirementResult {
    pub label: String,
    pub met: bool,
    pub evidence_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ControlResult {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: String,
    pub requirements: Vec<RequirementResult>,
    pub evidence_ids: Vec<String>,
    pub limitation: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Summary {
    pub files: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub evidence: usize,
    pub valid: usize,
    pub asserted: usize,
    pub invalid: usize,
    pub unverifiable: usize,
    pub evidenced: usize,
    pub partial: usize,
    pub missing: usize,
    pub broken: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Report {
    pub schema_version: String,
    pub engine_version: String,
    pub report_id: String,
    pub system: String,
    pub framework: Framework,
    pub inputs: Vec<InputRecord>,
    pub evidence: Vec<Evidence>,
    pub controls: Vec<ControlResult>,
    pub summary: Summary,
    pub limitations: String,
}

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn frameworks() -> Vec<Framework> {
    [
        include_str!("../../../mappings/nist-ai-rmf.json"),
        include_str!("../../../mappings/eu-ai-act.json"),
    ]
    .iter()
    .map(|s| serde_json::from_str(s).expect("bundled mapping is tested"))
    .collect()
}
fn check(name: &str, status: &str, reason: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        status: status.into(),
        reason: reason.into(),
    }
}
pub fn safe_path(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains(':')
        && !name.chars().any(char::is_control)
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
fn decode(file: &InputFile) -> Result<Vec<u8>, String> {
    if file.data.len() > MAX_FILE.div_ceil(3) * 4 {
        return Err(format!("{} exceeds the 10 MB file limit", file.name));
    }
    let bytes = STANDARD
        .decode(&file.data)
        .map_err(|_| format!("Invalid base64 input: {}", file.name))?;
    if bytes.len() > MAX_FILE {
        return Err(format!("{} exceeds the 10 MB file limit", file.name));
    }
    Ok(bytes)
}
/// Expand ZIPs in memory, never to disk. Metadata and actual expanded sizes are both bounded.
pub fn expand(files: Vec<InputFile>) -> Result<Vec<InputFile>, String> {
    let mut result = Vec::new();
    let mut total = 0usize;
    for file in files {
        if !safe_path(&file.name) {
            return Err(format!("Unsafe input path: {}", file.name));
        }
        let bytes = decode(&file)?;
        if file.name.to_ascii_lowercase().ends_with(".zip") || bytes.starts_with(b"PK\x03\x04") {
            let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
                .map_err(|e| format!("Invalid ZIP: {e}"))?;
            if zip.len() + result.len() > MAX_FILES {
                return Err("ZIP exceeds 1,000 entry limit".into());
            }
            for i in 0..zip.len() {
                let entry = zip
                    .by_index(i)
                    .map_err(|e| format!("Cannot read ZIP entry: {e}"))?;
                if entry.is_dir() {
                    if !safe_path(entry.name().trim_end_matches('/')) {
                        return Err("Unsafe ZIP directory".into());
                    }
                    continue;
                }
                let name = entry.name().to_string();
                if !safe_path(&name) || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
                {
                    return Err(format!("Unsafe ZIP path: {name}"));
                }
                if entry.size() > MAX_FILE as u64 {
                    return Err(format!("ZIP entry exceeds 10 MB: {name}"));
                }
                let mut content = Vec::new();
                entry
                    .take((MAX_FILE + 1) as u64)
                    .read_to_end(&mut content)
                    .map_err(|e| e.to_string())?;
                if content.len() > MAX_FILE
                    || name.to_lowercase().ends_with(".zip")
                    || content.starts_with(b"PK\x03\x04")
                {
                    return Err("Oversized or nested ZIP entries are not supported".into());
                }
                total += content.len();
                if total > MAX_TOTAL {
                    return Err("Expanded input exceeds 100 MB".into());
                }
                result.push(InputFile {
                    name,
                    data: STANDARD.encode(content),
                });
            }
        } else {
            total += bytes.len();
            result.push(file);
        }
        if total > MAX_TOTAL || result.len() > MAX_FILES {
            return Err("Input exceeds 100 MB or 1,000 files".into());
        }
    }
    let mut names = BTreeSet::new();
    for file in &result {
        if !names.insert(&file.name) {
            return Err(format!("Duplicate input path: {}", file.name));
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
fn trusted_keys(store: &TrustStore) -> Result<Vec<(String, VerifyingKey)>, String> {
    if store.keys.len() > 100 {
        return Err("Trust store exceeds 100 keys".into());
    }
    let mut ids = BTreeSet::new();
    store
        .keys
        .iter()
        .map(|k| {
            if k.id.is_empty() || !ids.insert(&k.id) {
                return Err("Trust store key IDs must be nonempty and unique".into());
            }
            let bytes: [u8; 32] = STANDARD
                .decode(&k.public_key)
                .map_err(|_| "Public keys must be base64 Ed25519 keys")?
                .try_into()
                .map_err(|_| "Ed25519 public key must be 32 bytes")?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "Invalid Ed25519 public key")?;
            Ok((k.label.clone(), key))
        })
        .collect()
}
fn dsse_checks(
    envelope: &aegis_adapters::SignedEnvelope,
    statement: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    keys: &[(String, VerifyingKey)],
) -> (Vec<Check>, Option<String>) {
    let mut checks = Vec::new();
    let mut signer = None;
    let pae = pre_authentication_encoding(&envelope.payload_type, &envelope.payload);
    let signatures = &envelope.signatures;
    if signatures.iter().all(|s| s.len() != 64) {
        checks.push(check(
            "Ed25519 signature",
            "Fail",
            "No signature has the required 64-byte Ed25519 structure",
        ));
    } else if keys.is_empty() {
        checks.push(check(
            "Ed25519 signature",
            "Unverifiable",
            "No trusted keys imported. A supplied key ID is only an unauthenticated hint.",
        ));
    } else {
        // DSSE keyid is unauthenticated and never changes the verification outcome.
        for bytes in signatures {
            if let Ok(signature) = Signature::from_slice(bytes) {
                for (label, key) in keys {
                    if key.verify_strict(&pae, &signature).is_ok() {
                        signer = Some(label.clone());
                        break;
                    }
                }
            }
            if signer.is_some() {
                break;
            }
        }
        checks.push(if let Some(label) = &signer { check("Ed25519 signature", "Pass", format!("Authenticated DSSE payload matches trusted key: {label}")) } else { check("Ed25519 signature", "Unverifiable", "No signature matched an imported trusted key. An unknown signer cannot be distinguished from an altered signature without an independent signer binding.") });
    }
    for subject in statement["subject"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let name = subject["name"].as_str().unwrap_or("");
        let digest = subject["digest"]["sha256"].as_str();
        checks.push(match (digest, files.get(name)) {
            (Some(expected), Some(bytes))
                if expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                if hash(bytes).eq_ignore_ascii_case(expected) {
                    check(
                        &format!("SHA-256 · {name}"),
                        "Pass",
                        "Supplied artifact bytes match the signed subject digest",
                    )
                } else {
                    check(
                        &format!("SHA-256 · {name}"),
                        "Fail",
                        "Supplied artifact bytes differ from the signed subject digest",
                    )
                }
            }
            (Some(_), Some(_)) => check(
                &format!("SHA-256 · {name}"),
                "Fail",
                "Malformed SHA-256 subject digest",
            ),
            (Some(_), None) => check(
                &format!("SHA-256 · {name}"),
                "Unverifiable",
                "Referenced artifact was not supplied",
            ),
            (None, _) => check(
                &format!("Digest · {name}"),
                "Unverifiable",
                "Subject does not use the supported SHA-256 algorithm",
            ),
        });
    }
    (checks, signer)
}
fn status(checks: &[Check]) -> String {
    if checks.iter().any(|c| c.status == "Fail") {
        "Invalid"
    } else if checks.iter().any(|c| c.status == "Unverifiable") {
        "Unverifiable"
    } else if checks.iter().any(|c| c.status == "Pass") {
        "Valid"
    } else {
        "Asserted"
    }
    .into()
}

pub fn analyze(request: Request) -> Result<Report, String> {
    let framework = frameworks()
        .into_iter()
        .find(|f| f.id == request.framework)
        .ok_or("Unknown framework")?;
    let keys = trusted_keys(&request.trust_store)?;
    let expanded = expand(request.files)?;
    if expanded.is_empty() {
        return Err("Select at least one evidence file".into());
    }
    let files: BTreeMap<String, Vec<u8>> = expanded
        .iter()
        .map(|f| Ok((f.name.clone(), decode(f)?)))
        .collect::<Result<_, String>>()?;
    let parsed: BTreeMap<_, _> = files
        .iter()
        .map(|(name, bytes)| (name.clone(), aegis_adapters::parse(bytes)))
        .collect();
    let mut referenced = BTreeSet::new();
    for p in parsed.values().filter_map(|p| p.as_ref().ok()) {
        if let Some(s) = &p.statement {
            for sub in s["subject"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if let Some(name) = sub["name"].as_str() {
                    referenced.insert(name.to_string());
                }
            }
        }
    }
    let mut evidence = Vec::new();
    let mut inputs = Vec::new();
    for (name, bytes) in &files {
        let sha256 = hash(bytes);
        let utf8 = String::from_utf8(bytes.clone());
        let (raw_text, encoding) = match utf8 {
            Ok(text) => (text, "utf8"),
            Err(_) => (STANDARD.encode(bytes), "base64"),
        };
        let (format, accepted, reason) = match &parsed[name] {
            Ok(p) => (p.format.clone(), true, None),
            Err(_)
                if referenced.contains(name)
                    && !name.ends_with(".json")
                    && !name.ends_with(".sarif") =>
            {
                ("Subject artifact".into(), true, None)
            }
            Err(reason) => ("Unsupported / rejected".into(), false, Some(reason.clone())),
        };
        inputs.push(InputRecord {
            name: name.clone(),
            sha256: sha256.clone(),
            bytes: bytes.len(),
            format,
            accepted,
            reason,
            raw: raw_text,
            encoding: encoding.into(),
        });
        if let Ok(p) = &parsed[name] {
            let (mut checks, signer) = if let Some(statement) = &p.statement {
                dsse_checks(
                    p.envelope.as_ref().ok_or("Missing parsed envelope")?,
                    statement,
                    &files,
                    &keys,
                )
            } else {
                (
                    vec![check(
                        "Source integrity",
                        "Asserted",
                        "Unsigned source. Parsing is not cryptographic verification.",
                    )],
                    None,
                )
            };
            checks.push(check("Time assurance", "Asserted", "Any timestamps are source assertions; no external timestamp or freshness validation"));
            for item in &p.items {
                if evidence.len() >= 10000 {
                    return Err("Evidence exceeds 10,000 normalized items".into());
                }
                evidence.push(Evidence {
                    id: hash(format!("{sha256}:{}:{}", name, item.pointer).as_bytes()),
                    title: item.title.clone(),
                    kind: item.kind.clone(),
                    format: item.format.clone(),
                    source: name.clone(),
                    pointer: item.pointer.clone(),
                    status: status(&checks),
                    signer: signer.clone(),
                    checks: checks.clone(),
                    normalized: item.normalized.clone(),
                });
            }
        }
    }
    // Authenticate referenced source bytes only when the envelope signature is trusted.
    // Digest failure is carried through to every normalized item from that source.
    let authenticated: Vec<_> = evidence
        .iter()
        .filter(|e| {
            e.kind == "Attestation"
                && e.checks
                    .iter()
                    .any(|c| c.name == "Ed25519 signature" && c.status == "Pass")
        })
        .flat_map(|e| {
            e.normalized["subject"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(move |s| {
                    let name = s["name"].as_str()?.to_string();
                    let check = e
                        .checks
                        .iter()
                        .find(|c| c.name == format!("SHA-256 · {name}"))?;
                    if check.status != "Pass" && check.status != "Fail" {
                        return None;
                    }
                    Some((name, check.status.clone(), e.signer.clone(), e.id.clone()))
                })
        })
        .collect();
    for e in &mut evidence {
        if e.kind != "Attestation" {
            let links: Vec<_> = authenticated
                .iter()
                .filter(|(name, _, _, _)| name == &e.source)
                .collect();
            if !links.is_empty() {
                e.checks.remove(0);
                for (_, outcome, signer, id) in links {
                    e.checks.push(check(
                        "Source integrity",
                        outcome,
                        format!(
                            "Exact source bytes {} the digest in trusted attestation {id}",
                            if outcome == "Pass" {
                                "match"
                            } else {
                                "differ from"
                            }
                        ),
                    ));
                    e.signer = signer.clone();
                }
                e.status = status(&e.checks);
            }
        }
    }
    let controls = framework
        .controls
        .iter()
        .map(|rule| {
            let mut ids = BTreeSet::new();
            let requirements: Vec<_> = rule
                .requirements
                .iter()
                .map(|r| {
                    let candidates: Vec<_> = evidence
                        .iter()
                        .filter(|e| {
                            e.kind == r.kind
                                && r.field.as_ref().is_none_or(|field| {
                                    e.normalized
                                        .pointer(field)
                                        .is_some_and(|v| !v.is_null() && v != "" && v != &json!([]))
                                })
                        })
                        .collect();
                    for e in &candidates {
                        ids.insert(e.id.clone());
                    }
                    let matched: Vec<_> = candidates
                        .into_iter()
                        .filter(|e| {
                            e.status == "Valid"
                                || (r.min_strength == "Asserted" && e.status == "Asserted")
                        })
                        .map(|e| e.id.clone())
                        .collect();
                    RequirementResult {
                        label: r.label.clone(),
                        met: !matched.is_empty(),
                        evidence_ids: matched,
                    }
                })
                .collect();
            let met = requirements.iter().filter(|r| r.met).count();
            let broken = evidence
                .iter()
                .any(|e| ids.contains(&e.id) && e.status == "Invalid");
            let outcome = if broken {
                "Broken"
            } else if met == requirements.len() && met > 0 {
                "Evidenced"
            } else if !ids.is_empty() {
                "Partial"
            } else {
                "Not evidenced"
            };
            ControlResult {
                id: rule.id.clone(),
                title: rule.title.clone(),
                description: rule.description.clone(),
                status: outcome.into(),
                requirements,
                evidence_ids: ids.into_iter().collect(),
                limitation: rule.limitation.clone(),
            }
        })
        .collect::<Vec<_>>();
    let summary = Summary {
        files: inputs.len(),
        accepted: inputs.iter().filter(|i| i.accepted).count(),
        rejected: inputs.iter().filter(|i| !i.accepted).count(),
        evidence: evidence.len(),
        valid: evidence.iter().filter(|e| e.status == "Valid").count(),
        asserted: evidence.iter().filter(|e| e.status == "Asserted").count(),
        invalid: evidence.iter().filter(|e| e.status == "Invalid").count(),
        unverifiable: evidence
            .iter()
            .filter(|e| e.status == "Unverifiable")
            .count(),
        evidenced: controls.iter().filter(|c| c.status == "Evidenced").count(),
        partial: controls.iter().filter(|c| c.status == "Partial").count(),
        missing: controls
            .iter()
            .filter(|c| c.status == "Not evidenced")
            .count(),
        broken: controls.iter().filter(|c| c.status == "Broken").count(),
    };
    let mut report = Report {
        schema_version: "1.0.0".into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        report_id: String::new(),
        system: request.system,
        framework,
        inputs,
        evidence,
        controls,
        summary,
        limitations: LIMITATIONS.into(),
    };
    report.report_id = hash(&serde_json::to_vec(&report).map_err(|e| e.to_string())?);
    Ok(report)
}

pub fn exit_code(report: &Report, mode: &str, strict: bool) -> i32 {
    if report.summary.rejected > 0 {
        3
    } else if mode == "inspect" {
        0
    } else if report.summary.invalid > 0 {
        2
    } else if report.summary.unverifiable > 0
        || (strict && report.summary.asserted > 0)
        || (mode != "verify"
            && report
                .controls
                .iter()
                .any(|c| c.status != "Evidenced" && c.status != "Out of scope"))
    {
        1
    } else {
        0
    }
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn render(report: &Report, format: &str) -> Result<String, String> {
    if format == "json" {
        return serde_json::to_string_pretty(report).map_err(|e| e.to_string());
    }
    if format == "html" {
        let rows = report
            .controls
            .iter()
            .map(|c| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape(&c.id),
                    escape(&c.title),
                    escape(&c.status)
                )
            })
            .collect::<String>();
        let details = report.controls.iter().map(|c| format!("<section><h3>{} · {}</h3><p>{}</p><ul>{}</ul><p>Evidence IDs: {}</p><p>Limitations: {}</p></section>", escape(&c.id), escape(&c.status), escape(&c.description), c.requirements.iter().map(|r| format!("<li>{}: {}</li>", escape(&r.label), if r.met {"Present"} else {"Missing"})).collect::<String>(), escape(&c.evidence_ids.join(", ")), escape(&c.limitation))).collect::<String>();
        let evidence = report
            .evidence
            .iter()
            .map(|e| {
                format!(
                    "<section><h3>{}</h3><p>{} · {} · {}</p><code>{}</code><ul>{}</ul></section>",
                    escape(&e.title),
                    escape(&e.source),
                    escape(&e.format),
                    escape(&e.status),
                    escape(&e.id),
                    e.checks
                        .iter()
                        .map(|c| format!(
                            "<li>{} · {}: {}</li>",
                            escape(&c.name),
                            escape(&c.status),
                            escape(&c.reason)
                        ))
                        .collect::<String>()
                )
            })
            .collect::<String>();
        let inputs = report
            .inputs
            .iter()
            .map(|i| {
                format!(
                    "<li>{} · {} · {} bytes · SHA-256 {} {}</li>",
                    escape(&i.name),
                    escape(&i.format),
                    i.bytes,
                    escape(&i.sha256),
                    escape(i.reason.as_deref().unwrap_or(""))
                )
            })
            .collect::<String>();
        return Ok(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Aegis evidence report</title><style>body{{font:16px/1.65 system-ui;color:#24342f;background:#fafbf8;max-width:1000px;margin:50px auto;padding:24px}}h1{{font-size:36px}}h2{{margin-top:40px}}td,th{{text-align:left;padding:14px;border-bottom:1px solid #d9e0dc}}table{{width:100%;border-collapse:collapse}}code{{overflow-wrap:anywhere}}section{{padding:18px 0;border-bottom:1px solid #d9e0dc}}</style><h1>Aegis / Evidence report</h1><p>{} · {} · {} mappings</p><p>Report <code>{}</code></p><p>{} accepted files / {} rejected files / {} evidence items</p><table><tr><th>Control</th><th>Technical evidence rule</th><th>Outcome</th></tr>{rows}</table>{details}<h2>Integrity checks and evidence</h2>{evidence}<h2>Input accounting</h2><ul>{inputs}</ul><h2>What this does not prove</h2><p>{}</p></html>", escape(&report.system), escape(&report.framework.title), escape(&report.framework.status), escape(&report.report_id), report.summary.accepted, report.summary.rejected, report.summary.evidence, escape(&report.limitations)));
    }
    if format != "md" {
        return Err("Report format must be json, md, or html".into());
    }
    // Escape embedded HTML and Markdown punctuation in all source-derived text.
    let md = |s: &str| {
        escape(s)
            .chars()
            .flat_map(|c| {
                if "\\`*_{}[]()#+-.!|>".contains(c) {
                    vec!['\\', c]
                } else {
                    vec![c]
                }
            })
            .collect::<String>()
    };
    let mut output = format!(
        "# Aegis evidence report\n\n{} · {} · Draft mappings\n\nReport: {}\n\n## Control results\n",
        md(&report.system),
        md(&report.framework.title),
        report.report_id
    );
    for c in &report.controls {
        output.push_str(&format!(
            "\n### {} — {}\n\n{}\n",
            md(&c.id),
            md(&c.title),
            md(&c.status)
        ));
        for r in &c.requirements {
            output.push_str(&format!(
                "\n- {}: {}",
                md(&r.label),
                if r.met { "Present" } else { "Missing" }
            ));
        }
        output.push_str(&format!(
            "\n\nEvidence IDs: {}\n\nLimitations: {}\n",
            c.evidence_ids.join(", "),
            md(&c.limitation)
        ));
    }
    output.push_str("\n## Evidence and checks\n");
    for e in &report.evidence {
        output.push_str(&format!(
            "\n### {}\n\n{} · {} · {}\n\nID: {}\n",
            md(&e.title),
            md(&e.source),
            md(&e.format),
            e.status,
            e.id
        ));
        for c in &e.checks {
            output.push_str(&format!(
                "\n- {} / {}: {}",
                md(&c.name),
                c.status,
                md(&c.reason)
            ));
        }
        output.push('\n');
    }
    output.push_str("\n## Input accounting\n");
    for i in &report.inputs {
        output.push_str(&format!(
            "\n- {}: {} · {} bytes · SHA256 {} {}",
            md(&i.name),
            md(&i.format),
            i.bytes,
            i.sha256,
            md(i.reason.as_deref().unwrap_or(""))
        ));
    }
    output.push_str(&format!(
        "\n\n## What this does not prove\n\n{}\n",
        md(&report.limitations)
    ));
    Ok(output)
}

/// DSSE protocol 1.0.2 PAE uses UTF-8 byte lengths and the original payload bytes.
pub fn pre_authentication_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    bytes.extend_from_slice(payload);
    bytes
}
