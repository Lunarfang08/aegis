use aegis_core::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::io::Write;
fn demo(name: &str) -> Request {
    let v: Value = serde_json::from_str(include_str!(
        "../../../web/verifier/src/generated/demos.json"
    ))
    .unwrap();
    serde_json::from_value(v[name].clone()).unwrap()
}
fn modify_json(f: &mut InputFile, callback: impl FnOnce(&mut Value)) {
    let mut v: Value = serde_json::from_slice(&STANDARD.decode(&f.data).unwrap()).unwrap();
    callback(&mut v);
    f.data = STANDARD.encode(serde_json::to_vec(&v).unwrap());
}
#[test]
fn clean_signatures_and_sources_verify() {
    let r = analyze(demo("clean")).unwrap();
    assert_eq!(r.summary.evidence, 10);
    assert_eq!(r.summary.valid, 10);
    assert_eq!(r.summary.invalid, 0);
    assert_eq!(r.summary.evidenced, 1);
    assert_eq!(exit_code(&r, "verify", false), 0);
    assert_eq!(exit_code(&r, "map", false), 1);
}
#[test]
fn payload_and_digest_tampering_fail() {
    let r = analyze(demo("tampered")).unwrap();
    assert!(r.summary.invalid >= 6);
    assert!(r.controls.iter().any(|c| c.status == "Broken"));
    assert_eq!(exit_code(&r, "verify", false), 2);
    assert!(r.evidence.iter().any(|e| e
        .checks
        .iter()
        .any(|c| c.name == "Ed25519 signature" && c.status == "Unverifiable")));
    assert!(r.evidence.iter().any(|e| e
        .checks
        .iter()
        .any(|c| c.name.starts_with("SHA-256") && c.status == "Fail")));
}
#[test]
fn unknown_keys_are_unverifiable() {
    let mut q = demo("clean");
    q.trust_store.keys.clear();
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.unverifiable, 2);
    assert_eq!(r.summary.asserted, 8);
    assert_eq!(exit_code(&r, "verify", false), 1);
}
#[test]
fn keyid_is_only_a_hint() {
    let mut q = demo("clean");
    for f in &mut q.files {
        if f.name.contains("attestation") {
            modify_json(f, |v| v["signatures"][0]["keyid"] = json!("untrusted-hint"));
        }
    }
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.valid, 10);
}
#[test]
fn wrong_key_is_not_accepted() {
    let mut q = demo("clean");
    q.trust_store.keys[0].public_key = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[21; 32])
            .verifying_key()
            .to_bytes(),
    );
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.unverifiable, 2);
    assert_eq!(r.summary.valid, 0);
}
#[test]
fn missing_artifact_is_unverifiable() {
    let mut q = demo("clean");
    q.files.retain(|f| f.name != "security.sarif");
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.unverifiable, 1);
    assert!(r
        .evidence
        .iter()
        .any(|e| e.checks.iter().any(|c| c.reason.contains("not supplied"))));
}
#[test]
fn partial_is_honest() {
    let r = analyze(demo("partial")).unwrap();
    assert_eq!(r.summary.valid, 0);
    assert!(r.summary.asserted > 0);
    assert!(r.summary.unverifiable > 0);
    assert!(r.controls.iter().any(|c| c.status == "Not evidenced"));
}
#[test]
fn deterministic_order_and_exports() {
    let q = demo("clean");
    let a = analyze(q.clone()).unwrap();
    let mut q = q;
    q.files.reverse();
    let b = analyze(q).unwrap();
    assert_eq!(render(&a, "json").unwrap(), render(&b, "json").unwrap());
    for f in ["json", "md", "html"] {
        assert_eq!(render(&a, f).unwrap(), render(&a, f).unwrap());
    }
    assert_eq!(a.report_id.len(), 64);
}
#[test]
fn malicious_markup_is_escaped() {
    let mut q = demo("clean");
    q.system = "<img src=x onerror=alert(1)>".into();
    let r = analyze(q).unwrap();
    let html = render(&r, "html").unwrap();
    assert!(!html.contains("<img"));
    assert!(html.contains("&lt;img"));
    assert!(!render(&r, "md").unwrap().contains("<img"));
}
#[test]
fn rejected_input_is_counted() {
    let mut q = demo("clean");
    q.files.push(InputFile {
        name: "broken.json".into(),
        data: STANDARD.encode(b"{broken"),
    });
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.rejected, 1);
    assert_eq!(exit_code(&r, "verify", false), 3);
    assert!(r.inputs.iter().any(|i| !i.accepted && i.reason.is_some()));
}
#[test]
fn unsupported_version_is_rejected() {
    let mut q = demo("clean");
    let f = q
        .files
        .iter_mut()
        .find(|f| f.name == "inventory.cdx.json")
        .unwrap();
    modify_json(f, |v| v["specVersion"] = json!("1.7"));
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.rejected, 1);
}
#[test]
fn unsafe_paths_duplicates_and_limits_fail() {
    for name in ["../escape", "/root", "x\\y", "C:disk", "a/../b", "a\0b"] {
        let mut q = demo("clean");
        q.files[0].name = name.into();
        assert!(analyze(q).is_err(), "{name}");
    }
    let mut q = demo("clean");
    q.files.push(q.files[0].clone());
    assert!(analyze(q).unwrap_err().contains("Duplicate"));
    let mut q = demo("clean");
    q.files[0].data = "A".repeat(MAX_FILE.div_ceil(3) * 4 + 1);
    assert!(analyze(q).is_err());
}
fn zip_file(name: &str, content: &[u8]) -> InputFile {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(content).unwrap();
    InputFile {
        name: "inputs.zip".into(),
        data: STANDARD.encode(zip.finish().unwrap().into_inner()),
    }
}
#[test]
fn zip_paths_and_nesting_are_rejected() {
    assert!(expand(vec![zip_file("../escape.json", b"{}")]).is_err());
    assert!(expand(vec![zip_file("nested.zip", b"PK\x03\x04")]).is_err());
}
#[test]
fn zip_roundtrip_matches_directory() {
    let mut q = demo("clean");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for f in &q.files {
        zip.start_file(&f.name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(&STANDARD.decode(&f.data).unwrap()).unwrap();
    }
    let expected = analyze(q.clone()).unwrap();
    q.files = vec![InputFile {
        name: "bundle.zip".into(),
        data: STANDARD.encode(zip.finish().unwrap().into_inner()),
    }];
    assert_eq!(analyze(q).unwrap().report_id, expected.report_id);
}
#[test]
fn trust_store_and_framework_validation() {
    let mut q = demo("clean");
    q.trust_store.keys.push(q.trust_store.keys[0].clone());
    assert!(analyze(q).is_err());
    let mut q = demo("clean");
    q.framework = "fake".into();
    assert!(analyze(q).is_err());
}
#[test]
fn eu_rules_never_claim_full_coverage() {
    let mut q = demo("clean");
    q.framework = "eu-ai-act".into();
    let r = analyze(q).unwrap();
    assert_eq!(r.controls.len(), 3);
    assert_eq!(r.summary.evidenced, 0);
    assert_eq!(r.framework.status, "draft");
}
#[test]
fn source_is_preserved_exactly() {
    let q = demo("clean");
    let expected = q
        .files
        .iter()
        .map(|f| (f.name.clone(), STANDARD.decode(&f.data).unwrap()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let r = analyze(q).unwrap();
    for i in &r.inputs {
        assert_eq!(i.raw.as_bytes(), expected[&i.name]);
        assert_eq!(i.sha256, hash(i.raw.as_bytes()));
    }
}

#[test]
fn published_dsse_pae_vector() {
    // DSSE protocol v1.0.2, Test Vectors.
    assert_eq!(
        pre_authentication_encoding("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );
    assert_eq!(
        pre_authentication_encoding("é", b""),
        b"DSSEv1 2 \xc3\xa9 0 "
    );
}
#[test]
fn dsse_urlsafe_base64_is_accepted() {
    let mut q = demo("clean");
    for f in &mut q.files {
        if f.name.contains("attestation") {
            modify_json(f, |v| {
                v["payload"] = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(STANDARD.decode(v["payload"].as_str().unwrap()).unwrap()));
                v["signatures"][0]["sig"] = json!(base64::engine::general_purpose::URL_SAFE
                    .encode(
                        STANDARD
                            .decode(v["signatures"][0]["sig"].as_str().unwrap())
                            .unwrap()
                    ));
            });
        }
    }
    assert_eq!(analyze(q).unwrap().summary.valid, 10);
}
#[test]
fn signature_structure_failure_is_invalid() {
    let mut q = demo("clean");
    for f in &mut q.files {
        if f.name.contains("attestation") {
            modify_json(f, |v| {
                v["signatures"][0]["sig"] = json!(STANDARD.encode(b"invalid-length"))
            });
        }
    }
    let r = analyze(q).unwrap();
    assert_eq!(r.summary.invalid, 2);
    assert_eq!(r.summary.valid, 0);
}
