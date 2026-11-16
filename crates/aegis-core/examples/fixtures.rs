use aegis_core::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Write, path::Path};
fn envelope(key: &SigningKey, name: &str, data: &[u8]) -> Value {
    let payload = serde_json::to_vec(&json!({"_type":"https://in-toto.io/Statement/v1", "subject":[{"name":name,"digest":{"sha256":hash(data)}}], "predicateType":"https://slsa.dev/provenance/v1", "predicate":{"buildDefinition":{"buildType":"https://example.invalid/aegis/demo","externalParameters":{},"resolvedDependencies":[]},"runDetails":{"builder":{"id":"https://example.invalid/aegis/demo-builder"}}}})).unwrap();
    let ty = "application/vnd.in-toto+json";
    let mut pae = format!("DSSEv1 {} {} {} ", ty.len(), ty, payload.len()).into_bytes();
    pae.extend_from_slice(&payload);
    json!({"payloadType":ty,"payload":STANDARD.encode(payload),"signatures":[{"keyid":"demo-ed25519","sig":STANDARD.encode(key.sign(&pae).to_bytes())}]})
}
fn bytes(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec_pretty(v).unwrap();
    b.push(b'\n');
    b
}

fn write_upload_example(root: &Path, files: &BTreeMap<String, Vec<u8>>, trust: &TrustStore) {
    let example_dir = root.join("examples/aegis-upload-demo");
    fs::create_dir_all(&example_dir).unwrap();

    let zip_path = example_dir.join("aegis-example-evidence.zip");
    let zip_file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(zip_file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for (name, data) in files {
        zip.start_file(name, options).unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap();

    fs::write(
        example_dir.join("trust-store.json"),
        bytes(&serde_json::to_value(trust).unwrap()),
    )
    .unwrap();
    fs::write(
        example_dir.join("README.md"),
        r#"# Aegis upload demo

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
"#,
    )
    .unwrap();
}
fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Public, deterministic TEST key; never use it to attest real evidence.
    let key = SigningKey::from_bytes(&[42; 32]);
    let trust = TrustStore {
        keys: vec![TrustedKey {
            id: "demo-ed25519".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            label: "Aegis demo builder (TEST KEY)".into(),
        }],
    };
    let inventory = json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"Atlas AI Assistant","version":"2.4.0"}},"components":[
        {"type":"machine-learning-model","name":"Atlas language model","version":"2.4.0","bom-ref":"atlas-llm","description":"Customer support language model","modelCard":{"considerations":{"useCases":["Assisted customer support"]}}},
        {"type":"machine-learning-model","name":"Text embedding model","version":"3.0","bom-ref":"atlas-embed"},
        {"type":"data","name":"Knowledge base dataset","version":"2026.11","bom-ref":"atlas-data"},
        {"type":"library","name":"Inference runtime","version":"1.8.2","bom-ref":"atlas-runtime"},
        {"type":"application","name":"Human review gateway","version":"1.2.0","bom-ref":"atlas-review"}
    ]});
    let scan = json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"Atlas security scan","version":"1.0.0"}},"results":[{"ruleId":"AI-001","level":"note","message":{"text":"Review model dependency provenance"}},{"ruleId":"AI-002","level":"warning","message":{"text":"Document the evaluation coverage boundary"}}]}]});
    let mut clean = BTreeMap::new();
    clean.insert("inventory.cdx.json".to_string(), bytes(&inventory));
    clean.insert("security.sarif".to_string(), bytes(&scan));
    clean.insert(
        "inventory.attestation.json".to_string(),
        bytes(&envelope(
            &key,
            "inventory.cdx.json",
            &clean["inventory.cdx.json"],
        )),
    );
    clean.insert(
        "scan.attestation.json".to_string(),
        bytes(&envelope(&key, "security.sarif", &clean["security.sarif"])),
    );
    let mut tampered = clean.clone();
    let mut changed = inventory.clone();
    changed["components"][0]["version"] = json!("9.9.9-modified");
    tampered.insert("inventory.cdx.json".to_string(), bytes(&changed));
    // A second attack: signed payload edited without re-signing.
    let mut envelope: Value = serde_json::from_slice(&tampered["scan.attestation.json"]).unwrap();
    let mut payload: Value = serde_json::from_slice(
        &STANDARD
            .decode(envelope["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    payload["predicate"]["runDetails"]["builder"]["id"] =
        json!("https://example.invalid/forged-builder");
    envelope["payload"] = json!(STANDARD.encode(serde_json::to_vec(&payload).unwrap()));
    tampered.insert("scan.attestation.json".to_string(), bytes(&envelope));
    let partial = BTreeMap::from([
        (
            "inventory.cdx.json".to_string(),
            clean["inventory.cdx.json"].clone(),
        ),
        (
            "scan.attestation.json".to_string(),
            clean["scan.attestation.json"].clone(),
        ),
    ]);
    fs::create_dir_all(root.join("web/verifier/src/generated")).unwrap();
    let mut demos = serde_json::Map::new();
    for (name, files) in [
        ("clean", clean),
        ("tampered", tampered),
        ("partial", partial),
    ] {
        if name == "clean" {
            write_upload_example(&root, &files, &trust);
        }
        let dir = root.join("fixtures").join(name);
        fs::create_dir_all(&dir).unwrap();
        for (file, data) in &files {
            fs::write(dir.join(file), data).unwrap();
        }
        let request = Request {
            files: files
                .iter()
                .map(|(name, data)| InputFile {
                    name: name.clone(),
                    data: STANDARD.encode(data),
                })
                .collect(),
            trust_store: if name == "partial" {
                TrustStore::default()
            } else {
                trust.clone()
            },
            framework: "nist-ai-rmf".into(),
            system: "Atlas AI Assistant".into(),
        };
        demos.insert(name.into(), serde_json::to_value(request).unwrap());
    }
    fs::write(
        root.join("fixtures/demo-trust-store.json"),
        bytes(&serde_json::to_value(&trust).unwrap()),
    )
    .unwrap();
    fs::write(
        root.join("web/verifier/src/generated/demos.json"),
        bytes(&Value::Object(demos)),
    )
    .unwrap();
}
