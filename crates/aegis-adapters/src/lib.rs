#![forbid(unsafe_code)]
use base64::{engine::general_purpose::STANDARD, Engine};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ParsedEvidence {
    pub title: String,
    pub kind: String,
    pub format: String,
    pub pointer: String,
    pub normalized: Value,
}

pub struct SignedEnvelope {
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

pub struct ParsedFile {
    pub format: String,
    pub items: Vec<ParsedEvidence>,
    pub statement: Option<Value>,
    pub envelope: Option<SignedEnvelope>,
}

fn item(
    title: String,
    kind: &str,
    format: &str,
    pointer: String,
    normalized: Value,
) -> ParsedEvidence {
    ParsedEvidence {
        title,
        kind: kind.into(),
        format: format.into(),
        pointer,
        normalized,
    }
}

pub fn parse(bytes: &[u8]) -> Result<ParsedFile, String> {
    let v: Value = parse_json(bytes).map_err(|e| format!("Not supported JSON: {e}"))?;
    let mut items = Vec::new();
    let format;
    let mut statement = None;
    let mut envelope = None;
    if v.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
        if v["specVersion"] != "1.6" {
            return Err("Only CycloneDX JSON 1.6 is supported".into());
        }
        format = "CycloneDX 1.6";
        let components = v["components"]
            .as_array()
            .ok_or("CycloneDX components must be an array")?;
        if components.len() > 10000 {
            return Err("Inventory exceeds 10,000 item limit".into());
        }
        for (i, c) in components.iter().enumerate() {
            let title = c["name"]
                .as_str()
                .ok_or("A CycloneDX component is missing its name")?;
            if !c["type"].is_string() {
                return Err("A CycloneDX component is missing its type".into());
            }
            items.push(item(
                title.into(),
                "Inventory",
                format,
                format!("/components/{i}"),
                c.clone(),
            ));
        }
        if items.is_empty() {
            return Err("CycloneDX inventory contains no components".into());
        }
    } else if v.get("payloadType").is_some() {
        if v["payloadType"] != "application/vnd.in-toto+json" {
            return Err("Unsupported DSSE payload type".into());
        }
        let payload = decode_base64(v["payload"].as_str().ok_or("DSSE payload must be base64")?)
            .map_err(|_| "Invalid DSSE payload base64")?;
        let s: Value = parse_json(&payload).map_err(|e| format!("Invalid in-toto payload: {e}"))?;
        if s["_type"] != "https://in-toto.io/Statement/v1" {
            return Err("Only in-toto Statement v1 is supported".into());
        }
        let subjects = s["subject"]
            .as_array()
            .filter(|x| !x.is_empty())
            .ok_or("in-toto subjects must be a nonempty array")?;
        for sub in subjects {
            if !sub["name"].is_string() || !sub["digest"].is_object() {
                return Err("Subject requires name and digest".into());
            }
        }
        if !s["predicateType"].is_string() || !s["predicate"].is_object() {
            return Err("Statement requires predicateType and predicate object".into());
        }
        let signatures = v["signatures"]
            .as_array()
            .filter(|s| !s.is_empty() && s.len() <= 16)
            .ok_or("DSSE requires 1 to 16 signatures")?;
        let signatures = signatures
            .iter()
            .map(|s| {
                if s.get("keyid").is_some_and(|k| !k.is_string()) {
                    return Err("DSSE keyid must be a string".to_string());
                }
                decode_base64(s["sig"].as_str().ok_or("DSSE signature.sig is required")?)
                    .map_err(|_| "Invalid DSSE signature base64".into())
            })
            .collect::<Result<Vec<_>, String>>()?;
        envelope = Some(SignedEnvelope {
            payload_type: "application/vnd.in-toto+json".into(),
            payload,
            signatures,
        });
        format = "in-toto / DSSE";
        items.push(item(
            format!(
                "Attestation · {}",
                subjects[0]["name"].as_str().unwrap_or("artifact")
            ),
            "Attestation",
            format,
            "/payload".into(),
            s.clone(),
        ));
        statement = Some(s);
    } else if v["version"] == "2.1.0" && v.get("runs").is_some() {
        format = "SARIF 2.1.0";
        let runs = v["runs"].as_array().ok_or("SARIF runs must be an array")?;
        if runs.is_empty() {
            return Err("SARIF runs must not be empty".into());
        }
        for (r, run) in runs.iter().enumerate() {
            let tool = run["tool"]["driver"]["name"]
                .as_str()
                .ok_or("SARIF tool.driver.name is required")?;
            let results = run["results"]
                .as_array()
                .ok_or("SARIF results must be an array")?;
            items.push(item(
                format!("{tool} · scan summary"),
                "Scan",
                format,
                format!("/runs/{r}"),
                serde_json::json!({"tool": tool, "findings": results.len()}),
            ));
            if items.len() + results.len() > 10000 {
                return Err("SARIF exceeds 10,000 item limit".into());
            }
            for (i, result) in results.iter().enumerate() {
                let title = result["message"]["text"]
                    .as_str()
                    .or_else(|| result["message"]["markdown"].as_str())
                    .ok_or("SARIF result.message text is required")?;
                items.push(item(
                    title.into(),
                    "Finding",
                    format,
                    format!("/runs/{r}/results/{i}"),
                    result.clone(),
                ));
            }
        }
    } else {
        return Err(
            "Unsupported format; expected CycloneDX 1.6, SARIF 2.1.0, or in-toto v1 / DSSE".into(),
        );
    }
    Ok(ParsedFile {
        format: format.into(),
        items,
        statement,
        envelope,
    })
}

/// Reject duplicate object members rather than silently choosing one interpretation.
pub fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
    use std::fmt;
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("JSON without duplicate members")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                    Ok(Strict(Value::Bool(v)))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                    serde_json::Number::from_f64(v)
                        .map(|n| Strict(Value::Number(n)))
                        .ok_or_else(|| E::custom("Non-finite JSON number"))
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                    Ok(Strict(Value::String(v.into())))
                }
                fn visit_string<E: de::Error>(self, v: String) -> Result<Strict, E> {
                    Ok(Strict(Value::String(v)))
                }
                fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                    let mut values = Vec::new();
                    while let Some(Strict(v)) = seq.next_element()? {
                        values.push(v);
                    }
                    Ok(Strict(Value::Array(values)))
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                    let mut values = serde_json::Map::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if values.contains_key(&key) {
                            return Err(de::Error::custom(format!("Duplicate JSON member: {key}")));
                        }
                        let Strict(v) = map.next_value()?;
                        values.insert(key, v);
                    }
                    Ok(Strict(Value::Object(values)))
                }
            }
            deserializer.deserialize_any(V)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut deserializer).map_err(|e| e.to_string())?;
    deserializer.end().map_err(|e| e.to_string())?;
    Ok(value)
}

/// DSSE 1.0.2 requires both standard and URL-safe base64 variants.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .or_else(|_| URL_SAFE_NO_PAD.decode(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_members_are_rejected_at_every_depth() {
        assert!(parse_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_json(br#"{"a":[{"b":true,"b":false}]}"#).is_err());
        assert!(parse_json(br#"{"a":1} trailing"#).is_err());
        assert_eq!(
            parse_json(br#"{"a":[null,true,-1,2,1.25,"ok"]}"#).unwrap()["a"][4],
            1.25
        );
    }
}
