#![forbid(unsafe_code)]
use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub fn analyze(request_json: &str) -> Result<String, JsValue> {
    let request = serde_json::from_str(request_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid request: {e}")))?;
    let report = aegis_core::analyze(request).map_err(|e| JsValue::from_str(&e))?;
    serde_json::to_string(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}
#[wasm_bindgen]
pub fn render(report_json: &str, format: &str) -> Result<String, JsValue> {
    let report =
        serde_json::from_str(report_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    aegis_core::render(&report, format).map_err(|e| JsValue::from_str(&e))
}
