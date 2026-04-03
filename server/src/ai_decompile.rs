use serde_json::json;

use crate::ai_dec_cache::AiDecLine;
use crate::disassembler::Instruction;

/// Call Claude to decompile a method. Returns lines with optional bytecode offsets.
/// Runs synchronously (blocking) — call from a background thread.
pub fn ai_decompile_method(
    api_key: &str,
    model: &str,
    class_sig: &str,
    method_name: &str,
    bytecodes: &[Instruction],
) -> Result<Vec<AiDecLine>, String> {
    if bytecodes.is_empty() {
        return Err("No bytecodes loaded".into());
    }

    let listing: String = bytecodes.iter()
        .map(|i| format!("  {:04x}: {}", i.offset, i.text))
        .collect::<Vec<_>>()
        .join("\n");

    let prompt = format!(
        r#"Decompile the following Dalvik bytecode method into readable pseudo-Java.

Class: {}
Method: {}

Bytecodes:
{}

Rules:
- Output ONLY the decompiled code lines, no explanation, no markdown
- Start every line with [XXXX] where XXXX is the 4-digit lowercase hex offset of the primary bytecode it maps to
- For structural lines with no offset (closing braces, blank lines between blocks), use [-]
- Rename obfuscated names (a, b, v0, p1, etc.) to meaningful names based on context
- Deobfuscate: use string literals and logic to infer what methods/variables actually do
- Use pseudo-Java syntax, keep each line under 100 characters
- Use 4-space indentation for all code blocks, consistently
- Every opening brace must have a matching closing brace on its own line at the same indentation level
- A const/4 or const/16 instruction immediately followed by return on the same register is ONE statement: write it as a single return line (e.g. `return false;` or `return 0;`), tagged with the const offset

Example format:
[0000] public boolean checkLicense(Context ctx) {{
[0004]     String deviceId = Build.SERIAL;
[0008]     if (deviceId == null) {{
[-]             return false;
[-]         }}
[000e]     return this.verify(deviceId);
[-] }}"#,
        class_sig, method_name, listing
    );

    let body = json!({
        "model": model,
        "max_tokens": 4096,
        "messages": [{"role": "user", "content": prompt}],
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(format!("Claude API error {}: {}", status, body));
    }

    let body = resp.text()
        .map_err(|e| format!("Failed to read response body: {}", e))?;
    let resp_json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

    let text = resp_json["content"][0]["text"]
        .as_str()
        .ok_or_else(|| "No text content in Claude response".to_string())?;

    let lines = parse_response(text);

    // Validate: at least one offset-tagged line
    if lines.iter().filter(|l| l.offset.is_some()).count() == 0 {
        return Err("AI response had no offset-tagged lines - unexpected output format".into());
    }

    Ok(lines)
}

fn parse_response(text: &str) -> Vec<AiDecLine> {
    let mut lines = Vec::new();
    for raw in text.lines() {
        let trimmed = raw.trim_end();
        if trimmed.starts_with('[') {
            if let Some(close) = trimmed.find(']') {
                let tag = &trimmed[1..close];
                let after_tag = &trimmed[close + 1..];
                let rest = after_tag.strip_prefix(' ').unwrap_or(after_tag).to_string();
                if tag == "-" {
                    lines.push(AiDecLine { offset: None, text: rest });
                } else if let Ok(off) = i64::from_str_radix(tag, 16) {
                    lines.push(AiDecLine { offset: Some(off), text: rest });
                } else {
                    lines.push(AiDecLine { offset: None, text: trimmed.to_string() });
                }
                continue;
            }
        }
        // No tag — still include the line, just untagged
        lines.push(AiDecLine { offset: None, text: trimmed.to_string() });
    }
    lines
}
