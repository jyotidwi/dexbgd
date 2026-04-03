use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiDecLine {
    pub offset: Option<i64>,
    pub text: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AiDecCache {
    #[serde(default)]
    pub methods: HashMap<String, Vec<AiDecLine>>,
}

fn ai_dec_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("ai_dec")))
}

fn safe_filename(package: &str) -> String {
    package
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

impl AiDecCache {
    pub fn load(package: &str) -> Self {
        let dir = match ai_dec_dir() {
            Some(d) => d,
            None => return Self::default(),
        };
        let path = dir.join(format!("{}.json", safe_filename(package)));
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    pub fn save(&self, package: &str) -> std::io::Result<()> {
        let dir = ai_dec_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "cannot determine exe path")
        })?;
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", safe_filename(package)));
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Cache key: "Lcom/foo/Bar;::methodName"
    pub fn method_key(class: &str, method: &str) -> String {
        format!("{}::{}", class, method)
    }
}
