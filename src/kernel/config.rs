use camino::Utf8Path;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotConfig {
    values: HashMap<String, String>,
}

impl DotConfig {
    pub fn from_path(path: impl AsRef<Utf8Path>) -> crate::Result<Self> {
        let content = fs::read_to_string(path.as_ref().as_std_path())?;
        Self::from_text(&content)
    }

    pub fn from_text(text: &str) -> crate::Result<Self> {
        let mut values = HashMap::new();

        for line in text.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse CONFIG_* lines
            if line.starts_with("CONFIG_") {
                if let Some(eq_pos) = line.find('=') {
                    let key = line[..eq_pos].to_string();
                    let value = line[eq_pos + 1..].to_string();
                    values.insert(key, value);
                }
            }
            // Handle "# CONFIG_* is not set" lines
            else if line.starts_with("# CONFIG_") && line.ends_with(" is not set") {
                let start = 2; // Skip "# "
                let end = line.len() - " is not set".len();
                let key = line[start..end].to_string();
                values.insert(key, "n".to_string());
            }
        }

        Ok(Self { values })
    }

    pub fn is_enabled(&self, symbol: &str, include_modules: bool) -> bool {
        match self.values.get(symbol) {
            Some(value) => match value.as_str() {
                "y" => true,
                "m" => include_modules,
                _ => false,
            },
            None => false,
        }
    }

    pub fn enabled_set(&self, include_modules: bool) -> HashSet<String> {
        self.values
            .iter()
            .filter_map(|(key, value)| match value.as_str() {
                "y" => Some(key.clone()),
                "m" if include_modules => Some(key.clone()),
                _ => None,
            })
            .collect()
    }
}
